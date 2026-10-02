import unittest, json, base64, hashlib, tempfile, pathlib, datetime, copy, subprocess, sys, os, struct
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa
from saml_metadata_review import audit
from saml_metadata_review.common import ReviewError,load,read
UTC=datetime.timezone.utc
def enc(b):return base64.b64encode(b).decode()
def url(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def pemkey(k):return k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def certs(leaf_extensions=(),issuer_extensions=()):
    now=datetime.datetime.now(UTC).replace(microsecond=0);issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);leaf_key=ed25519.Ed25519PrivateKey.generate()
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Review CA')])
    ku=x509.KeyUsage(True,False,False,False,False,True,True,False,False)
    builder=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(issuer_key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(ku,True).add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),False)
    for ext,critical in issuer_extensions:builder=builder.add_extension(ext,critical)
    issuer=builder.sign(issuer_key,hashes.SHA256())
    builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.invalid')])).issuer_name(subject).public_key(leaf_key.public_key()).serial_number(10).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
    for ext,critical in leaf_extensions:builder=builder.add_extension(ext,critical)
    leaf=builder.sign(issuer_key,hashes.SHA256());return now,issuer_key,issuer,leaf_key,leaf
def cpem(c):return c.public_bytes(serialization.Encoding.PEM).decode()
def save_example(d):
    if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':return
    out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True)
    (out/'valid.json').write_text(json.dumps(d,indent=2)+'\n')
class CommonTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_input(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(ReviewError):load(raw)
    def test_input_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t);(p/'file').write_text('x');(p/'link').symlink_to(p/'file');os.mkfifo(p/'pipe')
            for q in (p/'link',p/'pipe'):
                with self.assertRaises((ReviewError,OSError)):read(str(q))
    def test_missing_fields_and_cli_exit(self):
        with self.assertRaises((ReviewError,KeyError)):audit({})
        proc=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=b'{}',capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,1);self.assertEqual(json.loads(proc.stdout)['status'],'FAIL');self.assertFalse(json.loads(proc.stdout)['complete'])

class SamlTests(unittest.TestCase):
    def setUp(self):
        now,key,issuer,_,_=certs();der=enc(issuer.public_bytes(serialization.Encoding.DER));self.d={'now':now.isoformat(),'expected_entity_ids':['https://idp.synthetic.invalid/entity'],'metadata_xml':'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.synthetic.invalid/entity" validUntil="'+(now+datetime.timedelta(days=1)).isoformat()+'"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+der+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.synthetic.invalid/sso"/></IDPSSODescriptor></EntityDescriptor>'}
    def test_valid_static_metadata(self):self.assertFalse(audit(self.d)['verified']);save_example(self.d)
    def test_acs_unsigned_short_lexical_api_cli(self):
        sp=copy.deepcopy(self.d);sp['metadata_xml']=sp['metadata_xml'].replace('IDPSSODescriptor','SPSSODescriptor').replace('Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.synthetic.invalid/sso"','Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.synthetic.invalid/acs" index="INDEX"').replace('SingleSignOnService','AssertionConsumerService')
        for value in ('+1','000001',' '+chr(9)+'1'+chr(10)+' '):
            d={**sp,'metadata_xml':sp['metadata_xml'].replace('INDEX',value)};self.assertEqual(audit(d)['status'],'PASS')
        for value in ('١','1_0','-1','65536','1 0',chr(160)+'1',('0'*65)):
            d={**sp,'metadata_xml':sp['metadata_xml'].replace('INDEX',value)}
            with self.assertRaises(ReviewError):audit(d)
            p=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10);self.assertEqual(p.returncode,1);self.assertEqual(json.loads(p.stdout)['status'],'FAIL');self.assertFalse(json.loads(p.stdout)['complete'])
    def test_role_endpoints_key_use_and_cli(self):
        implicit=copy.deepcopy(self.d);implicit['metadata_xml']=implicit['metadata_xml'].replace(' use="signing"','');self.assertEqual(audit(implicit)['status'],'PASS')
        acs='<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.synthetic.invalid/acs" index="0"/>'
        sso='<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.synthetic.invalid/sso"/>'
        sp=copy.deepcopy(self.d);sp['metadata_xml']=sp['metadata_xml'].replace('IDPSSODescriptor','SPSSODescriptor').replace('Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.synthetic.invalid/sso"','Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.synthetic.invalid/acs" index="0"').replace('SingleSignOnService','AssertionConsumerService');self.assertEqual(audit(sp)['status'],'PASS')
        cases=[self.d['metadata_xml'].replace('use="signing"','use="both"'),self.d['metadata_xml'].replace('</IDPSSODescriptor>',acs+'</IDPSSODescriptor>'),sp['metadata_xml'].replace('</SPSSODescriptor>',sso+'</SPSSODescriptor>'),self.d['metadata_xml'].replace('<IDPSSODescriptor ','<IDPSSODescriptor WantAssertionsSigned="true" ')]
        for xml in cases:
            d={**self.d,'metadata_xml':xml}
            with self.assertRaises(ReviewError):audit(d)
            proc=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10);result=json.loads(proc.stdout);self.assertEqual(proc.returncode,1);self.assertEqual(result['status'],'FAIL');self.assertFalse(result['complete'])
    def test_depth_budget_in_skipped_signature_subtree(self):
        nested='<ds:Signature>'+('<ds:Object>'*40)+'</ds:Object>'*40+'</ds:Signature>'
        d=copy.deepcopy(self.d);d['metadata_xml']=d['metadata_xml'].replace('</EntityDescriptor>',nested+'</EntityDescriptor>')
        with self.assertRaises(ReviewError):audit(d)
    def test_identity_http_dtd_expiry_unknown(self):
        mutations=[lambda d:d.update(expected_entity_ids=['unexpected']),lambda d:d.update(metadata_xml=d['metadata_xml'].replace('https://idp.synthetic.invalid/sso','http://idp.synthetic.invalid/sso')),lambda d:d.update(metadata_xml='<!DOCTYPE x [<!ENTITY y "x">]>'+d['metadata_xml']),lambda d:d.update(now='2099-01-01T00:00:00Z'),lambda d:d.update(metadata_xml=d['metadata_xml'].replace('</IDPSSODescriptor>','<Extensions/></IDPSSODescriptor>'))]
        for change in mutations:
            d=copy.deepcopy(self.d);change(d)
            with self.assertRaises(ReviewError):audit(d)

if __name__=="__main__":unittest.main()
