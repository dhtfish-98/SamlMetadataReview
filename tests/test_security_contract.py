import unittest,json,subprocess,sys,copy,base64,hashlib,datetime,pathlib,re,struct
from saml_metadata_review import audit
from saml_metadata_review.common import ReviewError,load,string

class UnicodeContractTests(unittest.TestCase):
    def test_surrogate_rejected_api_and_cli(self):
        self.assertEqual(string('合法 Unicode'),'合法 Unicode')
        with self.assertRaises(ReviewError):string(chr(0xd800))
        for raw in (b'{"x":"\\ud800"}',b'{"\\udfff":1}'):
            with self.assertRaises(ReviewError):load(raw)
            p=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=raw,capture_output=True,timeout=10);self.assertEqual(p.returncode,1);self.assertEqual(json.loads(p.stdout)['status'],'FAIL');self.assertFalse(json.loads(p.stdout)['complete'])
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from saml_metadata_review.crypto import valid_public_key,pubkey,verify,verify_x509,certificate,signed_der,der_sequence
import test_review as fixtures
UTC=datetime.timezone.utc
BAD_POINTS=(bytes([1])+bytes(31),bytes(32),(2**255-19).to_bytes(32,'little'),bytes.fromhex('5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea'))
FORGED_SIGNATURE=bytes([1])+bytes(31)+bytes(32)
def pem_public(raw):return ed25519.Ed25519PublicKey.from_public_bytes(raw).public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def cert_for_point(raw,subject=None,issuer=None,key=None,ca=False,ocsp_signer=False):
    now=datetime.datetime.now(UTC).replace(microsecond=0);key=key or rsa.generate_private_key(public_exponent=65537,key_size=2048);subject=subject or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic point fixture')]);issuer=issuer or subject
    b=x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(ed25519.Ed25519PublicKey.from_public_bytes(raw)).serial_number(10).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=ca,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,ca,ca,False,False),True)
    if ocsp_signer:b=b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),False)
    return b.sign(key,hashes.SHA256())
def rejected_request(test,d):
    with test.assertRaises(ReviewError):audit(d)
    p=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10);result=json.loads(p.stdout);test.assertEqual(p.returncode,1);test.assertEqual(result['status'],'FAIL');test.assertFalse(result['complete']);test.assertFalse(result.get('verified',False))
class CryptoPrimitiveBoundaryTests(unittest.TestCase):
    def test_raw_pem_certificate_and_signature_public_point_gates(self):
        for raw in BAD_POINTS:
            key=ed25519.Ed25519PublicKey.from_public_bytes(raw)
            for f in (lambda:valid_public_key(key),lambda:pubkey(pem_public(raw)),lambda:verify(key,FORGED_SIGNATURE,b'authorized evidence','Ed25519'),lambda:certificate(cert_for_point(raw).public_bytes(serialization.Encoding.PEM).decode())):
                with self.assertRaises(ReviewError):f()
        k=ed25519.Ed25519PrivateKey.generate()
        for sig in (FORGED_SIGNATURE,k.sign(b'x')[:32]+(2**252+27742317777372353535851937790883648493).to_bytes(32,'little')):
            with self.assertRaises(ReviewError):verify(k.public_key(),sig,b'x','Ed25519')
    def test_duplicate_and_trailing_pem_rejected(self):
        k=ed25519.Ed25519PrivateKey.generate();key=k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode();cert=cert_for_point(k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).public_bytes(serialization.Encoding.PEM).decode()
        for text,check in ((key+key,pubkey),(key+'trailing garbage',pubkey),(cert+cert,certificate),(cert+'trailing garbage',certificate)):
            with self.assertRaises(ReviewError):check(text)
    def test_signature_oid_family_and_hash_binding(self):
        data=b'algorithm mismatch fixture';k=ed25519.Ed25519PrivateKey.generate()
        with self.assertRaises(ReviewError):verify_x509(k.public_key(),k.sign(data),data,hashes.SHA256(),ObjectIdentifier('1.2.840.113549.1.1.11'))
        k=ec.generate_private_key(ec.SECP256R1());sig=k.sign(data,ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(ReviewError):verify_x509(k.public_key(),sig,data,hashes.SHA256(),ObjectIdentifier('1.2.840.113549.1.1.11'))
        with self.assertRaises(ReviewError):verify_x509(k.public_key(),sig,data,hashes.SHA256(),ObjectIdentifier('1.2.840.10045.4.3.3'))
class ProfilePointGateTests(unittest.TestCase):
    def test_invalid_der_metadata_points_api_cli(self):
        t=fixtures.SamlTests();t.setUp()
        for raw in BAD_POINTS:
            der=cert_for_point(raw).public_bytes(serialization.Encoding.DER);d=copy.deepcopy(t.d);d['metadata_xml']=re.sub(r'<ds:X509Certificate>[^<]*</ds:X509Certificate>','<ds:X509Certificate>'+fixtures.enc(der)+'</ds:X509Certificate>',d['metadata_xml']);rejected_request(self,d)
