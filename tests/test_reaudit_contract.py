import unittest,json,sys,subprocess,copy,base64,hashlib,datetime
from saml_metadata_review import audit
from saml_metadata_review.common import ReviewError,load
import test_review as fixtures
def reject(test,d):
    with test.assertRaises(ReviewError):audit(d)
    p=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10)
    out=json.loads(p.stdout);test.assertEqual(p.returncode,1);test.assertEqual(out['status'],'FAIL');test.assertFalse(out['complete']);test.assertFalse(out.get('verified',False))
class FiniteInputTests(unittest.TestCase):
    def test_exponent_overflow_rejected_api_and_cli(self):
        for raw in (b'{"x":1e999}',b'{"x":[-1e999]}'):
            with self.assertRaises(ReviewError):load(raw)
            p=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=raw,capture_output=True,timeout=10);out=json.loads(p.stdout)
            self.assertEqual(p.returncode,1);self.assertFalse(out['complete']);self.assertEqual(out['status'],'FAIL')
        self.assertEqual(load(b'{"x":1.25}'),{'x':1.25})
    def test_unknown_fields_error_does_not_echo_canary(self):
        canary='SYNTHETIC-PRIVATE-CANARY-cc94e6f3'
        with self.assertRaises(ReviewError) as e:audit({canary:canary})
        self.assertNotIn(canary,str(e.exception))
        p=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=json.dumps({canary:canary}).encode(),capture_output=True,timeout=10)
        self.assertEqual(p.returncode,1);self.assertNotIn(canary,p.stdout.decode()+p.stderr.decode())
class EndpointTests(unittest.TestCase):
    def setUp(self):self.fixture=fixtures.SamlTests();self.fixture.setUp()
    def request(self,value,response=False):
        d=copy.deepcopy(self.fixture.d)
        if response:d['metadata_xml']=d['metadata_xml'].replace('Location="https://idp.synthetic.invalid/sso"','Location="https://idp.synthetic.invalid/sso" ResponseLocation="'+value+'"')
        else:d['metadata_xml']=d['metadata_xml'].replace('https://idp.synthetic.invalid/sso',value)
        return d
    def test_invalid_endpoint_uri_api_cli(self):
        bad=('https://idp.synthetic.invalid:evil/sso','https://idp.synthetic.invalid:65536/sso','https://@idp.synthetic.invalid/sso','https://idp.synthetic.invalid:/sso','https://idp.synthetic.invalid/'+chr(10)+'sso','https://bad host.invalid/sso','https://idp.synthetic.invalid/%zz','https://idp.synthetic.invalid'+chr(92)+'sso','https://idp.synthetic.invalid/sso#fragment')
        for response in (False,True):
            for value in bad:
                with self.subTest(uri=value,response=response):reject(self,self.request(value,response))
    def test_valid_endpoints_with_ports_paths_and_queries(self):
        for value in ('https://idp.synthetic.invalid:65535/sso','https://idp.synthetic.invalid:0/sso','https://[2001:db8::1]:8443/sso','https://192.0.2.1/sso','https://xn--bcher-kva.invalid/%E6%97%A5?view=1'):
            with self.subTest(uri=value):self.assertEqual(audit(self.request(value))['status'],'PASS')

class FilePlatformCapabilityTests(unittest.TestCase):
    def test_missing_or_unusable_file_flags_fail_closed(self):
        from unittest import mock
        from saml_metadata_review.common import read
        from saml_metadata_review import common
        for flag in ('O_NOFOLLOW','O_NONBLOCK'):
            for value in (None,0,'unusable'):
                with mock.patch.object(common.os,flag,value,create=True):
                    with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
            with mock.patch.object(common.os,flag,1,create=True):
                delattr(common.os,flag)
                with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')

class SupportedXmlIdTests(unittest.TestCase):
    def request(self,entity='entity_id',role='role.id-1',key='_key_1'):
        t=fixtures.SamlTests();t.setUp();xml=t.d['metadata_xml']
        xml=xml.replace('<EntityDescriptor ','<EntityDescriptor ID="'+entity+'" ').replace('<IDPSSODescriptor ','<IDPSSODescriptor ID="'+role+'" ').replace('<ds:KeyInfo>','<ds:KeyInfo Id="'+key+'">')
        return {**t.d,'metadata_xml':xml}
    def test_distinct_supported_ids_and_opaque_signature_ids(self):
        d=self.request();self.assertEqual(audit(d)['status'],'PASS')
        d['metadata_xml']=d['metadata_xml'].replace('</EntityDescriptor>','<ds:Signature Id="entity_id"><ds:Object Id="entity_id"/></ds:Signature></EntityDescriptor>')
        r=audit(d);self.assertEqual(r['status'],'PASS');self.assertFalse(r['verified']);self.assertFalse(r['entities'][0]['metadata_signature_verified'])
    def test_entity_role_keyinfo_cross_duplicates_api_cli(self):
        for ids in (('same','same','key'),('same','role','same'),('entity','same','same')):reject(self,self.request(*ids))
    def test_invalid_ascii_ncname_ids_api_cli(self):
        for value in ('','1invalid','has space','a:b','日本語','a'*257):
            for field in range(3):
                ids=['entity','role','key'];ids[field]=value;reject(self,self.request(*ids))

class XmlTextEncodingTests(unittest.TestCase):
    def test_utf16_utf32_dtd_carriers_and_forbidden_characters_api_cli(self):
        t=fixtures.SamlTests();t.setUp();eid=t.d['expected_entity_ids'][0]
        for encoding in ('utf-16-le','utf-16-be','utf-32-le','utf-32-be'):
            declaration='UTF-16' if encoding.startswith('utf-16') else 'UTF-32'
            xml='<?xml version="1.0" encoding="'+declaration+'"?><!DOCTYPE EntityDescriptor [<!ENTITY identity "'+eid+'">]>'+t.d['metadata_xml'].replace('entityID="'+eid+'"','entityID="&identity;"')
            d={**t.d,'metadata_xml':xml.encode(encoding).decode('utf-8')}
            with self.subTest(encoding=encoding):reject(self,d)
        for code in (0,1,11,12,31,0xd800,0xfffe,0xffff):
            d={**t.d,'metadata_xml':t.d['metadata_xml']+'<!--'+chr(code)+'-->'}
            with self.subTest(code=code):reject(self,d)
    def test_normal_unicode_utf8_and_allowed_xml_whitespace(self):
        t=fixtures.SamlTests();t.setUp();eid=t.d['expected_entity_ids'][0];unicode_eid='urn:synthetic:日本語:😀'
        xml=t.d['metadata_xml'].replace('entityID="'+eid+'"','entityID="'+unicode_eid+'"')
        d={**t.d,'expected_entity_ids':[unicode_eid],'metadata_xml':'<?xml version="1.0" encoding="UTF-8"?>\n\t\r'+xml+'<!--日本語😀-->'}
        r=audit(d);self.assertEqual(r['status'],'PASS');self.assertFalse(r['verified'])
        p=subprocess.run([sys.executable,'-m','saml_metadata_review','-'],input=json.dumps(d,ensure_ascii=False).encode('utf-8'),capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0);self.assertEqual(json.loads(p.stdout)['status'],'PASS')
