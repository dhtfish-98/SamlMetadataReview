from .common import *
from .crypto import *
import xml.etree.ElementTree as ET,re,ipaddress
from urllib.parse import urlsplit
MD='urn:oasis:names:tc:SAML:2.0:metadata';DS='http://www.w3.org/2000/09/xmldsig#'
BINDINGS={'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST','urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect','urn:oasis:names:tc:SAML:2.0:bindings:SOAP'}
def xs_ushort(v):
    value=re.sub(r'[ '+chr(9)+chr(10)+chr(13)+']+',' ',string(v,64)).strip(' ')
    need(re.fullmatch(r'[+]?[0-9]+',value) is not None,"invalid ASCII unsignedShort lexical form")
    return integer(int(value),0,65535)
def https(v):
    value=string(v,4096)
    need(re.fullmatch(r"[A-Za-z0-9\-._~:/?\[\]@!$&'()*+,;=%]+",value) is not None and not re.search(r'%(?![0-9A-Fa-f]{2})',value),"endpoint must use a valid ASCII HTTPS URI")
    try:p=urlsplit(value);host=p.hostname;port=p.port
    except ValueError:raise ReviewError("invalid endpoint host or port") from None
    need(p.scheme=='https' and host and p.username is None and p.password is None and not p.fragment,"endpoint must use HTTPS without userinfo or fragment")
    if ':' in host:
        try:ipaddress.IPv6Address(host)
        except ValueError:raise ReviewError("invalid endpoint host") from None
        need('%' not in host,"scoped IP endpoint unsupported")
    else:
        labels=host.removesuffix('.').split('.')
        need(len(host)<=253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in labels),"invalid endpoint host")
        if labels[-1].isdigit() or re.fullmatch(r'0x[0-9a-f]+',labels[-1]):
            try:ipaddress.IPv4Address(host)
            except ValueError:raise ReviewError("invalid endpoint IPv4 host") from None
        else:
            try:host.encode('ascii').decode('idna')
            except UnicodeError:raise ReviewError("invalid endpoint IDNA host") from None
    need(not p.netloc.endswith(':'),"empty endpoint port")
def audit(d):
    fields(d,['metadata_xml','expected_entity_ids','now']);raw=string(d['metadata_xml'],2097152)
    need(all(ord(c) in (9,10,13) or 0x20<=ord(c)<=0xd7ff or 0xe000<=ord(c)<=0xfffd or 0x10000<=ord(c)<=0x10ffff for c in raw),"XML character outside supported XML 1.0 text profile")
    need(not re.search(r'<!DOCTYPE|<!ENTITY',raw,re.I),"DTD and entity declarations forbidden")
    try:root=ET.fromstring(raw)
    except ET.ParseError:raise ReviewError("invalid XML metadata") from None
    stack=[(root,0)];total=0
    while stack:
        element,level=stack.pop();total+=1;need(total<=8192 and level<=32,"XML resource limit")
        stack.extend((child,level+1) for child in element)
    now=instant(d['now']);ids=seq(d['expected_entity_ids'],128);need(ids and len(set(ids))==len(ids),"expected entity identities missing or duplicated")
    expected=set(string(v,4096) for v in ids);seen=set();out=[];xmlids=set();nodes=0
    def check_id(el,attribute):
        if attribute not in el.attrib:return
        value=string(el.attrib[attribute],256)
        need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',value) is not None,"XML ID outside strict ASCII NCName profile")
        need(value not in xmlids,"duplicate supported XML ID");xmlids.add(value)
    def visit(el,depth=0,expiry=None):
        nonlocal nodes
        nodes+=1;need(nodes<=8192 and depth<=32,"XML resource limit")
        need(el.tag.startswith('{'+MD+'}') or el.tag.startswith('{'+DS+'}'),"foreign XML vocabulary unsupported")
        check_id(el,'ID')
        if 'validUntil' in el.attrib:
            e=instant(el.attrib['validUntil']);expiry=min(expiry,e) if expiry else e
        if el.tag=='{'+MD+'}EntitiesDescriptor':
            need(set(el.attrib)<={'ID','Name','validUntil','cacheDuration'},"unsupported aggregate metadata attributes")
            need(all(ch.tag in ('{'+MD+'}EntitiesDescriptor','{'+MD+'}EntityDescriptor','{'+DS+'}Signature') for ch in el),"unsupported aggregate metadata element")
            for ch in el:
                if ch.tag=='{'+DS+'}Signature':continue
                visit(ch,depth+1,expiry)
            return
        need(el.tag=='{'+MD+'}EntityDescriptor',"root or aggregate child must describe an entity")
        need(set(el.attrib)<={'ID','entityID','validUntil','cacheDuration'},"unsupported entity metadata attributes")
        eid=string(el.attrib.get('entityID'),4096);need(eid in expected and eid not in seen,"unexpected or duplicate entity identity");seen.add(eid)
        need(expiry is not None and now<expiry,"metadata expiry absent or expired")
        roles=[];roletypes=set()
        for role in el:
            if role.tag=='{'+DS+'}Signature':continue
            typ=role.tag.removeprefix('{'+MD+'}')
            need(typ in ('IDPSSODescriptor','SPSSODescriptor') and typ not in roletypes,"unsupported or duplicate SAML role");roletypes.add(typ)
            roleflags={'WantAuthnRequestsSigned'} if typ=='IDPSSODescriptor' else {'WantAssertionsSigned','AuthnRequestsSigned'}
            need(set(role.attrib)<={'ID','protocolSupportEnumeration','validUntil','cacheDuration'}|roleflags,"unsupported SSO role attributes")
            check_id(role,'ID')
            need('urn:oasis:names:tc:SAML:2.0:protocol'  in role.attrib.get('protocolSupportEnumeration','').split(),"SAML 2 protocol not declared")
            rexp=instant(role.attrib['validUntil']) if 'validUntil' in role.attrib else expiry;need(now<min(expiry,rexp),"role metadata expired")
            for flag in ('WantAuthnRequestsSigned','WantAssertionsSigned','AuthnRequestsSigned'):
                if flag in role.attrib:need(role.attrib[flag] in ('true','false','0','1'),"invalid SAML boolean")
            keyfps=[];endpoints=[];indices=set();signing=0
            for child in role:
                local=child.tag.removeprefix('{'+MD+'}')
                if local=='KeyDescriptor':
                    need(set(child.attrib)<={'use'} and all(k.tag=='{'+DS+'}KeyInfo' for k in child),"unsupported key descriptor semantics")
                    for info in child:
                        need(set(info.attrib)<={'Id'} and all(k.tag=='{'+DS+'}X509Data' for k in info),"unsupported key information")
                        check_id(info,'Id')
                        for data in info:
                            need(not data.attrib and all(k.tag=='{'+DS+'}X509Certificate' and not k.attrib and not list(k) for k in data),"unsupported certificate key information")
                    need('use' not in child.attrib or child.attrib['use'] in ('signing','encryption'),"explicit key use must be signing or encryption; omitted use permits both");use=child.attrib.get('use','both')
                    certnodes=child.findall('./{'+DS+'}KeyInfo/{'+DS+'}X509Data/{'+DS+'}X509Certificate')
                    need(certnodes,"public certificate missing in key descriptor")
                    for cn in certnodes:
                        der=b64(''.join((cn.text or '').split()),limit=262144)
                        try:cert=x509.load_der_x509_certificate(der)
                        except ValueError:raise ReviewError("invalid metadata signing certificate") from None
                        need(cert.not_valid_before_utc<=now<cert.not_valid_after_utc,"metadata certificate expired or not yet valid")
                        signed_der(cert.public_bytes(serialization.Encoding.DER),'certificate');k=valid_public_key(cert.public_key());need(isinstance(k,(rsa.RSAPublicKey,ec.EllipticCurvePublicKey,ed25519.Ed25519PublicKey)),"unsupported signing key")
                        if isinstance(k,rsa.RSAPublicKey):need(k.key_size>=2048,"weak metadata RSA signing key")
                        elif isinstance(k,ec.EllipticCurvePublicKey):need(isinstance(k.curve,(ec.SECP256R1,ec.SECP384R1,ec.SECP521R1)),"weak or unsupported metadata elliptic curve")
                        keyfps.append(cert.fingerprint(hashes.SHA256()).hex())
                        if use in ('signing','both'):signing+=1
                elif local in ('SingleSignOnService','SingleLogoutService','AssertionConsumerService'):
                    roleendpoints={'SingleSignOnService','SingleLogoutService'} if typ=='IDPSSODescriptor' else {'AssertionConsumerService','SingleLogoutService'}
                    need(local in roleendpoints,"endpoint incompatible with SSO role")
                    permitted={'Binding','Location','ResponseLocation'}|({'index','isDefault'} if local=='AssertionConsumerService' else set())
                    need(set(child.attrib)<=permitted and not list(child),"unsupported endpoint semantics")
                    need(child.attrib.get('Binding') in BINDINGS,"unsupported endpoint binding");https(child.attrib.get('Location'))
                    if 'ResponseLocation' in child.attrib:https(child.attrib['ResponseLocation'])
                    if local=='AssertionConsumerService':
                        idx=xs_ushort(child.attrib.get('index'));need(idx not in indices,"duplicate ACS index");indices.add(idx)
                        if 'isDefault' in child.attrib:need(child.attrib['isDefault'] in ('true','false','0','1'),"invalid endpoint default flag")
                    endpoints.append({'kind':local,'binding':child.attrib['Binding'],'endpoint_sha256':hashlib.sha256(child.attrib['Location'].encode()).hexdigest()})
                elif local=='NameIDFormat':need(not child.attrib and not list(child),"unsupported NameID semantics");need((child.text or '').strip().startswith('urn:oasis:names:tc:SAML:'),"unsupported NameID format")
                else:raise ReviewError("unsupported SAML role semantics")
            required='SingleSignOnService' if typ=='IDPSSODescriptor' else 'AssertionConsumerService'
            need(signing and any(e['kind']==required for e in endpoints),"role missing signing key or required endpoint")
            roles.append({'role':typ,'certificate_sha256':keyfps,'endpoints':endpoints})
        need(roles,"entity has no supported SSO role")
        out.append({'entity_id_sha256':hashlib.sha256(eid.encode()).hexdigest(),'valid_until':expiry.isoformat(),'roles':roles,'metadata_signature_verified':False})
    visit(root);need(seen==expected,"expected entity metadata absent")
    return report(verified=False,trust='configuration-only; XML signatures not verified',entities=out)
