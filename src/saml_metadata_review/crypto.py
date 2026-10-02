from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa,padding
from cryptography.exceptions import InvalidSignature
from nacl.bindings import crypto_core_ed25519_is_valid_point,crypto_scalarmult_ed25519_noclamp,crypto_core_ed25519_add
from .common import *

# Canonical, main-subgroup Ed25519 points exclude identity and torsion keys.
ED_ORDER=2**252+27742317777372353535851937790883648493
ED_IDENTITY=bytes([1])+bytes(31)
def valid_ed_point(raw):
    if len(raw)!=32 or not crypto_core_ed25519_is_valid_point(raw):return False
    # Native-primitives subgroup check also covers older system libsodium builds.
    try:return crypto_core_ed25519_add(crypto_scalarmult_ed25519_noclamp((ED_ORDER-1).to_bytes(32,'little'),raw),raw)==ED_IDENTITY
    except Exception:return False

def valid_public_key(k):
    if isinstance(k,ed25519.Ed25519PublicKey):
        raw=k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        need(valid_ed_point(raw),"invalid Ed25519 public point; canonical prime-subgroup key required")
    return k
def valid_ed_signature(sig):
    need(len(sig)==64 and valid_ed_point(sig[:32]) and int.from_bytes(sig[32:],'little')<ED_ORDER,"invalid Ed25519 signature encoding or point")

# Strict bounded DER profile. Lengths and AlgorithmIdentifiers are canonical.
def der_tlv(raw,pos=0):
    need(pos+2<=len(raw),"truncated DER")
    start=pos;tag=raw[pos];pos+=1;need(tag&31!=31,"high-tag DER outside supported profile");length=raw[pos];pos+=1
    if length&128:
        count=length&127;need(1<=count<=4 and pos+count<=len(raw) and raw[pos]!=0,"invalid DER length")
        length=int.from_bytes(raw[pos:pos+count],'big');pos+=count;need(length>=128,"nonminimal DER length")
    end=pos+length;need(end<=len(raw),"truncated DER value")
    return tag,raw[start:end],raw[pos:end],end
def der_sequence(raw):
    tag,full,value,end=der_tlv(raw);need(tag==48 and end==len(raw),"expected exact DER sequence")
    out=[];pos=0
    while pos<len(value):
        tag,full,content,pos=der_tlv(value,pos);out.append((tag,full,content));need(len(out)<=32,"DER field count limit")
    return out
ALGORITHMS={
    bytes.fromhex('300d06092a864886f70d01010b0500'):('1.2.840.113549.1.1.11','sha256'),
    bytes.fromhex('300d06092a864886f70d01010c0500'):('1.2.840.113549.1.1.12','sha384'),
    bytes.fromhex('300d06092a864886f70d01010d0500'):('1.2.840.113549.1.1.13','sha512'),
    bytes.fromhex('300a06082a8648ce3d040302'):('1.2.840.10045.4.3.2','sha256'),
    bytes.fromhex('300a06082a8648ce3d040303'):('1.2.840.10045.4.3.3','sha384'),
    bytes.fromhex('300a06082a8648ce3d040304'):('1.2.840.10045.4.3.4','sha512'),
    bytes.fromhex('300506032b6570'):('1.3.101.112',None),
}
def signed_der(raw,kind):
    need(len(raw)<=1048576,"signed DER size limit");parts=der_sequence(raw)
    need(len(parts)==3 and parts[0][0]==48 and parts[1][0]==48 and parts[2][0]==3 and parts[2][2] and parts[2][2][0]==0,"unsupported signed DER structure")
    body=der_sequence(parts[0][1])
    index=(2 if body and body[0][0]==160 else 1) if kind=='certificate' else (1 if body and body[0][0]==2 else 0)
    need(index<len(body) and body[index][0]==48 and body[index][1]==parts[1][1],"inner and outer signature AlgorithmIdentifier mismatch")
    need(parts[1][1] in ALGORITHMS,"unsupported signature AlgorithmIdentifier or parameters")
def ocsp_der(raw):
    need(len(raw)<=1048576,"OCSP DER size limit");outer=der_sequence(raw)
    need(len(outer)==2 and outer[0][0]==10 and outer[0][2]==bytes([0]) and outer[1][0]==160,"unsupported OCSP response structure")
    response=der_sequence(outer[1][2]);need(len(response)==2 and response[0][1]==bytes.fromhex('06092b0601050507300101') and response[1][0]==4,"only BasicOCSPResponse supported")
    basic=der_sequence(response[1][2]);need(len(basic) in (3,4) and basic[0][0]==48 and basic[1][0]==48 and basic[2][0]==3 and basic[2][2] and basic[2][2][0]==0,"invalid BasicOCSPResponse structure")
    if len(basic)==4:need(basic[3][0]==160,"unsupported BasicOCSPResponse field")
    need(basic[1][1] in ALGORITHMS,"unsupported OCSP signature AlgorithmIdentifier or parameters")
def pem_der(v,label,limit):
    text=string(v,limit).strip(' '+chr(9)+chr(10)+chr(13));start='-----BEGIN '+label+'-----';end='-----END '+label+'-----'
    need(text.startswith(start) and text.endswith(end),"expected one exact public PEM object")
    body=text[len(start):-len(end)];need(body and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= '+chr(9)+chr(10)+chr(13) for c in body),"duplicate or malformed PEM object")
    return b64(''.join(body.split()),limit=limit)
def certificate(v):
    raw=pem_der(v,'CERTIFICATE',262144);signed_der(raw,'certificate')
    try:c=x509.load_der_x509_certificate(raw)
    except ValueError:raise ReviewError("invalid PEM certificate") from None
    valid_public_key(c.public_key());return c
def pubkey(v):
    raw=pem_der(v,'PUBLIC KEY',16384);parts=der_sequence(raw);need(len(parts)==2 and parts[0][0]==48 and parts[1][0]==3 and parts[1][2] and parts[1][2][0]==0,"expected SubjectPublicKeyInfo")
    try:k=serialization.load_der_public_key(raw)
    except ValueError:raise ReviewError("invalid PEM public key") from None
    return valid_public_key(k)
def fingerprint(k):valid_public_key(k);return hashlib.sha256(k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
def verify(k,sig,data,alg):
    valid_public_key(k)
    try:
        if isinstance(k,ed25519.Ed25519PublicKey):need(alg=='Ed25519',"key and algorithm mismatch");valid_ed_signature(sig);k.verify(sig,data)
        elif isinstance(k,ec.EllipticCurvePublicKey):
            need(alg in ('ES256','ES384') and ((alg=='ES256' and isinstance(k.curve,ec.SECP256R1)) or (alg=='ES384' and isinstance(k.curve,ec.SECP384R1))),"key and algorithm mismatch")
            k.verify(sig,data,ec.ECDSA(hashes.SHA256() if alg=='ES256' else hashes.SHA384()))
        elif isinstance(k,rsa.RSAPublicKey):
            need(k.key_size>=2048 and alg in ('RS256','RS384','RS512'),"unsupported RSA key or algorithm")
            h={'RS256':hashes.SHA256,'RS384':hashes.SHA384,'RS512':hashes.SHA512}[alg]()
            k.verify(sig,data,padding.PKCS1v15(),h)
        else:raise ReviewError("unsupported key")
    except InvalidSignature:raise ReviewError("signature mismatch") from None
def verify_x509(k,sig,data,algorithm,oid):
    valid_public_key(k);name=oid.dotted_string
    if isinstance(k,ed25519.Ed25519PublicKey):
        need(name=='1.3.101.112' and algorithm is None,"Ed25519 signature algorithm mismatch");verify(k,sig,data,'Ed25519');return
    digest=algorithm.name if algorithm is not None else None
    rsa_alg={'1.2.840.113549.1.1.11':'sha256','1.2.840.113549.1.1.12':'sha384','1.2.840.113549.1.1.13':'sha512'}
    ec_alg={'1.2.840.10045.4.3.2':'sha256','1.2.840.10045.4.3.3':'sha384','1.2.840.10045.4.3.4':'sha512'}
    try:
        if isinstance(k,rsa.RSAPublicKey):
            need(k.key_size>=2048 and name in rsa_alg and rsa_alg[name]==digest,"unsupported RSA certificate signature or algorithm mismatch")
            k.verify(sig,data,padding.PKCS1v15(),algorithm)
        elif isinstance(k,ec.EllipticCurvePublicKey):
            need(isinstance(k.curve,(ec.SECP256R1,ec.SECP384R1,ec.SECP521R1)) and name in ec_alg and ec_alg[name]==digest,"unsupported elliptic curve or signature algorithm mismatch")
            k.verify(sig,data,ec.ECDSA(algorithm))
        else:raise ReviewError("unsupported certificate key")
    except InvalidSignature:raise ReviewError("certificate signature mismatch") from None
def issuer_pair(leaf,issuer,now):
    for cert in (leaf,issuer):
        signed_der(cert.public_bytes(serialization.Encoding.DER),'certificate');valid_public_key(cert.public_key())
        for ext in cert.extensions:
            if ext.critical:need(isinstance(ext.value,(x509.BasicConstraints,x509.KeyUsage,x509.ExtendedKeyUsage,x509.SubjectAlternativeName)),"unknown critical certificate extension")
    need(leaf.issuer==issuer.subject,"certificate issuer mismatch")
    need(issuer.not_valid_before_utc<=now<issuer.not_valid_after_utc,"issuer certificate outside validity interval")
    need(leaf.not_valid_before_utc<=now<leaf.not_valid_after_utc,"target certificate outside validity interval")
    try:need(issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,"issuer is not a CA")
    except x509.ExtensionNotFound:raise ReviewError("issuer CA constraint absent") from None
    try:need(issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign,"issuer cannot sign certificates")
    except x509.ExtensionNotFound:raise ReviewError("issuer key usage absent") from None
    try:leaf.verify_directly_issued_by(issuer)
    except (ValueError,TypeError,InvalidSignature):raise ReviewError("target direct issuer signature invalid") from None
    verify_x509(issuer.public_key(),leaf.signature,leaf.tbs_certificate_bytes,leaf.signature_hash_algorithm,leaf.signature_algorithm_oid)
