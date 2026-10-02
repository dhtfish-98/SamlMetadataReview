# Origin and implementation scope

SamlMetadataReview independently implements this selected scope: Local SAML 2.0 metadata identity, role, binding, endpoint and public signing-certificate configuration audit, across bounded entities and inherited expiration.

The research source is [SAML-Toolkits/python3-saml](https://github.com/SAML-Toolkits/python3-saml) at fixed commit `52d2ac8da3f35262755f6e1c32ba7c62a6011fe1`. Source archive SHA-256: `f010097720f4d5dedc944f4af11d7844372af00556d7bb5e53e8af7f899c3115`. Its license is MIT; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [src/onelogin/saml2/idp_metadata_parser.py](https://github.com/SAML-Toolkits/python3-saml/blob/52d2ac8da3f35262755f6e1c32ba7c62a6011fe1/src/onelogin/saml2/idp_metadata_parser.py) — SHA-256 `6b1a73125d67b869586bad688b24d6e03338d05112d8fd0211373f7b5fde8156`.
- [src/onelogin/saml2/schemas/saml-schema-metadata-2.0.xsd](https://github.com/SAML-Toolkits/python3-saml/blob/52d2ac8da3f35262755f6e1c32ba7c62a6011fe1/src/onelogin/saml2/schemas/saml-schema-metadata-2.0.xsd) — SHA-256 `e0b32d3b70dd301c4f3528a22310f50bf633734f1c8ffe46b66f503e66acbeca`.
- [src/onelogin/saml2/schemas/xmldsig-core-schema.xsd](https://github.com/SAML-Toolkits/python3-saml/blob/52d2ac8da3f35262755f6e1c32ba7c62a6011fe1/src/onelogin/saml2/schemas/xmldsig-core-schema.xsd) — SHA-256 `336147eb6d7ccf9b3d4df93080f8680a451c3411aae1b1f5e6009958a3215dd5`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on static entity/SSO role signing certificate and endpoint extraction, SAML metadata schema, role endpoint/key-use mutations and intentionally excluded online behavior. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required `metadata_xml`, complete `expected_entity_ids` and timezone-aware `now` describe local SAML 2.0 EntityDescriptor/EntitiesDescriptor metadata. Inherited expiration, exact identity set, unique declared SP/IDP roles, signing certificate material, HTTPS endpoints, known POST/Redirect/SOAP bindings and endpoint index/boolean fields are checked. Explicit KeyDescriptor use permits signing/encryption only; omitted use supplies dual use. IDP endpoints permit SingleSignOnService/SingleLogoutService, while SP endpoints permit AssertionConsumerService/SingleLogoutService. Role-specific flags are enforced. ACS index accepts bounded ASCII [+]?[0-9]+ after XML whitespace collapse, then checks 0 through 65535; Unicode digits and underscores are rejected. All XML nodes, including opaque XMLDSig subtrees, count toward 8192-node and depth-32 limits. DTD/entities, unknown operational children and unsupported attributes fail closed. An XMLDSig subtree may be present but is opaque and unverified; output always states entity `metadata_signature_verified=false` and overall `verified=false`. No SSO, XML signature, credential or identity-provider authenticity result is inferred.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.
