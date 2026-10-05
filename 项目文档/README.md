> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# SamlMetadataReview

New implementation author: **dhtfish98**. Package version: **0.1.3**.

Local SAML 2.0 metadata identity, role, binding, endpoint and public signing-certificate configuration audit, across bounded entities and inherited expiration.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. Cryptographic primitives use cryptography; no upstream application is called.

## Contract

Run `saml-metadata-review request.json` or pipe JSON to `saml-metadata-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- Full declared static profile; XMLDSig presence never implies validation. No SSO/SLO execution, credentials, fetch, XML signing, encryption, AttributeAuthority, extensions, or full OASIS schema equivalence. Unsupported role semantics are rejected.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required `metadata_xml`, complete `expected_entity_ids` and timezone-aware `now` describe local SAML 2.0 EntityDescriptor/EntitiesDescriptor metadata. Inherited expiration, exact identity set, unique declared SP/IDP roles, signing certificate material, HTTPS endpoints, known POST/Redirect/SOAP bindings and endpoint index/boolean fields are checked. Explicit KeyDescriptor use permits signing/encryption only; omitted use supplies dual use. IDP endpoints permit SingleSignOnService/SingleLogoutService, while SP endpoints permit AssertionConsumerService/SingleLogoutService. Role-specific flags are enforced. ACS index accepts bounded ASCII [+]?[0-9]+ after XML whitespace collapse, then checks 0 through 65535; Unicode digits and underscores are rejected. All XML nodes, including opaque XMLDSig subtrees, count toward 8192-node and depth-32 limits. DTD/entities, unknown operational children and unsupported attributes fail closed. An XMLDSig subtree may be present but is opaque and unverified; output always states entity `metadata_signature_verified=false` and overall `verified=false`. No SSO, XML signature, credential or identity-provider authenticity result is inferred.

All accepted Ed25519 public keys are canonical nonidentity points in the main subgroup, checked through libsodium. Ed25519 signature R points must also be canonical nonidentity main-subgroup points and S must be below the group order. Certificates and CRLs require exactly matching inner/outer AlgorithmIdentifiers; the strict profile permits only RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and Ed25519 with absent parameters. OCSP permits the same explicit algorithm encodings and key-family/hash binding.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; parsed floating-point overflow is rejected as nonfinite; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
saml-metadata-review examples/valid.json
```

See [ORIGIN.md](<ORIGIN.md>), [VALIDATION.md](<VALIDATION.md>), [LICENSE](<LICENSE>) and [UPSTREAM_LICENSE](<UPSTREAM_LICENSE>) for scope, evidence and attribution.

## File input platform contract

Regular-file input and file-based CLI requests require usable `os.O_NOFOLLOW` and `os.O_NONBLOCK` capabilities. Missing capabilities produce a controlled incomplete FAIL; there is no fallback that follows the final-component symlink or blocks on a FIFO. macOS and Linux CI have been exercised. Native Windows file-input behavior remains unverified.

## Re-audited input semantics

Endpoint Location and ResponseLocation use a strict ASCII HTTPS URI profile: valid DNS A-label or IP-literal host, valid optional port (0 through 65535), valid percent escapes, and no userinfo, fragment, controls or raw whitespace. Unicode URI text requires its corresponding ASCII/percent-encoded representation. This is selected endpoint syntax validation, not full OASIS schema validation or an endpoint ownership result. [WHATWG port state](https://url.spec.whatwg.org/#port-state) supplies the port failure reference.

Supported EntitiesDescriptor/EntityDescriptor and IDPSSODescriptor/SPSSODescriptor ID attributes, plus ds:KeyInfo Id, share document-wide uniqueness checking. Supplied values must be a nonempty ASCII NCName subset matching [A-Za-z_][A-Za-z0-9_.-]* and no more than 256 characters. IDs inside opaque ds:Signature subtrees are not interpreted or included in this selected ID set. XMLDSig validation and full OASIS/XML Schema validity remain unverified.


`metadata_xml` is Unicode XML text and must contain only characters permitted by the [XML 1.0 character production](https://www.w3.org/TR/2008/REC-xml-20081126/#charsets). NUL and forbidden controls fail before parsing, so UTF-16/UTF-32 byte carriers hidden inside JSON strings cannot bypass the DTD/entity declaration gate. Normal Unicode text and UTF-8 input remain supported; DTD/entity declarations remain forbidden.
