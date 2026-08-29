![version](https://img.shields.io/badge/version-20%2B-E23089)
![platform](https://img.shields.io/static/v1?label=platform&message=mac-intel%20|%20mac-arm%20|%20win-64&color=blue)
[![license](https://img.shields.io/github/license/miyako/4d-plugin-xmlsec)](LICENSE)
![downloads](https://img.shields.io/github/downloads/miyako/4d-plugin-xmlsec/total)

# 4d-plugin-xmlsec

XML digital signature (XMLDSig) and XAdES-BES signing for 4D, built on the
[xmlsec](https://www.aleksey.com/xmlsec/) / libxml2 / OpenSSL libraries.

The plugin exposes three commands:

| Command | Purpose |
|---|---|
| [`xmlsec sign`](#xmlsec-sign) | Sign an XML document (XMLDSig, optionally XAdES-BES) |
| [`xmlsec hash`](#xmlsec-hash) | Compute a Base64-encoded digest of a BLOB |
| [`xmlsec x509`](#xmlsec-x509) | Read basic validity info out of a certificate |

Platforms: macOS (Intel & Apple Silicon) and Windows (64-bit).

> **Note on scope.** The plugin's own C++ source also contains a `verify`
> code path (`xmlSecDSigCtxVerify`), but it is not wired into the plugin's
> command dispatch and is not listed in `manifest.json`, so **there is
> currently no 4D command to verify a signature** — only to create one. This
> document covers the three commands 4D can actually call.

---

## Requirements

- **Key formats accepted:** PEM, DER, PKCS#8 PEM/DER, or PKCS#12 (`.p12`/`.pfx`).
- **Certificate formats accepted:** PEM or DER.
- If the key (or a PEM-encrypted key inside a P12) is password-protected,
  pass the password in `options.password`.
- When the key is a **PKCS#12** file, it is expected to also contain the
  matching certificate — the separate `certs` parameter of `xmlsec sign` is
  **ignored** in that case. For PEM/DER keys, pass the signer's certificate
  (and any chain certificates) via `certs`.

---

## `xmlsec sign`

Signs an XML document and returns the signed XML.

### Syntax

```4d
status:=xmlsec sign(options{;key{;certs}})
```

| Parameter | Type | | Description |
|---|---|---|---|
| `options` | Object | → | Signing options and the XML to sign (see below) |
| `key` | BLOB | → | Optional. The private key: PEM, DER, PKCS#8, or PKCS#12 |
| `certs` | Array BLOB | → | Optional. Certificate chain (ignored if `key` is PKCS#12). Order doesn't matter, except element 0 must be the signer's own certificate — for XAdES, the same BLOB must appear twice in the array (once as the signer cert, once in the chain) |
| `status` | Object | ← | Result (see [Return object](#sign-return-object)) |

Both `key` and `certs` are optional: if you omit them, the plugin still
parses `options.xml`, builds the `<Signature>` template described by
`options.xmldsig`, and reports the errors from whichever step fails first —
useful for validating options before you have real key material.

### `options` object reference

#### Top level

| Field | Type | Default | Description |
|---|---|---|---|
| `xml` | Text | — | **Required.** The XML document to sign, as text. If `xmlParseDoc` can't parse it as a literal XML string, the plugin falls back to treating it as a **file path** and reads/parses the file at that path instead. |
| `password` | Text | — | Passphrase for an encrypted PEM key or a PKCS#12 file. |
| `key` | Text | `"pem"` | Format of the `key` BLOB parameter. One of: `"binary"`, `"pem"`, `"der"`, `"pkcs8pem"`, `"pkcs8der"`, `"pkcs12"`, `"pemcert"`, `"dercert"`. |
| `cert` | Text | `"pem"` | Format of each BLOB in the `certs` array. Same value list as `key`. |
| `ignoreManifests` | Boolean | `false` | Sets `XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS`. |
| `storeReferences` | Boolean | `false` | Sets `XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES` \| `XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES`. |
| `storeSignatures` | Boolean | `false` | Sets `XMLSEC_DSIG_FLAGS_STORE_SIGNATURE`. |
| `enableVisa3DHack` | Boolean | `false` | Sets `XMLSEC_DSIG_FLAGS_USE_VISA3D_HACK` (for the Visa 3-D Secure XML signature quirk). |
| `xmldsig` | Object | — | Signature template options — see below. |
| `xades` | Object | — | XAdES-BES qualifying properties — see [XAdES](#xades-bes-options). Omit entirely for a plain XMLDSig signature. |

> **Signing an already-signed document.** If `options.xml` already contains
> a `<dsig:Signature>` element, the plugin does **not** create a new one —
> it signs the existing `<Signature>` node in place (useful if you built
> your own signature template upstream). In that case every option under
> `xmldsig` below is ignored, because there is no new template to build.

#### `options.xmldsig`

Controls the `<dsig:Signature>` template that gets created (ignored if the
document already has one — see note above).

| Field | Type | Default | Description |
|---|---|---|---|
| `ns` | Text | `"ds"` | Namespace prefix used for the `dsig:` elements. |
| `id` | Text | — | `Id` attribute on the `<Signature>` element. |
| `c14n` | Text | `"1.0.e"` | Canonicalization method. One of `"1.0"` (inclusive), `"1.0.c"` (inclusive, with comments), `"1.1"` (inclusive v1.1), `"1.1.c"` (inclusive v1.1, with comments), `"1.0.e"` (**exclusive**, default), `"1.0.e.c"` (exclusive, with comments). |
| `sign` | Text | `"rsa-sha1"` | Signature algorithm. One of `"rsa-sha1"`, `"rsa-sha224"`, `"rsa-sha256"`, `"rsa-sha384"`, `"rsa-sha512"`, `"hmac-sha1"`…`"hmac-sha512"`, `"dsa-sha1"`, `"dsa-sha256"`, `"ecdsa-sha1"`, `"ecdsa-sha224"`, `"ecdsa-sha256"`, `"ecdsa-sha384"`, `"ecdsa-sha512"`. |
| `digest` | Text | `"sha1"` | Reference digest method. One of `"sha224"`, `"sha256"`, `"sha384"`, `"sha512"` (anything else, including omitted, is SHA-1). |
| `prefixList` | Text | — | `InclusiveNamespaces PrefixList` added to the signature's own canonicalization method (only meaningful with an exclusive `c14n`). |
| `refs` | Array of Object | — | One or more extra `<Reference>` elements to add to the signature (beyond the implicit whole-document reference). Each entry: `id` (Text), `type` (Text), `uri` (Text), `prefixList` (Text — inclusive-namespaces list for *this* reference's own C14N transform). |
| `ids` | Array of Object | — | Registers custom ID-bearing attributes with libxml2 before signing, so `URI="#..."` references resolve correctly against attributes that aren't a standard `xml:id`/`ID` attribute. Each entry: `prefix` (Text, namespace prefix), `namespace` (Text, namespace URI), `name` (Text, attribute local name) — **all three are required** for an entry to take effect. |
| `keyInfo` | Object | — | `id` (Text — `Id` attribute on `<KeyInfo>`), `keyName` (Text — adds a `<KeyName>` element). |
| `ski` | Boolean | `false` | Add `<X509SKI>` (subject key identifier) to `<X509Data>`. |
| `crl` | Boolean | `false` | Add `<X509CRL>` to `<X509Data>`. |
| `subjectName` | Boolean | `false` | Add `<X509SubjectName>` to `<X509Data>`. |
| `issuerSerial` | Boolean | `false` | Add `<X509IssuerSerial>` to `<X509Data>`. |
| `certificate` | Boolean | `true` | Add `<X509Certificate>` (the actual cert, base64) to `<X509Data>`. |

`<X509Data>`/`<KeyValue>` are only added at all if a key/certificate is
actually supplied to the command (i.e. the `key` BLOB parameter is non-empty).

### <a name="sign-return-object"></a>Return object

| Field | Type | When present |
|---|---|---|
| `crypto` | Text | Always. Name of the crypto engine in use (currently always `"openssl"`). |
| `success` | Boolean | Always. `true` only if signing completed. |
| `xml` | Text | On success. The full signed document, serialized as UTF-8 XML. |
| `debug` | Text | On some failures. The document as it stood when signing failed, to help diagnose which step went wrong. |
| `error` | Text | On failure. A short machine-readable code — see below. |

`error` values you may see: `failed:xmlParseDoc`, `failed:xmlSecTmplSignatureCreate`,
`failed:xmlSecTmplSignatureAddReference`, `failed:xmlSecKeysMngrCreate`,
`failed:xmlSecDSigCtxCreate`, `failed:xmlSecCryptoAppKeyLoadMemory`,
`failed:xmlSecCryptoAppDefaultKeysMngrAdoptKey`, `failed:xmlSecDSigCtxSign`,
`failed:xmlSecFindNode:xmlSecNodeSignature:xmlSecDSigNs`.

### Sample — sign with a PEM key + certificate

```4d
C_TEXT($xml)
$xml:="<Invoice><Number>1001</Number><Total>250.00</Total></Invoice>"

C_OBJECT($options)
$options:=New object
$options.xml:=$xml
$options.key:="pem"     // key BLOB below is a PEM private key
$options.cert:="pem"    // certs[] BLOBs below are PEM certificates

C_OBJECT($xmldsig)
$xmldsig:=New object
$xmldsig.sign:="rsa-sha256"
$xmldsig.digest:="sha256"
$xmldsig.certificate:=True   // embed the signer's cert in <X509Data>
$options.xmldsig:=$xmldsig

C_BLOB($key)
DOCUMENT TO BLOB(Get 4D folder(Current resources folder)+"signer.key.pem"; $key)

C_BLOB($cert)
DOCUMENT TO BLOB(Get 4D folder(Current resources folder)+"signer.cert.pem"; $cert)
ARRAY BLOB($certs; 1)
$certs{1}:=$cert

C_OBJECT($status)
$status:=xmlsec sign($options; $key; $certs)

If ($status.success)
    TEXT TO DOCUMENT(Get 4D folder(Current resources folder)+"invoice.signed.xml"; $status.xml)
Else
    ALERT("Signing failed: "+$status.error)
End if
```

### Sample — sign with a PKCS#12 key (certificate embedded in the P12)

```4d
C_OBJECT($options)
$options:=New object
$options.xml:="<Invoice><Number>1002</Number></Invoice>"
$options.key:="pkcs12"
$options.password:="the P12 passphrase"

C_BLOB($key)
DOCUMENT TO BLOB(Get 4D folder(Current resources folder)+"signer.p12"; $key)

// certs is not used for a PKCS#12 key — pass an empty array
ARRAY BLOB($certs; 0)

C_OBJECT($status)
$status:=xmlsec sign($options; $key; $certs)

If ($status.success)
    ALERT($status.xml)
Else
    ALERT("Signing failed: "+$status.error)
End if
```

### XAdES-BES options

Add `options.xades` to additionally produce an XAdES `<QualifyingProperties>`
block (`ds:Object > xades:QualifyingProperties`). Only the XAdES-BES form is
supported. If `xades.qualifyingProperties.signedProperties.signedSignatureProperties.signaturePolicyIdentifer.signaturePolicyId`
is empty or omitted, `<xades:SignaturePolicyImplied/>` is emitted automatically.

| Field | Type | Description |
|---|---|---|
| `xades.ns` | Text | XAdES namespace prefix. Default `"xades"`. |
| `xades.digest` | Text | Digest method used for `SigPolicyHash`. One of `"sha224"`/`"sha256"`/`"sha384"`/`"sha512"` (default SHA-1). |
| `xades.qualifyingProperties.id` | Text | `Id` attribute on `<QualifyingProperties>`. |
| `xades.qualifyingProperties.signedProperties.id` | Text | `Id` attribute on `<SignedProperties>` (also generates the `<Reference Type="...SignedProperties">` back to it). |
| `…signedSignatureProperties.signingTime` | Text | Value for `<xades:SigningTime>` (pass an ISO-8601 date-time string). |
| `…signedSignatureProperties.signaturePolicyIdentifer.signaturePolicyId` | Array of Object | *(sic — "Identifer" is the plugin's actual spelling.)* Non-empty ⇒ explicit policy; each entry: `sigPolicyId` (Object: `identifier` Text, `digest` Text — pre-computed base64 policy hash, `description` Text, `documentationReferences` Array of Object, each with a `documentationReference` Array of Text), `sigPolicyQualifiers` (Array of Object, each with `SPURI` Text). |
| `…signedSignatureProperties.signerRole.claimedRoles` | Array of Object | Each entry: `claimedRole` (Text). |
| `…signedSignatureProperties.signerRole.certifiedRoles` | Array of Object | Each entry: `certifiedRole` (Text). |
| `…signedDataObjectProperties.dataObjectFormat` | Array of Object | Each entry: `id` (Text — matches an existing `Reference Id`), `description` (Text), `mimeType` (Text), `encoding` (Text), `objectIdentifier` (Object: `identifier`, `identifier_qualifier`, `description`, all Text). |
| `…unsignedProperties.id` | Text | `Id` attribute on `<UnsignedProperties>`. |
| `…unsignedProperties.unsignedDataObjectProperties` | Array of Object | Each entry: `unsignedDataObjectProperty` (Text). |

The signer's certificate digest/issuer/serial for `xades:SigningCertificate`
is derived automatically from the `key`/`certs` (or P12) you pass — you
don't set it directly.

### Sample — XAdES-BES sign (implied policy)

```4d
C_OBJECT($options)
$options:=New object
$options.xml:="<Invoice><Number>1003</Number></Invoice>"
$options.key:="pkcs12"
$options.password:="the P12 passphrase"

C_OBJECT($xmldsig)
$xmldsig:=New object
$xmldsig.sign:="rsa-sha256"
$xmldsig.digest:="sha256"
$options.xmldsig:=$xmldsig

C_OBJECT($xades)
$xades:=New object
C_OBJECT($qualifyingProperties;$signedProperties;$signedSignatureProperties)
$signedSignatureProperties:=New object
$signedSignatureProperties.signingTime:=String(Current date;ISO date)+"T"+String(Current time)
$signedProperties:=New object
$signedProperties.signedSignatureProperties:=$signedSignatureProperties
$qualifyingProperties:=New object
$qualifyingProperties.signedProperties:=$signedProperties
$xades.qualifyingProperties:=$qualifyingProperties
$options.xades:=$xades

C_BLOB($key)
DOCUMENT TO BLOB(Get 4D folder(Current resources folder)+"signer.p12"; $key)
ARRAY BLOB($certs; 0)

C_OBJECT($status)
$status:=xmlsec sign($options; $key; $certs)
```

---

## `xmlsec hash`

Convenience command to Base64-hash a BLOB (not itself an XML operation —
useful for e.g. pre-computing an XAdES `SigPolicyHash` digest value).

### Syntax

```4d
hash:=xmlsec hash(data{;algorithm})
```

| Parameter | Type | | Description |
|---|---|---|---|
| `data` | BLOB | → | **Required.** The bytes to hash. |
| `algorithm` | Text | → | Optional. One of `"sha224"`, `"sha256"`, `"sha384"`, `"sha512"`. Anything else, or omitted, defaults to `"sha1"`. |
| `hash` | Text | ← | Base64-encoded digest. |

### Sample

```4d
C_BLOB($data)
DOCUMENT TO BLOB(Get 4D folder(Current resources folder)+"policy.pdf"; $data)

C_TEXT($hash)
$hash:=xmlsec hash($data; "sha256")
```

---

## `xmlsec x509`

Reads a certificate's validity dates.

### Syntax

```4d
status:=xmlsec x509(cert{;options})
```

| Parameter | Type | | Description |
|---|---|---|---|
| `cert` | BLOB | → | **Required.** The certificate (or a PKCS#12 containing one). |
| `options` | Object | → | Optional. `cert` (Text — format, same values as `xmlsec sign`'s `options.cert`, default `"pem"`) and `password` (Text — P12 passphrase, if `options.cert = "pkcs12"`). |
| `status` | Object | ← | Result (see below). |

### Return object

| Field | Type | Description |
|---|---|---|
| `success` | Boolean | `true` if the certificate parsed. |
| `notBefore` | Text | Validity start, e.g. `"Feb  3 00:55:52 2015 GMT"`. |
| `notAfter` | Text | Validity end, same format. |

### Sample

```4d
C_BLOB($cert)
DOCUMENT TO BLOB(Get 4D folder(Current resources folder)+"signer.cert.pem"; $cert)

C_OBJECT($options)
$options:=New object("cert"; "pem")

C_OBJECT($status)
$status:=xmlsec x509($cert; $options)

If ($status.success)
    ALERT("Valid from "+$status.notBefore+" to "+$status.notAfter)
Else
    ALERT("Could not read certificate")
End if
```

```4d
// Reading validity out of a PKCS#12 file instead:
C_BLOB($p12)
DOCUMENT TO BLOB(Get 4D folder(Current resources folder)+"signer.p12"; $p12)

C_OBJECT($options)
$options:=New object("cert"; "pkcs12"; "password"; "the P12 passphrase")

C_OBJECT($status)
$status:=xmlsec x509($p12; $options)
```

---

## Known caveat: OpenSSL 3 and legacy PKCS#12

Some PKCS#12 files created with older tools use legacy (RC2/3DES) encryption
that OpenSSL 3's default providers no longer support, and will fail with:

```
PKCS12_parse:error=4:crypto library function failed:openssl error: error:0308010C:digital envelope routines::unsupported
```

If you hit this, re-export the P12 with modern encryption (e.g.
`openssl pkcs12 -export ... ` using current defaults) rather than reusing
the old file as-is.
