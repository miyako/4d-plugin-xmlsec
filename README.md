![version](https://img.shields.io/badge/version-20%2B-E23089)
![platform](https://img.shields.io/static/v1?label=platform&message=mac-intel%20|%20mac-arm%20|%20win-64&color=blue)
[![license](https://img.shields.io/github/license/miyako/4d-plugin-xmlsec)](LICENSE)
![downloads](https://img.shields.io/github/downloads/miyako/4d-plugin-xmlsec/total)

# 4d-plugin-xmlsec
XML signature based on [xmlsec](https://www.aleksey.com/xmlsec/).

## Library Package Managers

as of `2024-04-16`, Monterey/Ventura bottle is `1.3.4`, vcpkg is `1.3.3`.

`1.3.x` breaks compatibility. set flag.

```c
pDsigCtx->keyInfoReadCtx.flags  |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
pDsigCtx->keyInfoWriteCtx.flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
```

OpenSSL3 may not work with legacy PKCS#12 

https://www.openssl.org/docs/man3.0/man1/openssl-pkcs12.html

```
PKCS12_parse:error=4:crypto library function failed:openssl error: error:0308010C:digital envelope routines::unsupported
```

[miyako.github.io](https://miyako.github.io/2021/05/31/4d-plugin-xmlsec.html)

## OpenSSL tips

* https://www.ssl.com/how-to/export-certificates-private-key-from-pkcs12-file-with-openssl/

the plugin accepts P12 or PEM/DER, but you can convert keys and certificates from one format to another.

 ## XAdES tools
 
 * [www.evrotrust.com](https://www.evrotrust.com/landing/en/a/validation)

* [lovele0107/signatures-conformance-checker](https://github.com/lovele0107/signatures-conformance-checker) on [ETSI](https://signatures-conformance-checker.etsi.org/pub/index.php)

## XML:DSIG tools

* https://tools.chilkat.io/xmlDsigVerify.cshtml
