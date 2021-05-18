# 4d-plugin-xmlsec
XML signature based on [xmlsec](https://www.aleksey.com/xmlsec/)

### Sign

```4d
$xml:=Folder(fk resources folder).folder("sign1").file("sign1-tmpl.xml")
$rsakey:=Folder(fk resources folder).file("rsakey.pem")

$params:=New object
$params.xml:=$xml.getText()
$params.name:="rsakey.pem"
$keyBLOB:=$rsakey.getContent()

$status:=xmlsec sign ($params;$keyBLOB) 
```

#### options for **sign**

* `xml`: XML template text or platform path  
* `key`: format of private key; one of \[binary,pem(default),der,pkcs8pem,pkcs8der,pkcs12,pemcert,dercert\]  
* `password`: password to open private key (optional)  
* `name`: `<dsig:KeyName>` (optional)  
* `tmpl`: add template to XML ``--sign-tmpl``
* `ignoreManifests`: `--ignore-manifests`
* `storeReferences`: `--store-references`
* `storeSignatures`: `--store-signatures`
* `enableVisa3DHack`: `--enable-visa3d-hack`

### Verify

```4d
$xml:=Folder(fk resources folder).folder("sign3").file("sign3-res.xml")
$rsapub:=Folder(fk resources folder).file("rsapub.pem")
$cacert:=Folder(fk resources folder).file("cacert.pem")

$params:=New object
$params.xml:=$xml.getText("utf-8";Document with LF)
$keyBLOB:=$rsapub.getContent()
$certBLOB:=$cacert.getContent()

$status:=xmlsec verify ($params;$keyBLOB;$certBLOB)
```

**Note**: there seems to be a bug in `xmlSecDSigCtxVerify`. the `status` is not correctly returned in `xmlSecDSigCtx.status`. the plugin is using a workaround.

---

# TODO

[ETSI](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.01.00_30/en_31913201v010100v.pdf)
