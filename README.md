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
* `ignoreManifests`: `--ignore-manifests`
* `storeReferences`: `--store-references`
* `storeSignatures`: `--store-signatures`
* `enableVisa3DHack`: `--enable-visa3d-hack`
