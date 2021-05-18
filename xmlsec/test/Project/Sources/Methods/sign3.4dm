//%attributes = {"invisible":true}
/*

signs a file using a dynamicaly created template, key from PEM file and an X509 certificate (based on examples/sign3.c)

*/

$doc:=Folder:C1567(fk resources folder:K87:11).folder("sign3").file("sign3-doc.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")
$rsacert:=Folder:C1567(fk resources folder:K87:11).file("rsacert.pem")

$params:=New object:C1471
$params.xml:=$doc.getText()
$params.tmpl:=True:C214  //--sign-tmpl
$keyBLOB:=$rsakey.getContent()
$certBLOB:=$rsacert.getContent()

$status:=xmlsec sign ($params;$keyBLOB;$certBLOB)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)

  //exptected result
$res:=Folder:C1567(fk resources folder:K87:11).folder("sign3").file("sign3-res.xml")
$resXml:=$res.getText("utf-8";Document with LF:K24:22)

SET TEXT TO PASTEBOARD:C523($resXml)

ASSERT:C1129(Length:C16($resXml)=Length:C16($xml))
ASSERT:C1129(Generate digest:C1147($resXml;SHA1 digest:K66:2)=Generate digest:C1147($xml;SHA1 digest:K66:2))
