//%attributes = {"invisible":true}
/*

signs a file using a dynamicaly created template and key from PEM file (based on examples/sign2.c)

*/

$doc:=Folder:C1567(fk resources folder:K87:11).folder("sign2").file("sign2-doc.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")

$params:=New object:C1471
$params.xml:=$doc.getText()
$params.name:="rsakey.pem"
$params.tmpl:=True:C214  //--sign-tmpl
$keyBLOB:=$rsakey.getContent()

$status:=xmlsec sign ($params;$keyBLOB)

ASSERT:C1129($status.success)

$xml:=$status.xml

  //exptected result
$res:=Folder:C1567(fk resources folder:K87:11).folder("sign2").file("sign2-res.xml")
$resXml:=$res.getText("utf-8";Document with LF:K24:22)

ASSERT:C1129(Length:C16($resXml)=Length:C16($xml))
ASSERT:C1129(Generate digest:C1147($resXml;SHA1 digest:K66:2)=Generate digest:C1147($xml;SHA1 digest:K66:2))
