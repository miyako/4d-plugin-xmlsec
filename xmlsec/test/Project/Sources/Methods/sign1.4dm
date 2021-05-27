//%attributes = {"invisible":true}
/*

signs a template file using a key from PEM file (based on examples/sign1.c)

*/

$doc:=Folder:C1567(fk resources folder:K87:11).folder("sign1").file("sign1-tmpl.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")

$params:=New object:C1471
$params.xml:=$doc.getText()
$keyBLOB:=$rsakey.getContent()

$status:=xmlsec sign ($params;$keyBLOB)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)
