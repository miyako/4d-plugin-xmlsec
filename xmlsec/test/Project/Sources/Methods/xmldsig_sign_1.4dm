//%attributes = {"invisible":true}
/*

sign -use template

*/

$params:=New object:C1471

  //when the xml contains a template it is used "as is"

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xmldsig_sign").file("sign-tmpl.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")

$params.xml:=$doc.getText()
$keyBLOB:=$rsakey.getContent()

$status:=xmlsec sign ($params;$keyBLOB)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)