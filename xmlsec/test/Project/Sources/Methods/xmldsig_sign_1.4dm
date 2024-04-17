//%attributes = {"invisible":true}
/*

sign - use template

*/

$params:=New object:C1471

//when the xml contains a template it is used "as is"

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xmldsig_sign").file("sign-tmpl.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")

var $keyBLOB : Blob

$params.xml:=$doc.getText()
$keyBLOB:=$rsakey.getContent()

//KeyInfo
//$params.name:="test"

$key_id:="keyInfo-"+generate_lowercase_uuid
$params.xmldsig:=New object:C1471
$params.xmldsig.keyInfo:=New object:C1471
$params.xmldsig.keyInfo.id:=$key_id  //mandatory for XAdES
$params.xmldsig.keyInfo.keyName:="test"

$status:=xmlsec sign($params; $keyBLOB)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)