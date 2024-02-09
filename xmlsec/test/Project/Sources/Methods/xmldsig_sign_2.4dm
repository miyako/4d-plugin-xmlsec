//%attributes = {"invisible":true}
/*

sign - add template

*/

$dsig_id:="xmldsig-"+generate_lowercase_uuid

$params:=New object:C1471
$params.xmldsig:=New object:C1471

//Signature, SignedInfo
$params.xmldsig.ns:="dsig"
$params.xmldsig.id:=$dsig_id  //optional

//CanonicalizationMethod
$params.xmldsig.c14n:="1.0"

//SignatureMethod
$params.xmldsig.sign:="rsa-sha256"

//when the xml does not contain a template, one is created according to xmldsig params

If (True:C214)  //optional
	
	//Reference
	$ref_id:="reference-"+generate_lowercase_uuid
	$params.xmldsig.digest:="sha1"  //default:sha1, sha224, sha256, sha384, sha512
	$params.xmldsig.ref:=New object:C1471
	$params.xmldsig.ref.id:=$ref_id
	$params.xmldsig.ref.type:="http://www.w3.org/2000/09/xmldsig#Object"
	
End if 

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xmldsig_sign").file("sign-doc.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")

var $keyBLOB : Blob

$params.xml:=$doc.getText()
$keyBLOB:=$rsakey.getContent()

$status:=xmlsec sign($params; $keyBLOB)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)