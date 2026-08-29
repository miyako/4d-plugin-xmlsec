//%attributes = {"invisible":true}
/*

sign - use pkcs#12

*/

$dsig_id:="xmldsig-"+generate_lowercase_uuid
$keyinfo_id:=$dsig_id+"-keyinfo"

$params:=New object:C1471
$params.xmldsig:=New object:C1471

//Signature, SignedInfo
$params.xmldsig.ns:="ds"
$params.xmldsig.id:=$dsig_id

//CanonicalizationMethod
$params.xmldsig.c14n:="1.0"

//SignatureMethod
$params.xmldsig.sign:="rsa-sha256"

//Reference
$ref_id:="reference-"+generate_lowercase_uuid
$params.xmldsig.digest:="sha1"
$params.xmldsig.refs:=[{id: $ref_id; type: "http://www.w3.org/2000/09/xmldsig#Object"}]

//when the xml does not contain a template, one is created according to xmldsig params

If (False:C215)  //optional
	
	//KeyInfo
	$key_id:="keyInfo-"+generate_lowercase_uuid
	$params.xmldsig.keyInfo:=New object:C1471
	$params.xmldsig.keyInfo.id:=$key_id
	
End if 

//use pkcs instead of der/pem

var $keyBLOB : Blob

$pkcs12key:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("facturae.p12")  //p12=PFX
$params.key:="pkcs12"  //default:pem, binary, der, pkcs8pem, pkcs8der, pkcs12, pemcert, dercert
$params.password:="1234"
$keyBLOB:=$pkcs12key.getContent()

$params.cert:="der"  //default:pem

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("FacturaElectronica.xml")
$params.xml:=$doc.getText()

$status:=xmlsec sign($params; $keyBLOB)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)