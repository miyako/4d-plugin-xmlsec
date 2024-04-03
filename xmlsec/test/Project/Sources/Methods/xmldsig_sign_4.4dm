//%attributes = {"invisible":true}
/*

sign - add template

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

//pass an array of X509 certificates

$cert1:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("EIDAS CERTIFICADO PRUEBAS - 99999999R.der")
$cert2:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("AC FNMT Usuarios.der")
$cert3:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("AC RAIZ FNMT-RCM.der")

ARRAY BLOB:C1222($certBLOBs; 3)
$certBLOBs{1}:=$cert1.getContent()
$certBLOBs{2}:=$cert2.getContent()
$certBLOBs{3}:=$cert3.getContent()

$params.cert:="der"  //default:pem

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("FacturaElectronica.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")

var $keyBLOB : Blob

$params.xml:=$doc.getText()
$keyBLOB:=$rsakey.getContent()

$status:=xmlsec sign($params; $keyBLOB; $certBLOBs)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)