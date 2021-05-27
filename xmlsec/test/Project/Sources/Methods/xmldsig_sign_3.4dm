//%attributes = {}
/*

sign - add template

*/

$dsig_id:="xmldsig-"+generate_lowercase_uuid 
$keyinfo_id:=$dsig_id+"-keyinfo"

$params:=New object:C1471
$params.xmldsig:=New object:C1471

  //Signature, SignedInfo
$params.xmldsig.ns:="dsig"  //default:ds
$params.xmldsig.id:=$dsig_id

  //CanonicalizationMethod
$params.xmldsig.c14n:="1.0"  //1.0, 1.0.c, 1.1, 1.1.c, default:1.0.e, 1.0.e.c (e=exclusive, c=comments) 

  //SignatureMethod
$params.xmldsig.sign:="rsa-sha256"  //default:rsa-sha1, hmac, rsa, ecdsa, dsa

  //Reference
$ref_id:="reference-"+generate_lowercase_uuid 
$params.xmldsig.digest:="sha1"  //default:sha1, sha224, sha256, sha384, sha512
$params.xmldsig.ref:=New object:C1471
$params.xmldsig.ref.id:=$ref_id
$params.xmldsig.ref.type:="http://www.w3.org/2000/09/xmldsig#Object"

  //when the xml does not contain a template, one is created according to xmldsig params

  //KeyInfo
$key_id:="keyInfo-"+generate_lowercase_uuid 
$params.xmldsig.keyInfo:=New object:C1471
$params.xmldsig.keyInfo.id:=$key_id

$doc:=Folder:C1567(fk resources folder:K87:11).folder("sign2").file("sign2-doc.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")
$rsacert:=Folder:C1567(fk resources folder:K87:11).file("rsacert.pem")

$params.xml:=$doc.getText()
$keyBLOB:=$rsakey.getContent()

  //pass an array of X509 certificates

ARRAY BLOB:C1222($certBLOBs;1)
$certBLOBs{1}:=$rsacert.getContent()

$status:=xmlsec sign ($params;$keyBLOB;$certBLOBs)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)