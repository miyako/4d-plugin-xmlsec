//%attributes = {"invisible":true}
/*

sign - XAdES - P12

*/

$dsig_id:="xmldsig-"+generate_lowercase_uuid

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
$params.xmldsig.digest:="sha512"
$params.xmldsig.ref:=New object:C1471
$params.xmldsig.ref.id:=$ref_id
$params.xmldsig.ref.type:="http://www.w3.org/2000/09/xmldsig#Object"

ARRAY BLOB:C1222($certBLOBs; 0)  //not used with when key=pkcs12

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("FacturaElectronica.xml")
$params.xml:=$doc.getText()

//use pkcs instead of der/pem

$pkcs12key:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("facturae.p12")  //p12=PFX
$params.key:="pkcs12"  //default:pem, binary, der, pkcs8pem, pkcs8der, pkcs12, pemcert, dercert
$params.password:="1234"
$keyBLOB:=$pkcs12key.getContent()

//the policy 
$policy:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("politica_de_firma_formato_facturae_v3_1.pdf")
$policyBLOB:=$policy.getContent()

//default XAdES options

$params.xades:=XAdES
$params.xades.digest:="sha256"  //policy digest algorithm
$policyDigest:=xmlsec hash($policyBLOB; $params.xades.digest)

//KeyInfo
$key_id:="keyInfo-"+generate_lowercase_uuid
$params.xmldsig.keyInfo:=New object:C1471
$params.xmldsig.keyInfo.id:=$key_id  //mandatory for XAdES

$signingTime:=String:C10(Current date:C33; ISO date GMT:K1:10; Current time:C178)

$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].mimeType:="text/xml"
$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].objectIdentifier.identifier_qualifier:="OIDAsURN"
$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].objectIdentifier.identifier:="urn:oid:1.2.840.10003.5.109.10"

$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signerRole.claimedRoles[0].claimedRole:="emisor"
$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signingTime:=$signingTime
$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signaturePolicyIdentifer.signaturePolicyId[0].sigPolicyId.identifier:="http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf"
$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signaturePolicyIdentifer.signaturePolicyId[0].sigPolicyId.digest:=$policyDigest

$status:=xmlsec sign($params; $keyBLOB; $certBLOBs)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)