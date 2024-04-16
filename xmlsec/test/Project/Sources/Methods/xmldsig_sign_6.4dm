//%attributes = {"invisible":true}
/*

sign - XAdES - PEM

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
$params.xmldsig.refs:=[{id: $ref_id; type: "http://www.w3.org/2000/09/xmldsig#Object"}]

$params.xmldsig.ski:=False:C215  //default:false
$params.xmldsig.crl:=False:C215  //default:false
$params.xmldsig.subjectName:=False:C215  //default:false
$params.xmldsig.issuerSerial:=False:C215  //default:false
$params.xmldsig.certificate:=False:C215  //default:false

//pass an array of X509 certificates to create a chain for xades

$cert1:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("EIDAS CERTIFICADO PRUEBAS - 99999999R.der")  //signing cert
$cert2:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("AC FNMT Usuarios.der")  //intermediate cert
$cert3:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("AC RAIZ FNMT-RCM.der")  //root cert

ARRAY BLOB:C1222($certBLOBs; 3)
$certBLOBs{0}:=$cert1.getContent()  //when key#pkcs, pass the signing cert in element #0
$certBLOBs{1}:=$cert1.getContent()
$certBLOBs{2}:=$cert2.getContent()
$certBLOBs{3}:=$cert3.getContent()
$params.cert:="der"

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("FacturaElectronica.xml")
$params.xml:=$doc.getText()

/*

this file was extracted from the pkcs12

openssl pkcs12 
-info 
-in /Resources/xades/facturae.p12 
-nodes 
-nocerts 
-out /Resources/xades/facturae.pem

*/

var $keyBLOB : Blob

$key:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("facturae.pem")  //PRIVATE KEY
$keyBLOB:=$key.getContent()

var $policyBLOB : Blob

//the policy 
$policy:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("politica_de_firma_formato_facturae_v3_1.pdf")
$policyBLOB:=$policy.getContent()

//default XAdES options

$params.xades:=XAdES
$params.xades.digest:="sha1"  //policy digest algorithm
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