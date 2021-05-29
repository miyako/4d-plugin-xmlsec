//%attributes = {"invisible":true}
/*

sign - add template

*/

$params:=New object:C1471
$params.xmldsig:=New object:C1471

  //Signature, SignedInfo
$params.xmldsig.id:="Signature-c7478edb-99a8-4b47-a91b-3ae6132a0717-Signature"

  //CanonicalizationMethod
$params.xmldsig.c14n:="1.0"  //1.0, 1.0.c, 1.1, 1.1.c, default:1.0.e, 1.0.e.c (e=exclusive, c=comments) 

  //SignatureMethod
$params.xmldsig.sign:="rsa-sha256"  //default:rsa-sha1, hmac, rsa, ecdsa, dsa

  //Reference
$params.xmldsig.digest:="sha512"  //default:sha1, sha224, sha256, sha384, sha512
$params.xmldsig.ref:=New object:C1471
$params.xmldsig.ref.id:="Reference-ff246aa2-7509-4c50-b48b-ef268fbf9f3f"
$params.xmldsig.ref.type:="http://www.w3.org/2000/09/xmldsig#Object"

  //when the xml does not contain a template, one is created according to xmldsig params

  //KeyInfo
$params.xmldsig.keyInfo:=New object:C1471
$params.xmldsig.keyInfo.id:="Signature-c7478edb-99a8-4b47-a91b-3ae6132a0717-KeyInfo"

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("FacturaElectronica.xml")

$params.xml:=$doc.getText()

  //pass an array of X509 certificates

$rsacert:=Folder:C1567(fk resources folder:K87:11).file("rsacert.pem")

  //the policy goes to element #0

$policy:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("politica_de_firma_formato_facturae_v3_1.pdf")

  //pass a key

$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")

ARRAY BLOB:C1222($certBLOBs;1)
$certBLOBs{0}:=$policy.getContent()
$certBLOBs{1}:=$rsacert.getContent()

$keyBLOB:=$rsakey.getContent()

$params.xmldsig.ski:=False:C215  //default:false
$params.xmldsig.crl:=False:C215  //default:false
$params.xmldsig.subjectName:=False:C215  //default:false
$params.xmldsig.keyValue:=True:C214  //default:true
$params.xmldsig.issuerSerial:=False:C215  //default:false
$params.xmldsig.certificate:=True:C214  //default:true

$params.xades:=XAdES 

$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].mimeType:="text/xml"
$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].objectIdentifier.identifier_qualifier:="OIDAsURN"
$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].objectIdentifier.identifier:="urn:oid:1.2.840.10003.5.109.10"

$params.xades.qualifyingProperties.id:="Signature-c7478edb-99a8-4b47-a91b-3ae6132a0717-QualifyingProperties"
$params.xades.qualifyingProperties.signedProperties.id:="Signature-c7478edb-99a8-4b47-a91b-3ae6132a0717-SignedProperties"
$params.xades.qualifyingProperties.signedProperties.type:=""

$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signerRole.claimedRoles[0].claimedRole:="emisor"
$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signingTime:="2021-05-15T20:00:43+02:00"
$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signaturePolicyIdentifer.signaturePolicyId[0].sigPolicyId.identifier:="http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf"

$status:=xmlsec sign ($params;$keyBLOB;$certBLOBs)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)