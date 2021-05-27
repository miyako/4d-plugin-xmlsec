//%attributes = {}
/*

XML Advanced Electronic Signatures (XAdES) proof-of-concept

*/

$doc:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("FacturaElectronica.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")
$rsacert:=Folder:C1567(fk resources folder:K87:11).file("rsacert.pem")

$params:=New object:C1471

$params.tmpl:=True:C214  //--sign-tmpl

  //global
$params.signature:="rsa-sha256"
$params.digest:="sha512"

$dsig_id:="xmldsig-"+Generate UUID:C1066
$keyinfo_id:=$dsig_id+"-keyinfo"

$params.xmldsig:=New object:C1471

  //<dsig:Signature> node
$params.xmldsig.ns:="ds"
$params.xmldsig.id:=$dsig_id

  //<ds:Reference> node 
$reference_id:="reference-"+Generate UUID:C1066
$params.xmldsig.reference:=New object:C1471
$params.xmldsig.reference.id:=$reference_id
$params.xmldsig.reference.uri:=""
$params.xmldsig.reference.type:="http://www.w3.org/2000/09/xmldsig#Object"

  //<dsig:KeyInfo> node
$params.xmldsig.keyInfo:=New object:C1471
$params.xmldsig.keyInfo.id:=$keyinfo_id
$params.xmldsig.keyInfo.name:=""  //ds:KeyInfo/ds:KeyName; optional
$params.xmldsig.keyInfo.issuer:=""  //ds:KeyInfo/ds:X509Data/ds:X509IssuerSerial/ds:IssuerName; optional
$params.xmldsig.keyInfo.serial:=""  //ds:KeyInfo/ds:X509Data/ds:X509IssuerSerial/ds:SerialNumber; optional
  //ds:KeyInfo/ds:X509Data <- $3 (BLOB)
$params.xmldsig.keyInfo.ski:=False:C215  //reference the X.509 certificate without copying the entire certificate

  //XAdES from here

$params.xades:=XAdES 

$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].mimeType:="text/xml"
$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].objectIdentifier.identifier_qualifier:="OIDAsURN"
$params.xades.qualifyingProperties.signedProperties.signedDataObjectProperties.dataObjectFormat[0].objectIdentifier.identifier:="urn:oid:1.2.840.10003.5.109.10"

$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signerRole.claimedRoles[0].claimedRole:="emisor"
$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signingTime:="2021-05-15T20:00:43+02:00"

  //$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signingCertificate.cert[0].issuerSerial.X509IssuerName:="CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES"
  //$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signingCertificate.cert[0].issuerSerial.X509SerialNumber:="96891622000445695554354105786026700712"

$params.xades.qualifyingProperties.signedProperties.signedSignatureProperties.signaturePolicyIdentifer.signaturePolicyId[0].sigPolicyId.identifier:="http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf"

$params.xml:=$doc.getText()
$keyBLOB:=$rsakey.getContent()
$certBLOB:=$rsacert.getContent()
$xadesCertBLOB:=$certBLOB

$status:=xmlsec sign ($params;$keyBLOB;$certBLOB;$xadesCertBLOB)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)
