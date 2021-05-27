//%attributes = {"invisible":true}
/*
this xml does not have a dsig:Signature element
a standard dsig template is automatically generated (--sign-tmpl)

*/
$doc:=Folder:C1567(fk resources folder:K87:11).folder("sign2").file("sign2-doc.xml")
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")



$params:=New object:C1471

$params.xmldsig:=New object:C1471

  //<dsig:Signature> node
$params.xmldsig.ns:="ds"
$params.xmldsig.id:=$dsig_id

  //<dsig:KeyInfo> node
$params.xmldsig.keyInfo:=New object:C1471
$params.xmldsig.keyInfo_id:=$keyinfo_id

$params.xmldsig.keyInfo.keyName:="name"

$params.xmldsig.keyInfo.retrievalMethod:=New object:C1471
$params.xmldsig.keyInfo.retrievalMethod.uri:=""
$params.xmldsig.keyInfo.retrievalMethod.type:=""

$params.xmldsig.keyInfo.x509Data:=New collection:C1472
$params.xmldsig.keyInfo.x509Data[0]:=New object:C1471

  //deprecated
$params.xmldsig.keyInfo.x509Data[0].issuerSerial:=New object:C1471
$params.xmldsig.keyInfo.x509Data[0].issuerSerial.issuerName:="CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP"
$params.xmldsig.keyInfo.x509Data[0].issuerSerial.serialNumber:="12345678"

$rsacert:=Folder:C1567(fk resources folder:K87:11).file("x509.pem")
$cert:=$rsacert.getContent()
$t:=""
BASE64 ENCODE:C895($cert;$t)


$params.xmldsig.keyInfo.x509Data[0].ski:="skiski"
$params.xmldsig.keyInfo.x509Data[0].subjectName:="subject"
$params.xmldsig.keyInfo.x509Data[0].certificate:=New collection:C1472
$params.xmldsig.keyInfo.x509Data[0].certificate[0]:=$t
$params.xmldsig.keyInfo.x509Data[0].crl:=""

  //dsig11:X509Digest not implemented

$params.xml:=$doc.getText()
$keyBLOB:=$rsakey.getContent()

$status:=xmlsec sign ($params;$keyBLOB;$cert)

ASSERT:C1129($status.success)

$xml:=$status.xml

SET TEXT TO PASTEBOARD:C523($xml)