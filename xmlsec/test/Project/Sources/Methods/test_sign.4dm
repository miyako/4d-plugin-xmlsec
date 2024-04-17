//%attributes = {}
$xml:=File:C1566("/RESOURCES/wsse/sign.xml").getText("UTF-8"; Document unchanged:K24:18)

var $certBLOB : Blob
$certBLOB:=File:C1566("/RESOURCES/wsse/cert.der").getContent()

ARRAY BLOB:C1222($certBLOBs; 1)  //array must have at least 1 element
$certBLOBs{0}:=$certBLOB  //the certificate goes in element #0

var $keyBLOB : Blob
$keyBLOB:=File:C1566("/RESOURCES/rsakey.pem").getContent()

$params:={}

$params.xml:=$xml
$params.key:="pem"
$params.cert:="der"
$params.xpath:="/soap:Envelope/soap:Header/*[@soap:mustUnderstand=1]/*"
$params.add:="previousSibling"

/*
previousSibling: immediately before
sibling: before (=youngest sibling)
nextSibling: after
default: first child
*/

$params.xmldsig:={}
$params.xmldsig.digest:="sha256"
$params.xmldsig.refs:=[]
$params.xmldsig.refs[0]:={uri: "#TS-14864704-99bb-45c7-8595-8f4820165f13"; prefixList: "wsse soap"}
$params.xmldsig.refs[1]:={uri: "#id-a16fcb0e-3378-4a7e-849b-5757ee04ab44"}
$params.xmldsig.ids:=[]
$params.xmldsig.ids[0]:={\
prefix: "wsu"; \
namespace: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"; \
name: "Id"}
$params.xmldsig.ns:="ds"
$params.xmldsig.id:="SIG-a74b7ebc-4eda-4b42-9add-52e0241fb605"
$params.xmldsig.sign:="rsa-sha256"
$params.xmldsig.c14n:="1.0.e"
$params.xmldsig.prefixList:="soap"
$params.xmldsig.keyInfo:={id: "KI-3a4dd53f-e024-4a6d-84e4-676e3e8ba177"}

$params.xenc:={}
$params.xenc.crypt:="rsa-oaep"
$params.xenc.digest:="sha256"
$params.xenc.encryptedKeyId:="EK-7c5be4a3-6562-435a-877e-05df0814e83c"
$params.xenc.encryptedDataId:="ED-957b3806-e391-433e-ba13-f5f5430e56b5"

$params.wsse:={}
$params.wsse.binarySecurityTokenId:="X509-1928feea-faf6-444f-99c7-ad5d8633682f"
$params.wsse.securityTokenReferenceId:="STR-4b1d0f7c-553e-4efb-b8aa-08bada6b7919"


$status:=xmlsec sign($params; $keyBLOB; $certBLOBs)

$result:=Folder:C1567(fk desktop folder:K87:19).file("signed.xml")
$result.setText($status.xml; "utf-8-no-bom"; Document with LF:K24:22)

OPEN URL:C673($result.platformPath)