//%attributes = {}
$doc:=Folder:C1567(fk desktop folder:K87:19).file("source.xml")

$cert:=Folder:C1567(fk desktop folder:K87:19).file("cert.pem")
var $certBLOB : Blob
$certBLOB:=$cert.getContent()

var $keyBLOB : Blob
$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")
$keyBLOB:=$rsakey.getContent()

$params:={}

$params.xml:=$doc.getText("UTF-8"; Document unchanged:K24:18)
$params.key:="pem"
$params.xpath:="/soap:Envelope/soap:Body"
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
$params.xmldsig.ids[0]:={prefix: "wsu"; \
namespace: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"; \
name: "Id"}
$params.xmldsig.ns:="ds"
$params.xmldsig.id:="SIG-a74b7ebc-4eda-4b42-9add-52e0241fb605"
$params.xmldsig.sign:="rsa-sha256"
$params.xmldsig.c14n:="1.0.e"
$params.xmldsig.prefixList:="soap"

$params.xmlenc:={}
$params.xmlenc.xpath:="/soap:Envelope/soap:Header/*[@soap:mustUnderstand=1]/*"  //can't use wsse ns because it is not defined in root
$params.xmlenc.add:="previousSibling"
$params.xmlenc.id:="EK-7c5be4a3-6562-435a-877e-05df0814e83c"
$params.xmlenc.crypt:="rsa-oaep"
$params.xmlenc.digest:="sha256"
$params.xmlenc.type:="wsse"

$params.xmldsig.keyInfo:={}
$params.xmldsig.keyInfo.id:="KI-3a4dd53f-e024-4a6d-84e4-676e3e8ba177"
$params.xmldsig.keyInfo.keyName:="SecurityTokenReference"

ARRAY BLOB:C1222($certBLOBs; 1)
$certBLOBs{0}:=$certBLOB

$status:=xmlsec sign($params; $keyBLOB; $certBLOBs)

$result:=Folder:C1567(fk desktop folder:K87:19).file("signed.xml")
$result.setText($status.xml)

OPEN URL:C673($result.platformPath)