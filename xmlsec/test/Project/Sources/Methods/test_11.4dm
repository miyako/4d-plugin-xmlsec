//%attributes = {}
var $t_signed; $t_digested; $t_encoded : Text
var $x_dummy; $x_pem : Blob

$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")
$x_pem:=$rsakey.getContent()

$status:=xmlsec sign({\
xml: Folder:C1567(fk desktop folder:K87:19).file("RefappsMessages_CheckInteroperability_2024-03-12_08_51_16.647.xml").getText("UTF-8"; Document unchanged:K24:18); \
key: "pem"; \
xmldsig: {\
digest: "sha256"; \
refs: [\
{uri: "#TS-14864704-99bb-45c7-8595-8f4820165f13"; prefixList: "wsse soap"}; \
{uri: "#id-a16fcb0e-3378-4a7e-849b-5757ee04ab44"}\
]; \
ids: [\
{\
prefix: "wsu"; \
namespace: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"; \
name: "Id"\
}\
]; \
sign: "rsa-sha256"; \
c14n: "1.0.e"; \
prefixList: "soap"; \
ns: "ds"; \
id: "SIG-a74b7ebc-4eda-4b42-9add-52e0241fb605"; \
keyInfo: {\
id: "KI-3a4dd53f-e024-4a6d-84e4-676e3e8ba177"; \
keyName: "SecurityTokenReference"\
}\
}\
}; $x_pem)

$result:=Folder:C1567(fk desktop folder:K87:19).file("dummy2.xml")

If ($status.xml#Null:C1517)
	$result.setText($status.xml)
Else 
	$result.setText($status.debug)
End if 

OPEN URL:C673($result.platformPath)

