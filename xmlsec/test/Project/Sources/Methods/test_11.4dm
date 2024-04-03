//%attributes = {}
var $t_signed; $t_digested; $t_encoded : Text
var $x_dummy; $x_pem : Blob

$rsakey:=Folder:C1567(fk resources folder:K87:11).file("rsakey.pem")
$x_pem:=$rsakey.getContent()

$status:=xmlsec sign({\
xml: Folder:C1567(fk desktop folder:K87:19).file("dummy.xml").getText("UTF-8"; Document unchanged:K24:18); \
key: "pem"; \
transform: TransformExclC14NId; \
xmldsig: {\
digest: "sha256"; \
refs: [{\
uri: "#TS-14864704-99bb-45c7-8595-8f4820165f13"\
}; {\
uri: "#id-a16fcb0e-3378-4a7e-849b-5757ee04ab44"\
}]; \
sign: "rsa-sha256"; \
c14n: "1.0"; \
ns: "ds"; \
id: "SIG-a74b7ebc-4eda-4b42-9add-52e0241fb605"; \
keyInfo: {\
id: "KI-3a4dd53f-e024-4a6d-84e4-676e3e8ba177"; \
keyName: "SecurityTokenReference"\
}\
}\
}; $x_pem)

Folder:C1567(fk desktop folder:K87:19).file("dummy2.xml").setText($status.xml)
