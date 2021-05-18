//%attributes = {"invisible":true}
/*

verifies a file signed with X509 certificate (based on examples/verify3.c)
TODO: load multiple keys and multiple certificates
*/

$xml:=Folder:C1567(fk resources folder:K87:11).folder("sign3").file("sign3-res.xml")
$rsapub:=Folder:C1567(fk resources folder:K87:11).file("rsapub.pem")
$cacert:=Folder:C1567(fk resources folder:K87:11).file("cacert.pem")

$params:=New object:C1471
$params.xml:=$xml.getText("utf-8";Document with LF:K24:22)
$keyBLOB:=$rsapub.getContent()
$certBLOB:=$cacert.getContent()

$status:=xmlsec verify ($params;$keyBLOB;$certBLOB)

ASSERT:C1129($status.success)
ASSERT:C1129($status.valid)