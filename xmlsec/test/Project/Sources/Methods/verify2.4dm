//%attributes = {"invisible":true}
/*

verifies a file using a key from PEM file (based on examples/verify2.c)
TODO: load multiple keys
*/

$xml:=Folder:C1567(fk resources folder:K87:11).folder("sign2").file("sign2-res.xml")
$rsapub:=Folder:C1567(fk resources folder:K87:11).file("rsapub.pem")

$params:=New object:C1471
$params.xml:=$xml.getText("utf-8";Document with LF:K24:22)
$keyBLOB:=$rsapub.getContent()

$status:=xmlsec verify ($params;$keyBLOB)

ASSERT:C1129($status.success)
ASSERT:C1129($status.valid)