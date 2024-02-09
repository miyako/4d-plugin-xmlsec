//%attributes = {"invisible":true}
$params:=New object:C1471

$pkcs12key:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("facturae.p12")  //p12=PFX
$params.cert:="pkcs12"  //default:pem, binary, der, pkcs8pem, pkcs8der, pkcs12, pemcert, dercert
$params.password:="1234"

var $keyBLOB : Blob

$keyBLOB:=$pkcs12key.getContent()

$status:=xmlsec x509($keyBLOB; $params)

$cert1:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("EIDAS CERTIFICADO PRUEBAS - 99999999R.der")  //signing cert
$cert2:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("AC FNMT Usuarios.der")  //intermediate cert
$cert3:=Folder:C1567(fk resources folder:K87:11).folder("xades").file("AC RAIZ FNMT-RCM.der")  //root cert

var $certBLOB1; $certBLOB2; $certBLOB3 : Blob

$certBLOB1:=$cert1.getContent()
$certBLOB2:=$cert2.getContent()
$certBLOB3:=$cert3.getContent()

$params.cert:="der"

$status:=xmlsec x509($certBLOB1; $params)
$status:=xmlsec x509($certBLOB2; $params)
$status:=xmlsec x509($certBLOB3; $params)

$cert:=Folder:C1567(fk resources folder:K87:11).file("rsacert.pem")

var $certBLOB : Blob

$certBLOB:=$cert.getContent()

$params.cert:="pem"

$status:=xmlsec x509($certBLOB; $params)