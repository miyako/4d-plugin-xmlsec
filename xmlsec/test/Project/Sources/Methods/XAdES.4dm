//%attributes = {"invisible":true}
C_OBJECT:C1216($0; $XAdES)

$XAdES:=New object:C1471

/*

XAdES-B

provides basic authentication and integrity protection
satisfies the legal requirements for advanced electronic signatures as defined in the European Directive
does NOT provide non-repudiation of its existence

design:

create 1 ds:Object
this will be the bag for the whole set of qualifying properties

SignedProperties are signed
UnsignedProperties are NOT signed

in addition, the document as a whole is sign as per XMLDSIG, namespace ds

*/

$uuid:=Generate UUID:C1066

ARRAY LONGINT:C221($pos; 0)
ARRAY LONGINT:C221($len; 0)

If (Match regex:C1019("([:hex_digit:]{8})([:hex_digit:]{4})([:hex_digit:]{4})([:hex_digit:]{16})"; $uuid; 1; $pos; $len))
	$uuid:=Lowercase:C14(New collection:C1472(Substring:C12($uuid; $pos{1}; $len{1}); Substring:C12($uuid; $pos{2}; $len{2}); Substring:C12($uuid; $pos{3}; $len{3}); Substring:C12($uuid; $pos{4}; $len{4})).join("-"); *)
End if 

//default Id for qualifyingProperties, signedProperties, unsignedProperties

$qualifyingProperties_id:="qualifyingProperties-"+$uuid
$signedProperties_id:="signedProperties-"+$uuid
$unsignedProperties_id:="unsignedProperties-"+$uuid

$XAdES.qualifyingProperties:=New object:C1471
$XAdES.qualifyingProperties.id:=$qualifyingProperties_id  //xsd:ID; optional

$issuerSerial:=New object:C1471
$issuerSerial.X509IssuerName:=""  //ds:X509IssuerName
$issuerSerial.X509SerialNumber:=""  //ds:X509SerialNumber

$cert:=New collection:C1472
$cert[0]:=New object:C1471
$cert[0].certDigest:=Null:C1517  //ds:DigestMethod,ds:DigestValue
$cert[0].issuerSerial:=$issuerSerial

$signingCertificate:=New object:C1471
$signingCertificate.cert:=$cert

$sigPolicyQualifiers:=New collection:C1472
$sigPolicyQualifiers.push({SPURL: "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf"})

$documentationReferences:=New collection:C1472
$documentationReferences[0]:=New object:C1471
$documentationReferences[0].documentationReference:=New collection:C1472
$documentationReferences[0].documentationReference[0]:=""  //xsd:anyURI

$sigPolicyId:=New object:C1471
$sigPolicyId.identifier:=""  //xsd:anyURI
$sigPolicyId.description:=""
$sigPolicyId.documentationReferences:=$documentationReferences  //optional

$signaturePolicyId:=New collection:C1472

If (True:C214)
	$signaturePolicyId[0]:=New object:C1471
	$signaturePolicyId[0].sigPolicyId:=$sigPolicyId
	$signaturePolicyId[0].sigPolicyQualifiers:=$sigPolicyQualifiers
End if 

$signaturePolicyIdentifer:=New object:C1471
$signaturePolicyIdentifer.signaturePolicyId:=$signaturePolicyId

//SignatureProductionPlaceType
$signatureProductionPlace:=New object:C1471
$signatureProductionPlace.city:=""
$signatureProductionPlace.stateOrProvince:=""
$signatureProductionPlace.postalCode:=""
$signatureProductionPlace.countryName:=""

$signerRole:=New object:C1471
$signerRole.claimedRoles:=New collection:C1472
$signerRole.claimedRoles[0]:=New object:C1471
$signerRole.claimedRoles[0].claimedRole:=""

If (False:C215)
	$signerRole.certifiedRoles:=New collection:C1472
	$signerRole.certifiedRoles[0]:=New object:C1471
	$signerRole.certifiedRoles[0].certifiedRole:=""
End if 

//SignedSignaturePropertiesType
$signedSignatureProperties:=New object:C1471
$signedSignatureProperties.signingTime:=""  //xsd:dateTime
$signedSignatureProperties.signingCertificate:=$signingCertificate
$signedSignatureProperties.signaturePolicyIdentifer:=$signaturePolicyIdentifer
$signedSignatureProperties.signatureProductionPlace:=$signatureProductionPlace
$signedSignatureProperties.signerRole:=$signerRole

/*

SignedProperties > SignedDataObjectProperties > DataObjectFormats[]

provides information that describes the format of the signed data object
MUST be present when it is mandatory to present the signed data object to human users on verification
document MAY contain more than one DataObjectFormat elements
each one qualifying one signed data object

*/

$signedDataObjectProperties:=New object:C1471
$objectIdentifier:=New object:C1471

$commitmentTypeId:=New object:C1471
$commitmentTypeId.allSignedDataObjects:=True:C214
$commitmentTypeId.objectReference:=""  //xsd:anyURI

$commitmentTypeQualifier:=New object:C1471
$commitmentTypeQualifier.commitmentTypeQualifier:=""

$commitmentTypeQualifiers:=New collection:C1472
$commitmentTypeQualifiers[0]:=$commitmentTypeQualifier

$commitmentTypeIndication:=New collection:C1472
$commitmentTypeIndication[0]:=New object:C1471
$commitmentTypeIndication[0].commitmentTypeId:=$commitmentTypeId
$commitmentTypeIndication[0].commitmentTypeQualifiers:=$commitmentTypeQualifiers


$dataObjectFormat:=New collection:C1472
$dataObjectFormat[0]:=New object:C1471
$dataObjectFormat[0].description:=""  //xsd:string; optional
$dataObjectFormat[0].mimeType:=""  //xsd:string; optional
$dataObjectFormat[0].encoding:=""  ////xsd:anyURI; optional
$dataObjectFormat[0].objectIdentifier:=$objectIdentifier  //optional
$dataObjectFormat[0].commitmentTypeIndication:=$commitmentTypeIndication

$documentationReferences:=New collection:C1472
$documentationReferences[0]:=New object:C1471
$documentationReferences[0].documentationReference:=""  //xsd:anyURI

$objectIdentifier.identifier:=""  //xsd:anyURI
$objectIdentifier.identifier_qualifier:=""  //OIDAsURN or OIDAsURI
$objectIdentifier.description:=""  //xsd:string; optional
$objectIdentifier.documentationReferences:=$documentationReferences  //optional

If (False:C215)
	
	//not implemented; for XAdES-T
	
	$allDataObjectsTimeStamp:=New collection:C1472
	$allDataObjectsTimeStamp[0]:=New object:C1471
	$allDataObjectsTimeStamp[0].hashDataInfo:=New object:C1471
	$allDataObjectsTimeStamp[0].hashDataInfo_uri:=""
	$allDataObjectsTimeStamp[0].hashDataInfo.transforms:=Null:C1517  //ds:TransformsType
	$allDataObjectsTimeStamp[0].encapsulatedTimeStamp:=Null:C1517  //base64
	$allDataObjectsTimeStamp[0].encapsulatedTimeStamp_id:=""
	$allDataObjectsTimeStamp[0].XMLTimeStamp:=""
	
	$individualDataObjectsTimeStamp:=New collection:C1472
	$individualDataObjectsTimeStamp[0]:=New object:C1471
	$individualDataObjectsTimeStamp[0].hashDataInfo:=New object:C1471
	$individualDataObjectsTimeStamp[0].hashDataInfo_uri:=""
	$individualDataObjectsTimeStamp[0].hashDataInfo.transforms:=Null:C1517  //ds:TransformsType
	$individualDataObjectsTimeStamp[0].encapsulatedTimeStamp:=Null:C1517  //base64
	$individualDataObjectsTimeStamp[0].encapsulatedTimeStamp_id:=""
	$individualDataObjectsTimeStamp[0].XMLTimeStamp:=""
	
End if 

If (False:C215)
	
	$unsignedSignatureProperties:=New object:C1471
	
	//not implemented
	
	$signatureTimeStamp:=New collection:C1472
	$signatureTimeStamp[0]:=New object:C1471
	
	$counterSignature:=New collection:C1472
	$counterSignature[0]:=New object:C1471  //ds:Signature
	
	$unsignedProperties:=New object:C1471
	$unsignedProperties.unsignedSignatureProperties:=$unsignedSignatureProperties
	
	$completeCertificateRefs:=New collection:C1472
	$completeCertificateRefs[0]:=New object:C1471
	$completeCertificateRefs[0].certRefs:=New collection:C1472
	
	$completeRevocationRefs:=New collection:C1472
	$completeRevocationRefs[0]:=New object:C1471
	
	$sigAndRefsTimeStamp:=New collection:C1472
	$sigAndRefsTimeStamp[0]:=New object:C1471
	
	$refsOnlyTimeStamp:=New collection:C1472
	$refsOnlyTimeStamp[0]:=New object:C1471
	
	$certificateValues:=New collection:C1472
	$certificateValues[0]:=New object:C1471
	
	$revocationValues:=New collection:C1472
	$revocationValues[0]:=New object:C1471
	
	$archiveTimeStamp:=New collection:C1472
	$archiveTimeStamp[0]:=New object:C1471
	
	//xsd:sequence
	$unsignedSignatureProperties.signatureTimeStamp:=$signatureTimeStamp
	$unsignedSignatureProperties.counterSignature:=$counterSignature
	$unsignedSignatureProperties.completeCertificateRefs:=$completeCertificateRefs
	$unsignedSignatureProperties.completeRevocationRefs:=$completeRevocationRefs
	$unsignedSignatureProperties.certificateValues:=$certificateValues
	$unsignedSignatureProperties.revocationValues:=$revocationValues
	$unsignedSignatureProperties.archiveTimeStamp:=$archiveTimeStamp
	$unsignedSignatureProperties.sigAndRefsTimeStamp:=$sigAndRefsTimeStamp
	$unsignedSignatureProperties.refsOnlyTimeStamp:=$refsOnlyTimeStamp
	
End if 

$signedDataObjectProperties.dataObjectFormat:=$dataObjectFormat
$signedDataObjectProperties.allDataObjectsTimeStamp:=$allDataObjectsTimeStamp

/*

SignedProperties

properties thatqualify the [XMLDSIG] signature itself or the signer
in particular, as parent to SignedSignatureProperties
optinally, parent to SignedDataObjectProperties

*/

//SignedPropertiesType
$signedProperties:=New object:C1471

/*

SignedProperties > SignedSignatureProperties

collection of signed XML elements that qualify the signature

*/

$signedProperties.signedSignatureProperties:=$signedSignatureProperties


/*

SignedProperties > SignedDataObjectProperties > DataObjectFormat[]


*/

$signedProperties.signedDataObjectProperties:=$signedDataObjectProperties

$XAdES.qualifyingProperties.signedProperties:=$signedProperties
$XAdES.qualifyingProperties.signedProperties.id:=$signedProperties_id  //xsd:ID; optional

If ($unsignedProperties#Null:C1517)
	
	$XAdES.qualifyingProperties.unsignedProperties:=$unsignedProperties
	$XAdES.qualifyingProperties.unsignedProperties.id:=$unsignedProperties_id  //xsd:ID; optional
	
End if 

/*

notes:

the version is hardcoded, for now 1.3.2

TODO: specify 1.4.1 or 1.4.2 namespaces (TimeStampValidationData, ArchiveTimeStamp)

format is hardcoded, enveloped only, for now

TODO: internal detached, external detached, enveloping

C14N is 1_0 (inclusive)

TODO: add exclusive c14n

level is baseline B only

*/

$0:=$XAdES