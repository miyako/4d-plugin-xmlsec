//%attributes = {"invisible":true}
$uuid:=Generate UUID:C1066

ARRAY LONGINT:C221($pos;0)
ARRAY LONGINT:C221($len;0)

If (Match regex:C1019("([:hex_digit:]{8})([:hex_digit:]{4})([:hex_digit:]{4})([:hex_digit:]{16})";$uuid;1;$pos;$len))
	$uuid:=Lowercase:C14(New collection:C1472(Substring:C12($uuid;$pos{1};$len{1});Substring:C12($uuid;$pos{2};$len{2});Substring:C12($uuid;$pos{3};$len{3});Substring:C12($uuid;$pos{4};$len{4})).join("-");*)
End if 

$0:=$uuid