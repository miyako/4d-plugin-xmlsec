# 4d-plugin-xmlsec
XML signature based on [xmlsec](https://www.aleksey.com/xmlsec/)

### Sign

```4d
$tmpl:=Folder(fk resources folder).folder("sign1").file("sign1-tmpl.xml")
$rsakey:=Folder(fk resources folder).file("rsakey.pem")

$params:=New object
$params.tmpl:=$tmpl.getText()
$params.name:=$rsakey.name+$rsakey.extension  //<KeyName>...</KeyName>

$keyBLOB:=$rsakey.getContent()

$status:=xmlsec sign ($params;$keyBLOB)

If ($status.success)
	SET TEXT TO PASTEBOARD($status.xml)
End if 
```

#### options for **sign**

* `name`: `<dsig:KeyName>` (optional)  
