$AdminUser = 'Administrator'
$AdminPass = ConvertTo-SecureString "password" -AsPlainText -Force
$AdminCreds = New-Object System.Management.Automation.PSCredential ($AdminUser, $AdminPass)
Start-Process "c:\windows\system32\cmd.exe" -ArgumentList "/c whoami" -Credential $AdminCreds -NoNewWindow -PassThru -RedirectStandardOutput $env:temp\log.txt