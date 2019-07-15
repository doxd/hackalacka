# Thorough, all levels/subfolders of events:
Get-WinEvent -ListLog * | Where-Object {$_.RecordCount} | ForEach-Object -Process { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }

# Shallow, top level only
Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log } 

# Clear PowerShell logs
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\*"
Clear-History
