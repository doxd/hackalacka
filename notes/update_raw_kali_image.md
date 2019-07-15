# Updates to fresh Kali Image

## Preferences
* Tweaks -> Themes: Kali-X Dark
* Settings -> Privacy: Screen Lock Off

## Add to Favorites
* Wireshark (GTK+)
* gedit (theme: oblivion)
* CherryTree
  * update color scheme: Don't highlight current line, custom bg #353535 fg #cccccc, code box 'oblivion', disable 'smart quotes auto replacement' 

## Download/Install
* VS Code https://code.visualstudio.com/#alt-downloads
* Local copy of CyberChef https://gchq.github.io/CyberChef/
* OWASP Amass https://github.com/OWASP/Amass
* Win enumeration script  https://github.com/411Hall/JAWS/blob/master/jaws-enum.ps1 `powershell -exec bypass .\jaws-enum.ps1 -outputfilename enum.txt`
* Lin enumeration script https://github.com/kevthehermit/pentest/blob/master/linuxenum-mod.sh
* Lin priv checker https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
* CTB template https://411hall.github.io/assets/ﬁles/CTF_template.ctb
* windows-privesc-check2.exe https://github.com/pentestmonkey/windows-privesccheck
* SysInternals https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternalssuite
* start_listeners.sh
```sh
#!/bin/bash
for LPORT in $(seq 2000 1000 7000); do
    tmux new -d -s "l$LPORT" " while true; do nc -nlvp $LPORT; done;"
done
```

## File Manager Bookmarks
* /var/www/html
* /home/ftpusers/hackerman
* working dir for exam/labs
* ~/utilities
* /usr/share/seclists

## Fix enum4linux smb issues
* Download and build
  * `https://download.samba.org/pub/samba/stable/samba-3.2.0.tar.gz`
  * Extract to `/root/`
  * `./conﬁgure --preﬁx=/root/samba3.2.0 --exec-preﬁx=/root/samba3.2.0`
  * `make && make install`
* Update conﬁguration
  * `cp /root/samba-3.2.0/examples/smb.conf.default /root/samba3.2.0/lib/smb.conf`
  * Create ﬁle `/etc/ld.so.conf.d/newsamba.conf`
  * add these 2 lines:
    * `/root/samba3.2.0/lib`
    * `/root/samba-3.2.0/source/bin`
  * Run `ldconfig`
* Set path and run (note this will only set the variables for the current session)
  * `PATH=/root/samba3.2.0/bin/:$PATH`
  * `PATH=/root/samba-3.2.0/source/bin:$PATH`
  * `enum4linux barry`

## Bookmarks
* https://forums.oﬀensive-security.com/ 
* https://github.com/411Hall/JAWS/blob/master/jaws-enum.ps1 
* https://github.com/kevthehermit/pentest/blob/master/linux-enum-mod.sh 
* https://411hall.github.io/assets/ﬁles/CTF_template.ctb 
* https://tmuxcheatsheet.com/ 
* ﬁle:///root/Desktop/cyberchef.htm 
* https://www.exploit-db.com/ 
* https://www.securityfocus.com/ 
* https://sushant747.gitbooks.io/total-oscp-guide/ 
* https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite 
* https://crackstation.net/ 
* http://www.fuzzysecurity.com/tutorials/16.html

## Configuration
PureFTPd setup
```sh
mkdir /home/ftpusers
mkdir /home/ftpusers/hackerman
# Create ftp user and group if they don't already exist:
groupadd ftpgroup   
useradd -b /home/ftpusers -g ftpgroup -M -s /bin/false ftpuser  
# /Create
pure-pw useradd hackerman -u ftpuser -d /home/ftpusers/hackerman 
Password: 
Enter it again: 
pure-pw mkdb 
sudo ln -s /etc/pure-ftpd/pureftpd.passwd /etc/pureftpd.passwd 
sudo ln -s /etc/pure-ftpd/pureftpd.pdb /etc/pureftpd.pdb
chown -hR ftpuser:ftpgroup /home/ftpusers 
service pure-ftpd restart
```