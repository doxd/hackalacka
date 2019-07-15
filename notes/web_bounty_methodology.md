# Web Bounty Methodology
## How do you eat an elephant? *One bite at a time!*

<img src ="images/web_bounty_methodology.png" width="700" />

## Books
* The Web Application Hacker's Handbook
* OWASP Testing Guide https://www.owasp.org/images/1/19/OTGv4.pdf
* Web Hacking 101 - Peter Yaworski
* Breaking Into Information Security - Andy Gill
* Mastering Modern Web Penetration Testing - Prakhar Prasad

## Recon
### Recon - Resouces
  * Determine relevant IP ranges https://bgp.he.net/
  * https://whois.arin.net/ui/query.do
  * https://apps.db.ripe.net/db-web-ui/#/query
  * Shodan 👉 `org:"company name"`

### Brand/TLD Discovery
#### Brand Discovery
 * Acquisitions
   * Wikipedia
   * Crunchbase Acquisitions Section
 * Linked Discovery
   * Burp Spidering
 * Weighted Link and Reverse Tracker Analysis
   * domLink - recursively search whois results by company emails and names
   * builtwith - browser plugin to show technologies used
 * Googledork Copyright snippets eg `"Tesla © 2016" "Tesla © 2017" inurl:tesla.com` (according to their pattern on known sites)

### Discovering New Targets (Subdomain Discovery)
 * Subdomain Scraping
   * Sources: search engines, ssl certs, virustotal, wayback machine
   * Tool: OWASP amass
   * Tool: subfinder https://github.com/subfinder/subfinder
 * Subdomain Bruteforcing
   * `gobuster -m dns -w wordlist.txt -u domain.tld -t 100`
   * massdns
   * Massive merged subdomain wordlist: jhaddix all.txt 👉 https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056
   * github recon

### Enumerating Targets
 * Port Scanning   
   1. **masscan** - *faster than nmap* but only takes IPs (not hostnames), so need to convert first
   1. `nmap -oG` - use on interesting results from masscan
   1. brutespray credential bruteforce using `-oG` output from nmap
 * Visual Identification
   * EyeWitness  - browses to each identified host and takes a screenshot, generates a report. Allows us to quickly triage/filter out duplicate/uninteresting results. We can focus on *custom applications that aren't their main site*
 * Wayback Enumeration - if a site is protected by basic auth, 401, 403: check archive.org. Might instantly find API keys or URL structure to browse unprotected content still there. `tomnomnom/waybackurls`
 * Platform identification and CVE search
   * `vulnersCom/burp-vulners-scanner`
   * Wappalyzer, builtwith
   * Retire.js
 
 #### Coverage for heavy JavaScript sites
 * ZAP AJAX Spider
 * Linkfinder - finds endpoints in JS files
 * JSParser - similar to Linkfinder
   
### Content Discovery/Directory Bruting
 * gobuster
   * Wordlists: seclists, *raft*, digger, robots.txt, *RobotsDisallowed*, **jhaddix content_discovery_all.txt** 👉 https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10
 * wpscan  
 * Parameter Bruting: parameth 

### Vulnerability Classes
 * XSS 
   * bXSS
   * ezXSS
 * SSRF
   * jhaddix cloud_metadata.txt 👉 https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b
 * IDOR (Insecure Direct Object Reference)/ MFLAC (Missing Function Level Access Control)
   * IDs, hashes, emails
 * Subdomain takeover
   * Check for CNAMEs that resolve to these services. If the service has lapsed, register and profit
   * EdOverflow/can-i-take-over-xyz
 * AWS Misconfigurations
   * sa7mon/SLScanner

### WAF or CDN vendor security (eg Akamai, Cloudflare)
 * Akamai
   * look for `origin-sub.domain.com` or `origin.sub.domain.com`, bypass the filtering by going to source
   * Try sending `Pragma: akamai-x-get-true-cache-key` - cache key often has the origin in it
 * Try other domains (dev.domain.com, stage.domain.com, ww1/ww2/ww3...domain.com, www.domain.co.uk/jp/au)