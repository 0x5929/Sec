# Enumeration 

### Please note that most of the scripts and binaries inside this directory are meant for post-exploitation

This means that the enumeration automated steps are completed after the an initial foothold of some sort. Assuming having RCE and a low privileged shell.


### For initial enumeration: 

1. `nmap` - port/host scanning
  - initial scanning : `nmap -p- -oA nmap/intial <host>`
  - deeper scanning : `nmap -p <ports-from-initial-scan> -sC -sV -oA nmap/deeper_scan <host>`
  - scans including vuln scripts : `nmap -p <ports-from-initial-scan> -sC -sV --script vuln -oA nmap/full_vuln_scan <host>`
  
2. `gobuster` - hidden web directory scanning
  - scanning with extensions : `gobuster dir -u <host> -w <dirbuster/directory-2-3-medium.txt> -x php,txt,html -o gobuster/results.txt`
  
3. `nikto` - vulnerability, hidden directory scanning
  - scanning a host : `nikto -h <host> | tee nikto/output.txt`

4. `sqlmap` - sql injection scanning
  - scanning a host with vulnerable request captured in Burpe : `sqlmap -r <GET/POST-request.txt>`

5. `wpscan` - wordpress site scanning

6. `wfuzz` - bruteforcing/directory scanning

7. `searchsploit` - exploit scanning
  - scanning for exploits containing keyword : `searchsploit (-x|-m|) <keyword-like-apache>`
