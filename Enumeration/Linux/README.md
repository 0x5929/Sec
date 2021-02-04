# Linux Privilege Esclation Scripts

**Note that most of the scripts are meant to be run on a target host with low priv to enumerate vulnerabilities for privilege esclation**

# LinEnum

**Usage Instructions**
```
user@debian:/dev/shm$ bash LinEnum.sh -h
LinEnum.sh: option requires an argument -- h

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com | @rebootuser 
# version 0.982

# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t 

OPTIONS:
-k      Enter keyword
-e      Enter export location
-s      Supply user password for sudo checks (INSECURE)
-t      Include thorough (lengthy) tests
-r      Enter report name
-h      Displays this help text


Running with no options = limited scans/no output file
#########################################################
user@debian:/dev/shm$ 

```

**Usage Example**
```
user@debian:/dev/shm$ bash LinEnum.sh -r vulnDebian -e /dev/shm/LinEnum -t

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Report name = vulnDebian-03-02-21
[+] Export location = /dev/shm/LinEnum
[+] Thorough tests = Enabled


Scan started at:
Wed Feb  3 22:44:33 EST 2021

...

```

**Downloadable shortcut** : `wget https://raw.githubusercontent.com/0x5929/Sec/main/Enumeration/Linux/LinEnum.sh`

**Original Repo for the latest version** [rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

**Comments**

> Don't forget to utilize thorough test with -t flag, utilizing -k we can also specify a keyword for our scan. Also -e and -r is useful to keep things organized



# linux-exploit-suggester

**Usage Instructions** 
```
user@debian:/dev/shm$ bash linux-exploit-suggester.sh -h
LES ver. v1.1 (https://github.com/mzet-/linux-exploit-suggester) by @_mzet_

Usage: linux-exploit-suggester.sh [OPTIONS]

 -V | --version               - print version of this script
 -h | --help                  - print this help
 -k | --kernel <version>      - provide kernel version
 -u | --uname <string>        - provide 'uname -a' string
 --skip-more-checks           - do not perform additional checks (kernel config, sysctl) to determine if exploit is applicable
 --skip-pkg-versions          - skip checking for exact userspace package version (helps to avoid false negatives)
 -p | --pkglist-file <file>   - provide file with 'dpkg -l' or 'rpm -qa' command output
 --cvelist-file <file>        - provide file with Linux kernel CVEs list
 --checksec                   - list security related features for your HW/kernel
 -s | --fetch-sources         - automatically downloads source for matched exploit
 -b | --fetch-binaries        - automatically downloads binary for matched exploit if available
 -f | --full                  - show full info about matched exploit
 -g | --short                 - show shorten info about matched exploit
 --kernelspace-only           - show only kernel vulnerabilities
 --userspace-only             - show only userspace vulnerabilities
 -d | --show-dos              - show also DoSes in results
user@debian:/dev/shm$ 

```

**Usage Example**
```
user@debian:/dev/shm$ uname -a                                                                                                                    
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux                                                                  
user@debian:/dev/shm$ bash linux-exploit-suggester.sh -k 2.6.32          
                                                                         
Available information:                                                                                                                            
                                                                         
Kernel version: 2.6.32
Architecture: N/A
Distribution: N/A
Distribution version: N/A
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): N/A
Package listing: N/A

Searching among:

74 kernel space exploits
0 user space exploits

Possible Exploits:

[+] [CVE-2016-5195] dirtycow

```


**Downloadable shortcut** : `wget https://raw.githubusercontent.com/0x5929/Sec/main/Enumeration/Linux/linux-exploit-suggester.sh`

**Original Repo for the latest version** [mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)

**Comments**
> Personal favorite is to actually run from testing machine, but grab kenerl version from target machine


# linux-exploit-suggester-2

**Usage Instructions**
```
user@debian:/dev/shm$ perl linux-exploit-suggester-2.pl -h

  #############################
    Linux Exploit Suggester 2
  #############################

  Usage: linux-exploit-suggester-2.pl [-h] [-k kernel] [-d]

  [-h] Help (this message)
  [-k] Kernel number (eg. 2.6.28)
  [-d] Open exploit download menu

  You can also provide a partial kernel version (eg. 2.4)
  to see all exploits available.

user@debian:/dev/shm$ 
```

**Usage Example**

```
user@debian:/dev/shm$ uname -a                                           
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux
user@debian:/dev/shm$ perl linux-exploit-suggester-2.pl -k 2.6.32
                                                                         
  #############################
    Linux Exploit Suggester 2                                            
  #############################                                          
                                    
  Local Kernel: 2.6.32
  Searching 72 exploits...                                                                                                                        
                                    
  Possible Exploits
  [1] american-sign-language                                             
      CVE-2010-4347
      Source: http://www.securityfocus.com/bid/45408
  [2] can_bcm                                                            
      CVE-2010-2959
      Source: http://www.exploit-db.com/exploits/14814
  [3] dirty_cow                                                          
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
...

```

**Downloadable shortcut** : `wget https://raw.githubusercontent.com/0x5929/Sec/main/Enumeration/Linux/linux-exploit-suggester-2.pl`

**Original Repo for the latest version** [jondonas/linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2)

**Comments**
> Same with the linux-exploit-sugguest, I personally like to run it on testing machine with target machine's kernel #, also its good to cross reference results from both linux-exploit-suggester and linux-exploit-suggester-2


# linuxprivchecker

**Usage Instructions** *from the original repo*

```
Command Options and arguments
If the system your testing has Python 2.6 or high and/or argparser installed, you can utilize the following options. If importing argparser does not work, all checks will be run and no log file will be written. However, you can still use terminal redirection to create a log, such as 'python linuxprivchecker.py > linuxprivchecker.log.'

usage: linuxprivchecker.py [-h] [-s] [-w] [-o OUTFILE]

Try to gather system information and find likely exploits

optional arguments: -h, --help show this help message and exit

-s, --searches Skip time consumming or resource intensive searches

-w, --write Wether to write a log file, can be used with -0 to specify name/location

-o OUTFILE, --outfile OUTFILE The file to write results (needs to be writable for current user)
```


**Usage Example** *note as per instructions, if the system does not have python2.6 + parsing arguments will not work, but we can write log file with redirection

```
user@debian:/dev/shm$ /usr/bin/python2.6 linuxprivchecker.py > linuxprivchecker.result
user@debian:/dev/shm$ head -n 30 linuxprivchecker.result
Arguments could not be processed, defaulting to print everything
=======================================================================================

        __    _                  ____       _       ________              __
       / /   (_)___  __  ___  __/ __ \_____(_)   __/ ____/ /_  ___  _____/ /_____  _____
      / /   / / __ \/ / / / |/_/ /_/ / ___/ / | / / /   / __ \/ _ \/ ___/ //_/ _ \/ ___/
     / /___/ / / / / /_/ />  </ ____/ /  / /| |/ / /___/ / / /  __/ /__/ ,< /  __/ /
    /_____/_/_/ /_/\__,_/_/|_/_/   /_/  /_/ |___/\____/_/ /_/\___/\___/_/|_|\___/_/

    
=======================================================================================

[*] ENUMERATING USER AND ENVIRONMENTAL INFO...

[+] List out any screens running for the current user
[+] Logged in User Activity
    2021-02-03 22:31               277 id=si    term=0 exit=0
    system boot  2021-02-03 22:31
    run-level 2  2021-02-03 22:31                   last=S
    2021-02-03 22:32              1490 id=l2    term=0 exit=0
    LOGIN      tty3         2021-02-03 22:32              2526 id=3
    LOGIN      tty4         2021-02-03 22:32              2527 id=4
    LOGIN      tty5         2021-02-03 22:32              2528 id=5
    LOGIN      tty6         2021-02-03 22:32              2529 id=6
    LOGIN      tty2         2021-02-03 22:32              2525 id=2
    LOGIN      tty1         2021-02-03 22:32              2524 id=1
    user     + pts/0        2021-02-03 22:34   .          2557 (ip-10-2-62-214.eu-west-1.compute.internal)
[+] Super Users Found:
    root
[+] Environment
user@debian:/dev/shm$

```

**Downloadable shortcut** : `wget https://raw.githubusercontent.com/0x5929/Sec/main/Enumeration/Linux/linuxprivchecker.py`

**Original Repo for the latest version** (sleventyeleven/linuxprivchecker)[https://github.com/sleventyeleven/linuxprivchecker]

**Comments**
> I don't use this tool too much, but always good to have additional enumerated script info to check when we are stuck


# linux smart enumeration

**Usage Instructions**

```
user@debian:/dev/shm$ bash lse.sh -h
Use: lse.sh [options]

 OPTIONS
  -c           Disable color
  -i           Non interactive mode
  -h           This help
  -l LEVEL     Output verbosity level
                 0: Show highly important results. (default)
                 1: Show interesting results.
                 2: Show all gathered information.
  -s SELECTION Comma separated list of sections or tests to run. Available
               sections:
                 usr: User related tests.
                 sud: Sudo related tests.
                 fst: File system related tests.
                 sys: System related tests.
                 sec: Security measures related tests.
                 ret: Recurrent tasks (cron, timers) related tests.
                 net: Network related tests.
                 srv: Services related tests.
                 pro: Processes related tests.
                 sof: Software related tests.
                 ctn: Container (docker, lxc) related tests.
               Specific tests can be used with their IDs (i.e.: usr020,sud)
  -e PATHS     Comma separated list of paths to exclude. This allows you
               to do faster scans at the cost of completeness
  -p SECONDS   Time that the process monitor will spend watching for
               processes. A value of 0 will disable any watch (default: 60)
  -S           Serve the lse.sh script in this host so it can be retrieved
               from a remote host.
user@debian:/dev/shm$ 

```

**Usage Example**
```
user@debian:/dev/shm$ bash lse.sh -i -l 0                                                                                                         
                                                                                                                                                  
 LSE Version: 3.0

        User: user
     User ID: 1000
    Password: none
        Home: /home/user
        Path: /usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin
       umask: 0022

    Hostname: debian
       Linux: 2.6.32-5-amd64
Architecture: x86_64
...
```

**Downloadable shortcut** : `wget https://raw.githubusercontent.com/0x5929/Sec/main/Enumeration/Linux/lse.sh`

**Original Repo for the latest version**  [diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

**Comments**
> This is a great tool, I personally like to use this along with LinEnum to do post-explotiation pre-privesc enumeration


# unixprivchecker (upc)

**Usage Instructions**
```
user@debian:/dev/shm/unix-privesc-check$ bash upc.sh -h                                                                                           
unix-privesc-check v2.1 ( http://code.google.com/p/unix-privesc-check )                                                                           
                                                                                                                                                  
Shell script to check for simple privilege escalation vectors on UNIX systems.                                                                    
                                                                                                                                                  
Usage: upc.sh                                                                                                                                     
                                                                                                                                                  
        --help  display this help and exit                                                                                                        
        --version       display version and exit                                                                                                  
        --color enable output coloring                                                                                                            
        --verbose       verbose level (0-2, default: 1)                                                                                           
        --type  select from one of the following check types:                                                                                     
                all                                                                                                                               
                attack_surface                                                                                                                    
                sdl                                                                                                                               
        --checks        provide a comma separated list of checks to run, select from the following checks:                                        
                credentials                                                                                                                       
                devices_options                                                                                                                   
                devices_permission                                                                                                                
                gpg_agent                                                                                                                         
                group_writable                                                                                                                    
                history_readable                                                                                                                  
                homedirs_executable                                                                                                               
                homedirs_writable                                                                                                                 
                jar                                                                                                                               
                key_material                                                                                                                      
                ldap_authentication                                                                                                               
                nis_authentication                                                                                                                
                passwd_hashes                                                                                                                     
                postgresql_configuration                                                                                                          
                postgresql_connection                                                                                                             
                postgresql_trust                                                                                                                  
                privileged_arguments 
                                privileged_banned
                privileged_change_privileges
                privileged_chroot
                privileged_dependency
                privileged_environment_variables
                privileged_nx
                privileged_path
                privileged_pie
                privileged_random
                privileged_relro
                privileged_rpath
                privileged_ssp
                privileged_tmp
                privileged_writable
                setgid
                setuid
                shadow_hashes
                ssh_agent
                ssh_key
                sudo
                system_aslr
                system_configuration 
                system_libraries
                system_mmap
                system_nx
                system_selinux
                world_writable
user@debian:/dev/shm/unix-privesc-check$

```
**Usage Example**
```
user@debian:/dev/shm/unix-privesc-check$ bash upc.sh --color --type all   
unix-privesc-check v2.1 ( http://code.google.com/p/unix-privesc-check )

I: [file] Generating file cache...
...
```

**Downloadable shortcut** : `wget https://raw.githubusercontent.com/0x5929/Sec/main/Enumeration/Linux/upc.zip`

**Original Repo for the latest version** [pentestmonkey/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)

**Comments**
> This tool needs to be downloaded to target machine as a zip file, unzip it, and run checks. The full checks are also rather slow.


# LinPEAS

**Usage Instructions**
```
user@debian:/dev/shm$ bash linpeas.sh -h
Enumerate and search Privilege Escalation vectors.
This tool enum and search possible misconfigurations (known vulns, user, processes and file permissions, special file permissions, readable/writable files, bruteforce other users(top1000pwds), passwords...) inside the host and highlight possible misconfigurations with colors.
      -h To show this message
      -q Do not show banner
      -a All checks (1min of processes and su brute) - Noisy mode, for CTFs mainly
      -s SuperFast (don't check some time consuming checks) - Stealth mode
      -w Wait execution between big blocks
      -n Do not export env variables related with history and do not check Internet connectivity
      -P Indicate a password that will be used to run 'sudo -l' and to bruteforce other users accounts via 'su'
      -o Only execute selected checks (SysI, Devs, AvaSof, ProCronSrvcsTmrsSocks, Net, UsrI, SofI, IntFiles). Select a comma separated list.
      -L Force linpeas execution.
      -M Force macpeas execution.
      -d <IP/NETMASK> Discover hosts using fping or ping. Ex: -d 192.168.0.1/24
      -p <PORT(s)> -d <IP/NETMASK> Discover hosts looking for TCP open ports (via nc). By default ports 22,80,443,445,3389 and another one indicated by you will be scanned (select 22 if you don't want to add more). You can also add a list of ports. Ex: -d 192.168.0.1/24 -p 53,139
      -i <IP> [-p <PORT(s)>] Scan an IP using nc. By default (no -p), top1000 of nmap will be scanned, but you can select a list of ports instead. Ex: -i 127.0.0.1 -p 53,80,443,8000,8080
       Notice that if you select some network action, no PE check will be performed

user@debian:/dev/shm$ 

```

**Usage Example**
```
user@debian:/dev/shm$ bash linpeas.sh -qa                                
 Starting linpeas. Caching Writable Folders...                                                                                                    
                                                                         
                                                                                                                                                  
                     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                                                                                               
             ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄▄                               
      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄                                                                                                    
  ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄                                                                                               
  ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                                                                              
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                                                                                ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄                                                                                              
  ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄                                                                                               
  ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄                     
  ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄                     
  ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄                                                                                              
  ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                                                                              
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄                                                                                              
  ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄                     
  ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄                     
  ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄                                                                                              
  ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
  ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   ▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄
        ▄▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄ 
             ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    linpeas v3.0.3 by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be 
the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEGEND:

```

**Downloadable shortcut** : `wget https://raw.githubusercontent.com/0x5929/Sec/main/Enumeration/Linux/linpeas.sh`

**Original Repo for the latest version** [carlopolop/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**Comments**
> Super awesome tool!
