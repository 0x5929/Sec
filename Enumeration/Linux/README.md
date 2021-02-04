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

**Downloadable shortcut** : `wget https://raw.githubusercontent.com/rennitbaby/Sec/main/Enumeration/Linux/LinEnum.sh`

**Original Repo for the latest version** [rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

**Comments**

> Don't forget to utilize thorough test with -t flag, utilizing -k we can also specify a keyword for our scan. Also -e and -r is useful to keep things organized

# linux-exploit-suggester

**Usage Instructions**

**Usage Example**

**Downloadable shortcut** : `coming soon`

**Original Repo for the latest version**

**Comments**

# linux-exploit-suggester-2

**Usage Instructions**

**Usage Example**

**Downloadable shortcut** : `coming soon`

**Original Repo for the latest version**

**Comments**

# linuxprivchecker

**Usage Instructions**

**Usage Example**

**Downloadable shortcut** : `coming soon`

**Original Repo for the latest version**

**Comments**

# linux smart enumeration

**Usage Instructions**

**Usage Example**

**Downloadable shortcut** : `coming soon`

**Original Repo for the latest version**

**Comments**

# unixprivchecker

**Usage Instructions**

**Usage Example**

**Downloadable shortcut** : `coming soon`

**Original Repo for the latest version**

**Comments**

# LinPEAS

**Usage Instructions**

**Usage Example**


**Downloadable shortcut** : `coming soon`

**Original Repo for the latest version**

**Comments**
