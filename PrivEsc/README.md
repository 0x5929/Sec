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
1. Insecure service permissions
    - Description: if a user's permission is allowed to access and modify a service, such as SERVICE_CHANGE_CONFIG, we can change its binary path
    - Requirements: 
      - service must be running as LocalSystem
      - SERVICE_CHANGE_CONFIG is within the permission of the user, or the group the user belongs to
      - ability to query service configurations
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
       - ability to start and stop the service
    - Related instructions: 
       - accesschk parameters : `/accepteula -uvwqd` 
          - `d` is for directory ACL check
       
3.  Weak registry permissions
    - Description: if the service itself has a strong ACL, and we are unable to modify, if we have writable access to the service's registry entry, we can also change its binary path
    - Requirements: 
        - service must be running as LocalSystem (if we are unable to query its config, we might not know until we try executing service for a System shell)
        - write access to the service's registry entry under: `HKLM\SYSTEM\CurrentControlSet\services\servicename`
        - ability to start and stop the service
    - Related instructions: 
        - accesschk parameters : `/accepteula -uvwqk` 
          - `k` is for registry key ACL check
        - reg command : `reg add HKLM\SYSETM\CurrentControlSet\services\servicename /v ImagePath /t REG_EXPAND_SZ /d C:\Malicious\path /f`
          - `/v ImagePath`: specifies ImagePath registry entry
          - `/t REG_EXPAND_SZ` : specifies expanded string registry entry type
          - `/d C:\Malicious\path` : specifies the data we want to put inside the registry entry
          - `/f` : forces execution without user interaction/confirmation
  
  
### Registry

### Password Management

### Scheduled Tasks

### Applications and Programs

### Token Abuse

# Linux Methodology 


