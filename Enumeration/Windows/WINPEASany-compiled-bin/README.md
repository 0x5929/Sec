# WINPEAS Enumeration Tool

**Please visit the repo page for additional references** [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)

### Usage Direction: 

*if executing inside windows cmd, make sure we turn on color, and restart cmd prompt*

`REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1`

```
winpeas.exe -h                        # Display help menu
winpeas.exe cmd searchall             # cmd commands, search all filenames and avoid sleepig (noisy - CTFs)
winpeas.exe                           # Will execute all checks except the ones that use external Windows binaries
winpeas.exe cmd                       # All checks
winpeas.exe systeminfo userinfo       # Only systeminfo and userinfo checks executed
winpeas.exe notcolor                  # Do not color the output
winpeas.exe cmd wait                  # cmd commands and wait between tests

```
#### Usage Examples: 

