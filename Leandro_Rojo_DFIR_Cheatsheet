
# LEANDRO'S DFIR CHEATSHEET
---------------------------

## TOOLS:
- [EXT] Check suspicious IPs for outgoing traffic (see ISP): https://whatismyipaddress.com
- [EXT] Sysinternals Suite (Procmon.exe, Autoruns.exe, procexp.exe): https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
- [EXT] Virustotal for searching by file hashes: https://www.virustotal.com/gui/home/upload
- eventvwr.msc
- regedit
- **Windows Event Viewer**: For analyzing logs.
- **PowerShell ISE**: For running scripts and automation.
- **FTK Imager**: Useful for creating disk images and analyzing file systems.
- **Wireshark**: For capturing and analyzing network traffic.
- **NetworkMiner**: For extracting artifacts from network traffic.

## FILE HASHING IN POWERSHELL:
C:\> Get-FileHash C:\path\to\suspicious\file.exe -Algorithm SHA1 | Format-List

## FOR STRANGE STARTUP PROGRAMS/SCHEDULED TASKS:
- Startup scheduled tasks using the command prompt --> C:\> wmic startup list full
- Look into Autoruns.exe (Sysinternals Suite)
- Look in Startup Folder C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
- Look for strange programs in startup registry keys in both HKLM & HKCU:
  - Software\Microsoft\Windows\CurrentVersion\Run
  - Software\Microsoft\Windows\CurrentVersion\Runonce
  - Software\Microsoft\Windows\CurrentVersion\RunonceEx

## FOR VIEW NETWORK USAGE BY PROCESS AND DLL:
- Execute C:\> netstat –anob
- Execute procexp.exe (Sysinternals Suite)

## FOR ADMINISTRATOR ACCOUNTS:
- List administrators --> (GUI) lusrmgr.msc | (CLI) C:\> net user | C:\> net localgroup administrators

## EVENTS ID CHEATSHEET (eventvwr):
- **Event ID 4688 [Security]**: Creation of a new process (useful to see when a malicious file was executed).
- **Event ID 4689 [Security]**: Process termination (helps identify when a suspicious process ends).
- **Event ID 4624 [Security]**: Successful logons (may indicate authorized or unauthorized access attempts).
- **Event ID 4625 [Security]**: Failed logons (useful for detecting possible intrusion attempts that failed).
- **Event ID 5140 [Security]**: Access to a shared resource (useful for monitoring access to network files).
- **Event ID 5145 [Security]**: Permissions to access shared files or folders (may reveal unauthorized access to network resources).
- **Event ID 4656 [Security]**: Attempted access to an object (helps detect attempts to tamper with files or folders).
- **Event ID 4663 [Security]**: Access to an object (helps identify actual access to important files or folders).
- **Event ID 4720 [Security]**: Creation of a user account (important for detecting possible malicious account creations).
- **Event ID 4726 [Security]**: Deletion of a user account (useful for spotting the removal of accounts, potentially by malicious actors).
- **Event ID 1102 [Security]**: Security log cleared (indicative of malicious activity attempting to cover its tracks).
- **Event ID 4657 [Security]**: Registry object modification (useful for detecting system changes made by malware).
- **Event ID 4698 [Security]**: Creation of a scheduled task (can be a sign of malware persistence).
- **Event ID 4723 [Security]**: Successful password change attempt (monitors credential changes to prevent unauthorized access).
- **Event ID 4732 [Security]**: User added to a security group (important for detecting when users are added to privileged groups).
- **Event ID 4907 [Security]**: Changes to security audit policies (can show modifications that may evade detection).
- **Event ID 4648 [Security]**: Logon with explicit credentials (useful for detecting access with different credentials than usual).
- **Event ID 4756 [Security]**: User added to a global security group (tracks changes to Active Directory groups).
- **Event ID 4776 [Security]**: NTLM authentication (useful for monitoring both successful and failed authentication attempts).
- **Event ID 7045 [System]**: Service installation (sometimes malware installs malicious services).
- **Event ID 6008 [System]**: The previous system shutdown was unexpected.
- **Event ID 41 [System]**: The system has rebooted without cleanly shutting down first.
- **Event ID 7036 [System]**: A service entered the running state (helps to track when services start).
- **Event ID 1116 [APPS/Microsoft-Windows-WindowsDefender/Operational]**: Windows Defender detected malware or other potentially unwanted software.
- **Event ID 1117 [APPS/Microsoft-Windows-WindowsDefender/Operational]**: Windows Defender took action to protect the system from malware or other potentially unwanted software.
- **Event ID 1000 [Application]**: Application Error (indicates when an application crashes unexpectedly).
- **Event ID 1001 [Application]**: Windows Error Reporting (records application errors and crashes).
- **Event ID 1026 [Application]**: .NET Runtime error (indicates .NET application issues).
- **Event ID 3001 [Application]**: Application crash (notifies of application failures).

## (REMINDER) DON'T FORGET TO LOOK HERE:
C:\Windows\Temp
C:\Users\%USERNAME%\AppData\Local\Temp
C:\ProgramData

## CHECKLIST FOR ANALYSIS:
- Check for Indicators of Compromise (IoCs): 
  - Look for known malicious IPs, hashes, or URLs associated with the incident.
  
- Examine the Event Log: 
  - Filter by user accounts, source IP addresses, and event types to narrow down suspicious activities.
  
- Perform Memory Analysis: 
  - Use tools like Volatility to analyze memory dumps for malware artifacts.
