# 001: Windows Server ISO booted into recovery

## Problem:

- Booted into recovery environment

## Cause: 

- Incorrect boot sequence

## Resolution: 

- Created New VM with correct boot sequence


# 002: Static IP

## Problem:

- Dynamic DHCP

## Resolution:

- Configured static IP

## Validated:

- PowerShell cmds: 
    - ping
    - nslookup


# 003: Domain Join:

- Validated with PowerShell cmds:
    - nslookup corp.local
    - pind dc01.corp.local

- Joined successfully


# 004 Wazuh Agent:

## Problem:

- Agent installed correctly, not producing Sysmon alerts in Wazuh dashboard

## Resolution:

- Added
    - Microsoft-Windows-Sysmon/Operational
- Restarted
    - Restart-Service WazuhSvc


# 005 Sysmon

## Problem:
 
- Events logged, not being displayed on Wazuh dashboard

## Resolution:

- Edited ossec.config file
    - Enabled:
        - logall
        - logall_json

- Restarted Manager 


# 006 Atomic Red Team

## Problem:

- Repository download was being blocked by Windows Defender detecting executable malware

## Resolution:

- Executed manual discovery commands instead