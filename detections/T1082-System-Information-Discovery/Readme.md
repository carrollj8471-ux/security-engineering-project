# MITRE ATT&CK Detection Engineering Case Study

    - Project:
        - Active Directory Attack & Defense Lab

        - Case Study:
            - 01

        - Technique:
            - T1082

        - Technique Name:
            - System Information Discovery

        - Date:
            - 7/12/2026

        - Status: Complete

## Executive Summary ## 

    - Attackers commonly gather operating system information after initial access to determin the environment they have compromise. This helps them choose privilege escalation methods, persistence mechanisms, and campatible malware. The purpose of this exercise is to validate that Sysmon and Wazuh detect and log this activity.


## Learning Objectives ##

- Detect Windows telemetry
- Validate Sysmon
- Validate Wazuh
- Perform threat hunting

## MITRE Information ##

- Technique ID:

- Technique Name:

- Tactic:

- Description:

- Reference URL:


## Lab Environment ##

Item:                      Value:
Hypervisor        |          VMware Workstation Pro
DC                |        DC01
Client            |         WIN11
Domain            |         corp.local
SIEM              |         Wazuh
Telemetry         |         Sysmon
Windows           |         Windows 11 Enterprise


## Attack Scenario ##

- After compromising WIN11, the attack then attempts to identify the operating system and hardware before deciding how to best proceeed.