# Lab Build Guide

## Purpose

This guide describes the target environment assumed by the detection engineering case studies.

## Components
# Virtual Machines on VMWare
| Component | Purpose |
|---|---| 

| Windows Server 2022 Domain Controller |
  - Active Directory, DNS, and domain policy |

| Windows 11 Workstation | Endpoint test system |
  - Sysmon | Endpoint process, file, registry, and network telemetry |
  - Wazuh Agent | Log forwarding from Windows endpoints | Atomic Red Team |

|Ubuntu VM |
  - Wazuh Manager | SIEM ingestion, indexing, alerting, and threat hunting |
  - Safe ATT&CK-aligned test execution |

## Build Notes

Deploy Sysmon before running tests, confirm the Wazuh agent is connected, and validate that Microsoft-Windows-Sysmon/Operational events appear in Wazuh before collecting evidence.
