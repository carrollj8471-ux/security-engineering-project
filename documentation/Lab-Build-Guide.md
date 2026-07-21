# Lab Build Guide

## Purpose

This guide describes the target environment assumed by the detection engineering case studies.

## Components

### Virtual machines on VMware

| Virtual machine | Platform | Roles and installed components | Security engineering purpose |
|---|---|---|---|
| `DC01` | Windows Server 2022 | Domain Controller; Active Directory Domain Services; DNS; domain policy; Wazuh agent; Sysmon | Provides centralized identity, authentication, name resolution, policy enforcement, and domain-controller security telemetry |
| `WIN11` | Windows 11 workstation | Endpoint test system; Wazuh agent; Sysmon; Atomic Red Team | Executes safe ATT&CK-aligned tests and scans while collecting process, file, registry, network, PowerShell, and Windows Security telemetry |
| `wazuh-manager` | Ubuntu Server | Wazuh platform; Wazuh Manager; Sysmon for Linux | Receives and analyzes endpoint events, evaluates detection rules, indexes alerts, supports threat hunting, and provides Linux host telemetry |

## Build Notes

Deploy and validate the appropriate Sysmon sensor and Wazuh agent on each monitored VM before running tests. Confirm that `DC01` and `WIN11` Windows events appear in Wazuh, verify Ubuntu telemetry separately, and record service health and timestamps before collecting case-study evidence.
