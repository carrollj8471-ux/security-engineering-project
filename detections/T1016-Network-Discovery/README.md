# Detecting Windows Network Configuration Discovery with Sysmon and Wazuh

This case study validates detection of native Windows network-configuration discovery and maps the resulting alerts to MITRE ATT&CK `T1016 – System Network Configuration Discovery`.

## Result

Atomic Red Team generated `ipconfig /all`, `netsh interface show interface`, `arp -a`, `nbtstat -n`, and `net config` activity on WIN11. Existing rule `100203` covered the `ipconfig` and `arp` paths. Three new level 8 rules detected the remaining commands: `100180` for the netsh parent command, `100181` for `nbtstat -n`, and `100182` for `net config`. All mapped to T1016. Argument-negative controls did not trigger the new rules.

| Validation point | Observed result |
|---|---|
| Simulation | Atomic Red Team T1016 test 1 |
| Endpoint telemetry | Sysmon Event ID `1` confirmed |
| Wazuh collection | Process events present in manager archives |
| Existing coverage | Rule `100203` covered `ipconfig /all` and `arp -a` |
| Netsh detection | Rule `100180`, level `8` |
| Nbtstat detection | Rule `100181`, level `8` |
| Net config detection | Rule `100182`, level `8` |
| ATT&CK mapping | `T1016` |
| Tactic | Discovery |
| Negative controls | No custom-rule alerts |
| Cleanup evidence | Screenshot not supplied; explicit evidence gap |

## Objective and hypothesis

The objective was to determine whether native Windows network-discovery commands could be distinguished from ordinary execution of the same utilities. The hypothesis was that Sysmon would retain the command lines, Wazuh would collect the events, and argument-aware rules attached to the active rule paths would provide accurate T1016 classification.

The final design focused on:

- preserving existing coverage for `ipconfig /all` and `arp -a`;
- detecting `netsh interface show interface` through its winning parent-command rule;
- detecting `nbtstat -n` and `net config` through their active built-in branches;
- rejecting help-only invocations of the same utilities.

## Lab environment

| Component | Observed value |
|---|---|
| Endpoint | `WIN11.corp.local` |
| Wazuh agent | `WIN11`, agent `002` |
| User | `CORP\Administrator` |
| Wazuh manager | `wazuh-manager` |
| Wazuh version | `4.14.6` |
| Primary channel | `Microsoft-Windows-Sysmon/Operational` |
| Primary event | Sysmon Event ID `1` – Process Create |
| Simulation framework | Atomic Red Team |

![Network discovery readiness](evidence/01-network-discovery-readiness.png)

*Figure 1. Endpoint readiness showing active Sysmon and Wazuh services and available process telemetry.*

## Safe simulation

Atomic Red Team T1016 test 1 used signed Windows utilities to display local network configuration. It did not modify adapters, routes, addressing, DNS, or firewall state.

![Atomic test details and prerequisites](evidence/02-t1016-test-details-and-prerequisites.png)

*Figure 2. T1016 test details and prerequisite review before execution.*

![Atomic T1016 execution](evidence/03-t1016-network-discovery-execution.png)

*Figure 3. Authorized execution of the bounded network-discovery simulation.*

## Endpoint telemetry

Sysmon Event ID `1` retained the executable image, full command line, parent process, user, process identifiers, integrity level, hashes, and timestamp for the discovery utilities.

![Local Sysmon discovery events](evidence/04-local-sysmon-network-discovery-events.png)

*Figure 4. Local Sysmon process-creation evidence for the network-discovery commands.*

## Wazuh hunt and collection validation

The investigation began with broad and progressively narrower searches:

```text
agent.name:"WIN11" AND data.win.system.eventID:"1"
```

```text
agent.name:"WIN11" AND (data.win.eventdata.image:*ipconfig.exe OR data.win.eventdata.image:*netsh.exe OR data.win.eventdata.image:*arp.exe OR data.win.eventdata.image:*nbtstat.exe OR data.win.eventdata.image:*net.exe)
```

![Initial Wazuh discovery hunt A](evidence/05-wazuh-network-discovery-hunt-a.png)

*Figure 5. Initial Wazuh hunt for network-discovery process events.*

![Initial Wazuh discovery hunt B](evidence/05-wazuh-network-discovery-hunt-b.png)

*Figure 6. Narrowed hunt used to compare command-specific coverage.*

Manager-side archive and alert inspection distinguished collected telemetry from events promoted by detection rules.

![Rule-path analysis](evidence/06-t1016-rule-path-analysis.png)

*Figure 7. Rule-path analysis for the collected T1016 activity.*

![Existing rule analysis](evidence/07-existing-t1016-rule-analysis.png)

*Figure 8. Existing coverage showing that rule `100203` already classified the ipconfig and ARP paths.*

## Troubleshooting and detection engineering

Initial coverage was partial. `ipconfig /all` and `arp -a` already mapped correctly through rule `100203`, but the other commands followed different branches:

- the `netsh.exe` child event was collected without a dedicated alert;
- `nbtstat -n` initially matched generic rule `92032`;
- `net config` initially matched generic rule `92036`.

The first `100180` implementation inherited from Sysmon baseline rule `61603`, but it did not win the live evaluation path. A second implementation inherited from custom rule `100208` and matched the parent `cmd.exe` command line, but it still failed because the child appeared before its parent in the XML file. Moving `100180` immediately after `100208` corrected the hierarchy. Fresh events then generated rule `100180` alerts.

| Step | Observation | Engineering action | Result |
|---|---|---|---|
| 1 | All commands existed in endpoint or manager telemetry | Compared archives with alerts | Collection confirmed |
| 2 | `ipconfig` and `arp` already matched `100203` | Preserved existing coverage | No duplicate rules added |
| 3 | `nbtstat` and `net config` matched generic built-in rules | Added argument-aware children | Rules `100181` and `100182` fired |
| 4 | Standalone netsh child did not fire | Followed the winning parent command through `100208` | Correct dependency identified |
| 5 | Revised netsh rule still did not fire | Inspected XML ordering | Child was before its parent |
| 6 | Rule `100180` moved immediately after `100208` | Restarted and generated fresh activity | Netsh T1016 alert fired |
| 7 | Help commands could create binary-only noise | Ran `/?” controls | No custom-rule alerts |

Pre-existing duplicate-ID and invalid-group warnings elsewhere in the ruleset were observed but were not the cause of this T1016 issue.

### Validated rule hierarchy

```text
ipconfig /all and arp -a
└── 100203 — existing T1016 coverage

cmd.exe /c "netsh interface show interface"
└── 100208 — active parent command rule
    └── 100180 — netsh interface discovery (T1016)

nbtstat.exe -n
└── 92032 — active built-in branch
    └── 100181 — NetBIOS configuration discovery (T1016)

net.exe config
└── 92036 — active built-in branch
    └── 100182 — network configuration discovery (T1016)
```

### Final rules

```xml
<rule id="100180" level="8">
  <if_sid>100208</if_sid>
  <field name="win.eventdata.commandLine"
         type="pcre2">(?i)\bnetsh(?:\.exe)?\s+interface\s+show\b</field>
  <description>Windows network interfaces enumerated with netsh</description>
  <mitre><id>T1016</id></mitre>
  <group>discovery,network_configuration_discovery,</group>
</rule>

<rule id="100181" level="8">
  <if_sid>92032</if_sid>
  <field name="win.eventdata.image"
         type="pcre2">(?i)\\nbtstat\.exe$</field>
  <field name="win.eventdata.commandLine"
         type="pcre2">(?i)\s-n(?:\s|$)</field>
  <description>Local NetBIOS configuration enumerated with nbtstat</description>
  <mitre><id>T1016</id></mitre>
  <group>discovery,network_configuration_discovery,</group>
</rule>

<rule id="100182" level="8">
  <if_sid>92036</if_sid>
  <field name="win.eventdata.image"
         type="pcre2">(?i)\\net\.exe$</field>
  <field name="win.eventdata.commandLine"
         type="pcre2">(?i)\bconfig\b</field>
  <description>Windows network configuration enumerated with net.exe</description>
  <mitre><id>T1016</id></mitre>
  <group>discovery,network_configuration_discovery,</group>
</rule>
```

![Rule validation and restart](evidence/08-t1016-rule-validation-and-restart.png)

*Figure 9. Ruleset validation and Wazuh manager restart.*

## Positive validation

Fresh activity was generated after each ruleset change because Wazuh does not retroactively evaluate archived events.

![Fresh positive validation](evidence/09-fresh-t1016-positive-validation.png)

*Figure 10. Fresh T1016 activity generated after activating the initial custom rules.*

![Partial positive alerts](evidence/10-positive-t1016-alerts-partial.png)

*Figure 11. Initial positive results for the nbtstat and net config paths, with netsh still under investigation.*

![First netsh rule correction](evidence/11-netsh-rule-correction.png)

*Figure 12. First netsh rule correction based on the active parent-command path.*

![Fresh netsh validation](evidence/12-fresh-netsh-positive-validation.png)

*Figure 13. Fresh netsh activity used to test the revised rule.*

The first revised netsh validation still produced no alert. No separate screenshot numbered 13 was supplied; the investigation continued with XML rule-order analysis.

![Netsh parent-rule correction](evidence/14-netsh-parent-rule-correction.png)

*Figure 14. Final correction placing child rule `100180` after parent rule `100208`.*

![Positive netsh alert](evidence/15-positive-netsh-t1016-alert.png)

*Figure 15. Successful rule `100180` alert after correcting rule hierarchy and order.*

### Netsh detection

| Field | Observed value |
|---|---|
| Rule | `100180` |
| Level | `8` |
| Timestamp | `2026-07-19 18:42:07 EDT` |
| Event record | `21839` |
| Image | `C:\Windows\System32\cmd.exe` |
| Command line | `cmd.exe /c "netsh interface show interface"` |
| Parent | PowerShell |
| User | `CORP\Administrator` |
| ATT&CK | `T1016`, Discovery |

![Netsh alert details](evidence/16-netsh-t1016-alert-details.png)

*Figure 16. Rule `100180` details retaining the parent command and T1016 mapping.*

### Nbtstat detection

| Field | Observed value |
|---|---|
| Rule | `100181` |
| Level | `8` |
| Timestamp | `2026-07-19 18:28:24 EDT` |
| Event record | `21804` |
| Image | `C:\Windows\System32\nbtstat.exe` |
| Command line | `nbtstat -n` |
| Parent | `cmd.exe` |
| ATT&CK | `T1016`, Discovery |

![Nbtstat alert details](evidence/17-nbtstat-t1016-alert-details.png)

*Figure 17. Rule `100181` details for local NetBIOS configuration discovery.*

### Net config detection

| Field | Observed value |
|---|---|
| Rule | `100182` |
| Level | `8` |
| Timestamp | `2026-07-19 18:28:24 EDT` |
| Event record | `21805` |
| Image | `C:\Windows\System32\net.exe` |
| Command line | `net config` |
| Parent | `cmd.exe` |
| ATT&CK | `T1016`, Discovery |

![Net config alert details](evidence/18-net-config-t1016-alert-details.png)

*Figure 18. Rule `100182` details for network configuration enumeration with net.exe.*

## Negative control

The controls used the same signed utilities without the discovery-specific arguments:

```cmd
cmd /c "netsh /?"
cmd /c "nbtstat /?"
cmd /c "net /?"
```

![Negative-control execution](evidence/19-t1016-negative-control-execution.png)

*Figure 19. Help-only negative controls executed with the same utilities.*

![No netsh control alert](evidence/20-netsh-negative-control-no-alert.png)

*Figure 20. No rule `100180` result for the netsh help control.*

![No nbtstat control alert](evidence/21-nbtstat-negative-control-no-alert.png)

*Figure 21. No rule `100181` result for the nbtstat help control.*

![No net config control alert](evidence/22-net-config-negative-control-no-alert.png)

*Figure 22. No rule `100182` result for the net help control.*

These results validate the tested argument boundaries; they do not establish a production false-positive rate.

## False positives and triage

Legitimate network discovery commonly occurs during:

- administrator troubleshooting;
- help-desk and endpoint-support sessions;
- inventory, monitoring, and compliance automation;
- VPN, DNS, DHCP, and adapter diagnostics;
- software installation and network-agent workflows;
- incident response and authorized threat hunting.

Analysts should review the user, parent process, host role, remote-session context, execution frequency, adjacent discovery commands, and follow-on behavior. Higher-risk context includes unusual accounts, encoded PowerShell, remote shells, user-writable parents, rapid multi-command discovery, credential access, or lateral movement.

## Engineering considerations

- Extend the rule that actually wins live evaluation.
- Place child rules after their custom parent when file order affects resolution.
- Match discovery arguments instead of alerting on every execution of a signed utility.
- Preserve useful existing coverage rather than duplicating it.
- Generate fresh events after each ruleset change.
- Correlate multiple discovery commands in a short window for higher confidence.
- Baseline management and support automation before production deployment.
- Test PowerShell, WMI, CIM, route, DNS, and remote-host variants separately.

## Cleanup

The commands were read-only and created no persistent operating-system artifact. A dedicated cleanup screenshot (`26-t1016-cleanup-validation.png`) was not supplied, so cleanup is documented as an explicit evidence gap rather than visually proven.

## Timeline

All observed events occurred on July 19, 2026 in Eastern Daylight Time.

| Time | Source | Event | Interpretation |
|---|---|---|---|
| Initial window | WIN11/Sysmon | Atomic T1016 commands executed | Endpoint telemetry confirmed |
| Initial window | Wazuh | Existing `100203` and generic rule paths observed | Partial coverage identified |
| 18:28:24 | Wazuh | Rules `100181` and `100182` fired | Nbtstat and net config validation passed |
| 18:28–18:41 | Manager | Netsh rule hierarchy and ordering investigated | Root cause identified |
| 18:41:29 | Wazuh | First rule `100180` alert | Netsh detection passed |
| 18:42:07 | Wazuh | Second rule `100180` alert, record `21839` | Final evidence captured |
| Control window | WIN11/Wazuh | Help-only controls executed and queried | No custom-rule alerts |

## Findings

### 1. Collection preceded complete detection coverage

Sysmon and Wazuh retained the discovery activity before every command had a dedicated T1016 alert. Telemetry collection and classification were separate outcomes.

### 2. Existing coverage reduced unnecessary rule creation

Rule `100203` already handled `ipconfig /all` and `arp -a`. The engineering effort focused only on uncovered or generically classified paths.

### 3. Live rule hierarchy determined the successful design

The netsh child process alone did not produce the desired alert. The successful rule extended `100208`, which processed the parent `cmd.exe` command line.

### 4. Custom-rule order mattered

Even with the correct parent ID, `100180` failed while positioned before `100208`. Moving it after the parent enabled evaluation.

### 5. Argument-aware controls improved confidence

Help-only executions of netsh, nbtstat, and net did not trigger the custom rules.

## Limitations

- The lab tested one Windows endpoint and one Atomic Red Team test.
- The controls covered one help invocation per utility.
- The netsh alert represents the parent `cmd.exe` command rather than promoting the child `netsh.exe` event.
- The simulation did not validate PowerShell, WMI/CIM, route, DNS, remote-host, or API-only discovery.
- No screenshot numbered 13 was supplied for the still-failing intermediate netsh test.
- The cleanup screenshot `26-t1016-cleanup-validation.png` was not supplied.
- Production tuning requires baselining administrative and management activity.

## Skills demonstrated

- Atomic Red Team execution;
- Sysmon Event ID `1` analysis;
- Wazuh archive and alert-index comparison;
- process lineage and command-line investigation;
- active-parent rule analysis;
- PCRE2 argument matching;
- Wazuh custom-rule ordering and validation;
- MITRE ATT&CK mapping;
- positive and negative testing;
- evidence-backed troubleshooting documentation.

## Evidence inventory

| Artifact | Purpose |
|---|---|
| `01-network-discovery-readiness.png` | Endpoint readiness |
| `02-t1016-test-details-and-prerequisites.png` | Atomic test review |
| `03-t1016-network-discovery-execution.png` | Atomic execution |
| `04-local-sysmon-network-discovery-events.png` | Local process telemetry |
| `05-wazuh-network-discovery-hunt-a.png` | Initial Wazuh hunt |
| `05-wazuh-network-discovery-hunt-b.png` | Narrowed Wazuh hunt |
| `06-t1016-rule-path-analysis.png` | Rule-path analysis |
| `07-existing-t1016-rule-analysis.png` | Existing T1016 coverage |
| `08-t1016-rule-validation-and-restart.png` | Initial custom-rule activation |
| `09-fresh-t1016-positive-validation.png` | Fresh post-restart activity |
| `10-positive-t1016-alerts-partial.png` | Partial positive results |
| `11-netsh-rule-correction.png` | First netsh correction |
| `12-fresh-netsh-positive-validation.png` | Revised netsh test |
| `14-netsh-parent-rule-correction.png` | Final hierarchy/order correction |
| `15-positive-netsh-t1016-alert.png` | Positive netsh result |
| `16-netsh-t1016-alert-details.png` | Rule `100180` fields |
| `17-nbtstat-t1016-alert-details.png` | Rule `100181` fields |
| `18-net-config-t1016-alert-details.png` | Rule `100182` fields |
| `19-t1016-negative-control-execution.png` | Control execution |
| `20-netsh-negative-control-no-alert.png` | No netsh control alert |
| `21-nbtstat-negative-control-no-alert.png` | No nbtstat control alert |
| `22-net-config-negative-control-no-alert.png` | No net control alert |
| `23-positive-t1016-netsh-rule-100180.json` | Raw netsh alert |
| `24-positive-t1016-nbtstat-rule-100181.json` | Raw nbtstat alert |
| `25-positive-t1016-net-config-rule-100182.json` | Raw net config alert |
| `26-t1016-cleanup-validation.png` | Missing cleanup screenshot |

## Reproduction and references

The validated procedure is included in [`T1016-Network-Discovery-Lab-Runbook.md`](T1016-Network-Discovery-Lab-Runbook.md).

- [MITRE ATT&CK T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [Atomic Red Team T1016 tests](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1016)
- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
