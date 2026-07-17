Query 1:
agent.name:"WIN11"

Purpose:
Review all endpoint activity during the test period.

Result:
Returned current events from WIN11 during the selected time window, confirming that the Wazuh agent was actively reporting telemetry.


Query 2:
agent.name:"WIN11" AND data.win.system.eventID:1

Purpose:
Identify Sysmon Process Create events.

Result:
Returned Sysmon Event ID 1 process-creation records from WIN11, including the account-discovery commands executed during the Atomic Red Team simulation.


Query 3:
agent.name:"WIN11" AND rule.id:100206

Purpose:
Locate the custom Local or Domain Account Discovery detection.

Result:
Returned the custom Wazuh detection labeled "MITRE T1087 - Local or domain account discovery" with Rule ID 100206 and Rule Level 8.


Query 4:
agent.name:"WIN11" AND rule.mitre.id:T1087

Purpose:
Locate all ATT&CK-mapped Account Discovery detections.

Result:
Returned the T1087 account-discovery alerts generated during the test window, confirming that the activity was mapped to the Discovery tactic.


Query 5:
agent.name:"WIN11" AND rule.description:"MITRE T1087 - Local or domain account discovery"

Purpose:
Verify the exact custom detection rule description.

Result:
Returned the matching custom account-discovery alerts associated with the Atomic Red Team simulation.