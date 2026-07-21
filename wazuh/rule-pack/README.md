# Security Engineering Lab Wazuh Rule Pack

Version **0.3.0** packages nine lab-validated Windows analytics under a dedicated `1101xx` custom-rule range. It is deliberately small: each rule has a case-study source, an ATT&CK mapping, and positive and negative behavioral fixtures.

## Contents

| Path | Purpose |
|---|---|
| `VERSION` | Authoritative semantic version |
| `manifest.json` | Rule inventory, compatibility, ID range, and external dependencies |
| `rules/1100-security-engineering-lab.xml` | Deployable Wazuh rule file |
| `tests/fixtures/rule-cases.json` | Decoded-field positive and negative cases |
| `tests/Test-WazuhRulePack.ps1` | Portable automated unit and policy tests |
| `tests/Test-OnManager.ps1` | Optional manager-side installation and syntax test |
| `CHANGELOG.md` | Version history and known limitations |

## Rule inventory

| Rule | Level | ATT&CK | Detection |
|---:|---:|---|---|
| 110101 | 8 | T1047 | WMI-spawned Windows command interpreter |
| 110102 | 8 | T1053.005 | Scheduled task containing a command or script interpreter |
| 110103 | 8 | T1078 | Explicit credentials through RunAs or Secondary Logon |
| 110104 | 8 | T1082 | `systeminfo.exe` or `hostname.exe` discovery |
| 110105 | 8 | T1547.001 | Run key configured with an interpreter |
| 110106 | 10 | T1112, T1547.001 | Elevated child classification for the Run-key modification |
| 110107 | 11 | T1552.001 | Credential-oriented file or command-output search |
| 110108 | 13 | T1003.001 | Rundll32 and `comsvcs.dll, MiniDump` behavior |
| 110109 | 12 | T1562.001 | Security tooling or logging impairment command |

## Run automated tests

From the repository root:

```powershell
pwsh -NoProfile -File .\wazuh\rule-pack\tests\Test-WazuhRulePack.ps1
```

The test fails when:

- semantic versions disagree;
- the XML is malformed;
- IDs are duplicated, undocumented, or outside the allocated range;
- a parent rule is neither packaged nor declared as an external dependency;
- a rule lacks a description or ATT&CK mapping;
- positive or negative decoded-field behavior regresses;
- any rule lacks both positive and negative fixture coverage.

## Deployment workflow

1. Run the portable test suite.
2. Back up `/var/ossec/etc/rules/` on the manager.
3. Copy `rules/1100-security-engineering-lab.xml` to `/var/ossec/etc/rules/` with owner `root:wazuh` and mode `640`.
4. Run `sudo /var/ossec/bin/wazuh-analysisd -t`.
5. Restart with `sudo systemctl restart wazuh-manager` only after syntax validation succeeds.
6. Generate fresh positive and negative events for every changed analytic.
7. Confirm collection in `archives.json` separately from alert generation in `alerts.json` or the dashboard.
8. Update the lifecycle register with the rule-pack version, event IDs, outcomes, and evidence.

The optional helper performs steps 1–4 interactively:

```powershell
pwsh -NoProfile -File .\wazuh\rule-pack\tests\Test-OnManager.ps1
```

It intentionally does not restart the manager or generate endpoint activity automatically.

## Versioning policy

- **Patch:** documentation, fixtures, or metadata corrections that do not change matching behavior.
- **Minor:** backward-compatible new rules or deliberately broadened/narrowed behavior with new fixtures.
- **Major:** rule-ID changes, removed rules, incompatible parent dependencies, or behavior that invalidates existing integrations.

Every release updates `VERSION`, `manifest.json`, the rule-file version comment, and `CHANGELOG.md` in the same commit.

## Compatibility and limitations

- The source case studies were validated on Wazuh `4.14.6`; other versions require manager-side revalidation.
- External parent rules `60103`, `60228`, `92069`, and `92300` must exist and retain compatible decoded fields.
- The portable suite tests normalized field logic, not the complete Windows EventChannel decoder.
- This lab pack is not a production allowlist. Baseline expected administrative activity before deployment beyond the lab.

Wazuh recommends custom IDs in the `100000–120000` range and testing with `wazuh-logtest`; see the [official custom-rule documentation](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) and [`wazuh-logtest` reference](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html).
