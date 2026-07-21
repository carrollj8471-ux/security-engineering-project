# Lab Security Architecture Diagram

## Logical architecture and trust boundaries

```mermaid
flowchart LR
    Analyst["Security engineer\nVMware host"]

    subgraph Lab["Trust boundary: isolated VMware network — 192.168.232.0/24"]
        direction LR

        subgraph Identity["Identity services"]
            DC["DC01\nActive Directory · DNS · Group Policy"]
        end

        subgraph Endpoint["Monitored endpoint"]
            WIN["WIN11.corp.local\nDomain member"]
            Sources["Sysmon · Security · PowerShell\nWindows EventChannel"]
            Agent["Wazuh agent 002"]
            WIN --> Sources --> Agent
        end

        subgraph SIEM["Wazuh security platform — 192.168.232.20"]
            Manager["Manager\nDecode · correlate · evaluate rules"]
            Archive["Raw event archive\narchives.json"]
            AlertStore["Alert store / index\nalerts.json + indexed alerts"]
            Dashboard["Wazuh dashboard\nThreat hunting"]
            Rules["Versioned local rules\nATT&CK mappings"]

            Manager --> Archive
            Manager --> AlertStore --> Dashboard
            Rules --> Manager
        end

        WIN <-->|"Kerberos · LDAP · DNS · policy"| DC
        Agent -->|"Authenticated EventChannel forwarding"| Manager
    end

    subgraph Evidence["Trust boundary: engineering evidence"]
        Repo["Git repository\nRules · runbooks · JSON · screenshots"]
        Metrics["Coverage matrix\nLifecycle metrics · decision register"]
        Repo --> Metrics
    end

    Analyst -->|"VM console · PowerShell"| WIN
    Analyst -->|"Administrative console"| DC
    Analyst -->|"Dashboard · SSH/VNC"| Manager
    Dashboard -->|"Validated findings and evidence"| Repo
    Archive -->|"Collection proof and hunts"| Repo
    Repo -->|"Reviewed rule changes"| Rules
```

## Boundary controls

| Boundary | Principal risk | Required control |
|---|---|---|
| Engineer → endpoint | Unsafe or ambiguous simulation | Bounded commands, synthetic markers, recorded start time, explicit cleanup |
| Endpoint → domain services | Identity misuse or unintended policy impact | Isolated domain, lab-only accounts, least privilege, documented group membership |
| Endpoint → Wazuh | Telemetry loss, spoofing, or clock mismatch | Enrolled agent, service-health checks, time synchronization, archive verification |
| Archive → alert index | Collection incorrectly reported as detection | Validate raw archive and intended alert independently |
| Engineer → manager | Invalid or unauthorized rule changes | Backup, syntax test, unique IDs, controlled restart, fresh post-change events |
| SIEM → repository | Exposure of secrets or misleading evidence | Redaction review, synthetic data, preserved failures, verified relative links |

## Design constraints

- The manager, index, and dashboard are represented as logical services but may share one lab VM.
- The environment is intentionally single-site and non-high-availability.
- Private addressing provides lab isolation; it is not equivalent to production network segmentation.
- Evidence publication is a separate trust boundary because logs and screenshots may contain identities, IP addresses, hashes, GUIDs, and commands.

Related documents: [lab architecture](../architecture/lab-architecture.md), [detection engineering architecture](../architecture/detection-engineering-lab-architecture.md), and [detection data flow](detection-data-flow.md).
