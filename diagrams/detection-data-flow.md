# Detection Engineering Data-Flow Diagram

## Telemetry, detection, and feedback flow

```mermaid
flowchart TB
    Start["1 · Define hypothesis<br/>expected behavior + control"]
    Sim["2 · Execute bounded simulation<br/>on WIN11"]

    subgraph Endpoint["Endpoint collection boundary"]
        Event["3 · Windows creates event<br/>Sysmon · Security · PowerShell"]
        LocalCheck{"Local event present?"}
        Agent["4 · Wazuh agent forwards EventChannel record"]
        Event --> LocalCheck
        LocalCheck -->|"Yes"| Agent
    end

    subgraph Manager["Wazuh processing boundary"]
        Decode["5 · Decode and normalize fields"]
        Archive["6a · Raw archive<br/>collection evidence"]
        Evaluate["6b · Rule hierarchy evaluates event"]
        Match{"Intended analytic matched?"}
        Alert["7 · Alert/index record<br/>rule · severity · ATT&CK"]

        Decode --> Archive
        Decode --> Evaluate --> Match
        Match -->|"Yes"| Alert
    end

    subgraph Analysis["Analyst and evidence boundary"]
        Hunt["8 · Hunt and correlate<br/>user · parent · command · host · time"]
        Disposition{"Expected outcome?"}
        Evidence["9 · Preserve evidence<br/>event IDs · queries · screenshots · JSON"]
        Response["10 · Triage · scope · contain<br/>eradicate · recover"]
        Register["11 · Update lifecycle register<br/>FP · blind spot · tuning · response"]
        Case["12 · Publish case study<br/>coverage matrix · metrics"]

        Hunt --> Disposition
        Disposition -->|"True positive / expected test"| Evidence
        Disposition -->|"False positive"| Register
        Disposition -->|"Confirmed malicious"| Response --> Evidence
        Evidence --> Register --> Case
    end

    subgraph Engineering["Detection feedback loop"]
        Diagnose["Separate collection, decoding,<br/>rule evaluation, and indexing"]
        Tune["Version tuning decision<br/>logic · hierarchy · severity · exclusions"]
        Syntax["Validate syntax and dependencies"]
        Retest["Generate fresh positive test<br/>and comparable negative control"]
        Diagnose --> Tune --> Syntax --> Retest
    end

    Start --> Sim --> Event
    Agent --> Decode
    Alert --> Hunt
    Archive --> Hunt
    LocalCheck -->|"No"| Diagnose
    Match -->|"No"| Diagnose
    Disposition -->|"False negative / wrong classification"| Diagnose
    Retest --> Sim
    Case -->|"Review ≤90 days or after material change"| Start
```

## Evidence states

| State | What it proves | What it does not prove |
|---|---|---|
| Local event | The endpoint sensor observed the activity | Successful forwarding or detection |
| Manager archive record | Collection and decoding reached the manager | That an alerting rule matched |
| Alert/index record | A rule evaluated and promoted the event | That the activity was malicious |
| Analyst disposition | Contextual assessment of the alert | Complete environment-wide scope unless a hunt was performed |
| Positive validation | The intended analytic recognized the tested behavior | Production precision or coverage of untested variants |
| Negative control | The analytic rejected one nearby benign behavior | Absence of every possible false positive |

## Failure-routing guide

| Failure point | First check | Engineering owner |
|---|---|---|
| No local event | Audit policy, Sysmon configuration, channel state, test timing | Endpoint engineering |
| Local event but no archive | Wazuh agent health, EventChannel subscription, connectivity, time range | Collection engineering |
| Archive but no intended alert | Decoded field names, winning parent rule, file order, dependencies, regex | Detection engineering |
| Alert exists but dashboard hunt misses it | Index pattern, time zone, query syntax, refresh window | SIEM operations |
| Excess benign alerts | Dispositions, stable context, narrow exclusions, severity split | Detection engineering + SOC |
| Confirmed alert lacks response | Ownership, runbook, access, containment authority | SOC / incident response |

Related documents: [detection methodology](../documentation/Detection-Engineering-Methodology.md), [lifecycle metrics](../metrics/detection-lifecycle-metrics.md), and [security architecture](lab-security-architecture.md).
