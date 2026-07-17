# Security Data Flow

## Flow

```mermaid
flowchart LR
    A[Security Tools and Projects] --> B[Findings and Signals]
    B --> C[Risk Triage]
    C --> D[Risk Register]
    C --> E[Remediation Backlog]
    E --> F[Owner Action]
    F --> G[Validation]
    G --> H[Security Metrics]
    H --> I[Executive Reporting]
    D --> I
```

## Data Sources

- Vulnerability findings
- Cloud control failures
- Pipeline security scan results
- Detection coverage gaps
- Alert triage outcomes
- Compliance baseline failures
- Threat modeling risks
- Penetration test findings
- AI data exposure risks

## Management Controls

- Risk severity assignment
- Business impact review
- Owner assignment
- SLA due date
- Remediation validation
- Exception approval
- Monthly reporting
