# Case-study README standard

Completed detection case studies use a common evidence-first structure. Additional technique-specific sections are allowed, but each completed README must contain these second-level headings:

1. Result
2. Objective and hypothesis
3. Lab environment
4. Safe simulation
5. Endpoint telemetry
6. Wazuh hunt and collection validation
7. Troubleshooting and detection engineering
8. Positive validation
9. Negative control
10. False positives and triage
11. Engineering considerations
12. Cleanup
13. Timeline
14. Findings
15. Evidence inventory
16. Reproduction

## Evidence rules

- State only results supported by preserved telemetry, alerts, screenshots, or transcripts.
- If a control or cleanup step was not preserved, label it as an evidence limitation; never imply a pass.
- Use relative links and verify that every referenced local artifact exists.
- Use synthetic markers and fake credentials only. Do not place real secrets in simulations or screenshots.
- Record the agent, event source, event or record ID, rule ID, and relevant timestamps when available.
- Preserve both positive validation and a behaviorally similar negative control.

## Validation

Run the repository checker after editing a completed case study:

```powershell
.\tools\Test-CaseStudyReadmes.ps1
```

The checker fails on missing required sections, duplicate second-level headings, placeholders, or broken local links. Detection directories without a README are treated as future work and are not represented as completed studies.
