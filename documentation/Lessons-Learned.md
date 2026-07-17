# Lessons Learned

## Technical Lessons

- Process creation telemetry is the foundation for most Windows detection validation.
- Parent-child process context is often more useful than process name alone.
- PowerShell logging materially improves investigation quality.
- Registry and file events help distinguish simple discovery from persistence or defense evasion.

## Program Lessons

- A consistent case-study format makes coverage easier to review.
- ATT&CK mapping helps translate technical alerts into leadership-readable risk.
- Detection metrics should include both successful validation and known gaps.
- Screenshots and raw evidence make portfolio claims more credible.

## Future Improvements

- Add Sigma rules for each detection.
- Add Wazuh custom rules and severity tuning.
- Track false positives by technique.
- Add a monthly detection coverage scorecard.
- Expand the lab with Microsoft Sentinel and SOAR automation.
