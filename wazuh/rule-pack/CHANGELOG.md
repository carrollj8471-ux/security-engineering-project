# Changelog

All notable changes to this rule pack are documented here. Versions follow semantic versioning: patch for non-behavioral corrections, minor for backward-compatible rule or test additions, and major for incompatible IDs, dependencies, or matching behavior.

## [0.1.0] - 2026-07-21

### Added

- Seven ATT&CK-mapped Windows rules derived from validated portfolio case studies.
- Dedicated custom ID range `110100–110199` to avoid the repository's earlier duplicated `1002xx` IDs.
- Fourteen positive, negative, dependency, and group-scope behavioral fixtures.
- Portable PowerShell validation for versions, XML, IDs, parent dependencies, rule metadata, regex behavior, and fixture coverage.
- Optional manager-side installation and `wazuh-analysisd -t` validation helper.
- GitHub Actions workflow for automatic testing.

### Known limitations

- Portable fixtures validate decoded-field logic and dependencies; they do not replace Wazuh decoder integration testing.
- Manager-side validation requires the built-in parent rules declared in `manifest.json`.
- Fresh endpoint events are still required after deployment because archived events are not reevaluated automatically.
