# Detection: Brute Force Login

## MITRE ATT&CK

T1110

## Windows Event ID

4625

## Detection

Repeated failed authentication attempts.

## Test Procedure

Attempt multiple incorrect logins.

## Expected Wazuh Alert

Authentication Failure

## Investigation

- Source IP
- Username
- Time
- Device

## Response

- Lock Account
- Investigate Source
- Review Logs

## Screenshots

screenshots/bruteforce.png