# Identity Governance Standard

## Objectives

- Grant access according to job need and least privilege.
- Maintain accountable, unique identities.
- Separate administrative and standard-user activity.
- Review privileged and sensitive access regularly.
- Remove access promptly when no longer required.

## Account Types

| Type | Requirement |
|---|---|
| Standard user | Used for routine work; no standing administrative rights |
| Privileged admin | Separate named account, restricted use, enhanced monitoring |
| Service account | Named owner, documented purpose, noninteractive where possible, credential rotation |
| Emergency account | Restricted, monitored, tested, and reviewed after every use |
| Test/lab account | Clearly labeled, scoped to the lab, prohibited from production reuse |

## Lifecycle

1. **Request:** document business purpose, role, manager, systems, and duration.
2. **Approve:** owner approves access; Security reviews privileged or exceptional access.
3. **Provision:** assign through approved groups rather than direct grants where possible.
4. **Review:** managers and control owners recertify access on schedule.
5. **Modify:** adjust access promptly after role or responsibility changes.
6. **Disable:** disable accounts promptly after separation, compromise, or expiration.
7. **Delete:** remove after the retention period and confirmation that dependencies are resolved.

## Privileged Access

Domain Admins and equivalent groups are limited to authorized administrators. Membership changes generate security telemetry and require review. Privileged accounts must not be used for email, browsing, or routine endpoint activity.

## Review Cadence

| Access | Review |
|---|---|
| Domain and enterprise administration | Monthly |
| Security and infrastructure administration | Quarterly |
| Application and shared-resource access | Semiannually |
| Service accounts | Quarterly and on owner change |
| Emergency accounts | Quarterly and after use |

## Monitoring

Monitor failed logons, unusual logon types, privileged group changes, new accounts, disabled-account use, password resets, remote administration, and authentication from unexpected hosts or times.

## Exceptions

Exceptions require a risk record, owner, compensating controls, approval, and expiration. Standing exceptions without review are prohibited.
