# Assessment architecture

```text
strict configuration / validated offline evidence
  -> explicit existing credentials
  -> scope-bound, metadata-only HTTP collectors
  -> complete / partial / unavailable / not-configured inventories
  -> pure checks + relationship graph + explainable scoring
  -> validated versioned snapshot
  -> local JSON / Markdown / no-script HTML
  -> same-scope snapshot comparison
```

There is no remediation subsystem, hosted backend, account-registration flow,
shell-command endpoint, secret store or automatic consent process.

## Main contracts

[model.ts](../src/model.ts) defines the public contracts. Configuration and
evidence have runtime validation, not just TypeScript assertions.

### Collection

A collection is identified by `(id, scope)`, names its provider and timestamp,
and contains projected JSON records with a stable `id`. Related records also
include `parentId`; GitHub child records identify `repository`. A record's
comparison identity is `(id, parentId, repository)`, so an owner or group
member can appear in multiple relationships without collision.

Known Graph dataset IDs use `entra.*`, `m365.*` and `intune.*`. Defender APIs
use `defender.*`. Azure datasets use `azure.*` and `defenderCloud.*`; source-control
datasets use `github.*` and `azureDevOps.*`. The runtime `catalog` command is
the authoritative registry, including permission and API documentation.

Record shapes retain selected upstream names, for example:

- Applications/service principals: `appId`, `servicePrincipalType`,
  `passwordCredentials` / `keyCredentials` metadata.
- Ownership and memberships: `id` is the owner/member; `parentId` is the owned
  object or containing group.
- App grants: `principalId`, `resourceId`, `appRoleId`. Delegated grants use
  `clientId`, `resourceId`, `scope`, `consentType`.
- Azure roles: selected `properties.permissions`; assignments include
  `principalId`, `roleDefinitionId`, `scope`, `condition`.
- Federation: `issuer`, `subject`, `audiences`, `parentId`.
- GitHub: repository `full_name`; child scope `organization/repository`.
- SharePoint/OneDrive: tenant singleton `m365.sharePointSettings`, selected
  security flags and sharing enums; no site, document or file content.
- Active Entra schedules: `entra.directoryRoleAssignmentScheduleInstances`
  preserves `assignmentType`, `memberType`, origin identifiers and explicit
  null versus omitted dates. Ordinary assignments do not determine lifetime.
- Azure Policy: `azure.policyCompliance` uses selected `properties` including
  resource/assignment/definition identifiers, action, state and timestamp.
  IDs are derived from the stable evaluation tuple, not its refresh timestamp.
  No policy parameters or detailed evaluation payloads are retrieved.

Resource Graph permits two named fixed queries, not arbitrary KQL. Continuation
cursors remain bound to their originating query and selected subscription.

Collection statuses are not finding severities:

| Status | Meaning |
| --- | --- |
| complete | All allowed pages obtained for the API/caller view |
| partial | Some evidence obtained or enumeration interrupted; absence cannot be established |
| unavailable | No usable evidence; reason required |
| not-configured | Source explicitly disabled or unconfigured |

Reasons distinguish permission/authentication failure, unsupported capability,
unknown/not-found resources, known licensing limits, request limits, timeouts
and dependency gaps. They never contain upstream payloads or credentials.

### Analysis

`analyze(collections, policy, now)` is deterministic and has no network or
filesystem access. It returns findings, graph nodes/edges and identity scores.
The engine inserts explicit coverage findings for missing or incomplete
catalog entries; unsupported manual controls remain part of the report.

Findings refer to `(collectionId, scope, recordId, field)` evidence. Snapshot
validation rejects references to missing collections/records and dangling
graph edges. A graph relationship can be confirmed as **metadata** without
establishing exploitability. Potential control remains distinct.

Scoring weights and thresholds are configurable. Permission-risk rules bind
documented capabilities to resource application ID + permission ID + type.
Role display names and numerical scores alone never establish risk. Checks
should identify privilege combinations and record conditions that prevent
concluding effective access.

Report processing groups failing findings by check/domain/recommendation and
retains distinct targets, individual finding IDs and evidence. It does not
alter the snapshot or combine unknown controls with failures. The evidence-gap
checklist distinguishes disabled sources, missing access, unsafe/unsupported
capabilities, partial results and invalid context; it never requests grants.

### Persistence and comparison

Schema `1.0` snapshots include tool version, scope, policy, evidence, findings,
graph, factors and collection coverage. The engine validates its own output
before persistence. The CLI writes a new local directory exclusively.

Diffing compares unordered metadata inventories by stable identity. It rejects
scope changes and time reversal. It reports missing evidence as indeterminate,
not deletion; finding disappearance is not proof of remediation. Changed
collector versions and omitted fields cannot establish precise posture
transitions.

Valid policy refresh timestamps and upstream row IDs alone are ignored as
posture noise when the logical evaluation tuple remains the same. A changed
policy evaluation with missing, future, regressing or inconsistent identity/
time evidence remains indeterminate. Exemptions and disabled effects do not
constitute remediation. Tool version 0.2 keeps schema 1.0 readable; comparisons
across collector versions remain deliberately conservative.

## Adding a collector/check

1. Verify official API behavior, read permission, metadata-only response
   projection, paging and licensing limitations.
2. Add the definition and permission/reference metadata to the catalog.
3. Add the exact read route and continuation rules to the HTTP allowlist.
   Do not add broad wildcard paths or generic user-provided URLs.
4. Implement safe projection and stable record identities. Propagate parent
   inventory incompleteness to all dependent collections.
5. Add a pure analyzer with evidence references, explicit unknown states,
   documented recommendations and applicable Zero Trust principles.
6. Test observed risk, explicit pass, missing/partial evidence, denied access,
   pagination, limits, cross-scope URLs, malformed responses and secret fields.
7. Update the coverage documentation. Do not call an API live against a
   customer as part of a unit test.

Tests, source files and local reports are kept separate. The CLI supports
offline fixtures to reproduce analysis without credentials or a customer
environment.
