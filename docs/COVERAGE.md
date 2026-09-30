# Coverage and interpretation

This release is a working assessment **foundation**, not a claim to implement
every Microsoft cloud control. Use the runtime `catalog` for the exact
collection list, read permissions and API references, and the generated report
for what the current identity actually observed.

## Implemented capabilities

| Domain | Collected or analyzed evidence | Important limits |
| --- | --- | --- |
| Entra ID | Organization, users, groups/memberships, role definitions/assignments/eligibility and active assignment schedule instances, authentication registration, Conditional Access inventory, risky users/sign-ins | Registration is not MFA enforcement; policy inventory is not a Conditional Access effective-access simulation; membership visibility, activation approvals and PIM policy requirements may be incomplete |
| Workload identities | Applications, service principals, credential metadata, owners, app roles, delegated grants, federation, managed identity associations | Ownership is potential control, not proof that credentials can be added; first-party and external applications require contextual review; custom permissions can remain unclassified |
| Microsoft 365 | Secure Score history/control profiles, subscribed-license metadata, and tenant-level SharePoint/OneDrive authentication/sharing settings | Tenant sharing settings are a ceiling, not effective site/item permissions or proof of public documents; Exchange/Teams configuration and detailed SharePoint access still require separate assessment; license inventory does not prove resource protection |
| Defender XDR | Incidents, alerts and endpoint inventory/security metadata | Empty alerts do not establish detection effectiveness; Office 365, Identity and Cloud Apps sensor/integration coverage is explicitly manual |
| Intune | Managed devices, compliance-policy and device-configuration inventories; observed noncompliance and supported device relationships | Policy presence is not effective assignment/enforcement; Settings Catalog, security baselines and full enrollment/endpoint integration need additional evidence |
| Azure | Approved subscriptions, accessible management-group metadata, projected Resource Graph inventory, role definitions/assignments, managed identities, selected resource security settings, and scoped PolicyStates evaluations | Public-network settings are potential exposure, not a connectivity test; data-plane ACLs, deny assignments, conditional role effectiveness, complete management-group RBAC, policy parameters/enforcement mode and freshness/effective protection need further evidence |
| Defender for Cloud | Plan/pricing configuration, assessments, Secure Score and regulatory-compliance metadata | A Free plan is a review opportunity, not proof that every paid plan is required; effective per-resource deployment, sensor/extension coverage, attack paths and API/AI workload protection require more evidence |
| GitHub | Organization metadata, members/outside collaborators, visible repositories, default-branch protection, rulesets, Actions permissions/workflow metadata, runners, environments, safe security metadata and secret **names** | GitHub Enterprise Server/enterprise settings, full effective permissions, workflow contents, third-party Action pinning, CODEOWNERS semantics, app/OAuth/deploy-key reach and audit policy are not fully assessed |
| Azure DevOps | Projects, repositories, branch policies, pipeline/environment metadata and agent-pool inventory | Service-connection authorization, variable values, secure files, environment checks, organization policy, classic/YAML contents, full permissions and extensions are not automatically collected |
| Code-to-cloud | Evidence-matched GitHub OIDC subjects, application-to-service-principal relationships, privileged Azure role links, repository control weaknesses and scored privilege combinations | Repository federation does not prove a specific workflow is authorized or exploitable. Azure DevOps end-to-end pipeline/service-connection reachability requires additional safe metadata. Repository metadata does not establish deployed source provenance |
| Change tracking | Stable inventory identities, owners, credential IDs/dates, federation, grants, roles, resource identity metadata and control-state changes | Same scope required; hidden objects, omitted fields, partial enumeration and changed collector versions remain indeterminate |
| Zero Trust | Finding mappings to verify explicitly, least-privilege access and assume breach | Mappings are guidance, not a maturity certification or a verified control implementation |

Workload identity prioritization exposes each factor, evidence and unknown
inputs. It considers observed Entra/API/Azure privileges, scope, persistent
credential and owner hygiene, privilege combinations and evidenced
code-to-cloud relationships. Scores cannot replace a human review of effective
permissions, business criticality, licensing or blast radius.

## Expanded metadata checks

Version 0.2 adds three live collections: tenant SharePoint/OneDrive settings,
active Entra role-assignment schedule instances, and Azure Policy evaluation
metadata. The catalog now has **60 live** and **16 manual** capabilities.

- A standing privileged assignment requires actual schedule/role context;
  explicit null end dates differ from omitted dates. Future, expired,
  malformed, indirect or uncertain instances are not unconditionally active.
  Current-origin evidence can establish an active legacy assignment whose
  start is explicitly null; missing start evidence is not silently defaulted.
- SharePoint legacy authentication and anonymous-sharing permission are
  observed configuration risks, not proof of bypass or publicly shared files.
  Sharing-dependent checks do not fail when external sharing is disabled.
- Azure Policy findings identify the exact resource, assignment, definition
  and evaluation timestamp. Noncompliance is a dated observation; exemption,
  disabled effects and manual attestations do not count as an automated
  compliant pass. Conflicts, unknown actions/states, malformed/future times
  and incomplete inventories remain reviewable or unable to assess.
- Policy parameters, assignment configuration and evaluation details are not
  retrieved. A readable PolicyStates list is not proof of complete/effective
  policy coverage, and audit results do not prove enforcement.

Intune Settings Catalog and baseline expansion remain manual in this batch:
the consulted configuration-policy interface is documented as `/beta`, even
when a v1.0 documentation URL redirects there. The collector does not silently
opt into preview APIs.

## What is deliberately not fetched

Some security APIs expose sensitive data even when they use GET. The platform
does not inspect repository files, workflow YAML, pipeline definitions with
variables, variable-group contents, service-connection authorization
parameters, secure-file content, Key Vault secret values or credential bytes.
Secret-scanning alert collection is only acceptable when the service has a
documented **server-side** mechanism that withholds secret values; otherwise
that capability must remain unavailable. Client-side removal after retrieval
is not an adequate substitute.

The GitHub.com adapter pins REST API version `2026-03-10` and mandates the
documented `hide_secret=true` parameter for secret-scanning alert metadata,
including continuation requests. There is no fallback without that flag.
An unexpected response containing an unmasked secret fails the collection
without persisting or logging its contents.

Safe metadata inventories and existing security-product recommendations can
indicate coverage gaps; they are not a source-code, IaC, dependency or secret
scanner. No third-party source from the inspiration project was copied.

## Understanding availability

- **Enabled/Disabled** requires an explicit observed configuration value.
- **Partially deployed** in repository reporting requires observed enabled
  and disabled repositories, with unknown counts retained separately.
- **Available** means the relevant API is readable; for example, readable
  code-scanning alerts do not prove a scanning workflow is deployed.
- **Not licensed/available** requires explicit licensing evidence. A generic
  access failure never establishes it.
- **Unable to Assess** covers missing permissions, unsupported capabilities,
  unknown configuration, licensing uncertainty and missing evidence.

Collection completeness describes the authenticated caller's API view.
Counts in the domain table are collection/scope outcomes, **not** a security
score or a percentage of protected resources. Repository coverage uses observed
repositories as its denominator; inaccessible repositories are not presumed
protected. The tool does not silently expand scope to discover what it cannot
see.

## Manual validation checklist

For a comprehensive engagement, supplement the initial implementation with
authorized evidence for:

- Effective Conditional Access/MFA behavior, authentication strength,
  emergency access, Identity Protection policy, PIM approval/activation-policy
  requirements beyond the observed active schedule instances,
  administrative-unit scoping and external-user lifecycle.
- Effective Exchange/Teams administration, site/item-level SharePoint sharing
  and permissions, collaboration and data-protection configuration beyond the
  collected tenant settings.
- Defender for Office 365, Identity and Cloud Apps licensing, integrations,
  sensor coverage and actual detection validation.
- Intune Settings Catalog, security baselines, assignment filters,
  enrollment restrictions, platform coverage and policy conflicts.
- Management-group RBAC and deny/conditional assignments, Azure Policy
  assignment parameters, enforcement mode and evaluation freshness,
  private endpoints/firewalls, logging/monitoring, compute/container/database
  hardening, Defender per-resource coverage and runtime exposure.
- GitHub enterprise/organization policy, effective contributor access,
  app/OAuth/deploy-key permissions, audit retention, signed-commit/CODEOWNERS
  rules, workflow trust, runner isolation and actual deployment approvals.
- Azure DevOps organization policy, effective permissions, extensions,
  pipeline authorization, service-connection scope/identity/federation,
  environment checks and self-hosted agent isolation.
- Source-to-deployment provenance and cross-platform relationships requiring
  pipeline/service-connection/source metadata not safely available here.

Keep assessment and remediation separate. Record additional metadata through
a reviewed collector or validated, secret-free offline fixture, never by
exporting secret-bearing responses wholesale.

## First-party references

- [Microsoft Graph permissions](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Password credential metadata](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0)
- [SharePoint and OneDrive tenant settings](https://learn.microsoft.com/en-us/graph/api/sharepointsettings-get?view=graph-rest-1.0)
- [Active role-assignment schedule instances](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentscheduleinstances?view=graph-rest-1.0)
- [Federated identity credentials](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-1.0)
- [Azure RBAC role definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)
- [Resource Graph data and paging](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/work-with-data)
- [PolicyStates Resource Graph examples](https://learn.microsoft.com/en-us/azure/governance/policy/samples/resource-graph-samples)
- [Disabled policy effects and default compliance](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-disabled)
- [Defender for Cloud REST API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/)
- [Azure DevOps REST API](https://learn.microsoft.com/en-us/rest/api/azure/devops/)
- [GitHub REST API](https://docs.github.com/en/rest)
- [GitHub secret-scanning metadata and hide_secret](https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2026-03-10#list-secret-scanning-alerts-for-a-repository)
- [Zero Trust principles](https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-overview)
