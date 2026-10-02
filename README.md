# Cloud Security Review

A read-only, evidence-based **Microsoft cloud security assessment** foundation.
It inventories the selected environment, identifies supported security risks,
correlates workload identity and code-to-cloud relationships, and produces
portable reports and comparable snapshots.

This is an independent project, not a Microsoft product, official assessment,
penetration test, or compliance certification. This release implements
working collectors and checks, **not every control in every Microsoft product**.
Unsupported capabilities, inaccessible APIs, missing licensing evidence and
incomplete inventories remain visible as **Unable to Assess**.

## Report Studio (version 0.3)

A small **Astro + React** workspace turns an existing assessment into
audience-specific reports. No backend, tenant sign-in, Starlight, drag-and-drop
library or database is required.

```powershell
npm ci --include=dev --ignore-scripts
npm start
```

`npm start` builds the current checkout, serves it only on
`http://127.0.0.1:4321`, and opens your default browser. Keep the terminal
open; **Ctrl+C** stops the server. Node.js **22.12+** and npm must already be
installed; **Node 24 LTS** is recommended. No administrator rights, Docker,
Azure CLI, GitHub CLI, or tenant sign-in are needed for Report Studio.

Select **Try fictional demo**, or
open a CLI-generated `assessment.json` snapshot (up to 50 MiB). Raw
`assessment-input.json` collection fixtures are not report snapshots.

### Run on Windows, macOS or Linux

Run the two commands above from the project directory on any supported OS.
Install dependencies once per checkout/machine, and again after dependency
updates. Keep development dependencies: Astro is a local build tool.

| Platform | Optional local shortcut after setup |
| --- | --- |
| Windows | Double-click [Report Studio.cmd](Report%20Studio.cmd), or run it from PowerShell |
| macOS | In Terminal, run `sh ./report-studio.sh` |
| Linux | In a terminal, run `sh ./report-studio.sh` |

The Windows and POSIX shortcuts call the same Node launcher and work even when
the current working directory is elsewhere. Quote paths containing spaces.
The POSIX script needs no executable-bit change when invoked with `sh`.
macOS and Linux use the Node installation on the terminal's `PATH`; if Node
was just installed, open a new terminal. Install native dependencies on each
OS rather than copying `node_modules` from another machine or architecture.

Common options, identical on all platforms:

```text
npm start -- --no-open
npm start -- --port 4330
npm start -- --no-build --no-open
npm start -- --help
```

`--no-open` is useful for headless/remote terminals; the local URL is always
printed. Linux desktop browser opening uses the system's browser opener; if
one is unavailable, open the printed URL manually. `--port 0` chooses an
available loopback port. A busy explicit port fails with instructions instead
of killing another process or silently switching ports.

The default rebuild avoids serving stale code. `--no-build` serves an existing
`studio/dist` only and requires a prior successful build. The launcher never
installs software automatically or requests cloud access, and it disables
Astro build/preview telemetry for its process. It stays in the foreground on
every OS. After first-time dependency setup, normal local startup does not
need internet access.

For live development with hot reload, `npm run studio:dev` remains available.
The local launcher is for your workstation, not a public or production server;
it deliberately rejects host overrides. This project is not a packaged native
desktop installer.

1. Choose **Executive**, **Technical**, or **Code to cloud**.
2. Set the title, domains, severities, finding status/scope and finding limit.
3. Include and reorder recommendations, detailed findings and analyst notes.
4. Preview the report, then download **HTML** or **Markdown**, or use
   **Print / Save as PDF**. PDF saving is provided by the browser print dialog.
5. Save a **recipe** to reuse the presentation. Save analyst notes separately
   if needed; they are tied to the source assessment identifier.

Every report retains assessment identity/date, original source counts,
filter/limit/section disclosures, and an unfiltered source coverage summary.
These cannot be removed by a recipe. Excluded finding bodies and raw
inventories are not hidden inside the exported HTML. Filters are **not**
automatic de-identification: selected descriptions, evidence references,
source identifiers and notes can still be sensitive. Review exports before
sharing.

Files are validated and processed in browser memory. Reloading or **Clear
data** clears the assessment and notes; nothing is uploaded or automatically
written to browser storage. Loading the demo requests only the packaged
fictional snapshot from the same site. Use a trusted browser and host:
extensions and other software with access to that browser can still inspect
its memory.

Recipes and notes use separate, strict JSON schemas. They cannot execute
JavaScript, HTML or MDX, change finding severity, or alter risk policy.
Applying a preset does not erase notes; loading a different snapshot does.
A saved scope absent from a new assessment is an explicit error, not a
silent fallback to all scopes.

### Reuse a recipe from the CLI

The browser and CLI share the same selection and rendering functions:

```powershell
npm run build
node dist\src\cli.js report --snapshot assessments\review-001\assessment.json --recipe report-recipe.json --output assessments\executive-report
node dist\src\cli.js report --snapshot assessments\review-001\assessment.json --recipe report-recipe.json --notes analyst-notes.json --output assessments\annotated-report
```

`report` performs no collection or reassessment. It writes `report.html`,
`report.md` and the applied `report-recipe.json` into a **new** directory.
It never copies the raw snapshot or the separate notes file. Notes appear
in the report only when their section is enabled. Exit 0 means rendering
succeeded, not that the source is secure; source coverage gaps stay visible.

For a production static build:

```powershell
npm run studio:check
npm run studio:build
npm run studio:preview
```

Only the app and the deliberately fictional demo go into `studio/dist`.
Never put customer snapshots or notes into the Studio source/public folders.
Starlight documentation, charts, live collection and account management are
deliberately outside this first version.

CI and GitHub CodeQL cover build, tests and static analysis. The separate
manual [fictional Studio deployment](.azure/pipeline-setup.md) is prepared
for an approved Azure Static Web App, but cannot deploy until a protected
GitHub environment and site-scoped token are configured. It verifies the
public asset inventory before publication; tenant assessments are never
deployment inputs.

## Version 0.2 additions

- SharePoint/OneDrive tenant settings: legacy authentication, the sharing
  ceiling, invitation identity matching and external resharing.
- Active Entra role-assignment schedule instances: evidence-backed standing
  privilege, time-bound assignments and eligible-role activations kept distinct.
- Azure Policy evaluation metadata through a second fixed, approved-scope
  Resource Graph query. Exempt or disabled-effect observations never establish
  security protection.
- Consolidated recommendations with distinct target counts and preserved
  evidence, plus an access-gap checklist that never requests or grants access.

These use stable Microsoft Graph v1.0 or documented Resource Graph metadata.
Preview-only Intune Settings Catalog APIs are not silently enabled.

## Safety contract

- No tenant, Azure, Microsoft 365, Defender, Intune, GitHub or Azure DevOps
  configuration changes.
- No consent grants, permission changes, credentials created/rotated/deleted,
  repository/workflow changes or automatic remediation.
- No secret-value endpoints, repository source downloads, variable-group
  values, service-connection credentials, Key Vault secrets or secure-file
  downloads.
- Credential assessment uses dates, identifiers and types only. Authentication
  tokens supplied by the operator are used in memory and never written to
  reports or logs.
- Collection uses curated, scope-bound API routes, not a general-purpose REST
  client. Redirects and cross-scope pagination are rejected. The only assessment
  POST endpoint accepts only two fixed, read-only Azure Resource Graph queries:
  projected resource metadata or projected policy-evaluation metadata.
- Recommendations are text for a separately authorized remediation process.

See [security boundaries](SECURITY.md) and [coverage and limitations](docs/COVERAGE.md).

## Quick start: no cloud account required

Requirements: Node.js **22.12 or newer** and npm. Astro requires this minimum.
The lockfile pins the installed dependency graph.

```powershell
npm ci --ignore-scripts
npm run typecheck
npm test
npm run sample
```

The fictional [sample input](samples/assessment-input.json) is evaluated as of
its recorded timestamp. It demonstrates credential hygiene, privileged
identities and role schedules, Azure configuration/policy evaluation, repository
controls, federation relationships, SharePoint/OneDrive settings,
Microsoft 365/endpoint evidence and explicit collection gaps. It contains no
customer data and makes **no network requests**.

Open `assessments\sample\report.html`, or read `report.md` and `assessment.json`
in that directory. The sample command explicitly acknowledges incomplete
coverage for its exit status; it does not hide gaps in the report.

**Output directories must be new.** Re-running the sample against the same
directory is deliberately refused. For another run:

```powershell
node dist\src\cli.js assess --input samples\assessment-input.json --output assessments\another-sample --allow-incomplete
```

To preserve an existing sample as a baseline when upgrading:

```powershell
node dist\src\cli.js assess --input samples\assessment-input.json --output assessments\expanded-sample --allow-incomplete
node dist\src\cli.js diff --previous assessments\sample\assessment.json --current assessments\expanded-sample\assessment.json --output assessments\expansion-comparison
```

Changed collector versions and newly available evidence are not treated as
proof of newly introduced or remediated vulnerabilities.

## Live assessment

Live collection is opt-in through `--config`. Obtain authorization for the
specified tenant, subscriptions and organizations before assessing them.

1. Copy [config.example.json](config.example.json) to `config.local.json`.
2. Replace the fictional tenant identifier with an explicitly approved tenant.
3. Add approved subscription and organization identifiers; enable the matching
   source switches. Azure collection cannot run with an empty subscription list.
4. Arrange an existing credential with the read permissions shown by `catalog`.
   This application does not register applications, sign users in, grant
   consent, assign roles or change product licensing.
5. Run the assessment and inspect both findings **and coverage gaps**.

```powershell
npm run build
node dist\src\cli.js validate --config config.local.json
node dist\src\cli.js catalog
node dist\src\cli.js assess --config config.local.json --output assessments\review-001
```

`validate` is offline. The catalog lists implemented/manual collections,
permissions and official reference URLs. Do not grant every listed permission
by default: enable only the products and scope approved for the engagement.
A 403 or 404 does **not** establish that a control is disabled or unlicensed.

The current registry includes 60 live metadata collections and 16 explicit
manual capabilities. A collection being implemented does not mean it is
authorized, licensed, or complete in a particular assessment.

### Authentication

| Mode | Use | Boundary |
| --- | --- | --- |
| `azure-cli` | Local operator with an existing Azure CLI session | Explicit tenant; no login or automatic credential fallback |
| `managed-identity` | Existing Azure-hosted assessment identity | Optional user-assigned client ID; permissions provisioned separately |
| `workload-identity` | Existing federated workload identity | Explicit client ID and tenant; projected credential managed outside this tool |
| GitHub environment credential | GitHub organization/repository metadata | `GITHUB_TOKEN`, or a configured environment-variable name; never a token in JSON configuration |
| Azure DevOps | Existing Entra credential | Dedicated Azure DevOps resource audience; no PAT stored in configuration |

Use read-only roles/scopes wherever the service permits them, and an identity
dedicated to assessment. The HTTP boundary still refuses mutations if the
operator's credential happens to have broader access. Microsoft Graph,
Defender, Azure and Azure DevOps use distinct token audiences. Public-cloud
endpoints are the initial supported environment; sovereign clouds and GitHub
Enterprise Server require a separately reviewed adapter.

Related documentation:
[Azure Identity](https://learn.microsoft.com/en-us/javascript/api/overview/azure/identity-readme),
[Microsoft Graph permissions](https://learn.microsoft.com/en-us/graph/permissions-reference),
[Azure Resource Graph pagination](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/work-with-data).

## Commands and exit status

```text
assess --input FILE --output NEW_DIRECTORY [--policy FILE] [--previous FILE]
assess --config FILE --output NEW_DIRECTORY [--policy FILE] [--previous FILE]
diff --previous FILE --current FILE --output NEW_DIRECTORY
report --snapshot FILE --recipe FILE --output NEW_DIRECTORY [--notes FILE]
validate --config FILE
validate --input FILE
catalog
policy
```

| Exit | Meaning |
| --- | --- |
| 0 | Requested command/report completed; **not** a declaration that the environment is secure |
| 1 | Invalid configuration/evidence, scope mismatch, output conflict or operational failure |
| 2 | Assessment persisted, but collection coverage is incomplete |
| 3 | A failing check meets the optional `--fail-on` threshold |

`--fail-on high` includes critical and high failures. `--allow-incomplete`
explicitly acknowledges collection gaps for the exit code only. Threshold
failures take precedence over incomplete-coverage status. Unsupported manual
controls count as incomplete; a broad first-release assessment will therefore
normally return 2 unless explicitly acknowledged.

Inputs larger than 50 MiB, unknown schema versions, duplicate record identities,
unsafe credential fields, inconsistent timestamps and out-of-scope evidence
are rejected. Invalid input values and API error bodies are not echoed.
JSON outputs use the same 50 MiB bound so persisted snapshots can be read back.
For larger environments, partition explicit assessment scopes or lower
collection limits and preserve the reported partial-coverage status.
If writing an output bundle fails, the process reports failure and any partial
directory must not be treated as a complete assessment.

## Findings, relationships and prioritization

- Findings include severity, confidence, recommendation, documentation,
  Zero Trust principles and references to the supporting inventory records.
- Application/service-principal relationships use `appId`, not display names.
  Permission rules use resource application ID, permission ID and permission
  type, not alarming words in permission names.
- Ownership, group membership, role assignments, federation and Azure resource
  identity relationships retain provenance. Observed relationships are not
  proof of an exploitable attack path.
- Workload identity scores are explainable, capped at 100, and explicitly
  incomplete when required evidence is unavailable. Federation does not
  cancel broad privilege or prove persistent credentials were removed.
- Registered MFA is not enforced MFA. Conditional Access policy presence is
  not proof of effective tenant-wide coverage. Eligible roles are not active
  role assignments.
- Permanent-role findings use active schedule evidence, explicit end-date
  semantics and a resolved role definition. Ordinary role assignments alone
  do not establish lifetime; schedule observations do not double privilege
  weighting.
- SharePoint tenant settings define a sharing ceiling, not whether any site,
  document or anonymous link is actually exposed.
- PolicyStates report dated resource/assignment evaluations. Exemption,
  disabled effects, manual attestations and incomplete evidence do not
  establish an automated compliance pass or effective protection.
- Repository coverage distinguishes explicit enabled/disabled settings from
  unknown settings and API availability. Empty alert lists do not demonstrate
  enabled scanning.

The report separates observed risks, explicit passes and unassessed controls.
Repeated recommendations are grouped by check, domain and recommendation
without losing distinct targets, finding IDs or evidence. Ranking uses the
highest observed severity and affected-target count, not estimated effort or
exploitability; group confidence is the lowest among its findings.
Targets are logical finding targets; multiple policy evaluations of one
physical resource remain distinguishable. Policy targets display resource and
assignment context alongside their stable evidence identifiers.

An evidence-gap checklist groups repeated collection failures by source and
reason, shows affected scopes and documented read permissions, and distinguishes
manual review from missing access. It is not an authorization request. Candidate
quick wins are limited to expired-credential metadata cleanup review, with
dependency, retention and ownership validation still required. No recommendations
are applied automatically.

Every risk score exposes its factors in the JSON snapshot and reports.

### Custom risk policy

Use the `policy` command to inspect the full default policy. The `policy`
object in local configuration accepts threshold and weight overrides.
`permissionRules`, when supplied, **replaces** the default permission rules;
include any defaults you want to retain. Duplicate resource/type/permission
keys and unbounded weights are rejected.

A rule specifies `resourceAppId`, `permissionId`, `permissionType`, `severity`,
documented `capabilities`, `rationale` and an HTTPS `reference`. Unknown
permissions remain unclassified, never implicitly harmless. The optional
`--policy FILE` accepts a complete policy and also works with offline evidence.

## Snapshots and change tracking

```powershell
node dist\src\cli.js assess --config config.local.json --previous assessments\review-001\assessment.json --output assessments\review-002
node dist\src\cli.js diff --previous assessments\review-001\assessment.json --current assessments\review-002\assessment.json --output assessments\comparison-001
```

Comparisons require the **same** tenant, selected subscriptions and
organizations, and chronological timestamps. They track record creation,
removal and metadata changes: owners, credentials, federation, permissions,
role assignments, identity associations and security-control state.

Incomplete previous evidence cannot establish that a newly visible object
was newly created. Incomplete current evidence cannot establish deletion.
Omitted fields and collector-version changes are indeterminate. Losing access
does not resolve a finding. Resolution requires an explicit passing recheck
with comparable policy and complete supporting evidence; otherwise it remains
indeterminate. Arrays are compared as unordered metadata collections.

Valid policy refresh timestamps and upstream bookkeeping IDs alone do not
create posture changes when the logical evaluation identity is stable.
Missing, future, regressing or inconsistent evaluation context remains
indeterminate. Policy compliance improvement is not inferred merely from
disabling a policy effect or adding an exemption.

Change impact is **potential increase/decrease**, **review required**, or
**unknown**, never an accusation of malicious intent. Raw old/new metadata
values are not duplicated into the change report.

## Outputs and handling

| File | Contents |
| --- | --- |
| `assessment.json` | Versioned, validated inventory, findings, relationship graph, score factors, scope and coverage |
| `report.md` | Grouped recommendations, evidence-gap steps, per-repository coverage, findings and evidence references |
| `report.html` | Standalone escaped report with no JavaScript, remote assets, telemetry or uploads; Studio recipes select its optional sections |
| `report-recipe.json` | Reusable presentation settings, not evidence or analyst notes |
| `changes.json` / `changes.md` | Optional snapshot differences and finding transitions |

Reports contain **sensitive tenant metadata**, even without credentials. Store
them in a restricted location with encryption and a retention policy suitable
for the engagement. They are not encrypted or cryptographically signed by
this tool. POSIX output modes are restrictive; on Windows, enforce suitable
NTFS ACLs on the destination. Git ignores the default report directory, local
configuration and environment files. Default Studio download filenames are
also ignored if saved inside the checkout. Do not publish assessment reports or use
customer metadata as public test fixtures.

## Development

[Architecture and extension contracts](docs/ARCHITECTURE.md) describe collection
boundaries and evidence formats. [Coverage](docs/COVERAGE.md) describes what is
not implemented or cannot be concluded from the initial checks.

```powershell
npm run typecheck
npm test
npm run studio:check
npm run studio:build
npx playwright install chromium
npm run studio:test
```

Browser tests verify local imports, real downloads, recipe/notes round trips,
validation failures, the exact upload-size limit, print invocation, native PDF output and mobile
layout. To use an existing Windows Edge installation instead of downloading
Chromium, set `$env:PLAYWRIGHT_CHANNEL = 'msedge'` before `npm run studio:test`.
The browser tests start the same local launcher with
`--no-build --no-open --port 4331` in the foreground, independently of an
operator's preview server, and stop it afterward.

Tests use fixtures and injected HTTP/token providers, never live customer
tenants. The CI matrix covers Node 22/24 on Windows, macOS and Linux, uses pinned actions, has only
repository-read permission and does not upload assessment artifacts. Studio
typecheck/build and launcher/shortcut tests run on the matrix; browser tests
run on Node 24 on all three operating systems. Native macOS/Linux verification
is performed by those runners, not emulated by the Windows developer shell.
