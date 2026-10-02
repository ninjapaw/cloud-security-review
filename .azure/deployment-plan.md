# Azure deployment plan

> **Status:** Deployment workflow prepared - deployment approval and Azure context pending

## 1. Project overview

**Goal:** Build, review and publish the Report Studio for `ninjapaw/cloud-security-review` from `dev`.
**Path:** Add hosting to an existing project. No Azure deployment has occurred.

## 2. Requirements and decisions

| Attribute | Proposed value |
| --- | --- |
| Classification | Development; public fictional demonstration only |
| Scale and budget | Small; cost-optimized |
| Subscription | Current CLI default: `ME-MngEnvMCAP951794-NinjaPaws-DevOps` (`16037566-d4df-4c7c-b484-346d8472b4c4`); **user confirmation required** |
| Location | Central US proposed; **user confirmation and service availability check required** |
| Hosting | Azure Static Web Apps Free proposed; **user approval required** |

Do not deploy private tenant assessment snapshots, recipes or analyst notes.
Uploaded snapshots are processed only in the visitor's browser; a public
deployment does not provide authentication or a trusted private workspace.
The documented launcher must remain loopback-only.

## 3. Detected components and recipe

| Component | Technology | Location | Proposed Azure service |
| --- | --- | --- | --- |
| Assessment CLI | TypeScript, Node.js | `src/` | None; not hosted |
| Report Studio | Astro static build, React | `studio/` | Static Web Apps Free |
| Demo | Fictional snapshot | `studio/public/` | Static assets only |

**Recipe:** Provision an approved site separately, then use the gated
GitHub Actions deploy-only workflow described in [pipeline-setup.md](pipeline-setup.md).
Do not replace the repository's local launcher or expose its Node preview server.
The deployment requires new infrastructure, protected `demo` environment and
site-scoped token secret. CI and CodeQL already exist.

## 4. Provisioning and safety gates

| Resource type | Planned new resources | Capacity check |
| --- | ---: | --- |
| `Microsoft.Web/staticSites` | 1 | Pending confirmed subscription, region and quota/limit review |

Before execution: confirm hosting choice, subscription, region and cost;
complete capacity and RBAC checks; create infrastructure and protected
deployment environment; validate the built asset inventory contains only the
app and fictional demo; run Azure validation and then deploy.

## 5. Review and validation performed

- Target security review: no high-confidence exploitable findings in the bounded read-only review.
- `npm run build`, `npm run typecheck`, `npm run studio:check`, `npm run studio:build`: passed locally.
- `npm test`: 256 passed locally, including the previously failing missing-dependency launcher test.
- `npm run studio:test`: 6 passed locally after installing the missing Playwright browser.
- `npm run sample`: passed using the fictional fixture; output is ignored and must never be published.
- Latest observed remote `dev` CI has a macOS Node 22/24 failure in the launcher test; the local fix is not yet verified in CI.
- No matching existing Static Web App was found. A manual, gated deployment workflow has been prepared, but no site or deployment secret is configured.

**Validation proof for Azure deployment:** Pending approval, infrastructure and preflight checks.
No Azure resources were created or changed.
