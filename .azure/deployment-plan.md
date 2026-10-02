# Azure deployment plan

> **Status:** Deployed

## 1. Project overview

**Goal:** Build, review and publish the Report Studio for `ninjapaw/cloud-security-review` from `dev`.
**Path:** Add hosting to an existing project. The public fictional demo is deployed.

## 2. Requirements and decisions

| Attribute | Proposed value |
| --- | --- |
| Classification | Development; public fictional demonstration only |
| Scale and budget | Small; cost-optimized |
| Subscription | `ME-MngEnvMCAP951794-NinjaPaws-DevOps` (`16037566-d4df-4c7c-b484-346d8472b4c4`); current Azure CLI default, approved 2026-10-02 |
| Location | Central US; `Microsoft.Web/staticSites` supports the region and four sites already run there |
| Hosting | Azure Static Web Apps Free; approved 2026-10-02 |
| Resource group | `NP-CloudSecurityReview-Dev-CentralUS` (created) |
| Site | `np-cloudsecurityreview-demo-centralus` — [public endpoint](https://proud-smoke-0a7ba5910.5.azurestaticapps.net) |

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

**Recipe:** Azure CLI provisioning via [infra/provision.ps1](../infra/provision.ps1), then use the gated
GitHub Actions deploy-only workflow described in [pipeline-setup.md](pipeline-setup.md).
Do not replace the repository's local launcher or expose its Node preview server.
The deployment requires new infrastructure, protected `demo` environment and
site-scoped token secret. CI and CodeQL already exist.

## 4. Provisioning and safety gates

| Resource type | Planned new resources | Capacity check |
| --- | ---: | --- |
| `Microsoft.Web/staticSites` | 1 Free | 3 Free sites in subscription; 4 after deployment vs 10 Free site limit ([Microsoft quotas](https://learn.microsoft.com/azure/static-web-apps/quotas)). `az quota list` for Microsoft.Web could not query because Microsoft.Quota is not registered; used Azure resource inventory and published service limit instead. |

Before execution, hosting choice, subscription, region, cost, capacity, RBAC,
protected environment and the public asset inventory were reviewed. Azure
validation preceded infrastructure provisioning and application deployment.

## 5. Review and validation performed

- Target security review: no high-confidence exploitable findings in the bounded read-only review.
- `npm run build`, `npm run typecheck`, `npm run studio:check`, `npm run studio:build`: passed locally.
- `npm test`: 256 passed locally, including the previously failing missing-dependency launcher test.
- `npm run studio:test`: 6 passed locally after installing the missing Playwright browser.
- `npm run sample`: passed using the fictional fixture; output is ignored and must never be published.
- Remote `dev` CI and CodeQL passed on `476805e0da74ab5f55eb8df42498770873bf0906` after fixing the
  macOS launcher test; no deployment was attempted.
- No matching existing Static Web App was found before provisioning. A manual deployment workflow
  and branch-restricted `demo` environment exist. Required review is enabled
  for the repository owner; because no independent write-access collaborator
  exists, self-review is permitted for this initial deployment.
- Provisioning script passed PowerShell parser validation; `actionlint` passed
  for CI and deployment workflows. Artifact check confirmed `index.html`,
  fictional `demo.json` and four bundled assets. Azure identity has inherited
  Owner access at management-group scope. Preparation is complete.

## 6. All validation checks pass

Azure CLI recipe validation steps:

- [x] Core validation: CLI/auth/context, infrastructure syntax and applicable
  preflight. The shared Bicep validation/what-if helper is not
  applicable: this deployment uses `infra/provision.ps1` and contains no
  `infra/main.bicep` or ARM template.
- [x] Docker build: not applicable; this is an Astro static site.
- [x] Azure Policy validation: inspect effective subscription assignments for
  allowed locations, SKUs, resource types and required tags.
- [x] Build verification and public-artifact allowlist.
- [x] Static role verification: no service identity or resource role assignments
  are needed for this deploy-only site; check the human provisioning access and
  the site-scoped GitHub environment credential boundary.

## 7. Validation Proof

Validation completed 2026-10-02 at 01:13 Eastern (UTC-04:00).

- `az account show --query id -o tsv`: approved subscription
  `16037566-d4df-4c7c-b484-346d8472b4c4` selected. `az provider show -n
  Microsoft.Web` lists `Central US` for `staticSites`. `az group exists`
  returned `false`, and `az staticwebapp list` returned no matching site.
  No creation or preview was attempted during validation.
- PowerShell parser: no syntax errors in `infra/provision.ps1`. `actionlint`
  passed on both CI and deployment workflows. No Bicep/ARM template or
  Dockerfile exists in this Azure CLI recipe, so template build, ARM what-if
  and Docker checks do not apply; no equivalent Azure CLI dry-run is claimed.
- Azure Policy assignment inspection included inherited management-group
  policies. The `Block Azure RM Resource Creation` deny rule targets Classic
  resource types, not Static Web Apps; the `MCAPSGovDenyPolicies`
  `NotAllowedResourceTypes` list contains Classic resources, not
  `Microsoft.Web/staticSites`. Other deny initiative members target VMs,
  AKS, SQL, OpenAI, Sentinel and Managed HSM, not this site. The deploy
  initiative includes a new-resource-group policy. Actual provisioning
  remains the final policy enforcement check.
- `npm run typecheck`, `npm test` (256 pass), `npm run studio:check`
  (zero errors/warnings), `npm run studio:build`, `npm run studio:test`
  (6 pass), and `node tools/check-studio-artifact.mjs` passed. The artifact
  contained `index.html`, fictional `demo.json` and four bundled assets.
- Static role review: no app-managed identity or data-plane access is
  involved. The human account has inherited Owner role from its
  management group for provisioning. The deployment workflow uses only
  the site-scoped token behind `demo` environment review, not an Azure
  subscription credential.

No Azure resources were created or changed during validation. After validation,
`infra/provision.ps1` created the Central US resource group and the Free Static
Web App. `az staticwebapp show` confirmed its SKU, location, HTTPS hostname
and absent `repositoryUrl`; the resource group contains only the site.
The site-scoped deployment token was stored (not printed) as the `demo`
environment secret `AZURE_STATIC_WEB_APPS_API_TOKEN`; `gh secret list --env demo`
confirmed its name.

## 8. Deployment Verification

- Commit `9b3622b6281d255b1ffff6f5686c84e9ba3ad0f9` passed
  [cross-platform CI](https://github.com/ninjapaw/cloud-security-review/actions/runs/36968188530)
  and [CodeQL](https://github.com/ninjapaw/cloud-security-review/actions/runs/36968188314).
  [Manual deployment](https://github.com/ninjapaw/cloud-security-review/actions/runs/36968325614)
  passed both verify and deploy jobs after `demo` reviewer approval.
- [The live home page](https://proud-smoke-0a7ba5910.5.azurestaticapps.net/)
  returned HTTP 200 and Report Studio content.
  [The live fictional demo](https://proud-smoke-0a7ba5910.5.azurestaticapps.net/demo.json)
  returned `assessmentId: fictional-report-studio-demo`.
  `/security-report.html`, `/security-report.md`, `/analyst-notes.json`,
  `/report-recipe.json` and `/assessments/` all returned HTTP 404.
- Azure reports the site as Free in Central US. The token-based deploy
  populated repository metadata with this repository and `dev`. GitHub still
  lists only CI, CodeQL and the reviewed manual deployment workflow; no
  generated workflow or repository-wide deployment secret was added.
