# Fictional Report Studio deployment setup

The existing `Offline assessment checks` workflow builds and tests on Node
22/24 across Linux, macOS and Windows. GitHub CodeQL is already enabled for
this repository. Neither workflow needs an Azure credential. The separate
`Deploy fictional Report Studio` workflow is manual, accepts only the `dev`
branch, reruns checks and browser tests, verifies the exact public artifact,
requires successful CI and CodeQL runs on the **same commit**, then publishes
it only after its `demo` environment gate. It does not
provision a site or deploy assessment outputs.

## Before the first deployment

1. The public **fictional-demo-only** Azure Static Web App, DevOps
   subscription, Central US region and Free tier are approved. The Free
   site `np-cloudsecurityreview-demo-centralus` is provisioned through
   `infra/provision.ps1` at
   https://proud-smoke-0a7ba5910.5.azurestaticapps.net.
   Do not connect the site to GitHub using
   the Azure portal's generated workflow: that would create a second,
   unreviewed deployment path. The first token-based deployment populated
   the site's repository metadata with this repository and `dev`; it did not
   generate another workflow.
2. The repository's **Settings > Environments > demo** environment requires
   review by `billmcilhargey` and restricts deployments to `dev`. Self-review
   is permitted because no independent write-access reviewer is available.
   Do not remove this protection. Merely naming an environment in workflow
   YAML does not enforce reviews.
3. The site's deployment token is stored as an **environment secret** named
   `AZURE_STATIC_WEB_APPS_API_TOKEN` in `demo`, not as a repository secret.
   Do not print or commit the token. The workflow fails explicitly if it is
   missing. Rotate it if compromised or when the deployment site changes.
4. Review `dev` CI and CodeQL results. In **Actions > Deploy fictional Report
   Studio > Run workflow**, choose `dev`, then approve the `demo` environment
   deployment. Verify the workflow succeeds and inspect the actual site's
   `/` and `/demo.json` endpoints. The demo ID must be
   `fictional-report-studio-demo`. No customer assessment files should ever
   appear at public URLs.

The official Static Web Apps action uses a **site-scoped deployment token**;
no Azure CLI login, broad subscription RBAC or OIDC identity is needed for
this deploy-only workflow. It receives a prebuilt `studio/dist` directory
with `skip_app_build: true` and no API. The verification script rejects
unexpected files and ensures the bundled demo matches the checked-in
fictional fixture. Only the explicitly verified directory is transferred
between jobs and published. A future CI refactor must preserve these gates.

Deployment is not automatic on push or pull request. Preserve the site,
environment protection and token boundary for future deployments.
