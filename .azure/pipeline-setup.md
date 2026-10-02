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

1. Approve a public **fictional-demo-only** Azure Static Web App, its
   subscription, region and cost. Provision it separately and review its
   deployment authorization policy. Do not connect the site to GitHub using
   the Azure portal's generated workflow: that would create a second,
   unreviewed deployment path.
2. In the repository's **Settings > Environments**, create `demo`. Restrict
   deployments to `dev` and configure required reviewers. Make sure the
   reviewers are not the person who triggers the workflow, where possible.
   Do not add a deployment token before this protection is in place. The
   environment does not currently exist; merely naming it in workflow YAML
   does not enforce reviews.
3. Get that site's deployment token from its Azure Static Web Apps deployment
   settings. Store it as an **environment secret** named
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

Deployment is not automatic on push or pull request. Do not activate the
workflow until the site, environment protections and token are reviewed.
