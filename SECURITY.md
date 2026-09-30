# Security and data handling

## Read-only by design

The platform assesses explicitly approved environments. Authentication setup,
authorization grants, product configuration and remediation are outside its
runtime. Never add a remediation mode or a generic REST escape hatch to a
collector.

The HTTP transport has a default-deny boundary for hosts, methods, routes and
scope. `GET` alone is insufficient: some GET APIs return secret values or
download files. Only reviewed metadata endpoints are allowed. The only
permitted assessment POST endpoint is Azure Resource Graph, with exactly two
fixed query choices: projected resource metadata and projected PolicyStates
metadata. Both require explicitly selected subscriptions. Policy parameters,
evaluation details and arbitrary property bags are not selected. Continuation
cursors cannot cross query or subscription boundaries.

New collectors must reject redirects and validate every continuation against
the original collection route and scope before sending authorization.
Pagination loops, response-size limits, request/time budgets, throttling and
dependency failures must result in explicit incomplete evidence.

## Secrets and authentication

- Do not retrieve Key Vault secret values, credential material, repository
  source contents, Azure DevOps variable values or service endpoint
  authorization parameters.
- Graph credential GET metadata is permitted: dates, IDs and credential type.
  Never retain password hints, `secretText`, private keys, certificate bytes
  or arbitrary unknown response fields.
- Secret-scanning alert metadata can be assessed, but never the exposed
  secret itself. If the upstream API cannot safely exclude sensitive values,
  do not call it; record the unsupported capability instead.
- Caller-supplied authentication credentials remain in process memory.
  Do not log headers, raw error bodies, SDK errors or token responses.
- Offline evidence is schema-validated and checked for prohibited fields and
  common credential signatures. Pattern checks cannot guarantee that an
  arbitrary string is not a secret: use curated projections and trusted,
  reviewed input rather than relying on redaction after collection.

This boundary reduces accidental disclosure; it is not protection from a
compromised host, malicious dependencies or someone modifying this application's
code. Run on a trusted host with a dedicated least-privilege identity.

## Evidence and reports

Tenant identifiers, identity names, ownership, roles, devices, repository
names and security posture are confidential metadata. No upload service or
telemetry is included. Store outputs in an encrypted, access-controlled
location; Windows requires appropriate destination ACLs. HTML reports escape
untrusted text and use a no-script/no-remote-resource Content Security Policy.

Reports are unsigned local observations. They cannot prove that an imported
fixture is authentic, or that a collector had visibility to every object a
service hides from the authenticated caller. An API returning a complete
page sequence is complete only for that caller's view.

Never describe unavailable controls as passing, infer licensing from 403/404,
or label potential relationships as proven exploitation. A failed collector
must not cause findings to be silently marked resolved.

Recommendation grouping must retain the affected scopes, targets, individual
finding identifiers and provenance. A permission checklist is not approval to
grant access. A compliant PolicyStates row caused by a disabled effect or manual
attestation must not be presented as automated enforcement or remediation.
Tenant-level SharePoint sharing permission is not proof that any document is
public; active-role schedules must not be treated as eligible-role assignments
or counted twice in identity scores.

## Reporting a vulnerability

Contact the repository maintainers through a private channel or GitHub private
vulnerability reporting if enabled. Do not include access tokens, tenant dumps,
customer identities, secret-scanning payloads or live assessment reports in a
public issue. Use synthetic reproductions.
