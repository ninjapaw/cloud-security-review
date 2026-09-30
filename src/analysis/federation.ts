import type { EvidenceRef, JsonObject } from '../model.js';
import {
  Context, REFERENCES as R, object, rule, sameId, severityRank, strings, text, type RecordRef,
} from './context.js';
import { azurePrincipalTenant } from './access.js';
import { repositoryName } from './development.js';
import { linkedServicePrincipals } from './workloads.js';

const checks = {
  inventory: rule('WORKLOAD.FEDERATION.INVENTORY', 'workload-identities', 'informational', 'Federated credential configuration',
    'Validate exact issuer, subject and audience matching, trusted workload controls and actual token exchange. Keep persistent-credential review separate.', R.federation),
  match: rule('CODETOCLOUD.FEDERATION.MATCH', 'code-to-cloud', 'informational', 'Federation relationship requires exact matching',
    'Collect exact repository/resource/identity relationships and applicable branch or environment controls; never correlate by similar names.', [R.federation, R.githubOidc]),
  potential: rule('CODETOCLOUD.POTENTIAL_CONTROL', 'code-to-cloud', 'high', 'Repository control weakness linked to potential Azure control',
    'Prioritize the exact repository/ref or environment, federated trust, workload identity and Azure assignment. Validate workflow id-token permission, trust evaluation and effective Azure authorization before claiming an attack path.', [R.federation, R.githubOidc, R.githubBranch, R.githubEnvironment, R.rbac]),
  ado: rule('CODETOCLOUD.ADO.FEDERATION', 'code-to-cloud', 'informational', 'Azure DevOps federation subject is not pipeline authorization',
    'Collect stable service-connection IDs, identity binding and explicit pipeline authorization before correlating a pipeline to cloud privileges.', [R.adoFederation, R.adoPipelines]),
};

interface GithubTrust {
  repository: string;
  kind: 'branch' | 'tag' | 'environment' | 'pull-request';
  target?: string;
}

export function githubTrust(data: JsonObject): GithubTrust | undefined {
  if (data.issuer !== 'https://token.actions.githubusercontent.com') return undefined;
  if (!Array.isArray(data.audiences) || data.audiences.length !== 1 || data.audiences[0] !== 'api://AzureADTokenExchange') return undefined;
  const subject = text(data.subject);
  if (!subject || /[*?[\]\\\u0000-\u001f\u007f]/.test(subject)) return undefined;
  const match = /^repo:([^/:\s]+\/[^/:\s]+):(.*)$/.exec(subject);
  if (!match) return undefined;
  const repository = match[1]!;
  const context = match[2]!;
  if (context.startsWith('ref:refs/heads/') && context.length > 'ref:refs/heads/'.length && !/\s/.test(context))
    return { repository, kind: 'branch', target: context.slice(4) };
  if (context.startsWith('ref:refs/tags/') && context.length > 'ref:refs/tags/'.length && !/\s/.test(context))
    return { repository, kind: 'tag', target: context.slice(4) };
  if (context === 'pull_request') return { repository, kind: 'pull-request' };
  if (context.startsWith('environment:') && context.length > 'environment:'.length) {
    const encoded = context.slice('environment:'.length);
    // GitHub encodes colons as %3A inside environment claims; other/custom formats need manual matching.
    if (encoded.replace(/%3A/g, '').includes('%') || encoded.includes(':')) return undefined;
    return { repository, kind: 'environment', target: encoded.replace(/%3A/g, ':') };
  }
  return undefined;
}

interface FederationTarget {
  tenant: string;
  identities: RecordRef[];
  node: string;
  evidence: EvidenceRef[];
  application?: RecordRef;
}

function graphTarget(ctx: Context, credential: RecordRef): FederationTarget | undefined {
  const parentId = text(credential.data.parentId);
  const app = parentId ? ctx.find('entra.applications', credential.scope, parentId) : undefined;
  if (!app) return undefined;
  return { tenant: credential.scope, identities: linkedServicePrincipals(ctx, app),
    node: ctx.node('application', credential.scope, app.id.toLowerCase(), app.evidence),
    evidence: app.evidence, application: app };
}

function managedIdentityTarget(ctx: Context, credential: RecordRef): FederationTarget | undefined {
  const parentId = text(credential.data.parentId);
  const matches = parentId ? ctx.records('azure.resources').filter((resource) => sameId(resource.id, parentId)
    && text(resource.data.type)?.toLowerCase() === 'microsoft.managedidentity/userassignedidentities') : [];
  if (matches.length !== 1) return undefined;
  const resource = matches[0]!;
  const principalId = text(object(resource.data.properties)?.principalId);
  const tenant = principalId ? azurePrincipalTenant(ctx, resource, principalId) : undefined;
  const sp = principalId && tenant ? ctx.find('entra.servicePrincipals', tenant, principalId) : undefined;
  if (!tenant || !sp) return undefined;
  return { tenant, identities: [sp], node: ctx.node('azure-resource', resource.scope, resource.id.toLowerCase(), resource.evidence),
    evidence: [...resource.evidence, ...sp.evidence] };
}

function correlateGithub(ctx: Context, credential: RecordRef, data: JsonObject, credentialNode: string, target: FederationTarget): void {
  const trust = githubTrust(data);
  const audience = strings(data.audiences);
  if (!trust) {
    ctx.emit(checks.match, credential.scope, credential.id, 'unable-to-assess',
      'A supported GitHub relationship requires the exact trusted issuer, a single AzureADTokenExchange audience and an exact supported repository/ref/environment subject. No similar issuer, wildcard, mismatched audience or custom subject is inferred to match.',
      credential.evidence);
    return;
  }
  const repositories = ctx.records('github.repositories').filter((record) => repositoryName(record) === trust.repository);
  const ids = new Set(repositories.map((record) => record.id));
  const repository = ids.size === 1 ? repositories[0] : undefined;
  if (!repository) {
    ctx.emit(checks.match, credential.scope, credential.id, 'unable-to-assess',
      'The exact case-sensitive repository named by this federated subject is not uniquely present in the repository inventory. No repository is inferred from a suffix, similar name or organization alone.',
      credential.evidence);
    return;
  }
  const evidence = [...credential.evidence, ...repository.evidence, ...target.evidence];
  const repoNode = ctx.node('github-repository', repository.scope, repository.id, repository.evidence, { repository: trust.repository });
  ctx.edge(repoNode, credentialNode, 'potential-federation-subject', evidence, 'potential');
  ctx.emit(checks.match, credential.scope, credential.id, 'informational',
    `The exact GitHub ${trust.kind} subject and ${audience[0]} audience identify an observed repository. This proves configured trust metadata, not workflow id-token permission, pipeline authorization, token exchange or Azure access.`,
    evidence);
  const weaknesses = ctx.repositoryWeaknesses.filter((weakness) => weakness.repository === trust.repository
    && ((trust.kind === 'branch' && weakness.kind === 'branch' && weakness.target === trust.target)
      || (trust.kind === 'environment' && weakness.kind === 'environment' && weakness.target === trust.target)));
  // Repo-wide workflow-token settings alone do not establish trust for a particular job/event.
  if (!weaknesses.length) return;
  for (const principal of target.identities) {
    const privileges = ctx.privileges.filter((privilege) => privilege.kind === 'azure' && privilege.tenant === target.tenant
      && sameId(privilege.principalId, principal.id) && !privilege.eligible && severityRank[privilege.severity] >= 2);
    for (const privilege of privileges) {
      const correlatedEvidence = [...evidence, ...principal.evidence, ...privilege.evidence,
        ...weaknesses.flatMap((weakness) => weakness.evidence)];
      const severity = severityRank[privilege.severity] >= 3 ? 'high' : 'medium';
      ctx.emit(checks.potential, credential.scope, principal.id, 'fail',
        `An observed repository-control weakness for the exact trusted ${trust.kind} is linked by federated-credential parent ID, application/service-principal ID and Azure assignment principal ID. `
        + `Modeled Azure capability is at ${privilege.scope ?? 'unresolved'} scope. This is potential control only; actual workflow authorization, token exchange, assignment conditions, deny assignments and reachable resources are not proven. No exploitable attack path is claimed.`,
        correlatedEvidence, `${credential.id}/${privilege.assignmentId}`, severity, 'medium');
      ctx.factor(target.tenant, principal.id, 'codeToCloud',
        'An exact trusted source-control context with an evidenced control weakness is linked to modeled Azure capability; runtime authorization remains unverified.', correlatedEvidence);
      ctx.incomplete(target.tenant, principal.id);
      if (target.application) {
        ctx.factor(target.tenant, target.application.id, 'codeToCloud',
          'A source-control context and associated service principal create a documented potential code-to-cloud relationship.', correlatedEvidence);
        ctx.incomplete(target.tenant, target.application.id);
      }
    }
  }
}

export function analyzeFederation(ctx: Context): void {
  for (const scope of ctx.scopes('entra.')) ctx.require(checks.inventory, scope, ['entra.federatedCredentials']);
  for (const scope of ctx.scopes('azure.federatedCredentials')) ctx.require(checks.inventory, scope, ['azure.federatedCredentials']);
  for (const dataset of ['entra.federatedCredentials', 'azure.federatedCredentials']) {
    for (const credential of ctx.records(dataset)) {
      const data = dataset === 'azure.federatedCredentials' ? object(credential.data.properties) ?? credential.data : credential.data;
      const target = dataset === 'entra.federatedCredentials' ? graphTarget(ctx, credential) : managedIdentityTarget(ctx, credential);
      const issuer = text(data.issuer);
      const subject = text(data.subject);
      const credentialNode = ctx.node('federated-credential', credential.scope,
        `${dataset}/${text(credential.data.parentId) ?? 'unresolved'}/${credential.id}`, credential.evidence,
        { issuerCategory: issuer === 'https://token.actions.githubusercontent.com' ? 'github'
          : /^https:\/\/vstoken\.dev\.azure\.com\/[0-9a-f-]{36}$/.test(issuer ?? '') ? 'azure-devops' : 'other-or-unknown' });
      if (!target) {
        ctx.emit(checks.inventory, credential.scope, credential.id, 'unable-to-assess',
          'Federated-credential metadata cannot be bound to an exact application or managed identity and service principal. Parent/resource names are not a substitute for IDs.',
          credential.evidence, dataset);
        continue;
      }
      const evidence = [...credential.evidence, ...target.evidence];
      ctx.edge(credentialNode, target.node, 'federated-identity-for', evidence);
      ctx.emit(checks.inventory, credential.scope, credential.id, 'informational',
        'A federated identity credential is configured. This is metadata, not proven authentication, and does not revoke or reduce the risk of existing persistent credentials or privileges.',
        evidence, dataset);
      if (issuer === 'https://token.actions.githubusercontent.com') {
        correlateGithub(ctx, credential, data, credentialNode, target);
      } else if (/^https:\/\/vstoken\.dev\.azure\.com\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(issuer ?? '')
        && /^sc:\/\/[^/]+\/[^/]+\/[^/]+$/.test(subject ?? '') && Array.isArray(data.audiences)
        && data.audiences.length === 1 && data.audiences[0] === 'api://AzureADTokenExchange') {
        const unverified = ctx.node('unverified-ado-service-connection-subject', credential.scope, credential.id, credential.evidence);
        ctx.edge(unverified, credentialNode, 'potential-federation-subject', credential.evidence, 'potential');
        ctx.emit(checks.ado, credential.scope, credential.id, 'unable-to-assess',
          'The issuer and sc:// subject resemble the documented Azure DevOps federation format. No confirmed service-connection metadata or pipeline authorization is available. No project/pipeline is matched by display name, and no code-to-cloud privilege score is inferred.',
          evidence);
      } else ctx.emit(checks.match, credential.scope, credential.id, 'unable-to-assess',
        'This issuer/subject/audience combination is not correlated by the initial rule set. It may be legitimate Kubernetes, a custom issuer, a custom subject or another cloud; unclassified trust is not safe or broken trust.',
        evidence);
      for (const principal of target.identities) ctx.incomplete(target.tenant, principal.id);
    }
  }
}
