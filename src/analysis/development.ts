import type { EvidenceRef, JsonObject } from '../model.js';
import {
  Context, REFERENCES as R, has, identifier, number, object, objects, rule, sameId, strings, text,
  type RecordRef,
} from './context.js';

const checks = {
  twoFactor: rule('GITHUB.ORG.TWO_FACTOR', 'github', 'high', 'GitHub organization two-factor requirement',
    'Review the organization requirement with SSO/managed-user controls; this setting alone does not establish actual member MFA enforcement.', R.github2fa, ['verify-explicitly']),
  basePermissions: rule('GITHUB.ORG.BASE_PERMISSION', 'github', 'medium', 'GitHub organization default repository permissions',
    'Use the least base permission appropriate to the organization and review explicit grants independently.', R.githubBase),
  security: rule('GITHUB.SECURITY.CAPABILITY', 'github', 'low', 'Repository security capability state',
    'Review the explicit capability state, licensing/entitlement and alternative controls. Enabled capability is not proof that scans run or cover all branches.', R.githubSecurity, ['assume-breach']),
  branch: rule('GITHUB.BRANCH.PROTECTION', 'github', 'high', 'Default branch protection inventory',
    'Review applicable classic protection and active rulesets, including bypass actors. An inventory finding is not a tested bypass.', [R.githubBranch, R.githubRules]),
  reviews: rule('GITHUB.BRANCH.REVIEWS', 'github', 'medium', 'Default branch required-reviewer configuration',
    'Review required approving reviews in both classic protection and applicable active rulesets, along with bypass permissions.', [R.githubBranch, R.githubRules]),
  token: rule('GITHUB.WORKFLOW.TOKEN', 'github', 'medium', 'Broad default workflow-token capability',
    'Prefer least-privilege workflow/job token permissions and review event/fork restrictions and explicit overrides.', R.githubToken),
  content: rule('GITHUB.WORKFLOW.CONTENT', 'github', 'informational', 'Workflow metadata does not establish supply-chain controls',
    'Manually inspect approved workflow content and reusable workflows for token scopes, action pinning, trigger trust and OIDC authorization. Metadata alone is insufficient.', R.githubRunners),
  runners: rule('GITHUB.RUNNER.TRUST', 'github', 'medium', 'Self-hosted runner trust boundary',
    'Review runner group/repository authorization, isolation, persistence and untrusted code execution. Runner presence is a potential trust issue, not proof of access.', R.githubRunners),
  environment: rule('GITHUB.ENVIRONMENT.REVIEWERS', 'github', 'medium', 'Environment required-reviewer configuration',
    'Review native required reviewers, deployment protection rules and branch restrictions for this exact environment. Alternative/custom approvals require manual validation.', R.githubEnvironment),
  alerts: rule('GITHUB.SECURITY.ALERT', 'github', 'medium', 'Open repository security alert metadata',
    'Review the alert in the native service without retrieving or exporting secret values. Validate severity, disposition and actual exposure.', R.githubSecurity, ['assume-breach']),
  adoPublic: rule('ADO.PROJECT.PUBLIC', 'azure-devops', 'medium', 'Azure DevOps project is public',
    'Confirm public visibility is intentional and review the exposure of repository and pipeline metadata.', R.adoProjects),
  adoBranch: rule('ADO.BRANCH.POLICY', 'azure-devops', 'medium', 'Azure DevOps default-branch policy inventory',
    'Review enabled blocking policies with an exact repository/ref scope, required reviewers, build validation and bypass permissions.', R.adoPolicies),
  adoPipeline: rule('ADO.PIPELINE.AUTHORIZATION', 'azure-devops', 'informational', 'Pipeline and deployment authorization needs additional evidence',
    'Review pipeline content, service-connection authorization, environment checks and agent-pool security manually; metadata alone cannot establish trust.', R.adoPipelines),
  adoAgent: rule('ADO.AGENT.TRUST', 'azure-devops', 'medium', 'Self-hosted Azure DevOps agent pool',
    'Review pool authorization and isolation from untrusted pipelines; metadata does not prove any particular pipeline can use this pool.', R.adoPipelines),
};

export function repositoryName(repository: RecordRef): string | undefined {
  const name = text(repository.data.full_name);
  return name && /^[^/\s:]+\/[^/\s:]+$/.test(name) ? name : undefined;
}
export function repositoryInventory(ctx: Context, dataset: string, repository: RecordRef): {
  scope: string; records: RecordRef[]; complete: boolean; evidence: EvidenceRef[];
} {
  const name = repositoryName(repository);
  const sourceScope = name && ctx.collections.some((source) => source.id === dataset && source.scope === name)
    ? name : repository.scope;
  return { scope: sourceScope, records: ctx.records(dataset, sourceScope)
    .filter((record) => !!name && record.data.repository === name),
  complete: !!name && ctx.complete(dataset, sourceScope)
    && ctx.records(dataset, sourceScope).every((record) => !!text(record.data.repository)),
  evidence: ctx.inventoryEvidence(dataset, sourceScope) };
}

type Applicability = 'yes' | 'no' | 'unknown';

function refMatches(pattern: string, ref: string, defaultRef: string): Applicability {
  if (pattern === '~ALL') return 'yes';
  if (pattern === '~DEFAULT_BRANCH') return ref === defaultRef ? 'yes' : 'no';
  if (pattern === ref) return 'yes';
  // GitHub uses fnmatch semantics, not a JavaScript glob; unsupported patterns must not prove absence.
  if (/[*?[\]\\]/.test(pattern)) return 'unknown';
  return 'no';
}

export function rulesetApplies(data: JsonObject, ref: string, defaultRef: string, repository?: RecordRef): Applicability {
  if (data.enforcement === 'disabled' || data.enforcement === 'evaluate') return 'no';
  if (data.enforcement !== 'active') return 'unknown';
  if (data.target && data.target !== 'branch') return 'no';
  if (data.target !== 'branch') return 'unknown';
  const conditions = object(data.conditions);
  if (!conditions || Object.keys(conditions).some((key) => !['ref_name', 'repository_id', 'repository_name'].includes(key))) return 'unknown';
  const ids = object(conditions.repository_id);
  if (conditions.repository_id !== undefined) {
    if (!repository || !ids || !Array.isArray(ids.repository_ids)) return 'unknown';
    if (!ids.repository_ids.some((id) => String(id) === repository.id)) return 'no';
  }
  const names = object(conditions.repository_name);
  if (conditions.repository_name !== undefined) {
    const name = repository ? repositoryName(repository)?.split('/')[1] : undefined;
    if (!name || !names || !Array.isArray(names.include) || !Array.isArray(names.exclude)
      || names.protected === true) return 'unknown';
    if (strings(names.include).length !== names.include.length || strings(names.exclude).length !== names.exclude.length) return 'unknown';
    const exclude = strings(names.exclude).map((pattern) => refMatches(pattern, name, ''));
    if (exclude.includes('yes')) return 'no';
    if (exclude.includes('unknown')) return 'unknown';
    const include = strings(names.include).map((pattern) => refMatches(pattern, name, ''));
    if (!include.includes('yes')) return include.includes('unknown') ? 'unknown' : 'no';
  }
  const refs = object(conditions.ref_name);
  if (!refs || !Array.isArray(refs.include) || !Array.isArray(refs.exclude)) return 'unknown';
  if (strings(refs.include).length !== refs.include.length || strings(refs.exclude).length !== refs.exclude.length) return 'unknown';
  const excludes = strings(refs.exclude).map((pattern) => refMatches(pattern, ref, defaultRef));
  if (excludes.includes('yes')) return 'no';
  if (excludes.includes('unknown')) return 'unknown';
  const includes = strings(refs.include).map((pattern) => refMatches(pattern, ref, defaultRef));
  if (includes.includes('yes')) return 'yes';
  return includes.includes('unknown') ? 'unknown' : 'no';
}

function branchProtection(ctx: Context, repository: RecordRef): void {
  const name = repositoryName(repository);
  if (!name || repository.data.archived === true) return;
  const branch = text(repository.data.default_branch);
  const classic = repositoryInventory(ctx, 'github.branchProtection', repository);
  const rulesets = repositoryInventory(ctx, 'github.rulesets', repository);
  const evidence = [...repository.evidence, ...classic.evidence, ...rulesets.evidence];
  if (!branch) {
    ctx.emit(checks.branch, name, name, 'unable-to-assess', 'The repository default branch is not visible; another branch is not substituted.', evidence);
    return;
  }
  const ref = `refs/heads/${branch}`;
  const classicRecords = classic.records.filter((record) => (text(record.data.branch) ?? text(record.data.branchName)) === branch);
  const classicUnknown = classic.records.some((record) => !text(record.data.branch) && !text(record.data.branchName));
  const knownFields = ['required_status_checks', 'required_pull_request_reviews', 'restrictions', 'enforce_admins', 'required_linear_history'];
  const classicProtected = classicRecords.some((record) => record.data.protected === true
    || (record.data.protected !== false && knownFields.some((field) => has(record.data, field))));
  const applications = rulesets.records.map((record) => ({ record, applicability: rulesetApplies(record.data, ref, ref, repository) }));
  const applicable = applications.filter((item) => item.applicability === 'yes').map((item) => item.record);
  const protectionTypes = ['pull_request', 'required_status_checks', 'required_signatures', 'non_fast_forward',
    'deletion', 'update', 'creation', 'required_linear_history', 'required_deployments'];
  const rulesetProtected = applicable.some((record) => objects(record.data.rules)
    .some((item) => protectionTypes.includes(text(item.type) ?? '')));
  const unknownRules = applicable.some((record) => !Array.isArray(record.data.rules)
    || objects(record.data.rules).length !== record.data.rules.length
    || objects(record.data.rules).some((item) => !protectionTypes.includes(text(item.type) ?? '')));
  const complete = ctx.complete('github.repositories', repository.scope) && classic.complete && rulesets.complete;
  const unknown = classicUnknown || applications.some((item) => item.applicability === 'unknown') || unknownRules
    || classicRecords.some((record) => record.data.protected !== false && record.data.protected !== true && !knownFields.some((field) => has(record.data, field)));
  const observedEvidence = [...evidence, ...classicRecords.flatMap((record) => record.evidence), ...applicable.flatMap((record) => record.evidence)];
  if (classicProtected || rulesetProtected) {
    ctx.emit(checks.branch, name, name, complete ? 'pass' : 'informational',
      'At least one classic protection or demonstrably applicable active ruleset is observed for the exact default branch. This is a presence check, not proof of effective enforcement or inability to bypass.',
      observedEvidence, branch, 'informational');
  } else if (complete && !unknown) {
    ctx.emit(checks.branch, name, name, 'fail',
      'Complete inventories contain no classic protection or applicable active protective ruleset for the default branch. Bypass and successful modification have not been tested.',
      observedEvidence, branch);
    ctx.repositoryWeaknesses.push({ repository: name, kind: 'branch', target: ref, severity: 'high', evidence: observedEvidence });
  } else ctx.emit(checks.branch, name, name, 'unable-to-assess',
    'Protection absence cannot be established: inventory completeness, branch binding, ruleset applicability or rule details are unresolved. A 403/404 is not an unprotected-branch finding.',
    observedEvidence, branch);

  const classicApprovals = classicRecords.some((record) => (number(object(record.data.required_pull_request_reviews)?.required_approving_review_count) ?? 0) > 0);
  const ruleApprovals = applicable.some((record) => objects(record.data.rules).some((item) => item.type === 'pull_request'
    && (number(object(item.parameters)?.required_approving_review_count) ?? 0) > 0));
  const reviewDetailsUnknown = classicRecords.some((record) => record.data.protected !== false
    && !has(record.data, 'required_pull_request_reviews'))
    || applicable.some((record) => objects(record.data.rules).some((item) => item.type === 'pull_request'
      && number(object(item.parameters)?.required_approving_review_count) === undefined));
  if (!classicApprovals && !ruleApprovals) {
    if (complete && !unknown && !reviewDetailsUnknown) {
      ctx.emit(checks.reviews, name, name, 'fail',
        'Complete, applicable protection metadata does not require a positive native approving-review count on the default branch. Other checks may still protect changes; no bypass is asserted.',
        observedEvidence, branch);
      ctx.repositoryWeaknesses.push({ repository: name, kind: 'branch', target: ref, severity: 'medium', evidence: observedEvidence });
    } else ctx.emit(checks.reviews, name, name, 'unable-to-assess',
      'Required reviewer absence cannot be established from incomplete or unresolved applicable protection metadata.', observedEvidence, branch);
  }
}

function githubOrganizations(ctx: Context): void {
  for (const organization of ctx.records('github.organizations')) {
    const twoFactor = organization.data.two_factor_requirement_enabled;
    if (typeof twoFactor !== 'boolean') ctx.emit(checks.twoFactor, organization.scope, organization.id, 'unable-to-assess',
      'The organization two-factor requirement is not visible; no licensing or disabled-state inference is made.', organization.evidence);
    else ctx.emit(checks.twoFactor, organization.scope, organization.id,
      twoFactor ? ctx.complete('github.organizations', organization.scope) ? 'pass' : 'informational' : 'fail',
      `The organization explicitly reports two_factor_requirement_enabled=${twoFactor}. SSO/enterprise-managed-user configuration and individual authentication are separate evidence.`, organization.evidence);
    const permission = text(organization.data.default_repository_permission);
    if (['write', 'maintain', 'admin'].includes(permission ?? '')) ctx.emit(checks.basePermissions, organization.scope, organization.id, 'fail',
      `The organization explicitly defaults repository permission to ${permission}. This is a broad base capability, not a report of every member effective permission.`, organization.evidence);
    else if (!permission || !['none', 'read'].includes(permission)) ctx.emit(checks.basePermissions, organization.scope, organization.id, 'unable-to-assess',
      'Default repository permissions are not visible or recognized.', organization.evidence);
  }
}

function githubRepositories(ctx: Context): void {
  for (const repository of ctx.records('github.repositories')) {
    const name = repositoryName(repository);
    if (!name) {
      ctx.emit(checks.security, repository.scope, repository.id, 'unable-to-assess',
        'A full owner/repository identifier is missing. No relationship is built from similar names.', repository.evidence);
      continue;
    }
    const repoNode = ctx.node('github-repository', repository.scope, repository.id, repository.evidence, { repository: name });
    const capabilities = object(repository.data.security_and_analysis);
    for (const capability of ['advanced_security', 'code_security', 'secret_scanning', 'secret_scanning_push_protection', 'dependabot_security_updates']) {
      const state = text(object(capabilities?.[capability])?.status);
      const evidence = ctx.evidenceFor(repository, `security_and_analysis.${capability}`);
      if (state === 'enabled' || state === 'disabled') ctx.emit(checks.security, name, name,
        state === 'enabled' ? ctx.complete('github.repositories', repository.scope) ? 'pass' : 'informational' : 'fail',
        `${capability} is explicitly ${state}. This is feature configuration, not effective scan coverage, license availability or proof of absent alternatives.`, evidence, capability);
      else ctx.emit(checks.security, name, name, 'unable-to-assess',
        `${capability} state is not visible or recognized. Omitted fields, 403 and 404 responses do not distinguish unavailable licensing from insufficient permission or disabled configuration.`,
        evidence, capability);
    }
    branchProtection(ctx, repository);
    const permissions = repositoryInventory(ctx, 'github.workflowPermissions', repository);
    if (!permissions.complete) ctx.emit(checks.token, name, name, 'unable-to-assess',
      'The workflow-permission inventory is incomplete; absence of a write token cannot be established.', permissions.evidence, 'coverage');
    for (const permission of permissions.records) {
      if (permission.data.default_workflow_permissions === 'write' || permission.data.can_approve_pull_request_reviews === true) {
        ctx.emit(checks.token, name, name, 'fail',
          'The repository explicitly permits a write-capable default workflow token or workflow approval of pull requests. Job overrides, event/fork restrictions and actual use require separate review.',
          permission.evidence, permission.id);
        ctx.repositoryWeaknesses.push({ repository: name, kind: 'workflow-token', severity: 'medium', evidence: permission.evidence });
      } else if (!text(permission.data.default_workflow_permissions)) ctx.emit(checks.token, name, name, 'unable-to-assess',
        'The default workflow-token permission is not visible.', permission.evidence, permission.id);
    }
    const workflows = repositoryInventory(ctx, 'github.workflows', repository);
    for (const workflow of workflows.records) ctx.edge(repoNode,
      ctx.node('github-workflow', name, workflow.id, workflow.evidence), 'contains-workflow', [...repository.evidence, ...workflow.evidence]);
    ctx.emit(checks.content, name, name, 'unable-to-assess',
      'Workflow-list metadata cannot establish action pinning, workflow contents, job token overrides, trigger trust, id-token permission or runtime authorization.',
      [...repository.evidence, ...workflows.evidence]);
    const environments = repositoryInventory(ctx, 'github.environments', repository);
    for (const environment of environments.records) {
      const environmentName = text(environment.data.name);
      const evidence = [...repository.evidence, ...environment.evidence];
      ctx.edge(repoNode, ctx.node('github-environment', name, environment.id, environment.evidence),
        'contains-environment', evidence);
      const protections = objects(environment.data.protection_rules);
      const required = protections.filter((protection) => protection.type === 'required_reviewers');
      const unknown = !Array.isArray(environment.data.protection_rules)
        || protections.length !== environment.data.protection_rules.length
        || required.some((protection) => !Array.isArray(protection.reviewers)
          || objects(protection.reviewers).length !== protection.reviewers.length
          || objects(protection.reviewers).some((reviewer) => !identifier(object(reviewer.reviewer)?.id)));
      const hasReviewers = required.some((protection) =>
        objects(protection.reviewers).some((reviewer) => !!identifier(object(reviewer.reviewer)?.id)));
      if (!hasReviewers) {
        if (!environments.complete || unknown || !environmentName) ctx.emit(checks.environment, name, environment.id, 'unable-to-assess',
          'Complete protection-rule details and an exact environment binding are required before concluding native required reviewers are missing.', evidence);
        else {
          ctx.emit(checks.environment, name, environment.id, 'fail',
            'This exact environment has no native required reviewers in the complete protection-rule inventory. Custom rules, wait timers and branch restrictions may still provide protection.',
            evidence);
          if (!protections.some((protection) => !['required_reviewers', 'wait_timer', 'branch_policy'].includes(text(protection.type) ?? '')))
            ctx.repositoryWeaknesses.push({ repository: name, kind: 'environment', target: environmentName, severity: 'medium', evidence });
        }
      }
    }
    for (const dataset of ['github.dependabotAlerts', 'github.codeScanningAlerts', 'github.secretScanningAlerts']) {
      const alerts = repositoryInventory(ctx, dataset, repository);
      for (const alert of alerts.records) {
        if (alert.data.state === 'open') ctx.emit(checks.alerts, name, `${dataset}/${alert.id}`, 'fail',
          'An open security alert is reported by the source. Only metadata is used; no secret, affected content or secret value is exported.', alert.evidence);
      }
    }
  }
  for (const runner of ctx.records('github.runners')) {
    const selfHosted = runner.data.type === 'self-hosted' || objects(runner.data.labels).some((label) => label.name === 'self-hosted');
    if (selfHosted) ctx.emit(checks.runners, runner.scope, runner.id, 'informational',
      'Self-hosted runner metadata is observed. Runner-group authorization, job trust and host isolation are not established; no particular repository is assumed authorized.',
      runner.evidence);
    else ctx.emit(checks.runners, runner.scope, runner.id, 'unable-to-assess',
      'Runner metadata is insufficient to classify hosting and job trust.', runner.evidence);
  }
}

function adoPolicyApplies(policy: RecordRef, repositoryId: string, defaultBranch: string): Applicability {
  if (policy.data.isEnabled === false || policy.data.isBlocking === false) return 'no';
  if (policy.data.isEnabled !== true || policy.data.isBlocking !== true) return 'unknown';
  const settings = object(policy.data.settings);
  if (!Array.isArray(settings?.scope)) return 'unknown';
  if (objects(settings.scope).length !== settings.scope.length) return 'unknown';
  let unknown = false;
  for (const scope of objects(settings.scope)) {
    if (!has(scope, 'repositoryId')) { unknown = true; continue; }
    if (scope.repositoryId !== null && !text(scope.repositoryId)) { unknown = true; continue; }
    if (scope.repositoryId !== null && !sameId(text(scope.repositoryId), repositoryId)) continue;
    const ref = text(scope.refName);
    const kind = text(scope.matchKind)?.toLowerCase();
    if (!ref || !kind) { unknown = true; continue; }
    if ((kind === 'exact' && ref === defaultBranch) || (kind === 'prefix' && defaultBranch.startsWith(ref))) return 'yes';
    if (!['exact', 'prefix'].includes(kind)) unknown = true;
  }
  return unknown ? 'unknown' : 'no';
}

function azureDevOps(ctx: Context): void {
  for (const project of ctx.records('azureDevOps.projects')) {
    ctx.node('ado-project', project.scope, project.id, project.evidence);
    if (project.data.visibility === 'public') ctx.emit(checks.adoPublic, project.scope, project.id, 'fail',
      'The project explicitly reports public visibility. Review whether repository and pipeline metadata exposure is intended; no secret exposure or unauthorized access is asserted.', project.evidence);
    else if (!text(project.data.visibility)) ctx.emit(checks.adoPublic, project.scope, project.id, 'unable-to-assess',
      'Project visibility is not explicitly available.', project.evidence);
  }
  for (const repository of ctx.records('azureDevOps.repositories')) {
    const branch = text(repository.data.defaultBranch);
    const projectId = text(object(repository.data.project)?.id);
    const organization = repository.scope.split('/')[0]!;
    const scope = projectId ? `${organization}/${projectId}` : repository.scope;
    const policies = ctx.records('azureDevOps.branchPolicies', scope);
    const matches = branch ? policies.map((policy) => ({ policy, applies: adoPolicyApplies(policy, repository.id, branch) })) : [];
    const applicable = matches.filter((item) => item.applies === 'yes');
    const evidence = [...repository.evidence, ...ctx.inventoryEvidence('azureDevOps.branchPolicies', scope)];
    if (applicable.length) ctx.emit(checks.adoBranch, scope, repository.id, 'informational',
      'An enabled blocking policy explicitly targets this repository/default ref. Policy presence is not a guarantee of review strength, effective enforcement or absence of bypass permissions.',
      [...evidence, ...applicable.flatMap((item) => item.policy.evidence)]);
    else if (branch && projectId && ctx.complete('azureDevOps.repositories', repository.scope)
      && ctx.complete('azureDevOps.branchPolicies', scope) && !matches.some((item) => item.applies === 'unknown')) {
      ctx.emit(checks.adoBranch, scope, repository.id, 'fail',
        'The complete policy inventory contains no enabled blocking policy applicable to this exact repository/default ref. This is not a tested bypass or a claim that no other control exists.',
        evidence);
    } else ctx.emit(checks.adoBranch, scope, repository.id, 'unable-to-assess',
      'Default branch, project binding, policy scope details or inventory completeness are insufficient to establish policy absence.', evidence);
    ctx.node('ado-repository', scope, repository.id, repository.evidence);
  }
  for (const scope of ctx.scopes('azureDevOps.')) {
    const pipelines = ctx.records('azureDevOps.pipelines', scope);
    const environments = ctx.records('azureDevOps.environments', scope);
    ctx.emit(checks.adoPipeline, scope, scope, 'unable-to-assess',
      'Pipeline/environment inventory is not service-connection authorization, YAML/classic content, approval/check or secret configuration evidence. No pipeline-to-identity association is invented from names.',
      [...ctx.inventoryEvidence('azureDevOps.pipelines', scope), ...ctx.inventoryEvidence('azureDevOps.environments', scope)]);
    for (const pipeline of pipelines) ctx.node('ado-pipeline', scope, pipeline.id, pipeline.evidence);
    for (const environment of environments) ctx.node('ado-environment', scope, environment.id, environment.evidence);
  }
  for (const pool of ctx.records('azureDevOps.agentPools')) {
    if (pool.data.isHosted === false) ctx.emit(checks.adoAgent, pool.scope, pool.id, 'informational',
      'A self-hosted agent pool is explicitly reported. Pipeline authorization, isolation and successful use are not established.', pool.evidence);
  }
}

export function analyzeDevelopment(ctx: Context): void {
  githubOrganizations(ctx);
  githubRepositories(ctx);
  azureDevOps(ctx);
}
