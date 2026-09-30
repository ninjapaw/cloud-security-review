import type { EvidenceRef, Severity } from '../model.js';
import {
  Context, DAY, REFERENCES as R, date, matchesAction, object, objects, policyNumber,
  rule, sameId, severityRank, strings, text, uniqueEvidence,
  type RecordRef,
} from './context.js';

const checks = {
  role: rule('ENTRA.ROLE.PRIVILEGED', 'entra', 'high', 'Privileged directory assignment',
    'Review the documented capabilities, assignment scope and activation requirements. Prefer narrowly scoped, time-bound access.', [R.roles, R.pim]),
  eligible: rule('ENTRA.ROLE.ELIGIBLE', 'entra', 'informational', 'Privileged directory role eligibility',
    'Review eligibility, approval, MFA and activation controls in PIM; eligibility is not active authorization.', [R.roles, R.pim]),
  unknownRole: rule('ENTRA.ROLE.UNCLASSIFIED', 'entra', 'informational', 'Directory role capability needs review',
    'Collect the exact role definition and classify documented resource actions rather than the display name.', R.roles),
  membership: rule('ENTRA.GROUP.PRIVILEGE', 'entra', 'high', 'Group-linked directory privilege relationship',
    'Validate supported direct membership and role scope. Do not assume nested membership confers an Entra role.', [R.groups, R.roles]),
  cycle: rule('ENTRA.GROUP.CYCLE', 'entra', 'informational', 'Cyclic group relationship observed',
    'Validate the membership inventory and review the cycle; no additional authorization is inferred from it.', R.groups),
  registration: rule('ENTRA.MFA.REGISTRATION', 'entra', 'medium', 'MFA registration for enabled identities',
    'Review strong authentication registration and allowed methods. Validate enforcement separately using sign-in context and policy evaluation.', R.registration, ['verify-explicitly']),
  enforcement: rule('ENTRA.MFA.ENFORCEMENT', 'entra', 'informational', 'Effective MFA enforcement requires validation',
    'Evaluate applicable policies, exclusions, authentication strengths, security defaults and actual sign-ins for representative access scenarios.', [R.registration, R.ca], ['verify-explicitly']),
  ca: rule('ENTRA.CA.INVENTORY', 'entra', 'medium', 'Conditional Access inventory',
    'Review enabled policies and their targets and exclusions. Policy existence is not effective user, application or workload coverage.', R.ca, ['verify-explicitly']),
  caState: rule('ENTRA.CA.NONENFORCING', 'entra', 'low', 'Conditional Access policy is not enforcing',
    'Confirm whether disabled/report-only state is intentional before manually planning enforcement and emergency-access exclusions.', R.ca, ['verify-explicitly']),
  riskyUser: rule('ENTRA.IDENTITY.RISK', 'entra', 'high', 'Unresolved identity risk observed',
    'Investigate the recorded risk in Identity Protection and correlate with sign-ins before taking remediation action.', R.risk, ['assume-breach', 'verify-explicitly']),
  riskySignIn: rule('ENTRA.SIGNIN.RISK', 'entra', 'high', 'Unresolved risky sign-in observed',
    'Investigate this risk event, user identity and sign-in context; a risk detection is not confirmation of compromise.', R.risk, ['assume-breach']),
  dormant: rule('ENTRA.USER.DORMANT', 'entra', 'low', 'Old successful sign-in for an enabled user',
    'Validate account purpose, report retention and successful sign-in history before reviewing access or account lifecycle.', R.dormant, ['least-privilege', 'verify-explicitly']),
};

const roleTemplates: Record<string, { severity: Severity; capabilities: string[] }> = {
  '62e90394-69f5-4237-9190-012177145e10': { severity: 'critical', capabilities: ['directory-administration', 'directory-role-management'] },
  'e8611ab8-c189-46e8-94e1-60213ab1f814': { severity: 'critical', capabilities: ['directory-role-management'] },
  '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': { severity: 'high', capabilities: ['application-control'] },
  '158c047a-c907-4556-b7ef-446551a6b5f7': { severity: 'high', capabilities: ['application-control'] },
  '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': { severity: 'high', capabilities: ['authentication-method-control'] },
};

export function directoryCapabilities(definition: RecordRef): { severity: Severity; capabilities: string[] } | undefined {
  const template = text(definition.data.templateId)?.toLowerCase();
  if (template && roleTemplates[template]) return roleTemplates[template];
  const actions = objects(definition.data.rolePermissions).flatMap((permission) => strings(permission.allowedResourceActions));
  if (actions.length === 0) return undefined;
  const targets: [string, Severity, string[]][] = [
    ['directory-role-management', 'critical', [
      'microsoft.directory/roleAssignments/allProperties/allTasks',
    ]],
    ['application-control', 'high', [
      'microsoft.directory/applications/credentials/update',
      'microsoft.directory/servicePrincipals/credentials/update',
    ]],
    ['authentication-method-control', 'high', [
      'microsoft.directory/users/authenticationMethods/basic/update',
      'microsoft.directory/users/authenticationMethods/create',
      'microsoft.directory/users/authenticationMethods/delete',
      'microsoft.directory/users/password/update',
    ]],
    ['group-management', 'high', ['microsoft.directory/groups/members/update']],
  ];
  const classified = targets.filter(([, , operations]) => operations.some((operation) =>
    actions.some((action) => matchesAction(action, operation))));
  return classified.length ? {
    capabilities: classified.map(([capability]) => capability).sort(),
    severity: classified.some(([, severity]) => severity === 'critical') ? 'critical' : 'high',
  } : undefined;
}

interface MemberPath { id: string; evidence: EvidenceRef[]; depth: number }
const membershipIndexes = new WeakMap<Context, Map<string, Map<string, RecordRef[]>>>();

/** Walk observed edges once per member; incomplete inventories can prove a relationship, not its absence. */
export function groupMembers(ctx: Context, scope: string, groupId: string): MemberPath[] {
  let indexes = membershipIndexes.get(ctx);
  if (!indexes) { indexes = new Map(); membershipIndexes.set(ctx, indexes); }
  let memberships = indexes.get(scope);
  if (!memberships) {
    memberships = new Map();
    for (const membership of ctx.records('entra.groupMemberships', scope)) {
      const parent = text(membership.data.parentId)?.toLowerCase();
      if (!parent) continue;
      const children = memberships.get(parent) ?? [];
      children.push(membership);
      memberships.set(parent, children);
    }
    indexes.set(scope, memberships);
  }
  const queue: MemberPath[] = [{ id: groupId, evidence: [], depth: 0 }];
  const visited = new Set([groupId.toLowerCase()]);
  const result: MemberPath[] = [];
  let index = 0;
  while (index < queue.length) {
    const current = queue[index++]!;
    for (const membership of memberships.get(current.id.toLowerCase()) ?? []) {
      const id = membership.id;
      const path = { id, evidence: uniqueEvidence([...current.evidence, ...membership.evidence]), depth: current.depth + 1 };
      if (visited.has(id.toLowerCase())) {
        if (sameId(id, groupId)) ctx.emit(checks.cycle, scope, groupId, 'informational',
          'A cycle exists in the observed group membership edges. Traversal stops at previously visited identities; this is not proof of effective inherited privilege.',
          path.evidence);
        continue;
      }
      visited.add(id.toLowerCase());
      result.push(path);
      queue.push(path);
    }
  }
  return result;
}

function inventoryGraph(ctx: Context, scope: string): void {
  for (const [dataset, kind] of [
    ['entra.users', 'user'], ['entra.groups', 'group'], ['entra.servicePrincipals', 'servicePrincipal'],
  ] as const) {
    for (const entry of ctx.records(dataset, scope)) {
      ctx.principal(scope, entry.id, entry.evidence, kind);
      ctx.identity(scope, entry.id, !ctx.complete(dataset, scope));
    }
  }
  for (const app of ctx.records('entra.applications', scope)) {
    const appId = text(app.data.appId);
    const appNode = ctx.node('application', scope, app.id.toLowerCase(), app.evidence, appId ? { appId } : {});
    ctx.identity(scope, app.id, !ctx.complete('entra.applications', scope));
    if (!appId) { ctx.incomplete(scope, app.id); continue; }
    if (ctx.records('entra.applications', scope).filter((candidate) => sameId(text(candidate.data.appId), appId)).length !== 1) {
      ctx.incomplete(scope, app.id);
      continue;
    }
    for (const sp of ctx.records('entra.servicePrincipals', scope).filter((sp) => sameId(text(sp.data.appId), appId))) {
      const principal = ctx.principal(scope, sp.id, sp.evidence, text(sp.data.servicePrincipalType) ?? 'servicePrincipal');
      ctx.edge(appNode, principal, 'application-service-principal', [...app.evidence, ...sp.evidence]);
    }
  }
  for (const membership of ctx.records('entra.groupMemberships', scope)) {
    const groupId = text(membership.data.parentId);
    if (!groupId) continue;
    const group = ctx.principal(scope, groupId, membership.evidence, 'group');
    const member = ctx.principal(scope, membership.id, membership.evidence);
    ctx.edge(member, group, 'member-of', membership.evidence);
  }
}

function directoryAssignments(ctx: Context, scope: string): void {
  ctx.require(checks.role, scope, ['entra.directoryRoleDefinitions', 'entra.directoryRoleAssignments']);
  ctx.require(checks.eligible, scope, ['entra.directoryRoleEligibility']);
  ctx.require(checks.membership, scope, ['entra.groups', 'entra.groupMemberships']);
  for (const dataset of ['entra.directoryRoleAssignments', 'entra.directoryRoleEligibility']) {
    const eligible = dataset === 'entra.directoryRoleEligibility';
    for (const assignment of ctx.records(dataset, scope)) {
      const principalId = text(assignment.data.principalId);
      const definitionId = text(assignment.data.roleDefinitionId);
      const definition = definitionId ? ctx.find('entra.directoryRoleDefinitions', scope, definitionId) : undefined;
      if (!principalId || !definition) {
        ctx.emit(checks.unknownRole, scope, assignment.id, 'unable-to-assess',
          'The stable principal or unique role definition could not be resolved. Names are not used as privilege evidence.', assignment.evidence);
        if (principalId) ctx.incomplete(scope, principalId);
        continue;
      }
      const evidence = [...assignment.evidence, ...definition.evidence];
      const principalNode = ctx.principal(scope, principalId, assignment.evidence);
      const roleNode = ctx.node('directory-role', scope, definition.id.toLowerCase(), definition.evidence);
      ctx.edge(principalNode, roleNode, eligible ? 'eligible-directory-role' : 'assigned-directory-role',
        evidence, 'confirmed', assignment.id);
      const classification = directoryCapabilities(definition);
      if (!classification) {
        ctx.emit(checks.unknownRole, scope, assignment.id, 'unable-to-assess',
          'This role definition has no capability classified by the initial rule set. Unclassified is not low risk; manually review its exact actions.', evidence);
        ctx.incomplete(scope, principalId);
        continue;
      }
      const directoryScope = text(assignment.data.directoryScopeId);
      const condition = !directoryScope || directoryScope !== '/';
      const check = eligible ? checks.eligible : checks.role;
      ctx.emit(check, scope, assignment.id, eligible ? 'informational' : 'fail',
        `${eligible ? 'Eligibility (not an active grant)' : 'An observed current assignment'} links identity ${principalId} to documented capabilities ${classification.capabilities.join(', ')}. `
        + `Directory scope: ${directoryScope ?? 'not visible'}. `
        + (eligible ? 'Activation requirements and actual activation are not established.' : 'The assignment inventory does not establish permanence, PIM controls or successful operation.'),
        evidence, '', eligible ? 'informational' : classification.severity, condition ? 'medium' : 'high');
      ctx.addPrivilege({ principalId, tenant: scope, kind: 'directory', ...classification,
        eligible, conditional: condition, evidence, scope: directoryScope, assignmentId: assignment.id });
      for (const member of groupMembers(ctx, scope, principalId)) {
        const membershipEvidence = [...evidence, ...member.evidence];
        const nested = member.depth > 1;
        ctx.emit(checks.membership, scope, member.id, 'informational',
          `Observed ${member.depth}-hop membership links this identity to an ${eligible ? 'eligible' : 'assigned'} privileged group. `
          + (nested ? 'Nested group role inheritance is not supported for Entra role-assignable groups; this is a potential control relationship, not effective role authorization. '
            : 'Validate role-assignable group semantics and the supported member type before treating this as effective access. ')
          + 'No exploitable path is asserted.',
          membershipEvidence, assignment.id, eligible || nested ? 'informational' : classification.severity, 'medium');
        ctx.edge(ctx.principal(scope, member.id, member.evidence), roleNode,
          eligible ? 'potential-eligible-group-role' : 'potential-group-role', membershipEvidence, 'potential', assignment.id);
        ctx.incomplete(scope, member.id);
        // A nested directory-role membership is not an active grant. Keep it in the graph, not the active privilege score.
        if (!nested) ctx.addPrivilege({ principalId: member.id, tenant: scope, kind: 'directory', ...classification,
          eligible, conditional: true, evidence: membershipEvidence, scope: directoryScope, assignmentId: assignment.id });
      }
    }
  }
}

function authentication(ctx: Context, scope: string): void {
  ctx.require(checks.registration, scope, ['entra.users', 'entra.authenticationRegistration']);
  for (const user of ctx.records('entra.users', scope)) {
    if (user.data.accountEnabled === false) continue;
    const registration = ctx.find('entra.authenticationRegistration', scope, user.id);
    const evidence = [...user.evidence, ...(registration?.evidence ?? [])];
    if (user.data.accountEnabled !== true || !registration || typeof registration.data.isMfaRegistered !== 'boolean') {
      ctx.emit(checks.registration, scope, user.id, 'unable-to-assess',
        'Enabled-account state or explicit MFA registration evidence is missing. A missing registration report row is not proof of being unregistered.', evidence);
      ctx.incomplete(scope, user.id);
      continue;
    }
    const privileged = ctx.privileges.some((privilege) => privilege.tenant === scope && sameId(privilege.principalId, user.id)
      && privilege.kind === 'directory' && !privilege.eligible && severityRank[privilege.severity] >= 3);
    if (registration.data.isMfaRegistered === false) {
      ctx.emit(checks.registration, scope, user.id, 'fail',
        `The report explicitly says this enabled ${privileged ? 'privileged ' : ''}user is not MFA-registered. Registration is distinct from MFA enforcement and from exclusion/break-glass design.`,
        evidence, '', privileged ? 'high' : 'medium');
    } else if (registration.data.isMfaCapable === false) {
      ctx.emit(checks.registration, scope, user.id, 'fail',
        'A strong method is registered, but the report says the user is not MFA-capable under the authentication methods policy. This is not proof of enforcement.', evidence);
    } else {
      ctx.emit(checks.registration, scope, user.id, 'informational',
        `MFA registration is observed; MFA capability is ${registration.data.isMfaCapable === true ? 'reported' : 'not visible'}. Neither registration nor capability proves MFA is enforced.`,
        evidence, '', 'informational');
    }
  }
  const ca = ctx.records('entra.conditionalAccess', scope);
  const caComplete = ctx.require(checks.ca, scope, ['entra.conditionalAccess']);
  const enabled = ca.filter((policy) => policy.data.state === 'enabled');
  const unknownState = ca.some((policy) => !['enabled', 'disabled', 'enabledForReportingButNotEnforced'].includes(text(policy.data.state) ?? ''));
  for (const policy of ca) {
    if (policy.data.state === 'disabled' || policy.data.state === 'enabledForReportingButNotEnforced') {
      ctx.emit(checks.caState, scope, policy.id, 'fail',
        `This policy is explicitly ${String(policy.data.state)}. It does not enforce access restrictions; another policy may cover the same scenarios.`, policy.evidence);
    }
  }
  if (enabled.length) {
    ctx.emit(checks.ca, scope, scope, 'informational',
      `${enabled.length} enabled Conditional Access policy record(s) observed. Targets, exclusions, grant operators, authentication strengths and runtime conditions have not been evaluated for effective coverage.`,
      enabled.flatMap((record) => record.evidence), '', 'informational');
  } else if (caComplete && !unknownState) {
    ctx.emit(checks.ca, scope, scope, 'fail',
      'The complete Conditional Access inventory contains no enabled policy. This is not a conclusion that MFA or all access protection is absent; security defaults, other controls and licensing require separate validation.',
      ctx.inventoryEvidence('entra.conditionalAccess', scope));
  } else if (unknownState) {
    ctx.emit(checks.ca, scope, scope, 'unable-to-assess',
      'One or more policy states are missing or unrecognized; absence of an enabled policy cannot be established.', ca.flatMap((record) => record.evidence));
  }
  ctx.emit(checks.enforcement, scope, scope, 'unable-to-assess',
    'Registration and a Conditional Access policy inventory alone cannot establish effective MFA enforcement for a user or workload. No effective-coverage pass is produced.',
    [...ctx.inventoryEvidence('entra.authenticationRegistration', scope), ...ctx.inventoryEvidence('entra.conditionalAccess', scope)]);
}

function identityRisk(ctx: Context, scope: string): void {
  for (const [dataset, check] of [['entra.riskyUsers', checks.riskyUser], ['entra.riskySignIns', checks.riskySignIn]] as const) {
    ctx.require(check, scope, [dataset]);
    for (const record of ctx.records(dataset, scope)) {
      const state = text(record.data.riskState);
      const level = text(record.data.riskLevel) ?? text(record.data.riskLevelDuringSignIn);
      if (['remediated', 'dismissed', 'confirmedSafe'].includes(state ?? '')) continue;
      if (state === 'atRisk' || state === 'confirmedCompromised') {
        ctx.emit(check, scope, record.id, 'fail',
          `The risk service reports unresolved state ${state} and level ${level ?? 'not visible'}. This is an observed risk-service assessment, not an independent proof of compromise.`,
          record.evidence, '', state === 'confirmedCompromised' || level === 'high' ? 'high' : 'medium');
        const userId = dataset === 'entra.riskyUsers' ? record.id : text(record.data.userId);
        if (userId && ctx.find('entra.users', scope, userId)) {
          ctx.edge(ctx.node('risk-event', scope, `${dataset}/${record.id}`, record.evidence),
            ctx.principal(scope, userId, record.evidence), 'risk-reported-for', record.evidence);
        }
      } else if (!state || state === 'unknownFutureValue' || level === 'hidden') {
        ctx.emit(check, scope, record.id, 'unable-to-assess',
          'Risk state or visibility is insufficient to classify unresolved risk.', record.evidence);
      }
    }
  }
  ctx.require(checks.dormant, scope, ['entra.users']);
  for (const user of ctx.records('entra.users', scope)) {
    if (user.data.accountEnabled !== true) continue;
    const last = date(object(user.data.signInActivity)?.lastSuccessfulSignInDateTime);
    if (last === undefined || !Number.isFinite(ctx.now) || last > ctx.now) {
      ctx.emit(checks.dormant, scope, user.id, 'unable-to-assess',
        'A valid past lastSuccessfulSignInDateTime is unavailable. Attempted sign-ins, null history and missing dates are not fabricated into inactivity.', user.evidence);
    } else if (ctx.now - last > policyNumber(ctx.policy.dormantUserDays, 90) * DAY) {
      ctx.emit(checks.dormant, scope, user.id, 'fail',
        `The reported last successful sign-in is older than ${policyNumber(ctx.policy.dormantUserDays, 90)} days. Confirm report coverage and the identity purpose before lifecycle decisions.`, user.evidence);
    }
  }
}

export function analyzeIdentity(ctx: Context): void {
  for (const scope of ctx.scopes('entra.')) {
    inventoryGraph(ctx, scope);
    directoryAssignments(ctx, scope);
    authentication(ctx, scope);
    identityRisk(ctx, scope);
  }
}
