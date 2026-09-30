import type { EvidenceRef } from '../model.js';
import {
  Context, REFERENCES as R, date, has, rule, sameId, text, type RecordRef,
} from './context.js';
import { directoryCapabilities } from './identity.js';

const DATASET = 'entra.directoryRoleAssignmentScheduleInstances';
const references = [R.roleSchedules, R.roleSchedulesList, R.roles];
const checks = {
  inventory: rule('ENTRA.ROLE.SCHEDULE.INVENTORY', 'entra', 'informational', 'Directory assignment lifetime evidence',
    'Collect assignment schedule instances and exact role definitions. Ordinary role assignments and eligibility do not establish assignment lifetime.', references),
  evidence: rule('ENTRA.ROLE.SCHEDULE.EVIDENCE', 'entra', 'informational', 'Directory assignment schedule needs validation',
    'Resolve exact principal/role/scope IDs, assignment semantics and explicit start/end metadata before classifying activation or permanence.', references, ['verify-explicitly']),
  permanent: rule('ENTRA.ROLE.SCHEDULE.PERMANENT', 'entra', 'high', 'Persistent active privileged directory assignment',
    'Review whether this direct, nonexpiring assignment needs permanent access; consider appropriately scoped, time-bound/PIM access without automatically changing the assignment.', [...references, R.pim]),
  timeBound: rule('ENTRA.ROLE.SCHEDULE.TIME_BOUND', 'entra', 'informational', 'Time-bound active directory assignment',
    'Review the role capability, assigned interval and continuing business need. A finite end date is not evidence that all PIM or access controls are effective.', references),
  activated: rule('ENTRA.ROLE.SCHEDULE.ACTIVATED', 'entra', 'informational', 'Activated privileged directory assignment',
    'Review the activation duration and supporting approval/authentication controls. This active instance is distinct from merely being eligible.', [...references, R.pim]),
  inactive: rule('ENTRA.ROLE.SCHEDULE.INACTIVE', 'entra', 'informational', 'Directory role schedule is outside its active interval',
    'Review future or historical assignments as lifecycle metadata; no active privilege is inferred from an inactive schedule.', references),
  indirect: rule('ENTRA.ROLE.SCHEDULE.INDIRECT', 'entra', 'informational', 'Group or inherited assignment schedule',
    'Validate the inheritance path and scope using separate membership and assignment evidence. Do not treat this as a direct, permanently active grant.', references),
};

function unknown(ctx: Context, instance: RecordRef, description: string, evidence: EvidenceRef[] = instance.evidence): void {
  ctx.emit(checks.evidence, instance.scope, instance.id, 'unable-to-assess', description, evidence);
  const principalId = text(instance.data.principalId);
  if (principalId) ctx.incomplete(instance.scope, principalId);
}

function analyzeInstance(ctx: Context, instance: RecordRef): void {
  const scope = instance.scope;
  const principalId = text(instance.data.principalId);
  const definitionId = text(instance.data.roleDefinitionId);
  const definition = definitionId ? ctx.find('entra.directoryRoleDefinitions', scope, definitionId) : undefined;
  if (!ctx.find(DATASET, scope, instance.id) || !principalId || !definition) {
    unknown(ctx, instance, 'The schedule instance, principal ID or exact role definition is missing or ambiguous. Names and schedule presence cannot establish privileged lifetime.');
    return;
  }
  const classification = directoryCapabilities(definition);
  const evidence = [...instance.evidence, ...definition.evidence];
  if (!classification) {
    unknown(ctx, instance, 'The role has no capability classified by the documented template/action rules. An unclassified role is not assumed harmless or privileged based on its name.', evidence);
    return;
  }
  const assignmentType = text(instance.data.assignmentType);
  const memberType = text(instance.data.memberType);
  if (!['Assigned', 'Activated'].includes(assignmentType ?? '') || !['Direct', 'Group', 'Inherited'].includes(memberType ?? '')) {
    unknown(ctx, instance, 'Assignment/member type is missing or unrecognized. Assigned, Activated and inherited/group semantics cannot be substituted for each other.', evidence);
    return;
  }
  if (instance.data.directoryScopeId !== '/' || instance.data.appScopeId !== null) {
    unknown(ctx, instance, 'A tenant-wide directoryScopeId "/" and explicit null appScopeId are not both visible. Application/administrative-unit/unusual scopes require contextual review; no tenant-wide or permanent privilege is inferred.', evidence);
    return;
  }
  const originId = text(instance.data.roleAssignmentOriginId);
  const origin = originId ? ctx.find('entra.directoryRoleAssignments', scope, originId) : undefined;
  const originMatches = !!origin && sameId(text(origin.data.principalId), principalId)
    && sameId(text(origin.data.roleDefinitionId), definitionId) && origin.data.directoryScopeId === '/'
    && (origin.data.appScopeId === null || !has(origin.data, 'appScopeId'));
  if (origin && memberType === 'Direct' && !originMatches) {
    unknown(ctx, instance, 'The stated origin assignment resolves to conflicting principal, role or scope identifiers. This schedule is not used to infer direct active control.', [...evidence, ...origin.evidence]);
    return;
  }
  if (originMatches) evidence.push(...origin!.evidence);
  const start = date(instance.data.startDateTime);
  // Native legacy assignment instances can have a null start. A matching current assignment
  // provides activity evidence, but never a fabricated creation date or credential-style age.
  const witnessedNullStart = instance.data.startDateTime === null && originMatches
    && assignmentType === 'Assigned' && memberType === 'Direct';
  const endIsNull = instance.data.endDateTime === null;
  const end = date(instance.data.endDateTime);
  if (!Number.isFinite(ctx.now) || (start === undefined && !witnessedNullStart) || !has(instance.data, 'endDateTime')
    || (!endIsNull && (end === undefined || (start !== undefined && end <= start)))) {
    unknown(ctx, instance, 'Valid lifetime metadata is insufficient: start/end is missing, malformed or reversed. Only explicit null end means no scheduled expiration. A null start needs an exact matching current direct Assigned origin; an omitted date is never substituted.', evidence);
    return;
  }
  const future = start !== undefined && start > ctx.now;
  const expired = !endIsNull && end! <= ctx.now;
  const state = future ? 'future' : expired ? 'expired' : 'active';
  const principal = ctx.principal(scope, principalId, instance.evidence);
  const role = ctx.node('directory-role', scope, definition.id.toLowerCase(), definition.evidence);
  const schedule = ctx.node('directory-role-schedule-instance', scope, instance.id, instance.evidence,
    { assignmentType: assignmentType!, memberType: memberType!, lifecycleState: state,
      startDateTime: instance.data.startDateTime!, endDateTime: instance.data.endDateTime! });
  ctx.edge(principal, schedule, 'has-role-assignment-schedule', instance.evidence);
  ctx.edge(schedule, role, 'schedule-role-definition', evidence);
  if (originMatches) ctx.edge(schedule, ctx.node('directory-role-assignment', scope, origin!.id, origin!.evidence),
    'schedule-origin-assignment', [...instance.evidence, ...origin!.evidence]);
  ctx.identity(scope, principalId, !ctx.complete(DATASET, scope) || !ctx.complete('entra.directoryRoleDefinitions', scope));
  if (future || expired) {
    ctx.emit(checks.inactive, scope, instance.id, 'informational',
      `This privileged role schedule is ${state} at the assessment timestamp. Its documented interval does not contribute an active privilege score; other independent assignments may still exist.`, evidence);
    return;
  }
  if (memberType !== 'Direct') {
    ctx.emit(checks.indirect, scope, instance.id, 'informational',
      `This active schedule reports memberType=${memberType} and assignmentType=${assignmentType}. It is retained as an indirect relationship, not classified as a direct permanent grant or added as independent direct privilege.`, evidence);
    ctx.edge(principal, role, 'potential-indirect-scheduled-role', evidence, 'potential', instance.id);
    ctx.incomplete(scope, principalId);
    return;
  }
  if (assignmentType === 'Activated' && endIsNull) {
    unknown(ctx, instance, 'The schedule reports Activated with an explicit null end. It is not relabeled as a permanent Assigned grant; activation bounds need manual validation.', evidence);
    return;
  }
  const capabilities = classification.capabilities.join(', ');
  if (assignmentType === 'Activated') {
    ctx.emit(checks.activated, scope, instance.id, 'informational',
      `A direct active activation with a finite end date is observed for capability ${capabilities}. This is an activated assignment instance, not mere eligibility. Approval, MFA and successful authorization are not established.`, evidence);
  } else if (endIsNull) {
    ctx.emit(checks.permanent, scope, instance.id, 'fail',
      `A direct active Assigned instance has explicit null endDateTime (no scheduled expiration) for capability ${capabilities}. `
      + (witnessedNullStart ? 'Its explicit null start is corroborated by the matching current origin assignment; no start/creation time is invented. '
        : 'The validity start is at or before the assessment timestamp. ')
      + 'This documents a persistent assignment, not successful use, an exploitable path or permanence inferred from an ordinary assignment alone.',
      evidence, '', classification.severity);
  } else {
    ctx.emit(checks.timeBound, scope, instance.id, 'informational',
      `A direct active Assigned instance has a finite expiration for capability ${capabilities}. It is time-bound assignment, not an eligibility activation or proof of complete PIM controls.`, evidence);
  }
  ctx.edge(principal, role, 'active-scheduled-directory-role', evidence, 'potential', instance.id);
  ctx.addPrivilege({ principalId, tenant: scope, kind: 'directory', ...classification,
    evidence, scope: '/', assignmentId: originMatches ? origin!.id : instance.id });
}

export function analyzeRoleSchedules(ctx: Context): void {
  for (const scope of ctx.scopes(DATASET, 'entra.directoryRoleAssignments')) {
    ctx.require(checks.inventory, scope, [DATASET, 'entra.directoryRoleDefinitions']);
    const instances = ctx.records(DATASET, scope);
    if (!instances.length && ctx.complete(DATASET, scope)) ctx.emit(checks.inventory, scope, scope, 'informational',
      'The complete caller-visible schedule-instance inventory is empty. This is not proof that all assignments are temporary, no privileged identities exist, or other role sources are fully covered.',
      ctx.inventoryEvidence(DATASET, scope), 'empty');
    for (const instance of instances) analyzeInstance(ctx, instance);
  }
}
