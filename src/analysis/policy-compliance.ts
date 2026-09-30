import {
  Context, REFERENCES as R, azureScopeKind, date, object, rule, sameId, text, withinAzureScope,
  type RecordRef,
} from './context.js';

const DATASET = 'azure.policyCompliance';
const references = [R.policyCompliance, R.policyEvaluation, R.policyEffects];
const automatedEffects = new Set([
  'addtonetworkgroup', 'append', 'audit', 'auditifnotexists', 'deny', 'denyaction',
  'deployifnotexists', 'modify', 'mutate',
]);
const checks = {
  inventory: rule('AZURE.POLICY.INVENTORY', 'azure', 'informational', 'Azure Policy evaluation inventory',
    'Collect caller-visible PolicyStates for each selected subscription. Empty/incomplete results are not a compliant estate or evidence of effective assignments.', references, ['verify-explicitly']),
  evidence: rule('AZURE.POLICY.EVIDENCE', 'azure', 'informational', 'Azure Policy evaluation context needs validation',
    'Validate exact subscription, resource, assignment/definition identifiers and historical evaluation timestamps. Do not substitute similar resource names or assume evaluation freshness.', references, ['verify-explicitly']),
  compliance: rule('AZURE.POLICY.COMPLIANCE', 'azure', 'medium', 'Last-reported Azure Policy compliance state',
    'Review the exact evaluated resource, assignment, effect and applicability. Disabled/manual effects cannot demonstrate automated compliance; audit compliance does not prove enforcement. Plan remediation separately.',
    [...references, R.policyDisabled, R.policyManual], ['verify-explicitly']),
  exemption: rule('AZURE.POLICY.EXEMPTION', 'azure', 'informational', 'Reported Azure Policy exemption requires review',
    'Validate exemption scope, owner, rationale and validity using separate exemption evidence; exempt is not protected or compliant-by-enforcement.', references, ['least-privilege', 'verify-explicitly']),
};

function path(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.startsWith('/') || /[?#\\\u0000-\u001f\u007f]/.test(value)
    || value.includes('//') || /(?:^|\/)\.{1,2}(?:\/|$)/.test(value)) return undefined;
  return value === '/' ? '/' : value.replace(/\/$/, '').toLowerCase();
}

function evaluate(ctx: Context, record: RecordRef): void {
  const properties = object(record.data.properties);
  const subscription = /^\/subscriptions\/([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})$/i.exec(record.scope)?.[1];
  const resourceId = path(properties?.resourceId);
  const assignmentId = path(properties?.policyAssignmentId);
  const assignmentScope = path(properties?.policyAssignmentScope);
  const definitionId = path(properties?.policyDefinitionId);
  const assignment = assignmentId ? /^(.*)\/providers\/microsoft\.authorization\/policyAssignments\/[^/]+$/i.exec(assignmentId) : undefined;
  const assignmentParent = assignment ? assignment[1] || '/' : undefined;
  const scopeKind = assignmentScope ? azureScopeKind(assignmentScope) : 'unknown';
  const resourceKind = resourceId ? azureScopeKind(resourceId) : 'unknown';
  if (!ctx.find(DATASET, record.scope, record.id) || !properties || !subscription
    || !sameId(text(record.data.subscriptionId), subscription) || !resourceId
    || !withinAzureScope(resourceId, record.scope) || !['subscription', 'resource-group', 'resource'].includes(resourceKind)
    || !assignmentId || !assignmentScope || !assignmentParent || !sameId(assignmentParent, assignmentScope)
    || scopeKind === 'unknown' || (scopeKind !== 'management-group' && !withinAzureScope(resourceId, assignmentScope))
    || !definitionId || !/\/providers\/microsoft\.authorization\/policyDefinitions\/[^/]+(?:\/versions\/[^/]+)?$/i.test(definitionId)) {
    ctx.emit(checks.evidence, record.scope, record.id, 'unable-to-assess',
      'The evaluation is ambiguous or lacks consistent selected-subscription, resource, assignment-scope/ID and definition-ID bindings. Cross-subscription resource records and name-only matches are not classified or correlated.',
      record.evidence);
    return;
  }
  const evaluatedAt = date(properties.timestamp);
  const sourceTimes = ctx.collections.filter((source) => source.id === DATASET && source.scope === record.scope
    && (source.status === 'complete' || source.status === 'partial')).map((source) => date(source.collectedAt));
  if (evaluatedAt === undefined || !Number.isFinite(ctx.now) || evaluatedAt > ctx.now || !sourceTimes.length
    || sourceTimes.some((time) => time === undefined || evaluatedAt > time)) {
    ctx.emit(checks.evidence, record.scope, record.id, 'unable-to-assess',
      'The last-evaluated timestamp is missing, malformed or later than collection/assessment time. No current compliance, freshness or historical evaluation date is fabricated.',
      [...record.evidence, ...ctx.evidenceFor(record, 'properties.timestamp')]);
    return;
  }
  const state = text(properties.complianceState);
  const observation = ctx.node('azure-policy-observation', record.scope, record.id, record.evidence,
    { evaluatedResourceId: resourceId, policyAssignmentId: assignmentId, evaluationState: state ?? 'not-visible',
      evaluatedAt: new Date(evaluatedAt).toISOString() });
  const assignmentNode = ctx.node('azure-policy-assignment', record.scope, assignmentId, record.evidence,
    { assignmentScope, configurationObserved: false });
  ctx.edge(observation, assignmentNode, 'evaluated-policy-assignment', record.evidence);
  const resource = ctx.find('azure.resources', record.scope, resourceId);
  if (resource && (!text(resource.data.subscriptionId) || sameId(text(resource.data.subscriptionId), subscription))) {
    ctx.edge(observation, ctx.node('azure-resource', resource.scope, resource.id.toLowerCase(), resource.evidence),
      'policy-evaluation-for-resource', [...record.evidence, ...resource.evidence]);
  }
  const context = `PolicyStates last reported ${state ?? 'an unrecognized state'} at ${new Date(evaluatedAt).toISOString()} `
    + `for resource ${resourceId} under assignment ${assignmentId}. `
    + 'This is a last-evaluated observation, not real-time posture, effect enforcement, full assignment configuration or all-policy compliance.';
  if (state === 'NonCompliant') {
    ctx.emit(checks.compliance, record.scope, record.id, 'fail', context, record.evidence);
  } else if (state === 'Compliant') {
    const effect = text(properties.policyDefinitionAction)?.toLowerCase();
    const evidence = [...record.evidence, ...ctx.evidenceFor(record, 'properties.policyDefinitionAction')];
    if (effect === 'disabled') {
      ctx.emit(checks.compliance, record.scope, record.id, 'informational',
        `${context} The explicitly disabled effect defaults resources to Compliant without establishing the policy condition is satisfied. This requires review, not a passing recheck or evidence of remediation.`, evidence, '', 'informational');
    } else if (effect === 'manual') {
      ctx.emit(checks.compliance, record.scope, record.id, 'informational',
        `${context} The manual effect uses a default state or manual attestation, not an automated configuration scan. No attestation, supporting evidence or control effectiveness is established here; this is review information, not a passing recheck.`, evidence, '', 'informational');
    } else if (!effect || !automatedEffects.has(effect)) {
      ctx.emit(checks.compliance, record.scope, record.id, 'unable-to-assess',
        `${context} policyDefinitionAction is missing, null or not a recognized documented effect. A reported Compliant state cannot establish an automated compliant pass without its effect context.`, evidence);
    } else {
      const auditBoundary = effect === 'audit' || effect === 'auditifnotexists'
        ? ' Audit effects report evaluation results but do not block resource operations; no preventive-control effectiveness is inferred.' : '';
      ctx.emit(checks.compliance, record.scope, record.id, ctx.complete(DATASET, record.scope) ? 'pass' : 'informational',
        `${context} ${ctx.complete(DATASET, record.scope)
          ? 'The limited pass concerns only this dated resource/assignment evaluation under a recognized automated effect.'
          : 'Collection coverage is incomplete; this observed row is not a compliance pass.'}${auditBoundary}`,
        evidence, '', 'informational');
    }
  } else if (state === 'Exempt') {
    ctx.emit(checks.exemption, record.scope, record.id, 'informational',
      `${context} Exempt is an exception needing review, not a protected-state or enforcement pass. No exemption rationale or expiry is inferred.`, record.evidence);
  } else {
    ctx.emit(checks.compliance, record.scope, record.id, 'unable-to-assess',
      `${context} ${state === 'Conflict' ? 'A reported Conflict needs evaluation-resolution review.' : 'Missing or future/unrecognized states are not interpreted as compliant.'}`, record.evidence);
  }
}

export function analyzePolicyCompliance(ctx: Context): void {
  for (const scope of ctx.scopes(DATASET)) {
    const complete = ctx.require(checks.inventory, scope, [DATASET]);
    const records = ctx.records(DATASET, scope);
    if (complete && !records.length) ctx.emit(checks.inventory, scope, scope, 'unable-to-assess',
      'The complete caller-visible PolicyStates inventory has no records. It does not prove compliance, policy applicability or protection; evaluation/visibility/assignment context requires review.',
      ctx.inventoryEvidence(DATASET, scope), 'empty');
    for (const record of records) evaluate(ctx, record);
  }
}
