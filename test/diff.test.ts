import assert from 'node:assert/strict';
import test from 'node:test';
import { compareSnapshots } from '../src/diff.js';
import { createAssessment } from '../src/engine.js';
import type { JsonObject } from '../src/model.js';
import { collection, finding, input, scope, snapshot, subscription } from './support.js';

test('identical evidence and reordering do not create spurious changes', () => {
  const before = snapshot([collection('entra.users', [{ id: 'a', groups: ['g1', 'g2'] }, { id: 'b' }])]);
  const after = snapshot([collection('entra.users', [{ id: 'b' }, { id: 'a', groups: ['g2', 'g1'] }])]);
  assert.deepEqual(compareSnapshots(before, after).changes, []);
});

test('new and removed records require completeness of the relevant inventory', () => {
  const before = snapshot([collection('entra.users', [{ id: 'old' }])]);
  const after = snapshot([collection('entra.users', [{ id: 'new' }])]);
  assert.deepEqual(compareSnapshots(before, after).changes.map(item => item.kind).sort(), ['added', 'removed']);
  after.collections[0]!.status = 'partial';
  after.collections[0]!.reason = 'limit-reached';
  const changes = compareSnapshots(before, after).changes;
  assert.equal(changes.find(item => item.recordId === 'old')?.kind, 'indeterminate');
  assert.equal(changes.find(item => item.recordId === 'new')?.kind, 'added');
  before.collections[0]!.status = 'partial';
  before.collections[0]!.reason = 'permission-denied';
  assert.equal(compareSnapshots(before, after).changes.find(item => item.recordId === 'new')?.kind, 'indeterminate');
});

test('denied collection is not a deletion and does not imply successful remediation', () => {
  const before = snapshot([collection('entra.users', [{ id: 'u1' }])], [finding()]);
  const after = snapshot([collection('entra.users', [], { status: 'unavailable', reason: 'permission-denied' })]);
  const result = compareSnapshots(before, after);
  assert.equal(result.changes.find(item => item.recordId === 'u1')?.kind, 'indeterminate');
  assert.deepEqual(result.findings.resolved, []);
  assert.deepEqual(result.findings.indeterminate, ['finding-1']);
});

test('finding resolution requires explicit comparable passing evidence', () => {
  const before = snapshot([collection()], [finding()]);
  const after = snapshot([collection()], [finding({ status: 'pass' })]);
  assert.deepEqual(compareSnapshots(before, after).findings.resolved, ['finding-1']);
  after.policy.maxOwners++;
  assert.deepEqual(compareSnapshots(before, after).findings.resolved, []);
  assert.deepEqual(compareSnapshots(before, after).findings.indeterminate, ['finding-1']);
});

test('distinct findings for the same check and resource cannot hide one another', () => {
  const previous = snapshot([collection()], [finding({ id: 'first' }), finding({ id: 'second' })]);
  const current = snapshot([collection()], [finding({ id: 'first', status: 'pass' }), finding({ id: 'second' })]);
  const result = compareSnapshots(previous, current);
  assert.deepEqual(result.findings.resolved, ['first']);
  assert.deepEqual(result.findings.persistent, ['second']);
});

test('scope and time changes cannot masquerade as deleted access', () => {
  const before = snapshot();
  const after = snapshot();
  after.scope = { ...scope, subscriptionIds: [] };
  assert.throws(() => compareSnapshots(before, after), /same tenant/);
  after.scope = scope;
  after.collectedAt = '2026-08-31T12:00:00.000Z';
  after.collections[0]!.collectedAt = after.collectedAt;
  assert.throws(() => compareSnapshots(before, after), /newer/);
});

test('new privileges and credential metadata are explained as potential, not malicious', () => {
  const previous = snapshot([
    collection('entra.directoryRoleAssignments'), collection('entra.applications', [{ id: 'a', passwordCredentials: [] }]),
  ]);
  const current = snapshot([
    collection('entra.directoryRoleAssignments', [{ id: 'assignment', principalId: 'sp' }]),
    collection('entra.applications', [{ id: 'a', passwordCredentials: [{ keyId: 'metadata-key-only' }] }]),
  ]);
  const result = compareSnapshots(previous, current);
  assert.ok(result.changes.every(item => item.securityImpact === 'potential-increase'));
  assert.ok(result.caveat.includes('not evidence of malicious intent'));
});

test('missing fields and changed collector version yield indeterminate metadata changes', () => {
  const before = snapshot([collection('entra.users', [{ id: 'a', accountEnabled: true }])]);
  const after = snapshot([collection('entra.users', [{ id: 'a' }])]);
  assert.equal(compareSnapshots(before, after).changes[0]?.kind, 'indeterminate');
  after.collections[0]!.records = [{ id: 'a', accountEnabled: false }];
  after.toolVersion = '0.2.0';
  assert.equal(compareSnapshots(before, after).changes[0]?.kind, 'indeterminate');
});

test('null is not an omitted field and owner changes retain their parent identity', () => {
  const before = snapshot([collection('entra.users', [{ id: 'a', nullable: null }])]);
  const after = snapshot([collection('entra.users', [{ id: 'a' }])]);
  assert.equal(compareSnapshots(before, after).changes[0]?.kind, 'indeterminate');
  const empty = snapshot([collection('entra.applicationOwners')]);
  const owned = snapshot([collection('entra.applicationOwners', [{ id: 'owner', parentId: 'application' }])]);
  assert.equal(compareSnapshots(empty, owned).changes[0]?.parentId, 'application');
});

test('control transitions preserve mixed-change uncertainty', () => {
  const before = snapshot([collection('entra.conditionalAccess', [{ id: 'ca', state: 'disabled' }])]);
  const after = snapshot([collection('entra.conditionalAccess', [{ id: 'ca', state: 'enabled' }])]);
  assert.equal(compareSnapshots(before, after).changes[0]?.securityImpact, 'potential-decrease');
  before.collections[0]!.records = [{ id: 'ca', a: { state: 'disabled' }, b: { state: 'enabled' } }];
  after.collections[0]!.records = [{ id: 'ca', a: { state: 'enabled' }, b: { state: 'disabled' } }];
  assert.equal(compareSnapshots(before, after).changes[0]?.securityImpact, 'review-required');
});

test('Azure assignment additions and comparable scope expansions show potential increased privilege', () => {
  const collectionScope = `/subscriptions/${subscription}`;
  const properties = { principalId: 'sp', roleDefinitionId: 'role', scope: `${collectionScope}/resourceGroups/limited`, condition: null };
  const empty = snapshot([collection('azure.roleAssignments', [], { provider: 'azure', scope: collectionScope })]);
  const before = snapshot([collection('azure.roleAssignments', [{ id: 'assignment', properties }], { provider: 'azure', scope: collectionScope })]);
  const after = snapshot([collection('azure.roleAssignments', [{ id: 'assignment', properties: { ...properties, scope: collectionScope } }], { provider: 'azure', scope: collectionScope })]);
  assert.equal(compareSnapshots(empty, before).changes[0]?.securityImpact, 'potential-increase');
  assert.equal(compareSnapshots(before, after).changes[0]?.securityImpact, 'potential-increase');
  assert.equal(compareSnapshots(after, before).changes[0]?.securityImpact, 'potential-decrease');
  after.collections[0]!.records = [{ id: 'assignment', properties: { ...properties, scope: collectionScope, principalId: 'different' } }];
  assert.equal(compareSnapshots(before, after).changes[0]?.securityImpact, 'review-required');
});

test('a real HTTPS check transition is reported as resolved only after an explicit passing recheck', () => {
  const evidence = (enabled: boolean) => input([collection('azure.resources', [{
    id: `/subscriptions/${subscription}/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/example`,
    subscriptionId: subscription, type: 'microsoft.storage/storageaccounts',
    properties: { supportsHttpsTrafficOnly: enabled },
  }], { provider: 'azure', scope: `/subscriptions/${subscription}` })]);
  const before = createAssessment(evidence(false));
  const after = createAssessment(evidence(true));
  const risk = before.findings.find(item => item.checkId === 'AZURE.STORAGE.HTTPS');
  assert.ok(risk);
  assert.equal(risk.status, 'fail');
  assert.equal(after.findings.find(item => item.id === risk.id)?.status, 'pass');
  const diff = compareSnapshots(before, after);
  assert.deepEqual(diff.findings.resolved, [risk.id]);
  assert.equal(diff.changes[0]?.securityImpact, 'potential-decrease');
});

function policyEvaluation(state: string, patch: JsonObject = {}) {
  return snapshot([collection('azure.policyCompliance', [{
    id: 'policy-state', subscriptionId: subscription,
    properties: {
      resourceId: `/subscriptions/${subscription}/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/example`,
      policyAssignmentId: `/subscriptions/${subscription}/providers/Microsoft.Authorization/policyAssignments/example`,
      policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/example',
      policyDefinitionAction: 'audit', complianceState: state,
      timestamp: '2026-09-01T10:00:00Z', ...patch,
    },
  }], { provider: 'azure', scope: `/subscriptions/${subscription}` })]);
}

test('refreshing an otherwise identical valid policy evaluation does not manufacture posture changes', () => {
  const before = policyEvaluation('NonCompliant');
  const after = policyEvaluation('NonCompliant', { timestamp: '2026-09-01T11:00:00Z' });
  before.collections[0]!.records[0]!.sourceId = 'provider-observation-one';
  after.collections[0]!.records[0]!.sourceId = 'provider-observation-two';
  assert.deepEqual(compareSnapshots(before, after).changes, []);
});

test('policy compliance improvement is limited to comparable evaluated records, never exemptions', () => {
  const before = policyEvaluation('NonCompliant');
  const after = policyEvaluation('Compliant', { timestamp: '2026-09-01T11:00:00Z' });
  const change = compareSnapshots(before, after).changes[0];
  assert.equal(change?.kind, 'changed');
  assert.equal(change?.securityImpact, 'potential-decrease');
  assert.match(change?.description ?? '', /not real-time proof/);
  assert.equal(compareSnapshots(after, policyEvaluation('NonCompliant', { timestamp: '2026-09-01T11:30:00Z' })).changes[0]?.securityImpact, 'potential-increase');
  assert.equal(compareSnapshots(before, policyEvaluation('Exempt')).changes[0]?.securityImpact, 'review-required');
  assert.equal(compareSnapshots(policyEvaluation('NonCompliant', { policyDefinitionAction: 'disabled' }),
    policyEvaluation('Compliant', { policyDefinitionAction: 'disabled' })).changes[0]?.securityImpact, 'review-required');
});

test('invalid, future, missing, regressing or rebound policy evidence is indeterminate', () => {
  const before = policyEvaluation('NonCompliant');
  const cases: JsonObject[] = [
    { timestamp: '2026-02-31T00:00:00Z' },
    { timestamp: '2026-09-02T00:00:00Z' },
    { timestamp: null },
    { timestamp: '2026-09-01T09:00:00Z' },
    { policyAssignmentId: '/providers/Microsoft.Management/managementGroups/other/providers/Microsoft.Authorization/policyAssignments/other' },
  ];
  for (const patch of cases) {
    const after = policyEvaluation('Compliant', patch);
    const change = compareSnapshots(before, after).changes[0];
    assert.equal(change?.kind, 'indeterminate');
    assert.equal(change?.securityImpact, 'unknown');
  }
});

test('SharePoint changes reflect documented sharing ceilings and conflicting changes remain reviewable', () => {
  const settings = (properties: JsonObject) => snapshot([collection('m365.sharePointSettings', [{ id: 'sharepoint-settings', ...properties }])]);
  const before = settings({ sharingCapability: 'existingExternalUserSharingOnly', isLegacyAuthProtocolsEnabled: true });
  const relaxed = settings({ sharingCapability: 'externalUserAndGuestSharing', isLegacyAuthProtocolsEnabled: true });
  assert.equal(compareSnapshots(before, relaxed).changes[0]?.securityImpact, 'potential-increase');
  const mixed = settings({ sharingCapability: 'externalUserAndGuestSharing', isLegacyAuthProtocolsEnabled: false });
  assert.equal(compareSnapshots(before, mixed).changes[0]?.securityImpact, 'review-required');
  const disabledBefore = settings({ sharingCapability: 'disabled', isResharingByExternalUsersEnabled: false });
  const disabledAfter = settings({ sharingCapability: 'disabled', isResharingByExternalUsersEnabled: true });
  assert.equal(compareSnapshots(disabledBefore, disabledAfter).changes[0]?.securityImpact, 'review-required');
});
