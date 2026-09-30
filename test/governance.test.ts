import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze } from '../src/analysis.js';
import { createAssessment } from '../src/engine.js';
import { compareSnapshots } from '../src/diff.js';
import { DEFAULT_POLICY } from '../src/policy.js';
import { parseSnapshot } from '../src/validation.js';
import type { AnalysisResult, CollectionResult, Finding, JsonObject } from '../src/model.js';

const TENANT = '11111111-1111-4111-8111-111111111111';
const SUB_ID = '22222222-2222-4222-8222-222222222222';
const SUB = `/subscriptions/${SUB_ID}`;
const OTHER_SUB = '/subscriptions/33333333-3333-4333-8333-333333333333';
const NOW = new Date('2026-09-29T12:00:00Z');
const SHAREPOINT = 'm365.sharePointSettings';
const SCHEDULES = 'entra.directoryRoleAssignmentScheduleInstances';
const POLICY = 'azure.policyCompliance';
const RESOURCE = `${SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account`;
const ASSIGNMENT = `${SUB}/providers/Microsoft.Authorization/policyAssignments/assignment-a`;
const DEFINITION = '/providers/Microsoft.Authorization/policyDefinitions/definition-a';

function collection(id: string, records: JsonObject[] = [], scope = TENANT,
  status: CollectionResult['status'] = 'complete'): CollectionResult {
  return { id, records, scope, provider: id.startsWith('azure.') ? 'azure' : 'graph', status, collectedAt: NOW.toISOString(),
    ...(status === 'complete' ? {} : { reason: status === 'partial' ? 'limit-reached' : 'dependency-unavailable' }) };
}
function run(collections: CollectionResult[]): AnalysisResult { return analyze(collections, DEFAULT_POLICY, NOW); }
function findings(result: AnalysisResult, checkId: string, status?: Finding['status']): Finding[] {
  return result.findings.filter((finding) => finding.checkId === checkId && (!status || finding.status === status));
}
function omit(data: JsonObject, ...keys: string[]): JsonObject {
  const result = { ...data };
  for (const key of keys) delete result[key];
  return result;
}
function sharePoint(overrides: JsonObject = {}): JsonObject {
  return { id: 'sharepoint-settings', isLegacyAuthProtocolsEnabled: false,
    sharingCapability: 'externalUserSharingOnly', isRequireAcceptingUserToMatchInvitedUserEnabled: true,
    isResharingByExternalUsersEnabled: false, isUnmanagedSyncAppForTenantRestricted: true,
    sharingDomainRestrictionMode: 'allowList', sharingAllowedDomainList: ['example.test'],
    idleSessionSignOut: { isEnabled: true, signOutAfterInSeconds: 900, warnAfterInSeconds: 300 }, ...overrides };
}
function schedule(overrides: JsonObject = {}): JsonObject {
  return { id: 'schedule-a', principalId: 'principal-a', roleDefinitionId: 'role-a', directoryScopeId: '/', appScopeId: null,
    assignmentType: 'Assigned', memberType: 'Direct', startDateTime: '2026-09-01T00:00:00Z', endDateTime: null,
    roleAssignmentOriginId: 'assignment-a', roleAssignmentScheduleId: 'schedule-definition-a', ...overrides };
}
function identityInputs(instances: JsonObject[] = [schedule()], status: CollectionResult['status'] = 'complete'): CollectionResult[] {
  return [
    collection('entra.servicePrincipals', [{ id: 'principal-a', appId: 'client-a', displayName: 'Workload identity',
      servicePrincipalType: 'Application', passwordCredentials: [], keyCredentials: [] }]),
    collection('entra.directoryRoleDefinitions', [{ id: 'role-a', templateId: '62e90394-69f5-4237-9190-012177145e10',
      displayName: 'Unimportant display label' }]),
    collection(SCHEDULES, instances, TENANT, status),
  ];
}
function ordinaryAssignment(overrides: JsonObject = {}): JsonObject {
  return { id: 'assignment-a', principalId: 'principal-a', roleDefinitionId: 'role-a', directoryScopeId: '/', appScopeId: null, ...overrides };
}
function policyRecord(properties: JsonObject = {}, top: JsonObject = {}): JsonObject {
  return { id: 'policy-state-a', subscriptionId: SUB_ID, properties: {
    resourceId: RESOURCE, policyAssignmentId: ASSIGNMENT, policyAssignmentName: 'Arbitrary display label',
    policyAssignmentScope: SUB, policyDefinitionId: DEFINITION, policyDefinitionReferenceId: '',
    policySetDefinitionId: '', policyDefinitionAction: 'audit', complianceState: 'NonCompliant',
    timestamp: '2026-09-28T12:00:00Z', ...properties,
  }, ...top };
}
function azureResource(id = RESOURCE): JsonObject {
  return { id, type: 'Microsoft.Storage/storageAccounts', name: 'account', subscriptionId: SUB_ID };
}
function identityRisk(result: AnalysisResult) {
  const identity = result.identityRisks.find((entry) => entry.identityId === `${TENANT}/principal-a`);
  assert.ok(identity);
  return identity;
}
function snapshot(collections: CollectionResult[], result = run(collections)) {
  return parseSnapshot({ kind: 'cloud-security-assessment', schemaVersion: '1.0', toolVersion: '0.1.0',
    assessmentId: 'governance-test', scope: { tenantId: TENANT, subscriptionIds: [SUB_ID],
      githubOrganizations: [], azureDevOpsOrganizations: [] }, collectedAt: NOW.toISOString(),
    collections, policy: DEFAULT_POLICY, coverage: [], ...result });
}

test('SharePoint explicit legacy enablement is a high-risk configuration, not proof of bypass', () => {
  const result = run([collection(SHAREPOINT, [sharePoint({ isLegacyAuthProtocolsEnabled: true })])]);
  const finding = findings(result, 'M365.SHAREPOINT.LEGACY_AUTH', 'fail')[0]!;
  assert.equal(finding.severity, 'high');
  assert.match(finding.description, /does not prove.*bypass/);
  assert.ok(finding.evidence.some((ref) => ref.recordId === 'sharepoint-settings' && ref.field === 'isLegacyAuthProtocolsEnabled'));
});

test('SharePoint missing, null and nonboolean values never become false or a pass', () => {
  const controls = [
    ['isLegacyAuthProtocolsEnabled', 'M365.SHAREPOINT.LEGACY_AUTH'],
    ['isRequireAcceptingUserToMatchInvitedUserEnabled', 'M365.SHAREPOINT.INVITATION_IDENTITY'],
    ['isResharingByExternalUsersEnabled', 'M365.SHAREPOINT.EXTERNAL_RESHARING'],
    ['isUnmanagedSyncAppForTenantRestricted', 'M365.SHAREPOINT.UNMANAGED_SYNC'],
  ] as const;
  for (const [field, checkId] of controls) {
    const cases = [omit(sharePoint(), field), sharePoint({ [field]: null }), sharePoint({ [field]: 'false' })];
    for (const settings of cases) {
      const result = run([collection(SHAREPOINT, [settings])]);
      assert.equal(findings(result, checkId, 'unable-to-assess').length, 1, field);
      assert.equal(findings(result, checkId, 'pass').length, 0);
    }
  }
});

test('anonymous SharePoint ceiling identifies potential exposure without asserting shared files', () => {
  const result = run([collection(SHAREPOINT, [sharePoint({ sharingCapability: 'externalUserAndGuestSharing' })])]);
  const finding = findings(result, 'M365.SHAREPOINT.ANONYMOUS_LINKS', 'fail')[0]!;
  assert.equal(finding.severity, 'medium');
  assert.match(finding.description, /no publicly shared content is observed/);
  assert.match(finding.description, /tenant-level ceilings/);
});

test('disabled external sharing does not trigger invitation, resharing or domain failures', () => {
  const result = run([collection(SHAREPOINT, [sharePoint({ sharingCapability: 'disabled',
    isRequireAcceptingUserToMatchInvitedUserEnabled: false, isResharingByExternalUsersEnabled: true,
    sharingDomainRestrictionMode: 'none' })])]);
  for (const id of ['M365.SHAREPOINT.INVITATION_IDENTITY', 'M365.SHAREPOINT.EXTERNAL_RESHARING', 'M365.SHAREPOINT.DOMAIN_RESTRICTIONS']) {
    assert.equal(findings(result, id, 'fail').length, 0);
    assert.equal(findings(result, id, 'informational').length, 1);
  }
  assert.equal(findings(result, 'M365.SHAREPOINT.ANONYMOUS_LINKS', 'pass').length, 1);
});

test('sharing controls are evaluated only with a known external-sharing state', () => {
  for (const state of ['externalUserSharingOnly', 'externalUserAndGuestSharing', 'existingExternalUserSharingOnly']) {
    const result = run([collection(SHAREPOINT, [sharePoint({ sharingCapability: state,
      isRequireAcceptingUserToMatchInvitedUserEnabled: false, isResharingByExternalUsersEnabled: true })])]);
    assert.equal(findings(result, 'M365.SHAREPOINT.INVITATION_IDENTITY', 'fail').length, 1);
    assert.equal(findings(result, 'M365.SHAREPOINT.EXTERNAL_RESHARING', 'fail').length, 1);
  }
  for (const settings of [sharePoint({ sharingCapability: 'unknownFutureValue' }), sharePoint({ sharingCapability: null }),
    omit(sharePoint(), 'sharingCapability')]) {
    const result = run([collection(SHAREPOINT, [settings])]);
    for (const id of ['M365.SHAREPOINT.ANONYMOUS_LINKS', 'M365.SHAREPOINT.INVITATION_IDENTITY', 'M365.SHAREPOINT.EXTERNAL_RESHARING']) {
      assert.equal(findings(result, id, 'unable-to-assess').length, 1);
      assert.equal(findings(result, id, 'fail').length, 0);
    }
  }
});

test('partial SharePoint singleton supports specific risks but no positive configuration passes', () => {
  const result = run([collection(SHAREPOINT, [sharePoint({ isLegacyAuthProtocolsEnabled: true,
    sharingCapability: 'externalUserAndGuestSharing' })], TENANT, 'partial')]);
  assert.equal(findings(result, 'M365.SHAREPOINT.LEGACY_AUTH', 'fail').length, 1);
  assert.equal(findings(result, 'M365.SHAREPOINT.ANONYMOUS_LINKS', 'fail').length, 1);
  assert.ok(findings(result, 'M365.SHAREPOINT.INVENTORY', 'unable-to-assess').length);
  assert.equal(result.findings.filter((finding) => finding.checkId.startsWith('M365.SHAREPOINT.')).some((finding) => finding.status === 'pass'), false);
  assert.doesNotThrow(() => snapshot([collection(SHAREPOINT, [sharePoint()], TENANT, 'partial')]));
});

test('SharePoint singleton absence and conflicting metadata stay unassessed', () => {
  for (const records of [[], [sharePoint(), sharePoint({ isLegacyAuthProtocolsEnabled: true })],
    [sharePoint({ id: 'different-singleton' })]]) {
    const result = run([collection(SHAREPOINT, records)]);
    assert.ok(findings(result, 'M365.SHAREPOINT.INVENTORY', 'unable-to-assess').length);
    assert.equal(findings(result, 'M365.SHAREPOINT.LEGACY_AUTH').length, 0);
  }
  const unavailable = run([collection(SHAREPOINT, [], TENANT, 'unavailable')]);
  assert.equal(unavailable.findings.some((finding) => finding.checkId.startsWith('M365.SHAREPOINT.') && finding.status === 'pass'), false);
});

test('SharePoint domain restrictions are metadata reviews with explicit mode/list semantics', () => {
  const cases: JsonObject[] = [
    { sharingDomainRestrictionMode: 'none' },
    { sharingDomainRestrictionMode: 'allowList', sharingAllowedDomainList: [] },
    { sharingDomainRestrictionMode: 'blockList', sharingBlockedDomainList: ['blocked.example'] },
  ];
  for (const value of cases) {
    const result = run([collection(SHAREPOINT, [sharePoint(value)])]);
    assert.equal(findings(result, 'M365.SHAREPOINT.DOMAIN_RESTRICTIONS', 'informational').length, 1);
    assert.equal(findings(result, 'M365.SHAREPOINT.DOMAIN_RESTRICTIONS', 'fail').length, 0);
  }
  for (const value of [
    sharePoint({ sharingDomainRestrictionMode: 'unknownFutureValue' }),
    sharePoint({ sharingDomainRestrictionMode: null }),
    omit(sharePoint(), 'sharingAllowedDomainList'),
    sharePoint({ sharingAllowedDomainList: [42] }),
    sharePoint({ sharingDomainRestrictionMode: 'blockList', sharingBlockedDomainList: null }),
  ]) {
    assert.equal(findings(run([collection(SHAREPOINT, [value])]), 'M365.SHAREPOINT.DOMAIN_RESTRICTIONS', 'unable-to-assess').length, 1);
  }
});

test('SharePoint idle-session and sync reviews do not invent an enterprise timeout or device policy', () => {
  const values: JsonObject[] = [
    { idleSessionSignOut: { isEnabled: false } },
    { idleSessionSignOut: { isEnabled: true, signOutAfterInSeconds: 999999, warnAfterInSeconds: 900000 } },
  ];
  for (const value of values) {
    const result = run([collection(SHAREPOINT, [sharePoint({ ...value, isUnmanagedSyncAppForTenantRestricted: false })])]);
    assert.equal(findings(result, 'M365.SHAREPOINT.IDLE_SESSION', 'informational').length, 1);
    assert.equal(findings(result, 'M365.SHAREPOINT.UNMANAGED_SYNC', 'informational').length, 1);
    assert.equal(findings(result, 'M365.SHAREPOINT.IDLE_SESSION', 'fail').length, 0);
  }
});

test('SharePoint enabled idle sessions require valid nonfabricated warning/sign-out intervals', () => {
  const values: JsonObject[] = [
    { idleSessionSignOut: null }, { idleSessionSignOut: {} },
    { idleSessionSignOut: { isEnabled: true } },
    { idleSessionSignOut: { isEnabled: true, signOutAfterInSeconds: 0, warnAfterInSeconds: 0 } },
    { idleSessionSignOut: { isEnabled: true, signOutAfterInSeconds: 300, warnAfterInSeconds: 600 } },
    { idleSessionSignOut: { isEnabled: true, signOutAfterInSeconds: 300.5, warnAfterInSeconds: 200 } },
  ];
  for (const value of values) {
    const result = run([collection(SHAREPOINT, [sharePoint(value)])]);
    assert.equal(findings(result, 'M365.SHAREPOINT.IDLE_SESSION', 'unable-to-assess').length, 1);
  }
});

test('SharePoint tenant evidence does not claim full product policy coverage', () => {
  const result = run([collection(SHAREPOINT, [sharePoint()])]);
  const coverage = findings(result, 'M365.POLICY.COVERAGE', 'unable-to-assess')[0]!;
  assert.match(coverage.description, /selected SharePoint tenant settings/);
  assert.match(coverage.description, /site\/item/);
  assert.ok(coverage.evidence.some((ref) => ref.collectionId === SHAREPOINT));
});

test('direct active Assigned role with explicit null end is a capability-based persistent risk', () => {
  const input = identityInputs();
  const result = run(input);
  const finding = findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT', 'fail')[0]!;
  assert.equal(finding.severity, 'critical');
  assert.match(finding.description, /explicit null endDateTime/);
  assert.ok(finding.evidence.some((ref) => ref.collectionId === SCHEDULES && ref.recordId === 'schedule-a'));
  assert.ok(finding.evidence.some((ref) => ref.collectionId === 'entra.directoryRoleDefinitions'));
  assert.equal(identityRisk(result).factors.filter((factor) => factor.name === 'directoryPrivilege').length, 1);
  assert.doesNotThrow(() => snapshot(input, result));
});

test('schedule classification cannot derive risk from display names', () => {
  const input = identityInputs();
  input[1] = collection('entra.directoryRoleDefinitions', [{ id: 'role-a', displayName: 'Global Administrator',
    rolePermissions: [{ allowedResourceActions: ['microsoft.directory/users/standard/read'] }] }]);
  const harmlessLabel = run(input);
  assert.equal(findings(harmlessLabel, 'ENTRA.ROLE.SCHEDULE.PERMANENT', 'fail').length, 0);
  assert.equal(findings(harmlessLabel, 'ENTRA.ROLE.SCHEDULE.EVIDENCE', 'unable-to-assess').length, 1);
  input[1] = collection('entra.directoryRoleDefinitions', [{ id: 'role-a', displayName: 'Reader',
    rolePermissions: [{ allowedResourceActions: ['microsoft.directory/applications/credentials/update'] }] }]);
  assert.equal(findings(run(input), 'ENTRA.ROLE.SCHEDULE.PERMANENT', 'fail')[0]!.severity, 'high');
});

test('missing and ambiguous role definitions leave schedule privilege/lifetime unassessed', () => {
  for (const records of [[], [
    { id: 'role-a', templateId: '62e90394-69f5-4237-9190-012177145e10' },
    { id: 'role-a', templateId: '158c047a-c907-4556-b7ef-446551a6b5f7' },
  ]]) {
    const input = identityInputs();
    input[1] = collection('entra.directoryRoleDefinitions', records);
    const result = run(input);
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT', 'fail').length, 0);
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.EVIDENCE', 'unable-to-assess').length, 1);
  }
});

test('time-bound Assigned and Activated instances are different from permanent assignment and eligibility', () => {
  const endDateTime = '2026-09-30T12:00:00Z';
  const assigned = run(identityInputs([schedule({ endDateTime })]));
  assert.equal(findings(assigned, 'ENTRA.ROLE.SCHEDULE.TIME_BOUND', 'informational').length, 1);
  assert.equal(findings(assigned, 'ENTRA.ROLE.SCHEDULE.ACTIVATED').length, 0);
  assert.equal(findings(assigned, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
  const activated = run(identityInputs([schedule({ assignmentType: 'Activated', endDateTime })]));
  assert.equal(findings(activated, 'ENTRA.ROLE.SCHEDULE.ACTIVATED', 'informational').length, 1);
  assert.ok(identityRisk(activated).factors.some((factor) => factor.name === 'directoryPrivilege'));
  const eligible = run([
    ...identityInputs([]), collection('entra.directoryRoleEligibility', [{ id: 'eligibility-a', principalId: 'principal-a',
      roleDefinitionId: 'role-a', directoryScopeId: '/' }]),
  ]);
  assert.equal(identityRisk(eligible).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
});

test('Activated with null end is not reclassified as a permanent Assigned instance', () => {
  const result = run(identityInputs([schedule({ assignmentType: 'Activated' })]));
  assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
  assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.EVIDENCE', 'unable-to-assess').length, 1);
  assert.equal(identityRisk(result).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
});

test('expired and future schedule intervals do not contribute active privilege', () => {
  const cases: JsonObject[] = [
    { startDateTime: '2026-01-01T00:00:00Z', endDateTime: NOW.toISOString() },
    { startDateTime: '2026-09-30T00:00:00Z', endDateTime: null },
  ];
  for (const value of cases) {
    const result = run(identityInputs([schedule(value)]));
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.INACTIVE', 'informational').length, 1);
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
    assert.equal(identityRisk(result).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
    assert.equal(result.graph.edges.some((edge) => edge.relationship === 'active-scheduled-directory-role'), false);
  }
  assert.equal(findings(run(identityInputs([schedule({ startDateTime: NOW.toISOString() })])),
    'ENTRA.ROLE.SCHEDULE.PERMANENT', 'fail').length, 1);
});

test('missing, malformed and reversed schedule dates are not invented into permanent access', () => {
  const cases: JsonObject[] = [
    omit(schedule(), 'startDateTime'), omit(schedule(), 'endDateTime'),
    schedule({ startDateTime: null }), schedule({ startDateTime: '2026-02-30T00:00:00Z' }),
    schedule({ endDateTime: '' }), schedule({ endDateTime: '2026-08-01T00:00:00Z' }),
    schedule({ endDateTime: '2026-09-01T00:00:00Z' }), schedule({ endDateTime: false }),
  ];
  for (const value of cases) {
    const result = run(identityInputs([value]));
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.EVIDENCE', 'unable-to-assess').length, 1);
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
    assert.equal(identityRisk(result).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
  }
});

test('native explicit null start requires an exact current origin; missing start is not equivalent', () => {
  const input = [...identityInputs([schedule({ startDateTime: null })]),
    collection('entra.directoryRoleAssignments', [ordinaryAssignment()])];
  const result = run(input);
  assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT', 'fail').length, 1);
  assert.match(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT')[0]!.description, /no start\/creation time is invented/);
  assert.ok(result.graph.edges.some((edge) => edge.relationship === 'schedule-origin-assignment'));
  const missing = run([...identityInputs([omit(schedule(), 'startDateTime')]), input[3]!]);
  assert.equal(findings(missing, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
  const wrongOrigin = run([...identityInputs([schedule({ startDateTime: null })]),
    collection('entra.directoryRoleAssignments', [ordinaryAssignment({ principalId: 'other-principal' })])]);
  assert.equal(findings(wrongOrigin, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
});

test('ordinary assignments alone never establish permanence and schedule evidence does not double score', () => {
  const ordinary = collection('entra.directoryRoleAssignments', [ordinaryAssignment()]);
  const baseline = run([...identityInputs([]), ordinary]);
  assert.equal(findings(baseline, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
  const additional = run([...identityInputs(), ordinary]);
  assert.equal(identityRisk(additional).score, identityRisk(baseline).score);
  const factors = identityRisk(additional).factors.filter((factor) => factor.name === 'directoryPrivilege');
  assert.equal(factors.length, 1);
  assert.equal(factors[0]!.weight, DEFAULT_POLICY.weights.directoryPrivilege);
  assert.ok(factors[0]!.evidence.some((ref) => ref.collectionId === SCHEDULES));
  assert.ok(factors[0]!.evidence.some((ref) => ref.collectionId === 'entra.directoryRoleAssignments'));
});

test('group and inherited schedule instances never add direct-control privilege or permanent findings', () => {
  for (const memberType of ['Group', 'Inherited']) {
    const result = run(identityInputs([schedule({ memberType })]));
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.INDIRECT', 'informational').length, 1);
    assert.equal(identityRisk(result).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
    assert.ok(result.graph.edges.some((edge) => edge.relationship === 'potential-indirect-scheduled-role' && edge.confidence === 'potential'));
    assert.equal(identityRisk(result).incomplete, true);
  }
});

test('unusual directory/app scopes and future assignment/member types remain contextual unknowns', () => {
  const cases: JsonObject[] = [
    schedule({ directoryScopeId: '/administrativeUnits/unit-a' }),
    schedule({ directoryScopeId: null }), schedule({ appScopeId: '/' }),
    schedule({ appScopeId: '/applications/application-a' }), omit(schedule(), 'appScopeId'),
    schedule({ assignmentType: 'Eligible' }), schedule({ memberType: 'unknownFutureValue' }),
  ];
  for (const value of cases) {
    const result = run(identityInputs([value]));
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.EVIDENCE', 'unable-to-assess').length, 1);
    assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
    assert.equal(identityRisk(result).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
  }
});

test('partial schedules support specific observed risk while keeping inventory and score incomplete', () => {
  const input = identityInputs([schedule()], 'partial');
  const result = run(input);
  assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT', 'fail').length, 1);
  assert.ok(findings(result, 'ENTRA.ROLE.SCHEDULE.INVENTORY', 'unable-to-assess').length);
  assert.equal(identityRisk(result).incomplete, true);
  assert.doesNotThrow(() => snapshot(input, result));
});

test('conflicting schedule records stay ambiguous instead of adding contradictory privilege', () => {
  const result = run(identityInputs([schedule(), schedule({ assignmentType: 'Activated' })]));
  assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
  assert.ok(findings(result, 'ENTRA.ROLE.SCHEDULE.EVIDENCE', 'unable-to-assess').length);
  assert.equal(identityRisk(result).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
});

test('schedule-only active user privilege is available to existing MFA priority analysis', () => {
  const input = identityInputs().filter((source) => source.id !== 'entra.servicePrincipals');
  input.push(collection('entra.users', [{ id: 'principal-a', accountEnabled: true, userType: 'Member' }]));
  input.push(collection('entra.authenticationRegistration', [{ id: 'principal-a', isMfaRegistered: false }]));
  assert.equal(findings(run(input), 'ENTRA.MFA.REGISTRATION', 'fail')[0]!.severity, 'high');
});

test('Azure Policy NonCompliant reports a dated resource/assignment risk with exact resource graph evidence', () => {
  const input = [collection(POLICY, [policyRecord()], SUB), collection('azure.resources', [azureResource()], SUB)];
  const result = run(input);
  const finding = findings(result, 'AZURE.POLICY.COMPLIANCE', 'fail')[0]!;
  assert.equal(finding.severity, 'medium');
  assert.match(finding.description, /2026-09-28T12:00:00.000Z/);
  assert.match(finding.description, /not real-time posture/);
  assert.ok(finding.description.includes(RESOURCE.toLowerCase()) && finding.description.includes(ASSIGNMENT.toLowerCase()));
  const edge = result.graph.edges.find((value) => value.relationship === 'policy-evaluation-for-resource')!;
  assert.ok(edge.evidence.some((ref) => ref.collectionId === 'azure.resources' && ref.recordId === RESOURCE));
  assert.doesNotThrow(() => snapshot(input, result));
});

test('explicit valid Compliant is a limited last-reported pass, not estate or real-time protection', () => {
  const result = run([collection(POLICY, [policyRecord({ complianceState: 'Compliant' })], SUB)]);
  const finding = findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass')[0]!;
  assert.match(finding.description, /limited pass concerns only this dated resource\/assignment evaluation/);
  assert.match(finding.description, /not real-time posture/);
  assert.equal(result.graph.nodes.some((node) => node.type === 'azure-resource'), false);
});

test('policy exemption is a review, never protected or compliant-by-enforcement', () => {
  const result = run([collection(POLICY, [policyRecord({ complianceState: 'Exempt' })], SUB)]);
  const finding = findings(result, 'AZURE.POLICY.EXEMPTION', 'informational')[0]!;
  assert.match(finding.description, /not a protected-state or enforcement pass/);
  assert.equal(result.findings.some((item) => item.checkId.startsWith('AZURE.POLICY.') && item.status === 'pass'), false);
});

test('policy Conflict, future and missing states are unknown rather than compliance', () => {
  const states: JsonObject[] = [{ complianceState: 'Conflict' }, { complianceState: 'UnknownFutureValue' }, { complianceState: null }];
  for (const state of states) {
    const result = run([collection(POLICY, [policyRecord(state)], SUB)]);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'unable-to-assess').length, 1);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
  }
  const data = policyRecord();
  data.properties = omit(data.properties as JsonObject, 'complianceState');
  assert.equal(findings(run([collection(POLICY, [data], SUB)]), 'AZURE.POLICY.COMPLIANCE', 'unable-to-assess').length, 1);
});

test('missing or empty policy observations do not prove compliance', () => {
  for (const status of ['complete', 'partial', 'unavailable'] as const) {
    const result = run([collection(POLICY, [], SUB, status)]);
    assert.ok(findings(result, 'AZURE.POLICY.INVENTORY', 'unable-to-assess').length);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
  }
});

test('partial PolicyStates retain specific NonCompliant evidence but do not issue compliant passes', () => {
  const input = [collection(POLICY, [policyRecord(),
    policyRecord({ complianceState: 'Compliant', policyDefinitionReferenceId: 'other-rule' }, { id: 'policy-state-b' })], SUB, 'partial')];
  const result = run(input);
  assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'fail').length, 1);
  assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'informational').length, 1);
  assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
  assert.doesNotThrow(() => snapshot(input, result));
});

test('invalid, missing, null and future evaluation timestamps cannot yield a policy pass', () => {
  const values: JsonObject[] = [
    { timestamp: null }, { timestamp: 'not-a-date' }, { timestamp: '2026-02-30T00:00:00Z' },
    { timestamp: '2026-09-30T00:00:00Z' },
  ];
  for (const value of values) {
    const result = run([collection(POLICY, [policyRecord({ complianceState: 'Compliant', ...value })], SUB)]);
    assert.equal(findings(result, 'AZURE.POLICY.EVIDENCE', 'unable-to-assess').length, 1);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
  }
  const missing = policyRecord({ complianceState: 'Compliant' });
  missing.properties = omit(missing.properties as JsonObject, 'timestamp');
  assert.equal(findings(run([collection(POLICY, [missing], SUB)]), 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
});

test('evaluation cannot postdate collection even when before the assessment time', () => {
  const input = collection(POLICY, [policyRecord({ complianceState: 'Compliant' })], SUB);
  input.collectedAt = '2026-09-27T12:00:00Z';
  const result = run([input]);
  assert.equal(findings(result, 'AZURE.POLICY.EVIDENCE', 'unable-to-assess').length, 1);
  assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
});

test('old evaluated states are explicitly historical without an invented freshness threshold', () => {
  const result = run([collection(POLICY, [policyRecord({ complianceState: 'Compliant', timestamp: '2020-01-01T00:00:00Z' })], SUB)]);
  const finding = findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass')[0]!;
  assert.match(finding.description, /last reported Compliant at 2020-01-01/);
  assert.match(finding.description, /not real-time/);
});

test('cross-subscription resource and subscriptionId mismatches are not classified or linked', () => {
  const records = [
    policyRecord({}, { subscriptionId: '33333333-3333-4333-8333-333333333333' }),
    policyRecord({ resourceId: RESOURCE.replace(SUB, OTHER_SUB) }),
    policyRecord({ resourceId: `${SUB}-suffix/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account` }),
    policyRecord({ resourceId: `${SUB}/../other` }),
    policyRecord({ resourceId: `${RESOURCE}/../other` }),
  ];
  for (const record of records) {
    const result = run([collection(POLICY, [record], SUB), collection('azure.resources', [azureResource()], SUB)]);
    assert.equal(findings(result, 'AZURE.POLICY.EVIDENCE', 'unable-to-assess').length, 1);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE').length, 0);
    assert.equal(result.graph.edges.some((edge) => edge.relationship === 'policy-evaluation-for-resource'), false);
  }
});

test('missing or inconsistent resource, assignment and definition metadata is not a policy pass', () => {
  const values: JsonObject[] = [
    { resourceId: null }, { policyAssignmentId: 'name-only' }, { policyAssignmentScope: OTHER_SUB },
    { policyAssignmentScope: null }, { policyDefinitionId: null }, { policyDefinitionId: 'same-display-name' },
    { policyAssignmentId: `${OTHER_SUB}/providers/Microsoft.Authorization/policyAssignments/assignment-a`, policyAssignmentScope: OTHER_SUB },
  ];
  for (const value of values) {
    const result = run([collection(POLICY, [policyRecord({ complianceState: 'Compliant', ...value })], SUB)]);
    assert.equal(findings(result, 'AZURE.POLICY.EVIDENCE', 'unable-to-assess').length, 1);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
  }
});

test('PolicyStates resource association uses exact IDs rather than display names', () => {
  const different = RESOURCE.replace('/account', '/other');
  const result = run([
    collection(POLICY, [policyRecord()], SUB),
    collection('azure.resources', [{ ...azureResource(different), name: 'account' }], SUB),
  ]);
  assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'fail').length, 1);
  assert.equal(result.graph.edges.some((edge) => edge.relationship === 'policy-evaluation-for-resource'), false);
  const exact = run([collection(POLICY, [policyRecord({ resourceId: RESOURCE.toUpperCase() })], SUB),
    collection('azure.resources', [azureResource()], SUB)]);
  assert.equal(exact.graph.edges.filter((edge) => edge.relationship === 'policy-evaluation-for-resource').length, 1);
});

test('a management-group assignment remains a reported policy context, not invented hierarchy enforcement', () => {
  const groupScope = '/providers/Microsoft.Management/managementGroups/group-a';
  const result = run([collection(POLICY, [policyRecord({
    policyAssignmentId: `${groupScope}/providers/Microsoft.Authorization/policyAssignments/assignment-a`,
    policyAssignmentScope: groupScope,
  })], SUB)]);
  assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'fail').length, 1);
  assert.equal(result.graph.edges.some((edge) => edge.relationship.includes('protected')), false);
  assert.equal(result.graph.nodes.some((node) => node.type === 'azure-resource'), false);
});

test('policy binding rejects mismatched resource metadata even with a matching resource path', () => {
  const result = run([collection(POLICY, [policyRecord()], SUB),
    collection('azure.resources', [{ ...azureResource(), subscriptionId: 'other-subscription' }], SUB)]);
  assert.equal(result.graph.edges.some((edge) => edge.relationship === 'policy-evaluation-for-resource'), false);
});

test('governance findings are deterministic, documented and scoped to actual record evidence', () => {
  const input = [
    collection(SHAREPOINT, [sharePoint({ isLegacyAuthProtocolsEnabled: true, sharingCapability: 'externalUserAndGuestSharing' })]),
    ...identityInputs([schedule(), schedule({ id: 'schedule-b', assignmentType: 'Activated', endDateTime: '2026-09-30T00:00:00Z' })]),
    collection(POLICY, [policyRecord(), policyRecord({ complianceState: 'Exempt', policyDefinitionReferenceId: 'second' }, { id: 'policy-state-b' })], SUB),
    collection('azure.resources', [azureResource()], SUB),
  ];
  const saved = structuredClone(input);
  const result = run(input);
  assert.deepEqual(input, saved);
  assert.deepEqual(result, run([...input].reverse().map((source) => ({ ...source, records: [...source.records].reverse() }))));
  assert.equal(new Set(result.findings.map((finding) => finding.id)).size, result.findings.length);
  const prefixes = ['M365.SHAREPOINT.', 'ENTRA.ROLE.SCHEDULE.', 'AZURE.POLICY.'];
  for (const finding of result.findings.filter((entry) => prefixes.some((prefix) => entry.checkId.startsWith(prefix)))) {
    assert.ok(finding.references.length && finding.references.every((reference) => reference.startsWith('https://learn.microsoft.com/')));
    assert.ok(finding.zeroTrust.length);
    for (const ref of finding.evidence) {
      assert.ok(input.some((source) => source.id === ref.collectionId && source.scope === ref.scope
        && (!ref.recordId || source.records.some((record) => String(record.id) === ref.recordId))));
    }
  }
  assert.doesNotThrow(() => snapshot(input, result));
});

test('the parent engine persists all three governance datasets with strict snapshot provenance', () => {
  const collections = [
    collection(SHAREPOINT, [sharePoint({ isLegacyAuthProtocolsEnabled: true })]),
    ...identityInputs(),
    collection(POLICY, [policyRecord()], SUB),
    collection('azure.resources', [azureResource()], SUB),
  ];
  const result = createAssessment({ schemaVersion: '1.0', scope: { tenantId: TENANT, subscriptionIds: [SUB_ID],
    githubOrganizations: [], azureDevOpsOrganizations: [] }, collectedAt: NOW.toISOString(), collections });
  assert.doesNotThrow(() => parseSnapshot(result));
  assert.equal(findings(result, 'M365.SHAREPOINT.LEGACY_AUTH', 'fail').length, 1);
  assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT', 'fail').length, 1);
  assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'fail').length, 1);
});

test('missing governance collections never produce synthetic references or positive coverage', () => {
  const collections = [
    collection('entra.directoryRoleAssignments', [ordinaryAssignment()]),
    collection(SHAREPOINT, [], 'assessment', 'unavailable'),
    collection(SCHEDULES, [], 'assessment', 'unavailable'),
    collection(POLICY, [], 'assessment', 'unavailable'),
  ];
  const result = run(collections);
  assert.doesNotThrow(() => snapshot(collections, result));
  assert.equal(result.findings.some((finding) => finding.status === 'pass'), false);
});

test('role schedule definitions and lifetime evidence never cross tenant scopes', () => {
  const input = identityInputs();
  input[1] = { ...input[1]!, scope: '44444444-4444-4444-8444-444444444444' };
  const result = run(input);
  assert.equal(findings(result, 'ENTRA.ROLE.SCHEDULE.PERMANENT').length, 0);
  const unresolved = findings(result, 'ENTRA.ROLE.SCHEDULE.EVIDENCE', 'unable-to-assess')[0]!;
  assert.ok(unresolved.evidence.every((ref) => ref.scope === TENANT));
});

test('conflicting policy records cannot generate a compliant pass or ambiguous resource link', () => {
  const result = run([collection(POLICY, [policyRecord(), policyRecord({ complianceState: 'Compliant' })], SUB),
    collection('azure.resources', [azureResource()], SUB)]);
  assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
  assert.ok(findings(result, 'AZURE.POLICY.EVIDENCE', 'unable-to-assess').length);
  assert.equal(result.graph.edges.some((edge) => edge.relationship === 'policy-evaluation-for-resource'), false);
});

test('policy rule observations sharing resource and assignment have distinct stable finding IDs', () => {
  const input = [collection(POLICY, [
    policyRecord({ policyDefinitionReferenceId: 'rule-a' }, { id: `${RESOURCE}|${ASSIGNMENT}|rule-a` }),
    policyRecord({ policyDefinitionReferenceId: 'rule-b' }, { id: `${RESOURCE}|${ASSIGNMENT}|rule-b` }),
  ], SUB)];
  const result = run(input);
  const classified = findings(result, 'AZURE.POLICY.COMPLIANCE', 'fail');
  assert.equal(classified.length, 2);
  assert.notEqual(classified[0]!.id, classified[1]!.id);
  assert.doesNotThrow(() => snapshot(input, result));
});

test('disabled and manual policy effects make reported Compliant a review rather than a pass', () => {
  for (const effect of ['disabled', 'Disabled', 'manual', 'MANUAL']) {
    const result = run([collection(POLICY, [policyRecord({ complianceState: 'Compliant', policyDefinitionAction: effect })], SUB)]);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0, effect);
    const review = findings(result, 'AZURE.POLICY.COMPLIANCE', 'informational')[0]!;
    assert.ok(review, effect);
    assert.match(review.description, effect.toLowerCase() === 'disabled' ? /default.*Compliant/i : /attestation/i);
    assert.ok(review.evidence.some((ref) => ref.field === 'properties.policyDefinitionAction'));
  }
});

test('missing, null and future policy effects cannot establish an automated compliant pass', () => {
  const values: JsonObject[] = [
    { policyDefinitionAction: null }, { policyDefinitionAction: '' }, { policyDefinitionAction: true },
    { policyDefinitionAction: 'unknownFutureValue' }, { policyDefinitionAction: 'futureAutomaticEffect' },
    { policyDefinitionAction: 'audit-like' },
  ];
  for (const value of values) {
    const result = run([collection(POLICY, [policyRecord({ complianceState: 'Compliant', ...value })], SUB)]);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass').length, 0);
    assert.equal(findings(result, 'AZURE.POLICY.COMPLIANCE', 'unable-to-assess').length, 1);
  }
  const missing = policyRecord({ complianceState: 'Compliant' });
  missing.properties = omit(missing.properties as JsonObject, 'policyDefinitionAction');
  assert.equal(findings(run([collection(POLICY, [missing], SUB)]), 'AZURE.POLICY.COMPLIANCE', 'unable-to-assess').length, 1);
});

test('documented automated effects support only a dated limited state pass, with no audit enforcement claim', () => {
  const effects = ['addToNetworkGroup', 'append', 'audit', 'auditIfNotExists', 'deny', 'denyAction',
    'deployIfNotExists', 'modify', 'mutate'];
  for (const effect of effects) {
    const result = run([collection(POLICY, [policyRecord({ complianceState: 'Compliant', policyDefinitionAction: effect })], SUB)]);
    const pass = findings(result, 'AZURE.POLICY.COMPLIANCE', 'pass')[0]!;
    assert.ok(pass, effect);
    assert.match(pass.description, /not real-time posture, effect enforcement/);
    if (effect === 'audit' || effect === 'auditIfNotExists') assert.match(pass.description, /do not block/i);
    assert.ok(pass.references.some((reference) => reference.endsWith('/effect-basics')));
  }
});

test('real assessment diffs do not resolve earlier policy noncompliance merely because its effect is disabled or manual', () => {
  const assessment = (record: JsonObject, id: string) => createAssessment({
    schemaVersion: '1.0', scope: { tenantId: TENANT, subscriptionIds: [SUB_ID],
      githubOrganizations: [], azureDevOpsOrganizations: [] }, collectedAt: NOW.toISOString(),
    collections: [collection(POLICY, [record], SUB)],
  }, DEFAULT_POLICY, id);
  const before = assessment(policyRecord(), 'before-effect-change');
  const original = findings(before, 'AZURE.POLICY.COMPLIANCE', 'fail')[0]!;
  for (const effect of ['disabled', 'manual']) {
    const after = assessment(policyRecord({ complianceState: 'Compliant', policyDefinitionAction: effect,
      timestamp: '2026-09-29T11:00:00Z' }), `after-${effect}`);
    const diff = compareSnapshots(before, after);
    assert.equal(findings(after, 'AZURE.POLICY.COMPLIANCE')[0]!.id, original.id);
    assert.equal(diff.findings.resolved.includes(original.id), false, effect);
    assert.ok(diff.findings.indeterminate.includes(original.id), effect);
    assert.doesNotThrow(() => parseSnapshot(after));
  }
});

test('real policy diffs preserve unknown-effect findings as indeterminate, while an explicit audit recheck may resolve its dated state', () => {
  const assessment = (record: JsonObject) => createAssessment({
    schemaVersion: '1.0', scope: { tenantId: TENANT, subscriptionIds: [SUB_ID],
      githubOrganizations: [], azureDevOpsOrganizations: [] }, collectedAt: NOW.toISOString(),
    collections: [collection(POLICY, [record], SUB)],
  });
  const before = assessment(policyRecord());
  const original = findings(before, 'AZURE.POLICY.COMPLIANCE', 'fail')[0]!;
  const missing = policyRecord({ complianceState: 'Compliant', timestamp: '2026-09-29T11:00:00Z' });
  missing.properties = omit(missing.properties as JsonObject, 'policyDefinitionAction');
  for (const record of [missing,
    policyRecord({ complianceState: 'Compliant', policyDefinitionAction: null, timestamp: '2026-09-29T11:00:00Z' }),
    policyRecord({ complianceState: 'Compliant', policyDefinitionAction: 'futureEffect', timestamp: '2026-09-29T11:00:00Z' })]) {
    const diff = compareSnapshots(before, assessment(record));
    assert.equal(diff.findings.resolved.includes(original.id), false);
    assert.ok(diff.findings.indeterminate.includes(original.id));
  }
  const evaluated = assessment(policyRecord({ complianceState: 'Compliant', timestamp: '2026-09-29T11:00:00Z' }));
  assert.ok(compareSnapshots(before, evaluated).findings.resolved.includes(original.id));
});
