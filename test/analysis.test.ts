import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze } from '../src/analysis.js';
import { DEFAULT_POLICY, MICROSOFT_GRAPH_APP_ID } from '../src/policy.js';
import { COLLECTION_CATALOG } from '../src/catalog.js';
import { createAssessment } from '../src/engine.js';
import { Context } from '../src/analysis/context.js';
import { parseSnapshot } from '../src/validation.js';
import type { AnalysisResult, CollectionResult, Finding, JsonObject, RiskPolicy } from '../src/model.js';

const TENANT = 'tenant-a';
const NOW = new Date('2026-09-29T12:00:00Z');
const SUB = '/subscriptions/sub-a';
const ROLE = `${SUB}/providers/Microsoft.Authorization/roleDefinitions/custom-role`;
const APP_CONTROL = '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9';
const CONSENT = '06b708a9-e830-4db3-a914-8e69da51d44f';
const DELEGATED_APP_CONTROL = 'bdfbf15f-ee85-4955-8675-146e8e5296b5';

function collection(id: string, records: JsonObject[] = [], scope = TENANT,
  status: CollectionResult['status'] = 'complete'): CollectionResult {
  const provider = id.startsWith('github.') ? 'github' : id.startsWith('azureDevOps.') ? 'azureDevOps'
    : id.startsWith('azure.') || id.startsWith('defenderCloud.') ? 'azure' : id.startsWith('defender.') ? 'defender' : 'graph';
  return { id, records, scope, provider, status, collectedAt: NOW.toISOString() };
}
function replace(input: CollectionResult[], id: string, records: JsonObject[], scope = TENANT,
  status: CollectionResult['status'] = 'complete'): CollectionResult[] {
  return [...input.filter((item) => item.id !== id || item.scope !== scope), collection(id, records, scope, status)];
}
function base(): CollectionResult[] {
  return [
    collection('entra.organization', [{ id: TENANT }]),
    collection('entra.users', [{ id: 'owner-a', userType: 'Member', accountEnabled: true,
      signInActivity: { lastSuccessfulSignInDateTime: '2026-09-28T12:00:00Z' } }]),
    collection('entra.groups'), collection('entra.groupMemberships'),
    collection('entra.applications', [{ id: 'app-a', appId: 'client-a', signInAudience: 'AzureADMyOrg',
      passwordCredentials: [], keyCredentials: [] }]),
    collection('entra.servicePrincipals', [
      { id: 'sp-a', appId: 'client-a', servicePrincipalType: 'Application', accountEnabled: true,
        passwordCredentials: [], keyCredentials: [], appRoles: [], oauth2PermissionScopes: [] },
      { id: 'graph-api', appId: MICROSOFT_GRAPH_APP_ID, servicePrincipalType: 'Application',
        passwordCredentials: [], keyCredentials: [],
        appRoles: [{ id: APP_CONTROL, value: 'Application.ReadWrite.All', allowedMemberTypes: ['Application'] },
          { id: CONSENT, value: 'AppRoleAssignment.ReadWrite.All', allowedMemberTypes: ['Application'] }],
        oauth2PermissionScopes: [{ id: DELEGATED_APP_CONTROL, value: 'Application.ReadWrite.All' }] },
    ]),
    collection('entra.applicationOwners', [{ id: 'owner-a', parentId: 'app-a', userType: 'Member' }]),
    collection('entra.servicePrincipalOwners', [
      { id: 'owner-a', parentId: 'sp-a', userType: 'Member' },
      { id: 'owner-a', parentId: 'graph-api', userType: 'Member' },
    ]),
    collection('entra.federatedCredentials'), collection('entra.appRoleAssignments'),
    collection('entra.oauth2PermissionGrants'),
    collection('entra.directoryRoleDefinitions', [{ id: 'role-global', templateId: '62e90394-69f5-4237-9190-012177145e10' }]),
    collection('entra.directoryRoleAssignments'), collection('entra.directoryRoleEligibility'),
    collection('entra.authenticationRegistration', [{ id: 'owner-a', isMfaRegistered: true, isMfaCapable: true }]),
    collection('entra.conditionalAccess', [{ id: 'ca-a', state: 'enabled',
      conditions: { users: { includeUsers: ['All'], excludeUsers: ['owner-a'] } },
      grantControls: { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] } }]),
    collection('entra.riskyUsers'), collection('entra.riskySignIns'),
  ];
}
function withGrant(input = base(), permissionId = APP_CONTROL): CollectionResult[] {
  return replace(input, 'entra.appRoleAssignments', [{ id: 'grant-a', parentId: 'sp-a', principalId: 'sp-a',
    resourceId: 'graph-api', appRoleId: permissionId }]);
}
function withAzure(input = base(), permissions: JsonObject[] = [
  { actions: ['*'], notActions: [], dataActions: [], notDataActions: [] },
], condition: string | null = null): CollectionResult[] {
  return [...input,
    collection('azure.subscriptions', [{ id: SUB, tenantId: TENANT }], SUB),
    collection('azure.resources', [], SUB),
    collection('azure.roleDefinitions', [{ id: ROLE, properties: { roleName: 'Harmless-looking label', permissions } }], SUB),
    collection('azure.roleAssignments', [{ id: `${SUB}/providers/Microsoft.Authorization/roleAssignments/assignment-a`,
      properties: { principalId: 'sp-a', roleDefinitionId: ROLE, scope: SUB, condition } }], SUB),
    collection('azure.federatedCredentials', [], SUB),
  ];
}
function github(input: CollectionResult[] = [], name = 'org/repo'): CollectionResult[] {
  return [...input,
    collection('github.repositories', [{ id: `id-${name}`, full_name: name, default_branch: 'main',
      archived: false, visibility: 'private' }], name.split('/')[0]!),
    collection('github.branchProtection', [], name), collection('github.rulesets', [], name),
    collection('github.workflowPermissions', [{ id: 'permissions', repository: name, default_workflow_permissions: 'read' }], name),
    collection('github.workflows', [], name), collection('github.environments', [], name),
  ];
}
function federated(input = github(withAzure(withGrant())), overrides: JsonObject = {}): CollectionResult[] {
  return replace(input, 'entra.federatedCredentials', [{ id: 'fic-a', parentId: 'app-a',
    issuer: 'https://token.actions.githubusercontent.com', subject: 'repo:org/repo:ref:refs/heads/main',
    audiences: ['api://AzureADTokenExchange'], ...overrides }]);
}
function run(input: CollectionResult[], policy = DEFAULT_POLICY): AnalysisResult { return analyze(input, policy, NOW); }
function findings(result: AnalysisResult, checkId: string, status?: Finding['status']): Finding[] {
  return result.findings.filter((finding) => finding.checkId === checkId && (!status || finding.status === status));
}
function risk(result: AnalysisResult, id = 'sp-a') {
  const value = result.identityRisks.find((item) => item.identityId === `${TENANT}/${id}`);
  assert.ok(value, `risk for ${id}`);
  return value;
}

test('default permission rules bind verified IDs to resource and application/delegated context', () => {
  assert.equal(DEFAULT_POLICY.permissionRules.length, 24);
  assert.ok(DEFAULT_POLICY.permissionRules.every((permission) => permission.resourceAppId === MICROSOFT_GRAPH_APP_ID
    && /^[0-9a-f-]{36}$/.test(permission.permissionId) && permission.reference.startsWith('https://learn.microsoft.com/')
    && permission.capabilities.length > 0));
  assert.ok(DEFAULT_POLICY.permissionRules.some((permission) => permission.permissionId === APP_CONTROL
    && permission.permissionType === 'application'));
  assert.ok(DEFAULT_POLICY.permissionRules.some((permission) => permission.permissionId === DELEGATED_APP_CONTROL
    && permission.permissionType === 'delegated'));
});

test('empty input is pure and has no invented inventory', () => {
  assert.deepEqual(run([]), { findings: [], graph: { nodes: [], edges: [] }, identityRisks: [] });
});

test('application grants resolve exact resource app ID and permission ID', () => {
  const result = run(withGrant());
  const actual = findings(result, 'WORKLOAD.API.APPLICATION', 'fail');
  assert.equal(actual.length, 1);
  assert.match(actual[0]!.description, /application ID 00000003/);
  assert.ok(actual[0]!.evidence.some((ref) => ref.recordId === 'graph-api'));
  assert.ok(result.graph.edges.some((edge) => edge.relationship === 'application-permission-grant'));
});

test('familiar permission names on a different API are unclassified, not safe', () => {
  const input = withGrant();
  const principals = input.find((source) => source.id === 'entra.servicePrincipals')!.records
    .map((record) => record.id === 'graph-api' ? { ...record, appId: 'custom-api' } : record);
  const result = run(replace(input, 'entra.servicePrincipals', principals));
  assert.equal(findings(result, 'WORKLOAD.API.APPLICATION', 'fail').length, 0);
  assert.equal(findings(result, 'WORKLOAD.API.UNCLASSIFIED', 'unable-to-assess').length, 1);
  assert.equal(risk(result).incomplete, true);
});

test('appRoleId must be exposed by the exact resource service principal', () => {
  const input = withGrant();
  const principals = input.find((source) => source.id === 'entra.servicePrincipals')!.records
    .map((record) => record.id === 'graph-api' ? { ...record, appRoles: [{ id: 'other-id', value: 'Application.ReadWrite.All' }] } : record);
  const result = run(replace(input, 'entra.servicePrincipals', principals));
  assert.equal(findings(result, 'WORKLOAD.API.APPLICATION', 'fail').length, 0);
  assert.ok(findings(result, 'WORKLOAD.API.UNCLASSIFIED', 'unable-to-assess').length);
});

test('grant client and parent mismatch is not correlated', () => {
  const result = run(replace(withGrant(), 'entra.appRoleAssignments', [{ id: 'grant-a', parentId: 'unrelated',
    principalId: 'sp-a', resourceId: 'graph-api', appRoleId: APP_CONTROL }]));
  assert.equal(findings(result, 'WORKLOAD.API.APPLICATION', 'fail').length, 0);
});

test('delegated scope values resolve to IDs and retain user-dependent semantics', () => {
  const result = run(replace(base(), 'entra.oauth2PermissionGrants', [{ id: 'delegated-a', clientId: 'sp-a',
    resourceId: 'graph-api', scope: 'Application.ReadWrite.All', consentType: 'AllPrincipals', principalId: null }]));
  const actual = findings(result, 'WORKLOAD.API.DELEGATED', 'fail');
  assert.equal(actual.length, 1);
  assert.match(actual[0]!.description, new RegExp(DELEGATED_APP_CONTROL));
  assert.match(actual[0]!.description, /signed-in user/);
  assert.equal(findings(result, 'WORKLOAD.API.APPLICATION', 'fail').length, 0);
  assert.equal(findings(result, 'WORKLOAD.PRIVILEGE.COMBINATION', 'fail').length, 0);
});

test('delegated dangerous names never substitute for resolved permission GUIDs', () => {
  const input = replace(base(), 'entra.oauth2PermissionGrants', [{ id: 'delegated-a', clientId: 'sp-a',
    resourceId: 'graph-api', scope: 'Application.ReadWrite.All', consentType: 'AllPrincipals' }]);
  const principals = input.find((source) => source.id === 'entra.servicePrincipals')!.records.map((record) =>
    record.id === 'graph-api' ? { ...record, oauth2PermissionScopes: [{ id: 'custom-id', value: 'Application.ReadWrite.All' }] } : record);
  const result = run(replace(input, 'entra.servicePrincipals', principals));
  assert.equal(findings(result, 'WORKLOAD.API.DELEGATED', 'fail').length, 0);
  assert.equal(findings(result, 'WORKLOAD.API.UNCLASSIFIED', 'unable-to-assess').length, 1);
});

test('ambiguous delegated scope definitions and missing Principal context stay unknown', () => {
  const input = replace(base(), 'entra.oauth2PermissionGrants', [{ id: 'delegated-a', clientId: 'sp-a',
    resourceId: 'graph-api', scope: 'Application.ReadWrite.All', consentType: 'Principal' }]);
  assert.ok(findings(run(input), 'WORKLOAD.API.UNCLASSIFIED', 'unable-to-assess').length);
  const principals = base().find((source) => source.id === 'entra.servicePrincipals')!.records.map((record) =>
    record.id === 'graph-api' ? { ...record, oauth2PermissionScopes: [
      { id: DELEGATED_APP_CONTROL, value: 'Application.ReadWrite.All' }, { id: 'other', value: 'Application.ReadWrite.All' },
    ] } : record);
  const granted = replace(input, 'entra.oauth2PermissionGrants', [{ ...input.find((source) => source.id === 'entra.oauth2PermissionGrants')!.records[0]!,
    consentType: 'AllPrincipals' }]);
  assert.equal(findings(run(replace(granted, 'entra.servicePrincipals', principals)), 'WORKLOAD.API.DELEGATED', 'fail').length, 0);
});

test('colliding policy rules aggregate strongest severity deterministically without finding-ID collisions', () => {
  const baseRule = DEFAULT_POLICY.permissionRules.find((permission) => permission.permissionId === APP_CONTROL)!;
  const policy: RiskPolicy = { ...DEFAULT_POLICY, permissionRules: [
    { ...baseRule, severity: 'low', capabilities: ['one'], rationale: 'First documented capability.' },
    { ...baseRule, severity: 'critical', capabilities: ['two'], rationale: 'Second documented capability.' },
  ] };
  const result = run(withGrant(), policy);
  assert.equal(findings(result, 'WORKLOAD.API.APPLICATION').length, 1);
  assert.equal(findings(result, 'WORKLOAD.API.APPLICATION')[0]!.severity, 'critical');
  assert.deepEqual(result, run(withGrant(), { ...policy, permissionRules: [...policy.permissionRules].reverse() }));
});

test('role display names cannot influence capability risk', () => {
  const assignment = [{ id: 'dir-a', principalId: 'sp-a', roleDefinitionId: 'role-a', directoryScopeId: '/' }];
  let input = replace(base(), 'entra.directoryRoleAssignments', assignment);
  input = replace(input, 'entra.directoryRoleDefinitions', [{ id: 'role-a', displayName: 'Global Administrator',
    rolePermissions: [{ allowedResourceActions: ['microsoft.directory/users/standard/read'] }] }]);
  assert.equal(findings(run(input), 'ENTRA.ROLE.PRIVILEGED', 'fail').length, 0);
  const harmless = replace(input, 'entra.directoryRoleDefinitions', [{ id: 'role-a', displayName: 'Read only',
    templateId: '62e90394-69f5-4237-9190-012177145e10' }]);
  assert.equal(findings(run(harmless), 'ENTRA.ROLE.PRIVILEGED', 'fail')[0]!.severity, 'critical');
});

test('custom Entra role capabilities use allowed actions', () => {
  let input = replace(base(), 'entra.directoryRoleDefinitions', [{ id: 'role-a', displayName: 'Reader',
    rolePermissions: [{ allowedResourceActions: ['microsoft.directory/roleAssignments/allProperties/allTasks'] }] }]);
  input = replace(input, 'entra.directoryRoleAssignments', [{ id: 'dir-a', principalId: 'sp-a', roleDefinitionId: 'role-a', directoryScopeId: '/' }]);
  assert.equal(findings(run(input), 'ENTRA.ROLE.PRIVILEGED', 'fail')[0]!.severity, 'critical');
});

test('eligible roles are not scored as active grants', () => {
  const result = run(replace(base(), 'entra.directoryRoleEligibility', [
    { id: 'eligible-a', principalId: 'sp-a', roleDefinitionId: 'role-global', directoryScopeId: '/' },
  ]));
  assert.equal(findings(result, 'ENTRA.ROLE.ELIGIBLE', 'informational').length, 1);
  assert.equal(findings(result, 'ENTRA.ROLE.PRIVILEGED', 'fail').length, 0);
  assert.equal(risk(result).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
  assert.ok(result.graph.edges.some((edge) => edge.relationship === 'eligible-directory-role'));
});

test('group traversal is cycle-safe and does not assert unsupported nested Entra inheritance', () => {
  let input = replace(base(), 'entra.groups', [{ id: 'group-a' }, { id: 'group-b' }]);
  input = replace(input, 'entra.groupMemberships', [
    { id: 'group-b', parentId: 'group-a' }, { id: 'group-a', parentId: 'group-b' },
    { id: 'owner-a', parentId: 'group-a' }, { id: 'sp-a', parentId: 'group-b' },
  ]);
  input = replace(input, 'entra.directoryRoleAssignments', [
    { id: 'dir-a', principalId: 'group-a', roleDefinitionId: 'role-global', directoryScopeId: '/' },
  ]);
  const result = run(input);
  assert.equal(findings(result, 'ENTRA.GROUP.CYCLE').length, 1);
  const nested = findings(result, 'ENTRA.GROUP.PRIVILEGE').find((finding) => finding.resourceId === 'sp-a')!;
  assert.match(nested.description, /not supported/);
  assert.equal(risk(result).factors.some((factor) => factor.name === 'directoryPrivilege'), false);
  assert.ok(risk(result, 'owner-a').factors.some((factor) => factor.name === 'directoryPrivilege'));
  assert.ok(result.graph.edges.filter((edge) => edge.relationship === 'potential-group-role').every((edge) => edge.confidence === 'potential'));
});

test('owner absence requires complete relevant inventories and remains scoped', () => {
  const complete = run(replace(base(), 'entra.applicationOwners', []));
  assert.equal(findings(complete, 'WORKLOAD.OWNERSHIP.MISSING', 'fail').filter((finding) => finding.resourceId === 'app-a').length, 1);
  for (const status of ['partial', 'unavailable', 'not-configured'] as const) {
    const result = run(replace(base(), 'entra.applicationOwners', [], TENANT, status));
    assert.equal(findings(result, 'WORKLOAD.OWNERSHIP.MISSING', 'fail').filter((finding) => finding.resourceId === 'app-a').length, 0);
    assert.ok(findings(result, 'WORKLOAD.OWNERSHIP.MISSING', 'unable-to-assess').length);
  }
  const input = [...replace(base(), 'entra.applicationOwners', [], TENANT, 'partial'),
    collection('entra.applications', [{ id: 'app-a', appId: 'other-client', passwordCredentials: [], keyCredentials: [] }], 'tenant-b'),
    collection('entra.applicationOwners', [], 'tenant-b')];
  const result = run(input);
  assert.equal(findings(result, 'WORKLOAD.OWNERSHIP.MISSING', 'fail').filter((finding) => finding.scope === TENANT && finding.resourceId === 'app-a').length, 0);
  assert.equal(findings(result, 'WORKLOAD.OWNERSHIP.MISSING', 'fail').filter((finding) => finding.scope === 'tenant-b' && finding.resourceId === 'app-a').length, 1);
});

test('malformed owner parent relationships cannot prove ownerlessness', () => {
  const result = run(replace(base(), 'entra.applicationOwners', [{ id: 'owner-a', userType: 'Member' }]));
  assert.equal(findings(result, 'WORKLOAD.OWNERSHIP.MISSING', 'fail').filter((finding) => finding.resourceId === 'app-a').length, 0);
});

test('guest/external ownership uses explicit identity metadata and includes source evidence', () => {
  let input = replace(withGrant(), 'entra.applicationOwners', [{ id: 'owner-a', parentId: 'app-a' }]);
  input = replace(input, 'entra.users', [{ id: 'owner-a', userType: 'Guest', accountEnabled: true }]);
  const result = run(input);
  const external = findings(result, 'WORKLOAD.OWNERSHIP.EXTERNAL', 'fail');
  assert.ok(external.some((finding) => finding.resourceId === 'app-a'));
  assert.ok(external[0]!.evidence.some((ref) => ref.collectionId === 'entra.users'));
  assert.ok(risk(result).factors.some((factor) => factor.name === 'externalOwner'));
  assert.ok(findings(result, 'WORKLOAD.OWNERSHIP.PRIVILEGED', 'fail').length);
  assert.ok(result.graph.edges.filter((edge) => edge.relationship === 'potential-owner-control').every((edge) => edge.confidence === 'potential'));
});

test('external-looking names do not override Member evidence and owners are deduplicated', () => {
  const owner = { id: 'owner-a', parentId: 'app-a', userType: 'Member', displayName: 'Guest #EXT#' };
  const result = run(replace(base(), 'entra.applicationOwners', [owner, owner]), { ...DEFAULT_POLICY, maxOwners: 1 });
  assert.equal(findings(result, 'WORKLOAD.OWNERSHIP.EXTERNAL', 'fail').length, 0);
  assert.equal(findings(result, 'WORKLOAD.OWNERSHIP.EXCESSIVE', 'fail').length, 0);
});

test('credential lifecycle distinguishes expired, active, old and long validity periods', () => {
  const input = replace(base(), 'entra.applications', [{ id: 'app-a', appId: 'client-a', keyCredentials: [],
    passwordCredentials: [
      { keyId: 'expired', startDateTime: '2025-01-01T00:00:00Z', endDateTime: '2026-01-01T00:00:00Z' },
      { keyId: 'active', startDateTime: '2026-01-01T00:00:00Z', endDateTime: '2026-10-01T00:00:00Z' },
      { keyId: 'future', startDateTime: '2026-10-01T00:00:00Z', endDateTime: '2026-11-01T00:00:00Z' },
    ] }]);
  const result = run(input);
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.EXPIRED', 'fail').length, 1);
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.EXPIRING', 'fail').length, 1);
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.OLD', 'fail').length, 1);
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.LIFETIME', 'fail').length, 2);
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.MULTIPLE_ACTIVE', 'fail').length, 0);
  assert.ok(risk(result).factors.some((factor) => factor.name === 'persistentCredential'));
});

test('future activation and missing dates do not fabricate currently active or expired credentials', () => {
  const result = run(replace(base(), 'entra.applications', [{ id: 'app-a', appId: 'client-a', keyCredentials: [],
    passwordCredentials: [
      { keyId: 'future', startDateTime: '2026-10-01T00:00:00Z', endDateTime: '2026-11-01T00:00:00Z' },
      { keyId: 'undated', createdDateTime: '2020-01-01T00:00:00Z' },
    ] }]));
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.EXPIRED', 'fail').length, 0);
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.OLD', 'fail').length, 0);
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.CLIENT_SECRET').length, 0);
  assert.ok(findings(result, 'WORKLOAD.CREDENTIAL.DATES', 'unable-to-assess').length);
  assert.equal(risk(result).factors.some((factor) => factor.name === 'persistentCredential'), false);
});

test('conflicting credential key IDs are unknown rather than double-counted active credentials', () => {
  const result = run(replace(base(), 'entra.applications', [{ id: 'app-a', appId: 'client-a', keyCredentials: [],
    passwordCredentials: [
      { keyId: 'same', startDateTime: '2026-09-01T00:00:00Z', endDateTime: '2026-12-01T00:00:00Z' },
      { keyId: 'same', startDateTime: '2027-01-01T00:00:00Z', endDateTime: '2027-02-01T00:00:00Z' },
    ] }]));
  assert.equal(findings(result, 'WORKLOAD.CREDENTIAL.MULTIPLE_ACTIVE', 'fail').length, 0);
  assert.equal(risk(result).factors.some((factor) => factor.name === 'persistentCredential'), false);
  assert.ok(findings(result, 'WORKLOAD.CREDENTIAL.DATES', 'unable-to-assess').length);
});

test('multiple active credentials and persistent credentials remain risky when federation exists', () => {
  const input = replace(base(), 'entra.applications', [{ id: 'app-a', appId: 'client-a', keyCredentials: [],
    passwordCredentials: ['one', 'two'].map((keyId) => ({ keyId, startDateTime: '2026-09-01T00:00:00Z', endDateTime: '2026-12-01T00:00:00Z' })) }]);
  const before = run(input);
  const after = run(federated(input));
  assert.equal(findings(after, 'WORKLOAD.CREDENTIAL.MULTIPLE_ACTIVE', 'fail').length, 1);
  assert.equal(risk(after).score, risk(before).score);
  assert.ok(risk(after).factors.some((factor) => factor.name === 'persistentCredential'));
});

test('raw secret fields and unneeded descriptive payloads are never included in findings or graph', () => {
  const secret = 'test-secret-value-must-not-leak';
  const result = run(replace(base(), 'entra.applications', [{ id: 'app-a', appId: 'client-a',
    displayName: 'Deployment automation', description: secret, keyCredentials: [], passwordCredentials: [{ keyId: 'key-a', secretText: secret,
      value: secret, startDateTime: '2026-09-01T00:00:00Z', endDateTime: '2026-12-01T00:00:00Z' }] }]));
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('combined capabilities drive high-impact findings rather than a role-name list', () => {
  let input = withAzure(withGrant());
  input = replace(input, 'entra.appRoleAssignments', [
    { id: 'grant-a', parentId: 'sp-a', principalId: 'sp-a', resourceId: 'graph-api', appRoleId: APP_CONTROL },
    { id: 'grant-b', parentId: 'sp-a', principalId: 'sp-a', resourceId: 'graph-api', appRoleId: CONSENT },
  ]);
  const result = run(input);
  assert.equal(findings(result, 'WORKLOAD.PRIVILEGE.COMBINATION', 'fail')[0]!.severity, 'critical');
  assert.ok(risk(result).factors.some((factor) => factor.name === 'privilegeCombination'));
});

test('advisory scores are finite, capped and explainable even with invalid runtime weights', () => {
  const policy: RiskPolicy = { ...DEFAULT_POLICY, weights: { ...DEFAULT_POLICY.weights, apiPrivilege: 999,
    azurePrivilege: Number.POSITIVE_INFINITY, broadScope: Number.NaN, privilegeCombination: -10 } };
  const result = run(withAzure(withGrant()), policy);
  assert.ok(result.identityRisks.every((identity) => Number.isFinite(identity.score) && identity.score >= 0 && identity.score <= 100));
  assert.ok(result.identityRisks.flatMap((identity) => identity.factors).every((factor) => Number.isFinite(factor.weight)
    && factor.weight >= 0 && factor.explanation && factor.evidence.length));
  assert.equal(risk(result).score, 100);
  assert.equal(risk(result).incomplete, true);
  assert.match(risk(result).caveat, /not exploitability/);
});

test('Azure custom role exclusions subtract wildcard actions, not role names', () => {
  const result = run(withAzure(base(), [{ actions: ['*'], notActions: ['Microsoft.Authorization/*'],
    dataActions: [], notDataActions: [] }]));
  const description = findings(result, 'AZURE.RBAC.CAPABILITY', 'fail')[0]!.description;
  assert.doesNotMatch(description, /azure-role-assignment-write/);
  assert.match(description, /azure-compute-write/);
  const reader = run(withAzure(base(), [{ actions: ['*/read'], notActions: [], dataActions: [], notDataActions: [] }]));
  assert.equal(findings(reader, 'AZURE.RBAC.CAPABILITY', 'fail').length, 0);
  assert.ok(findings(reader, 'AZURE.RBAC.UNCLASSIFIED', 'unable-to-assess').length);
});

test('NotActions are per-block subtraction rather than a global deny', () => {
  const result = run(withAzure(base(), [
    { actions: ['*'], notActions: ['Microsoft.Authorization/*'], dataActions: [], notDataActions: [] },
    { actions: ['Microsoft.Authorization/roleAssignments/write'], notActions: [], dataActions: [], notDataActions: [] },
  ]));
  assert.match(findings(result, 'AZURE.RBAC.CAPABILITY', 'fail')[0]!.description, /azure-role-assignment-write/);
});

test('NotDataActions are honored without confusing control plane with data plane', () => {
  const result = run(withAzure(base(), [{ actions: ['*/read'], notActions: [],
    dataActions: ['Microsoft.Storage/*'], notDataActions: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*'] }]));
  assert.equal(findings(result, 'AZURE.RBAC.CAPABILITY', 'fail').length, 0);
});

test('Azure conditions and missing restrictions reduce confidence and keep access potential', () => {
  const conditional = run(withAzure(base(), [{ actions: ['*'], notActions: [], dataActions: [], notDataActions: [] }], 'uninterpreted condition'));
  assert.equal(findings(conditional, 'AZURE.RBAC.CAPABILITY', 'fail')[0]!.confidence, 'low');
  assert.equal(findings(conditional, 'AZURE.RBAC.CAPABILITY', 'fail')[0]!.severity, 'medium');
  assert.equal(risk(conditional).incomplete, true);
  const missing = run(withAzure(base(), [{ actions: ['*'], dataActions: [] }]));
  assert.match(findings(missing, 'AZURE.RBAC.CAPABILITY', 'fail')[0]!.description, /not visible/);
});

test('a role definition with a matching suffix in a different subscription is not substituted', () => {
  const input = withAzure();
  const definition = input.find((source) => source.id === 'azure.roleDefinitions')!.records[0]!;
  const result = run(replace(input, 'azure.roleDefinitions', [{ ...definition,
    id: '/subscriptions/other/providers/Microsoft.Authorization/roleDefinitions/custom-role' }], SUB));
  assert.equal(findings(result, 'AZURE.RBAC.CAPABILITY', 'fail').length, 0);
  assert.ok(findings(result, 'AZURE.RBAC.UNCLASSIFIED', 'unable-to-assess').length);
});

test('resource identity relationships require matching principal IDs, not names or client IDs', () => {
  const input = replace(withAzure(), 'azure.resources', [
    { id: `${SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/app`, type: 'Microsoft.Web/sites',
      identity: { principalId: 'sp-a', tenantId: TENANT } },
    { id: `${SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/other`, type: 'Microsoft.Web/sites',
      identity: { principalId: 'client-a', tenantId: TENANT } },
  ], SUB);
  const result = run(input);
  const edges = result.graph.edges.filter((edge) => edge.relationship === 'uses-managed-identity');
  assert.equal(edges.length, 2);
  const sp = result.graph.nodes.find((node) => node.type === 'identity' && node.properties.resourceId === 'sp-a')!;
  assert.equal(edges.filter((edge) => edge.to === sp.id).length, 1);
});

test('Azure scope matching respects resource-group segment boundaries', () => {
  let input = withAzure();
  const binding = input.find((source) => source.id === 'azure.roleAssignments')!.records[0]!;
  input = replace(input, 'azure.roleAssignments', [{ ...binding, properties: { ...(binding.properties as JsonObject),
    scope: `${SUB}/resourceGroups/rg` } }], SUB);
  input = replace(input, 'azure.resources', [
    { id: `${SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/a`, type: 'Microsoft.Web/sites' },
    { id: `${SUB}/resourceGroups/rg-other/providers/Microsoft.Web/sites/b`, type: 'Microsoft.Web/sites' },
  ], SUB);
  assert.equal(run(input).graph.edges.filter((edge) => edge.relationship === 'potential-control-within-scope').length, 1);
});

test('MFA registration is distinct from enforced MFA and CA presence is not coverage', () => {
  const result = run(base());
  assert.equal(findings(result, 'ENTRA.MFA.REGISTRATION', 'informational').length, 1);
  assert.equal(findings(result, 'ENTRA.MFA.ENFORCEMENT', 'unable-to-assess').length, 1);
  assert.equal(findings(result, 'ENTRA.CA.INVENTORY', 'pass').length, 0);
  assert.equal(findings(result, 'ENTRA.CA.INVENTORY', 'informational').length, 1);
});

test('explicit unregistered privileged users are prioritized, missing registration is not assumed false', () => {
  let input = replace(base(), 'entra.directoryRoleAssignments', [{ id: 'dir-a', principalId: 'owner-a',
    roleDefinitionId: 'role-global', directoryScopeId: '/' }]);
  input = replace(input, 'entra.authenticationRegistration', [{ id: 'owner-a', isMfaRegistered: false }]);
  assert.equal(findings(run(input), 'ENTRA.MFA.REGISTRATION', 'fail')[0]!.severity, 'high');
  const missing = run(replace(input, 'entra.authenticationRegistration', []));
  assert.equal(findings(missing, 'ENTRA.MFA.REGISTRATION', 'fail').length, 0);
  assert.ok(findings(missing, 'ENTRA.MFA.REGISTRATION', 'unable-to-assess').length);
});

test('no enabled CA is a limited inventory finding only on complete known states', () => {
  assert.equal(findings(run(replace(base(), 'entra.conditionalAccess', [])), 'ENTRA.CA.INVENTORY', 'fail').length, 1);
  for (const status of ['partial', 'unavailable'] as const) {
    const result = run(replace(base(), 'entra.conditionalAccess', [], TENANT, status));
    assert.equal(findings(result, 'ENTRA.CA.INVENTORY', 'fail').length, 0);
    assert.ok(findings(result, 'ENTRA.CA.INVENTORY', 'unable-to-assess').length);
  }
  assert.equal(findings(run(replace(base(), 'entra.conditionalAccess', [{ id: 'unknown' }])), 'ENTRA.CA.INVENTORY', 'fail').length, 0);
});

test('risk events preserve resolved state and inactivity uses successful sign-ins only', () => {
  let input = replace(base(), 'entra.riskyUsers', [
    { id: 'risk-a', riskState: 'dismissed', riskLevel: 'high' },
    { id: 'risk-b', riskState: 'atRisk', riskLevel: 'high' },
  ]);
  input = replace(input, 'entra.users', [{ id: 'owner-a', accountEnabled: true, userType: 'Member',
    signInActivity: { lastSignInDateTime: '2020-01-01T00:00:00Z' } }]);
  const result = run(input);
  assert.equal(findings(result, 'ENTRA.IDENTITY.RISK', 'fail').length, 1);
  assert.equal(findings(result, 'ENTRA.USER.DORMANT', 'fail').length, 0);
  assert.equal(findings(result, 'ENTRA.USER.DORMANT', 'unable-to-assess').length, 1);
});

test('Secure Score improvement checks use matched current control profiles, not full policy claims', () => {
  const result = run([
    collection('m365.secureScores', [
      { id: 'older', createdDateTime: '2026-01-01T00:00:00Z', controlScores: [{ controlName: 'control-a', score: 0 }] },
      { id: 'newer', createdDateTime: '2026-09-28T00:00:00Z', controlScores: [{ controlName: 'control-a', score: 5 }, { controlName: 'control-b', score: 1 }] },
    ]),
    collection('m365.secureScoreControls', [{ id: 'control-a', maxScore: 5 }, { id: 'control-b', maxScore: 10 }]),
    collection('m365.licenses', [{ id: 'license-a', skuPartNumber: 'EXAMPLE' }]),
  ]);
  assert.equal(findings(result, 'M365.SECURESCORE.CONTROL', 'fail').length, 1);
  assert.equal(findings(result, 'M365.SECURESCORE.CONTROL', 'fail')[0]!.resourceId, 'control-b');
  assert.ok(findings(result, 'M365.POLICY.COVERAGE', 'unable-to-assess').length);
});

test('Intune/Defender matches require unique stable device IDs and complete relevant inventories', () => {
  const input = [
    collection('intune.devices', [{ id: 'intune-a', azureADDeviceId: 'device-a', operatingSystem: 'Windows', complianceState: 'noncompliant',
      lastSyncDateTime: '2026-09-28T00:00:00Z' }]),
    collection('defender.machines', [{ id: 'machine-a', aadDeviceId: 'device-a', onboardingStatus: 'Onboarded', healthStatus: 'Active' }]),
  ];
  const complete = run(input);
  assert.equal(complete.graph.edges.filter((edge) => edge.relationship === 'same-entra-device-id').length, 1);
  assert.equal(findings(complete, 'INTUNE.DEVICE.COMPLIANCE', 'fail').length, 1);
  const partial = run(replace(input, 'defender.machines', [], TENANT, 'partial'));
  assert.equal(findings(partial, 'ENDPOINT.INVENTORY.MATCH', 'fail').length, 0);
  assert.ok(findings(partial, 'ENDPOINT.INVENTORY.MATCH', 'unable-to-assess').length);
  const absent = run(replace(input, 'defender.machines', []));
  assert.equal(findings(absent, 'ENDPOINT.INVENTORY.MATCH', 'fail').length, 1);
});

test('ambiguous same-device IDs cannot manufacture a cross-inventory identity edge', () => {
  const result = run([
    collection('intune.devices', [{ id: 'intune-a', azureADDeviceId: 'device-a', complianceState: 'compliant' },
      { id: 'intune-b', azureADDeviceId: 'device-a', complianceState: 'compliant' }]),
    collection('defender.machines', [{ id: 'machine-a', aadDeviceId: 'device-a' }]),
  ]);
  assert.equal(result.graph.edges.filter((edge) => edge.relationship === 'same-entra-device-id').length, 0);
});

test('Azure security checks require explicit properties and do not infer public blob data', () => {
  const resource = { id: `${SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account`,
    type: 'Microsoft.Storage/storageAccounts', properties: { publicNetworkAccess: 'Enabled',
      allowBlobPublicAccess: true, supportsHttpsTrafficOnly: true, allowSharedKeyAccess: false } };
  const incompleteNetwork = run([collection('azure.resources', [resource], SUB)]);
  assert.equal(findings(incompleteNetwork, 'AZURE.NETWORK.PUBLIC_CONFIGURATION', 'fail').length, 0);
  assert.ok(findings(incompleteNetwork, 'AZURE.NETWORK.PUBLIC_CONFIGURATION', 'unable-to-assess').length);
  assert.match(findings(incompleteNetwork, 'AZURE.STORAGE.ANONYMOUS_CAPABILITY', 'fail')[0]!.description, /not evidence/);
  const open = run([collection('azure.resources', [{ ...resource, properties: { ...resource.properties, networkAcls: { defaultAction: 'Allow' } } }], SUB, 'partial')]);
  assert.equal(findings(open, 'AZURE.NETWORK.PUBLIC_CONFIGURATION', 'fail').length, 1);
  assert.equal(findings(open, 'AZURE.STORAGE.HTTPS', 'pass').length, 0);
});

test('Key Vault missing properties are unknown, explicit recovery-control disablement is observed', () => {
  const result = run([collection('azure.resources', [
    { id: `${SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/a`, type: 'Microsoft.KeyVault/vaults', properties: {} },
    { id: `${SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/b`, type: 'Microsoft.KeyVault/vaults',
      properties: { enablePurgeProtection: false, enableSoftDelete: false } },
  ], SUB)]);
  assert.equal(findings(result, 'AZURE.KEYVAULT.PURGE_PROTECTION', 'unable-to-assess').length, 1);
  assert.equal(findings(result, 'AZURE.KEYVAULT.PURGE_PROTECTION', 'fail').length, 1);
});

test('Defender Free tier is a workload-scoped review, not a universal paid-plan requirement', () => {
  const result = run([
    collection('azure.resources', [{ id: `${SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/a`, type: 'Microsoft.Compute/virtualMachines' }], SUB),
    collection('defenderCloud.pricings', [{ id: `${SUB}/providers/Microsoft.Security/pricings/VirtualMachines`,
      name: 'VirtualMachines', properties: { pricingTier: 'Free' } }], SUB),
    collection('defenderCloud.assessments', [{ id: 'assessment-a', properties: { status: { code: 'Unhealthy' } } }], SUB, 'partial'),
  ]);
  const plan = findings(result, 'DEFENDER.CLOUD.PLAN', 'informational');
  assert.equal(plan.length, 1);
  assert.match(plan[0]!.description, /not universally mandatory/);
  assert.equal(findings(result, 'DEFENDER.CLOUD.ASSESSMENT', 'fail').length, 1);
});

test('GitHub omitted capability is unknown rather than disabled or not licensed', () => {
  const result = run(github());
  const unknown = findings(result, 'GITHUB.SECURITY.CAPABILITY', 'unable-to-assess');
  assert.equal(unknown.length, 5);
  assert.equal(findings(result, 'GITHUB.SECURITY.CAPABILITY', 'fail').length, 0);
  const input = replace(github(), 'github.repositories', [{ id: 'id-org/repo', full_name: 'org/repo', default_branch: 'main',
    security_and_analysis: { secret_scanning: { status: 'disabled' }, secret_scanning_push_protection: { status: 'enabled' } } }], 'org');
  assert.equal(findings(run(input), 'GITHUB.SECURITY.CAPABILITY', 'fail').length, 1);
  assert.equal(findings(run(input), 'GITHUB.SECURITY.CAPABILITY', 'pass').length, 1);
});

test('GitHub branch absence needs complete classic and alternative-protection inventories', () => {
  assert.equal(findings(run(github()), 'GITHUB.BRANCH.PROTECTION', 'fail').length, 1);
  for (const status of ['partial', 'unavailable', 'not-configured'] as const) {
    const result = run(replace(github(), 'github.branchProtection', [], 'org/repo', status));
    assert.equal(findings(result, 'GITHUB.BRANCH.PROTECTION', 'fail').length, 0);
    assert.equal(findings(result, 'GITHUB.BRANCH.PROTECTION', 'unable-to-assess').length, 1);
  }
  const missingRulesets = run(github().filter((source) => source.id !== 'github.rulesets'));
  assert.equal(findings(missingRulesets, 'GITHUB.BRANCH.PROTECTION', 'fail').length, 0);
});

test('applicable active rulesets are valid alternatives to classic branch protection', () => {
  const ruleset = { id: 'ruleset-a', repository: 'org/repo', enforcement: 'active', target: 'branch',
    conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } },
    rules: [{ type: 'pull_request', parameters: { required_approving_review_count: 2 } }] };
  const result = run(replace(github(), 'github.rulesets', [ruleset], 'org/repo'));
  assert.equal(findings(result, 'GITHUB.BRANCH.PROTECTION', 'fail').length, 0);
  assert.equal(findings(result, 'GITHUB.BRANCH.PROTECTION', 'pass').length, 1);
  assert.equal(findings(result, 'GITHUB.BRANCH.REVIEWS', 'fail').length, 0);
  const otherBranch = run(replace(github(), 'github.rulesets', [{ ...ruleset,
    conditions: { ref_name: { include: ['refs/heads/other'], exclude: [] } } }], 'org/repo'));
  assert.equal(findings(otherBranch, 'GITHUB.BRANCH.PROTECTION', 'fail').length, 1);
});

test('unknown ruleset applicability and rules are never treated as absent protection', () => {
  const cases: JsonObject[] = [
    { id: 'rs', repository: 'org/repo', enforcement: 'active', target: 'branch' },
    { id: 'rs', repository: 'org/repo', enforcement: 'active', target: 'branch',
      conditions: { ref_name: { include: ['refs/heads/*'], exclude: [] } }, rules: [{ type: 'pull_request' }] },
  ];
  for (const ruleset of cases) {
    const result = run(replace(github(), 'github.rulesets', [ruleset], 'org/repo'));
    assert.equal(findings(result, 'GITHUB.BRANCH.PROTECTION', 'fail').length, 0);
    assert.ok(findings(result, 'GITHUB.BRANCH.PROTECTION', 'unable-to-assess').length);
  }
});

test('write tokens, runners and exact environment reviewers retain their manual boundaries', () => {
  let input = replace(github(), 'github.workflowPermissions', [{ id: 'permission', repository: 'org/repo',
    default_workflow_permissions: 'write' }], 'org/repo');
  input = replace(input, 'github.environments', [{ id: 'environment', repository: 'org/repo', name: 'production', protection_rules: [] }], 'org/repo');
  input.push(collection('github.runners', [{ id: 'runner-a', labels: [{ name: 'self-hosted' }] }], 'org'));
  const result = run(input);
  assert.equal(findings(result, 'GITHUB.WORKFLOW.TOKEN', 'fail').length, 1);
  assert.equal(findings(result, 'GITHUB.ENVIRONMENT.REVIEWERS', 'fail').length, 1);
  assert.equal(findings(result, 'GITHUB.RUNNER.TRUST', 'informational').length, 1);
  assert.match(findings(result, 'GITHUB.RUNNER.TRUST')[0]!.description, /no particular repository/);
  assert.equal(findings(run(replace(input, 'github.environments',
    [{ id: 'environment', repository: 'org/repo', name: 'production' }], 'org/repo', 'partial')),
  'GITHUB.ENVIRONMENT.REVIEWERS', 'fail').length, 0);
});

test('exact repo/ref, federation, app/SP and Azure principal relationships produce only potential paths', () => {
  const result = run(federated());
  const correlated = findings(result, 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail');
  assert.equal(correlated.length, 1);
  assert.equal(correlated[0]!.confidence, 'medium');
  assert.match(correlated[0]!.description, /No exploitable attack path is claimed/);
  for (const id of ['github.repositories', 'github.branchProtection', 'entra.federatedCredentials',
    'entra.applications', 'entra.servicePrincipals', 'azure.roleAssignments', 'azure.roleDefinitions']) {
    assert.ok(correlated[0]!.evidence.some((ref) => ref.collectionId === id), id);
  }
  assert.ok(risk(result).factors.some((factor) => factor.name === 'codeToCloud'));
  assert.ok(result.graph.edges.some((edge) => edge.relationship === 'potential-federation-subject' && edge.confidence === 'potential'));
});

test('federation matching rejects issuer/audience/subject lookalikes and mismatched repository casing', () => {
  const cases: JsonObject[] = [
    { issuer: 'https://token.actions.githubusercontent.com.evil.example' },
    { issuer: 'https://token.actions.githubusercontent.com/' },
    { audiences: ['different-audience'] }, { audiences: ['api://AzureADTokenExchange', 'extra'] },
    { audiences: ['api://AzureADTokenExchange', 42] },
    { subject: 'repo:org/repo:ref:refs/heads/*' },
    { subject: 'repo:Org/repo:ref:refs/heads/main' },
    { subject: 'repo:other/repo:ref:refs/heads/main' },
  ];
  for (const overrides of cases) {
    const result = run(federated(undefined, overrides));
    assert.equal(findings(result, 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 0, JSON.stringify(overrides));
    assert.equal(result.graph.edges.filter((edge) => edge.relationship === 'potential-federation-subject').length, 0);
  }
});

test('a default branch weakness cannot be substituted for another trusted ref/event/environment', () => {
  for (const subject of ['repo:org/repo:ref:refs/heads/staging', 'repo:org/repo:pull_request',
    'repo:org/repo:environment:production', 'repo:org/repo:ref:refs/tags/v1']) {
    assert.equal(findings(run(federated(undefined, { subject })), 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 0, subject);
  }
});

test('environment federation is scoped to the exact repository and encoded environment name', () => {
  const input = replace(github(withAzure()), 'github.environments', [
    { id: 'env-a', repository: 'org/repo', name: 'Production:V1', protection_rules: [] },
  ], 'org/repo');
  assert.equal(findings(run(federated(input, { subject: 'repo:org/repo:environment:Production%3AV1' })),
    'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 1);
  assert.equal(findings(run(federated(input, { subject: 'repo:org/repo:environment:production%3AV1' })),
    'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 0);
});

test('distinct repository scopes cannot leak protection or federation evidence into each other', () => {
  let input = github(github(withAzure()), 'other/repo');
  input = replace(input, 'github.branchProtection', [{ id: 'bp', repository: 'other/repo', branch: 'main', protected: true,
    required_pull_request_reviews: { required_approving_review_count: 2 } }], 'other/repo');
  const result = run(federated(input));
  const correlated = findings(result, 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail')[0]!;
  assert.ok(correlated);
  assert.ok(!correlated.evidence.some((ref) => ref.scope === 'other/repo'));
  const missing = findings(result, 'GITHUB.BRANCH.PROTECTION', 'fail');
  assert.equal(missing.length, 1);
  assert.equal(missing[0]!.scope, 'org/repo');
});

test('Azure DevOps federation metadata never proves a service connection or pipeline authorization', () => {
  const input = withAzure();
  input.push(collection('azureDevOps.projects', [{ id: 'project-a', name: 'Project', visibility: 'private' }], 'org/project-a'));
  input.push(collection('azureDevOps.pipelines', [{ id: 'pipeline-a', name: 'Connection' }], 'org/project-a'));
  const result = run(federated(input, { issuer: 'https://vstoken.dev.azure.com/11111111-1111-1111-1111-111111111111',
    subject: 'sc://org/Project/Connection' }));
  assert.equal(findings(result, 'CODETOCLOUD.ADO.FEDERATION', 'unable-to-assess').length, 1);
  assert.equal(findings(result, 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 0);
  assert.equal(risk(result).factors.some((factor) => factor.name === 'codeToCloud'), false);
  assert.equal(result.graph.edges.some((edge) => edge.relationship.includes('pipeline-identity')), false);
});

test('ADO policy scope is matched by repository ID and ref, not name or unproven bypass', () => {
  const scope = 'org/project-a';
  const input = [
    collection('azureDevOps.projects', [{ id: 'project-a', visibility: 'public' }], scope),
    collection('azureDevOps.repositories', [{ id: 'repo-a', defaultBranch: 'refs/heads/main', project: { id: 'project-a' } }], scope),
    collection('azureDevOps.branchPolicies', [{ id: 'policy-a', isEnabled: true, isBlocking: true,
      settings: { scope: [{ repositoryId: 'repo-a', refName: 'refs/heads/main', matchKind: 'Exact' }] } }], scope),
  ];
  const result = run(input);
  assert.equal(findings(result, 'ADO.PROJECT.PUBLIC', 'fail').length, 1);
  assert.equal(findings(result, 'ADO.BRANCH.POLICY', 'fail').length, 0);
  assert.equal(findings(result, 'ADO.BRANCH.POLICY', 'informational').length, 1);
  const missing = run(replace(input, 'azureDevOps.branchPolicies', [], scope));
  assert.equal(findings(missing, 'ADO.BRANCH.POLICY', 'fail').length, 1);
  const unknown = run(replace(input, 'azureDevOps.branchPolicies', [], scope, 'partial'));
  assert.equal(findings(unknown, 'ADO.BRANCH.POLICY', 'fail').length, 0);
});

test('positive risk can be observed on partial input; unavailable records are never interpreted', () => {
  const input = withGrant();
  const grants = input.find((source) => source.id === 'entra.appRoleAssignments')!.records;
  assert.equal(findings(run(replace(input, 'entra.appRoleAssignments', grants, TENANT, 'partial')),
    'WORKLOAD.API.APPLICATION', 'fail').length, 1);
  assert.equal(findings(run(replace(input, 'entra.appRoleAssignments', grants, TENANT, 'unavailable')),
    'WORKLOAD.API.APPLICATION', 'fail').length, 0);
});

test('all findings are documented, Zero Trust mapped, stable, deduplicated and backed by record references', () => {
  const input = federated();
  const before = structuredClone(input);
  const result = run(input);
  assert.deepEqual(input, before);
  const reversed = input.slice().reverse().map((source) => ({ ...source, records: source.records.slice().reverse() }));
  assert.deepEqual(result, run(reversed));
  assert.deepEqual(result, run([...input, ...input]));
  assert.equal(new Set(result.findings.map((finding) => finding.id)).size, result.findings.length);
  assert.equal(new Set(result.graph.edges.map((edge) => edge.id)).size, result.graph.edges.length);
  assert.ok(result.findings.every((finding) => finding.references.length && finding.zeroTrust.length
    && finding.references.every((url) => url.startsWith('https://'))));
  const nodes = new Set(result.graph.nodes.map((node) => node.id));
  for (const edge of result.graph.edges) {
    assert.ok(nodes.has(edge.from) && nodes.has(edge.to));
    assert.ok(edge.evidence.length);
  }
  const refs = [...result.findings.flatMap((finding) => finding.evidence),
    ...result.graph.nodes.flatMap((node) => node.evidence), ...result.graph.edges.flatMap((edge) => edge.evidence)];
  for (const ref of refs.filter((ref) => ref.recordId !== undefined)) {
    assert.ok(input.some((source) => source.id === ref.collectionId && source.scope === ref.scope
      && source.records.some((record) => String(record.id) === ref.recordId)), JSON.stringify(ref));
  }
});

test('invalid calendar dates are not normalized into valid credential history', () => {
  const result = run(replace(base(), 'entra.applications', [{ id: 'app-a', appId: 'client-a', keyCredentials: [],
    passwordCredentials: [{ keyId: 'invalid', startDateTime: '2026-02-30T00:00:00Z', endDateTime: '2026-12-01T00:00:00Z' }] }]));
  assert.ok(findings(result, 'WORKLOAD.CREDENTIAL.DATES', 'unable-to-assess').length);
  assert.equal(risk(result).factors.some((factor) => factor.name === 'persistentCredential'), false);
});

test('conflicting complete collector records cannot yield secure-state passes', () => {
  const secure = { id: `${SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a`,
    type: 'Microsoft.Storage/storageAccounts', properties: { supportsHttpsTrafficOnly: true } };
  const result = run([
    collection('azure.resources', [secure], SUB),
    collection('azure.resources', [{ ...secure, properties: { supportsHttpsTrafficOnly: false } }], SUB),
  ]);
  assert.equal(findings(result, 'AZURE.STORAGE.HTTPS', 'pass').length, 0);
  assert.equal(findings(result, 'AZURE.STORAGE.HTTPS', 'fail').length, 1);
});

test('repository selectors in rulesets must match before protection can be credited', () => {
  const ruleset = { id: 'ruleset-a', repository: 'org/repo', enforcement: 'active', target: 'branch',
    conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] }, repository_id: { repository_ids: ['different-id'] } },
    rules: [{ type: 'pull_request', parameters: { required_approving_review_count: 2 } }] };
  const result = run(replace(github(), 'github.rulesets', [ruleset], 'org/repo'));
  assert.equal(findings(result, 'GITHUB.BRANCH.PROTECTION', 'pass').length, 0);
  assert.equal(findings(result, 'GITHUB.BRANCH.PROTECTION', 'fail').length, 1);
  const unknown = { ...ruleset, conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] },
    repository_property: { arbitrary: 'not collected' } } };
  const unresolved = run(replace(github(), 'github.rulesets', [unknown], 'org/repo'));
  assert.equal(findings(unresolved, 'GITHUB.BRANCH.PROTECTION', 'pass').length, 0);
  assert.equal(findings(unresolved, 'GITHUB.BRANCH.PROTECTION', 'fail').length, 0);
});

test('tenant-root Azure scope is not projected across a different tenant', () => {
  let input = withAzure();
  const assignment = input.find((source) => source.id === 'azure.roleAssignments')!.records[0]!;
  input = replace(input, 'azure.roleAssignments', [{ ...assignment, properties: { ...(assignment.properties as JsonObject), scope: '/' } }], SUB);
  input = replace(input, 'azure.resources', [{ id: `${SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/a`, type: 'Microsoft.Web/sites' }], SUB);
  input.push(collection('azure.subscriptions', [{ id: '/subscriptions/other', tenantId: 'tenant-b' }], '/subscriptions/other'));
  input.push(collection('azure.resources', [{ id: '/subscriptions/other/resourceGroups/rg/providers/Microsoft.Web/sites/b', type: 'Microsoft.Web/sites' }], '/subscriptions/other'));
  const result = run(input);
  assert.equal(result.graph.edges.filter((edge) => edge.relationship === 'potential-control-within-scope').length, 1);
});

test('ambiguous application IDs cannot create app/service-principal federation correlations', () => {
  const input = federated();
  const apps = input.find((source) => source.id === 'entra.applications')!.records;
  const result = run(replace(input, 'entra.applications', [...apps, { ...apps[0]!, id: 'app-other' }]));
  assert.equal(result.graph.edges.filter((edge) => edge.relationship === 'application-service-principal').length, 0);
  assert.equal(findings(result, 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 0);
});

test('unknown Defender health is missing evidence rather than an observed failure', () => {
  const result = run([collection('defender.machines', [{ id: 'machine-a', onboardingStatus: 'InsufficientInfo', healthStatus: 'Unknown' }])]);
  assert.equal(findings(result, 'DEFENDER.ENDPOINT.POSTURE', 'fail').length, 0);
  assert.equal(findings(result, 'DEFENDER.ENDPOINT.POSTURE', 'unable-to-assess').length, 1);
});

test('future Secure Score snapshots do not fabricate current improvement evidence', () => {
  const result = run([
    collection('m365.secureScores', [{ id: 'future', createdDateTime: '2027-01-01T00:00:00Z',
      controlScores: [{ controlName: 'control-a', score: 0 }] }]),
    collection('m365.secureScoreControls', [{ id: 'control-a', maxScore: 10 }]),
  ]);
  assert.equal(findings(result, 'M365.SECURESCORE.CONTROL', 'fail').length, 0);
  assert.ok(findings(result, 'M365.SECURESCORE.CONTROL', 'unable-to-assess').length);
});

test('malformed protection metadata cannot establish missing branch or environment controls', () => {
  let input = replace(github(), 'github.rulesets', [{ id: 'rule', repository: 'org/repo', enforcement: 'active', target: 'branch',
    conditions: { ref_name: { include: [42], exclude: [] } }, rules: [{ type: 'pull_request' }] }], 'org/repo');
  input = replace(input, 'github.environments', [{ id: 'env', repository: 'org/repo', name: 'production', protection_rules: [42] }], 'org/repo');
  const result = run(input);
  assert.equal(findings(result, 'GITHUB.BRANCH.PROTECTION', 'fail').length, 0);
  assert.equal(findings(result, 'GITHUB.ENVIRONMENT.REVIEWERS', 'fail').length, 0);
  assert.ok(findings(result, 'GITHUB.ENVIRONMENT.REVIEWERS', 'unable-to-assess').length);
});

test('a supported environment name containing spaces is matched exactly', () => {
  const input = replace(github(withAzure()), 'github.environments', [
    { id: 'env-a', repository: 'org/repo', name: 'Production West', protection_rules: [] },
  ], 'org/repo');
  assert.equal(findings(run(federated(input, { subject: 'repo:org/repo:environment:Production West' })),
    'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 1);
});

test('custom authentication role classification uses the documented basic/update action', () => {
  let input = replace(base(), 'entra.directoryRoleDefinitions', [{ id: 'role-auth',
    rolePermissions: [{ allowedResourceActions: ['microsoft.directory/users/authenticationMethods/basic/update'] }] }]);
  input = replace(input, 'entra.directoryRoleAssignments', [{ id: 'auth-role', principalId: 'sp-a',
    roleDefinitionId: 'role-auth', directoryScopeId: '/' }]);
  const result = run(input);
  assert.match(findings(result, 'ENTRA.ROLE.PRIVILEGED', 'fail')[0]!.description, /authentication-method-control/);
  const unsupported = replace(input, 'entra.directoryRoleDefinitions', [{ id: 'role-auth',
    rolePermissions: [{ allowedResourceActions: ['microsoft.directory/users/authenticationMethods/update'] }] }]);
  assert.equal(findings(run(unsupported), 'ENTRA.ROLE.PRIVILEGED', 'fail').length, 0);
});

test('global coverage placeholders and sparse evidence satisfy snapshot reference validation', () => {
  const tenantId = '11111111-1111-4111-8111-111111111111';
  const input: CollectionResult[] = [
    collection('entra.users', [{ id: 'user-a', userType: 'Member', accountEnabled: true }], tenantId),
    ...COLLECTION_CATALOG.filter((definition) => definition.id !== 'entra.users').map((definition): CollectionResult => ({
      id: definition.id, provider: definition.provider,
      scope: definition.provider === 'graph' || definition.provider === 'defender' || definition.id === 'azure.managementGroups'
        ? tenantId : 'assessment',
      status: 'unavailable', reason: 'dependency-unavailable', collectedAt: NOW.toISOString(), records: [],
    })),
  ];
  const result = run(input);
  const snapshot = {
    kind: 'cloud-security-assessment', schemaVersion: '1.0', toolVersion: '0.1.0', assessmentId: 'snapshot-fixture',
    scope: { tenantId, subscriptionIds: [], githubOrganizations: [], azureDevOpsOrganizations: [] },
    collectedAt: NOW.toISOString(), collections: input, policy: DEFAULT_POLICY, coverage: [], ...result,
  };
  assert.doesNotThrow(() => parseSnapshot(snapshot));
  const sparse = [input[0]!];
  assert.doesNotThrow(() => parseSnapshot({ ...snapshot, collections: sparse, ...run(sparse) }));
  const global: CollectionResult[] = input.map((source) => source.id === 'entra.users'
    ? { ...source, status: 'partial', reason: 'limit-reached' }
    : { ...source, scope: 'assessment' });
  const partialAnalysis = run(global);
  assert.doesNotThrow(() => parseSnapshot({ ...snapshot, collections: global, ...partialAnalysis }));
  assert.equal(partialAnalysis.findings.some((finding) => finding.status === 'pass'), false);
  assert.equal(findings(partialAnalysis, 'WORKLOAD.OWNERSHIP.MISSING', 'fail').length, 0);
  for (const ref of result.findings.flatMap((finding) => finding.evidence)) {
    assert.ok(input.some((source) => source.id === ref.collectionId && source.scope === ref.scope));
  }
});

test('full code-to-cloud findings, graph and scoring satisfy parent snapshot validation', () => {
  const tenantId = '11111111-1111-4111-8111-111111111111';
  const subscriptionId = '22222222-2222-4222-8222-222222222222';
  const input = JSON.parse(JSON.stringify(federated())
    .replaceAll(TENANT, tenantId).replaceAll(SUB, `/subscriptions/${subscriptionId}`)) as CollectionResult[];
  const result = run(input);
  const snapshot = parseSnapshot({
    kind: 'cloud-security-assessment', schemaVersion: '1.0', toolVersion: '0.1.0', assessmentId: 'correlation-fixture',
    scope: { tenantId, subscriptionIds: [subscriptionId], githubOrganizations: ['org'], azureDevOpsOrganizations: [] },
    collectedAt: NOW.toISOString(), collections: input, policy: DEFAULT_POLICY, coverage: [], ...result,
  });
  assert.equal(findings(snapshot, 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 1);
  assert.ok(snapshot.identityRisks.some((identity) => identity.factors.some((factor) => factor.name === 'codeToCloud')));
});

test('createAssessment with only one enabled user preserves valid evidence references', () => {
  const tenantId = '11111111-1111-4111-8111-111111111111';
  const snapshot = createAssessment({
    schemaVersion: '1.0',
    scope: { tenantId, subscriptionIds: [], githubOrganizations: [], azureDevOpsOrganizations: [] },
    collectedAt: NOW.toISOString(),
    collections: [collection('entra.users', [{ id: 'u1', accountEnabled: true }], tenantId)],
  });
  assert.doesNotThrow(() => parseSnapshot(snapshot));
  assert.ok(snapshot.findings.some((finding) => finding.status === 'unable-to-assess'));
  assert.equal(snapshot.findings.some((finding) => finding.status === 'pass'), false);
  assert.equal(snapshot.graph.nodes.length, 1);
});

test('unknown evidence helpers never fabricate a collection scope or borrow another tenant', () => {
  const context = new Context([
    collection('entra.users', [{ id: 'u1', accountEnabled: true }]),
    collection('entra.riskySignIns', [], 'assessment', 'unavailable'),
    collection('entra.conditionalAccess', [], 'assessment', 'unavailable'),
    collection('entra.groups', [], 'another-tenant'),
  ], DEFAULT_POLICY, NOW);
  assert.deepEqual(context.inventoryEvidence('entra.riskySignIns', TENANT),
    [{ collectionId: 'entra.riskySignIns', scope: 'assessment' }]);
  assert.deepEqual(context.inventoryEvidence('entra.conditionalAccess', TENANT),
    [{ collectionId: 'entra.conditionalAccess', scope: 'assessment' }]);
  assert.deepEqual(context.inventoryEvidence('entra.users', 'assessment'), []);
  assert.deepEqual(context.inventoryEvidence('entra.groups', TENANT), []);
  assert.deepEqual(context.inventoryEvidence('entra.directoryRoleAssignments', TENANT), []);
  assert.equal(context.complete('entra.riskySignIns', TENANT), false);
});

test('dedicated Defender API casing and numeric incident relationships are normalized', () => {
  const result = run([
    collection('defender.incidents', [
      { id: '42', incidentId: 42, incidentName: 'Incident metadata', status: 'Active', severity: 'High' },
      { id: '43', incidentId: 43, status: 'Resolved', severity: 'High' },
    ]),
    collection('defender.alerts', [
      { id: 'alert-a', incidentId: 42, machineId: 'machine-a', status: 'New', severity: 'High' },
      { id: 'alert-b', incidentId: 42, status: 'InProgress', severity: 'Medium' },
      { id: 'alert-c', incidentId: 42, status: 'Resolved', severity: 'High' },
      { id: 'alert-d', incidentId: 42, status: 'New', severity: 'Informational' },
    ]),
    collection('defender.machines', [{ id: 'machine-a', aadDeviceId: 'device-a',
      onboardingStatus: 'Onboarded', healthStatus: 'Active', riskScore: 'None', exposureLevel: 'Low' }]),
  ]);
  assert.equal(findings(result, 'DEFENDER.XDR.INCIDENT', 'fail').length, 1);
  assert.equal(findings(result, 'DEFENDER.XDR.INCIDENT', 'fail')[0]!.severity, 'high');
  assert.equal(findings(result, 'DEFENDER.XDR.ALERT', 'fail').length, 2);
  assert.equal(findings(result, 'DEFENDER.XDR.ALERT', 'informational')[0]!.severity, 'informational');
  assert.equal(result.graph.edges.filter((edge) => edge.relationship === 'alert-in-incident').length, 4);
  assert.equal(result.graph.edges.filter((edge) => edge.relationship === 'alert-on-machine').length, 1);
});

test('unrecognized Defender statuses and severity remain manual rather than passing or invented severity', () => {
  const result = run([
    collection('defender.incidents', [{ id: '1', incidentId: 1, status: 'Active', severity: 'FutureSeverity' }]),
    collection('defender.alerts', [{ id: 'alert-a', status: 'FutureStatus', severity: 'High' }]),
  ]);
  assert.equal(findings(result, 'DEFENDER.XDR.INCIDENT', 'unable-to-assess').length, 1);
  assert.equal(findings(result, 'DEFENDER.XDR.ALERT', 'unable-to-assess').length, 1);
  assert.equal(findings(result, 'DEFENDER.XDR.INCIDENT', 'fail').length, 0);
  assert.equal(findings(result, 'DEFENDER.XDR.ALERT', 'pass').length, 0);
});

test('tenant management-group inventory never creates subscription RBAC or federation prerequisites at tenant scope', () => {
  const tenantId = '11111111-1111-4111-8111-111111111111';
  const subscriptionId = '22222222-2222-4222-8222-222222222222';
  const subscriptionScope = `/subscriptions/${subscriptionId}`;
  const input: CollectionResult[] = COLLECTION_CATALOG.map((definition): CollectionResult => ({
    id: definition.id, provider: definition.provider,
    scope: definition.provider === 'graph' || definition.provider === 'defender' || definition.id === 'azure.managementGroups'
      ? tenantId : definition.provider === 'azure' ? subscriptionScope : 'assessment',
    status: definition.id === 'entra.users' ? 'complete' : 'unavailable',
    ...(definition.id === 'entra.users' ? {} : { reason: 'dependency-unavailable' }),
    collectedAt: NOW.toISOString(),
    records: definition.id === 'entra.users' ? [{ id: 'u1', accountEnabled: true }] : [],
  }));
  const snapshot = createAssessment({
    schemaVersion: '1.0',
    scope: { tenantId, subscriptionIds: [subscriptionId], githubOrganizations: [], azureDevOpsOrganizations: [] },
    collectedAt: NOW.toISOString(), collections: input,
  });
  assert.doesNotThrow(() => parseSnapshot(snapshot));
  const rbac = findings(snapshot, 'AZURE.RBAC.CAPABILITY');
  assert.equal(rbac.length, 1);
  assert.equal(rbac[0]!.scope, subscriptionScope);
  assert.ok(findings(snapshot, 'WORKLOAD.FEDERATION.INVENTORY').filter((finding) => finding.scope === tenantId)
    .every((finding) => !finding.description.includes('azure.federatedCredentials')));
  for (const finding of snapshot.findings) {
    for (const ref of finding.evidence) {
      if (['azure.roleAssignments', 'azure.roleDefinitions', 'azure.federatedCredentials'].includes(ref.collectionId)) {
        assert.equal(ref.scope, subscriptionScope);
      }
    }
  }
});

test('identity display names survive placeholder references without changing stable IDs or privilege scores', () => {
  const plain = withAzure(withGrant());
  const names = new Map([
    ['app-a', 'Named deployment application'], ['sp-a', 'Named deployment service principal'], ['owner-a', 'Named owner'],
  ]);
  const input = plain.map((source) => ({
    ...source, records: source.records.map((record) => names.has(String(record.id))
      && ['entra.applications', 'entra.servicePrincipals', 'entra.users'].includes(source.id)
      ? { ...record, displayName: names.get(String(record.id))! } : record),
  }));
  const before = run(plain);
  const result = run(input);
  for (const [id, name] of names) {
    assert.equal(risk(result, id).displayName, name);
    const node = result.graph.nodes.find((entry) => entry.properties.resourceId === id
      && entry.type === (id === 'app-a' ? 'application' : 'identity'));
    assert.equal(node?.label, name);
    assert.ok(node?.evidence.some((ref) => ref.recordId === id
      && ['entra.applications', 'entra.servicePrincipals', 'entra.users'].includes(ref.collectionId)));
    assert.equal(risk(result, id).score, risk(before, id).score);
  }
  assert.deepEqual(result.findings.map((finding) => finding.id), before.findings.map((finding) => finding.id));
  assert.deepEqual(result.graph.nodes.map((node) => node.id), before.graph.nodes.map((node) => node.id));
  assert.deepEqual(result.graph.edges.map((edge) => edge.id), before.graph.edges.map((edge) => edge.id));
});

test('display-name metadata falls back safely for ambiguous and credential-shaped labels', () => {
  const tokenLikeName = `ghp_${'a'.repeat(40)}`;
  const principals = base().find((source) => source.id === 'entra.servicePrincipals')!.records;
  const result = run(replace(base(), 'entra.servicePrincipals', principals.map((record) =>
    record.id === 'sp-a' ? { ...record, displayName: tokenLikeName } : record)));
  assert.equal(risk(result).displayName, 'sp-a');
  assert.equal(JSON.stringify(result).includes(tokenLikeName), false);
  const conflicting = run(replace(base(), 'entra.servicePrincipals', [...principals,
    { ...principals[0]!, displayName: 'Conflicting name' }]));
  assert.equal(risk(conflicting).displayName, 'sp-a');
});

test('resource-managed identities require accountability review rather than directory ownerless scoring', () => {
  for (const resourceType of ['system-assigned', 'user-assigned', 'not-observed']) {
    let input = withAzure();
    const principals = input.find((source) => source.id === 'entra.servicePrincipals')!.records;
    input = replace(input, 'entra.servicePrincipals', [...principals,
      { id: 'mi-a', appId: 'mi-client', servicePrincipalType: 'ManagedIdentity', displayName: 'Resource-managed identity' }]);
    const resource: JsonObject = resourceType === 'user-assigned'
      ? { id: `${SUB}/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi`,
        type: 'Microsoft.ManagedIdentity/userAssignedIdentities', properties: { principalId: 'mi-a' } }
      : { id: `${SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account`,
        type: 'Microsoft.Storage/storageAccounts', identity: { type: 'SystemAssigned', principalId: 'mi-a', tenantId: TENANT } };
    input = replace(input, 'azure.resources', resourceType === 'not-observed' ? [] : [resource], SUB);
    const result = run(input);
    assert.equal(findings(result, 'WORKLOAD.OWNERSHIP.MISSING', 'fail').some((finding) => finding.resourceId === 'mi-a'), false);
    assert.equal(risk(result, 'mi-a').factors.some((factor) => factor.name === 'missingOwner'), false);
    assert.equal(risk(result, 'mi-a').score, 0);
    assert.equal(risk(result, 'mi-a').incomplete, true);
    const review = findings(result, 'WORKLOAD.OWNERSHIP.RESOURCE_ACCOUNTABILITY', 'unable-to-assess')
      .find((finding) => finding.resourceId === 'mi-a');
    assert.ok(review);
    assert.match(review.description, /resource-managed/);
    if (resourceType !== 'not-observed') {
      assert.ok(review.evidence.some((ref) => ref.collectionId === 'azure.resources' && ref.recordId === resource.id));
      assert.match(review.description, /1 resource association/);
    }
  }
});

test('ordinary application ownerlessness is not suppressed by a managed-identity-looking display name', () => {
  const principals = base().find((source) => source.id === 'entra.servicePrincipals')!.records;
  const result = run(replace(base(), 'entra.servicePrincipals', [...principals,
    { id: 'ordinary-sp', appId: 'ordinary-app', displayName: 'Managed Identity', servicePrincipalType: 'Application',
      passwordCredentials: [], keyCredentials: [] }]));
  assert.ok(findings(result, 'WORKLOAD.OWNERSHIP.MISSING', 'fail').some((finding) => finding.resourceId === 'ordinary-sp'));
  assert.ok(risk(result, 'ordinary-sp').factors.some((factor) => factor.name === 'missingOwner'));
});

test('weak classic reviewer settings correlate only when bound to the trusted default branch', () => {
  const record: JsonObject = { id: 'main', repository: 'org/repo',
    required_pull_request_reviews: null, required_status_checks: null, enforce_admins: { enabled: false } };
  const incompleteBinding = replace(federated(), 'github.branchProtection', [record], 'org/repo');
  assert.equal(findings(run(incompleteBinding), 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 0);
  const result = run(replace(incompleteBinding, 'github.branchProtection', [{ ...record, branch: 'main' }], 'org/repo'));
  assert.equal(findings(result, 'GITHUB.BRANCH.REVIEWS', 'fail').length, 1);
  assert.equal(findings(result, 'CODETOCLOUD.POTENTIAL_CONTROL', 'fail').length, 1);
});
