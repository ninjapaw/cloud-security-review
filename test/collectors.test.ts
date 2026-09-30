import assert from 'node:assert/strict';
import test from 'node:test';
import { collect } from '../src/collectors.js';
import { COLLECTION_CATALOG } from '../src/catalog.js';
import { ARG_POLICY_QUERY, ARG_RESOURCE_QUERY, GITHUB_API_VERSION, GRAPH_SELECT } from '../src/http.js';
import type { AssessmentConfig, CollectionResult, CollectorOptions, JsonObject, Provider } from '../src/model.js';
import { assertSafeEvidence } from '../src/safety.js';

const TENANT = '11111111-1111-4111-8111-111111111111';
const SUB = '22222222-2222-4222-8222-222222222222';
const APP = '33333333-3333-4333-8333-333333333333';
const SP = '44444444-4444-4444-8444-444444444444';
const USER = '55555555-5555-4555-8555-555555555555';
const GROUP = '66666666-6666-4666-8666-666666666666';
const PROJECT = '77777777-7777-4777-8777-777777777777';
const SECOND = '88888888-8888-4888-8888-888888888888';
const TOKEN = 'collector-auth-credential-DO-NOT-EXPOSE';
const SECRET = 'unexpected-sensitive-value-MUST-NOT-PERSIST';
const RESOURCE = `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agent`;
const STORAGE = `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store`;
const POLICY_SOURCE = `${STORAGE}/providers/Microsoft.PolicyInsights/policyStates/latest`;
const POLICY_ASSIGNMENT = `/subscriptions/${SUB}/providers/Microsoft.Authorization/policyAssignments/security`;
const POLICY_DEFINITION = `/providers/Microsoft.Authorization/policyDefinitions/${APP}`;
const SHAREPOINT_PATH = '/v1.0/admin/sharepoint/settings';
const SCHEDULE_PATH = '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances';
const CLOCK = () => new Date('2026-01-01T12:00:00.000Z');

function config(enabled: Provider[] = ['graph', 'azure', 'defender', 'github', 'azureDevOps']): AssessmentConfig {
  return {
    scope: { tenantId: TENANT, subscriptionIds: [SUB], githubOrganizations: ['contoso'], azureDevOpsOrganizations: ['contoso'] },
    sources: {
      graph: enabled.includes('graph'), azure: enabled.includes('azure'), defender: enabled.includes('defender'),
      github: enabled.includes('github'), azureDevOps: enabled.includes('azureDevOps'),
    },
    auth: { azure: { mode: 'azure-cli' }, github: { tokenEnvironmentVariable: 'ASSESSMENT_GITHUB_TOKEN' } },
    limits: { maxPages: 5, maxRecords: 1000, maxRequests: 200, timeoutMs: 1000, maxRetries: 0, maxResponseBytes: 100_000 },
    policy: {
      expiringWithinDays: 30, maxCredentialLifetimeDays: 365, staleCredentialDays: 90,
      maxOwners: 5, dormantUserDays: 90, permissionRules: [],
      weights: {
        directoryPrivilege: 1, apiPrivilege: 1, azurePrivilege: 1, broadScope: 1,
        persistentCredential: 1, externalOwner: 1, missingOwner: 1, credentialHygiene: 1,
        privilegeCombination: 1, codeToCloud: 1,
      },
    },
  };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

function policyState(properties: Record<string, unknown> = {}, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: POLICY_SOURCE, type: 'microsoft.policyinsights/policystates', subscriptionId: SUB, resourceGroup: 'rg',
    properties: {
      resourceId: STORAGE, policyAssignmentId: POLICY_ASSIGNMENT, policyAssignmentName: 'security',
      policyAssignmentScope: `/subscriptions/${SUB}`, policyDefinitionId: POLICY_DEFINITION,
      policyDefinitionReferenceId: '', policySetDefinitionId: null, policyDefinitionAction: 'audit',
      complianceState: 'NonCompliant', timestamp: '2025-12-31T12:00:00Z', ...properties,
    },
    ...overrides,
  };
}

const healthyFetch: typeof fetch = async (input, init) => {
  const address = new URL(String(input));
  const path = address.pathname;
  const headers = new Headers(init?.headers);
  assert.equal(headers.get('authorization'), `Bearer ${TOKEN}`);
  assert.equal(init?.redirect, 'error');
  if (address.hostname === 'graph.microsoft.com') {
    assert.equal(init?.method, 'GET');
    if (path === SHAREPOINT_PATH) {
      assert.equal(address.searchParams.get('$select'), GRAPH_SELECT['admin/sharepoint/settings']);
      assert.equal(address.searchParams.has('$top'), false);
      return json({
        isLegacyAuthProtocolsEnabled: false, isRequireAcceptingUserToMatchInvitedUserEnabled: true,
        isResharingByExternalUsersEnabled: false, isUnmanagedSyncAppForTenantRestricted: true,
        sharingCapability: 'existingExternalUserSharingOnly', sharingDomainRestrictionMode: 'allowList',
        sharingAllowedDomainList: ['partner.invalid'], sharingBlockedDomainList: [],
        idleSessionSignOut: { isEnabled: true, signOutAfterInSeconds: 3600, warnAfterInSeconds: 3300 },
      });
    }
    const recordSets: Record<string, unknown[]> = {
      '/v1.0/organization': [{ id: TENANT, displayName: 'Contoso', secret: SECRET }],
      '/v1.0/users': [{ id: USER, displayName: 'Reader', userPrincipalName: 'reader@contoso.invalid',
        accountEnabled: true, userType: 'Member', signInActivity: { lastSuccessfulSignInDateTime: '2025-12-01T00:00:00Z' },
        passwordProfile: { password: SECRET } }],
      '/v1.0/groups': [{ id: GROUP, displayName: 'Operators', securityEnabled: true, isAssignableToRole: true }],
      '/v1.0/applications': [{ id: APP, appId: SECOND, displayName: 'Deployment', signInAudience: 'AzureADMyOrg',
        passwordCredentials: [{ keyId: 'key-1', displayName: 'legacy', startDateTime: '2025-01-01T00:00:00Z',
          endDateTime: '2027-01-01T00:00:00Z', secretText: SECRET, hint: SECRET }],
        keyCredentials: [{ keyId: 'key-2', type: 'AsymmetricX509Cert', key: SECRET, customKeyIdentifier: SECRET }] }],
      '/v1.0/servicePrincipals': [{ id: SP, appId: SECOND, displayName: 'Deployment', servicePrincipalType: 'Application',
        accountEnabled: true, appOwnerOrganizationId: TENANT, appRoles: [{ id: 'api-role', value: 'Read.Inventory',
          allowedMemberTypes: ['Application'], description: SECRET }], oauth2PermissionScopes: [] }],
      [`/v1.0/groups/${GROUP}/members`]: [{ id: USER, '@odata.type': '#microsoft.graph.user', userType: 'Member' }],
      [`/v1.0/applications/${APP}/owners`]: [{ id: USER, '@odata.type': '#microsoft.graph.user', userType: 'Member' }],
      [`/v1.0/servicePrincipals/${SP}/owners`]: [{ id: USER, '@odata.type': '#microsoft.graph.user', userType: 'Member' }],
      [`/v1.0/applications/${APP}/federatedIdentityCredentials`]: [{ id: 'federation-1', name: 'github',
        issuer: 'https://token.actions.githubusercontent.com', subject: 'repo:contoso/app:ref:refs/heads/main',
        audiences: ['api://AzureADTokenExchange'] }],
      [`/v1.0/servicePrincipals/${SP}/appRoleAssignments`]: [{ id: 'grant-1', principalId: SP, resourceId: SECOND, appRoleId: 'api-role' }],
      '/v1.0/oauth2PermissionGrants': [{ id: 'oauth-1', clientId: SP, resourceId: SECOND, scope: 'User.Read', consentType: 'AllPrincipals' }],
      [SCHEDULE_PATH]: [{ id: 'active-assignment-1', principalId: USER, roleDefinitionId: SECOND,
        directoryScopeId: '/', appScopeId: null, assignmentType: 'Assigned', memberType: 'Direct',
        startDateTime: '2025-12-01T00:00:00Z', endDateTime: null,
        roleAssignmentOriginId: 'assignment-1', roleAssignmentScheduleId: 'schedule-1' }],
      '/v1.0/reports/authenticationMethods/userRegistrationDetails': [{ id: USER,
        userPrincipalName: 'reader@contoso.invalid', userType: 'member', isMfaRegistered: true,
        isMfaCapable: true, isPasswordlessCapable: false }],
      '/v1.0/identity/conditionalAccess/policies': [{ id: 'ca-1', displayName: 'Require MFA', state: 'enabled',
        conditions: { users: { includeUsers: ['All'], excludeUsers: [] }, clientAppTypes: ['all'], unapproved: SECRET },
        grantControls: { operator: 'OR', builtInControls: ['mfa'] } }],
      '/v1.0/deviceManagement/managedDevices': [{ id: 'device-1', azureADDeviceId: SECOND, complianceState: 'compliant',
        operatingSystem: 'Windows', managedDeviceOwnerType: 'company', lastSyncDateTime: '2025-12-31T00:00:00Z' }],
      '/v1.0/security/secureScores': [{ id: 'secure-score-1', currentScore: 30, maxScore: 100 }],
    };
    return json({ value: recordSets[path] ?? [] });
  }
  if (address.hostname === 'management.azure.com') {
    if (path === '/providers/Microsoft.ResourceGraph/resources') {
      assert.equal(init?.method, 'POST');
      const body = JSON.parse(String(init.body));
      assert.deepEqual(body.subscriptions, [SUB]);
      if (body.query === ARG_POLICY_QUERY) {
        return json({ count: 1, totalRecords: 1, resultTruncated: 'false', data: [policyState({
          policyAssignmentParameters: SECRET, policyEvaluationDetails: { secret: SECRET },
        })] });
      }
      assert.equal(body.query, ARG_RESOURCE_QUERY);
      return json({ count: 2, totalRecords: 2, resultTruncated: 'false', data: [
        { id: RESOURCE, name: 'agent', type: 'microsoft.managedidentity/userassignedidentities', subscriptionId: SUB, resourceGroup: 'rg',
          identity: { type: 'SystemAssigned', principalId: SP, tenantId: TENANT }, properties: {} },
        { id: STORAGE, name: 'store', type: 'microsoft.storage/storageaccounts', subscriptionId: SUB, resourceGroup: 'rg',
          identity: { type: 'UserAssigned', userAssignedIdentities: { [RESOURCE]: { clientId: SECOND, principalId: SP, secretText: SECRET } } },
          properties: { publicNetworkAccess: 'Enabled', allowBlobPublicAccess: false, connectionString: SECRET,
            administratorLoginPassword: SECRET, networkAcls: { defaultAction: 'Deny', ipRules: [SECRET] } } },
      ] });
    }
    assert.equal(init?.method, 'GET');
    if (path === `/subscriptions/${SUB}`) {
      return json({ id: path, subscriptionId: SUB, tenantId: TENANT, displayName: 'Production', state: 'Enabled' });
    }
    if (path.endsWith('/roleDefinitions')) return json({ value: [{
      id: `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/${SECOND}`,
      name: SECOND, properties: { roleName: 'Reader', roleType: 'BuiltInRole',
        permissions: [{ actions: ['*/read'], notActions: [], dataActions: [], notDataActions: [] }] },
    }] });
    if (path.endsWith('/roleAssignments')) return json({ value: [{
      id: `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleAssignments/${USER}`,
      properties: { principalId: SP, roleDefinitionId: `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/${SECOND}`,
        scope: `/subscriptions/${SUB}`, condition: null },
    }] });
    if (path.endsWith('/federatedIdentityCredentials')) return json({ value: [{
      id: `${RESOURCE}/federatedIdentityCredentials/github`, name: 'github',
      properties: { issuer: 'https://token.actions.githubusercontent.com',
        subject: 'repo:contoso/app:ref:refs/heads/main', audiences: ['api://AzureADTokenExchange'], secret: SECRET },
    }] });
    if (path.endsWith('/pricings')) return json({ value: [{ id: `${path}/VirtualMachines`, name: 'VirtualMachines',
      properties: { pricingTier: 'Standard', subPlan: 'P2', extensions: [{ name: 'AgentlessVmScanning', isEnabled: 'True', additionalExtensionProperties: SECRET }] } }] });
    return json({ value: [] });
  }
  if (address.hostname === 'api.security.microsoft.com') {
    const rows: Record<string, unknown[]> = {
      '/api/incidents': [{ incidentId: 11, incidentName: 'Suspicious sign-in', severity: 'High', status: 'Active',
        alerts: [{ evidence: SECRET }] }],
      '/api/alerts': [{ id: 'alert-1', incidentId: 11, title: 'Suspicious activity', severity: 'High',
        aadTenantId: TENANT, machineId: 'machine-1', evidence: [{ commandLine: SECRET }] }],
      '/api/machines': [{ id: 'machine-1', aadDeviceId: SECOND, onboardingStatus: 'Onboarded', healthStatus: 'Active',
        riskScore: 'Low', exposureLevel: 'Medium', deviceValue: 'High' }],
    };
    return json({ value: rows[path] ?? [] });
  }
  if (address.hostname === 'api.github.com') {
    assert.equal(headers.get('x-github-api-version'), GITHUB_API_VERSION);
    if (path === '/orgs/contoso') return json({ id: 1, login: 'contoso', two_factor_requirement_enabled: true, default_repository_permission: 'read' });
    if (path.endsWith('/members')) return json([{ id: address.searchParams.get('role') === 'admin' ? 2 : 3, login: 'member', type: 'User' }]);
    if (path.endsWith('/outside_collaborators')) return json([]);
    if (path === '/orgs/contoso/repos') return json([{ id: 4, name: 'app', full_name: 'contoso/app',
      visibility: 'private', private: true, archived: false, default_branch: 'main',
      security_and_analysis: { secret_scanning: { status: 'enabled', secret: SECRET }, dependabot_security_updates: { status: 'enabled' } } }]);
    if (path.endsWith('/actions/secrets')) return json({ total_count: 1, secrets: [{ name: 'DEPLOYMENT_CONFIGURATION', value: SECRET }] });
    if (path.endsWith('/branches/main/protection')) return json({
      required_pull_request_reviews: { required_approving_review_count: 2, require_code_owner_reviews: true },
      enforce_admins: { enabled: true }, required_status_checks: { strict: true, contexts: ['build'] },
    });
    if (path.endsWith('/rulesets')) return json([{ id: 40, name: 'production', target: 'branch', enforcement: 'active' }]);
    if (path.endsWith('/rulesets/40')) return json({ id: 40, name: 'production', target: 'branch', enforcement: 'active',
      conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } },
      rules: [{ type: 'pull_request', parameters: { required_approving_review_count: 2, arbitraryBody: SECRET } }] });
    if (path.endsWith('/actions/permissions/workflow')) return json({ default_workflow_permissions: 'read', can_approve_pull_request_reviews: false });
    if (path.endsWith('/actions/workflows')) return json({ total_count: 1, workflows: [{ id: 5, name: 'Build',
      path: '.github/workflows/build.yml', state: 'active', source: SECRET }] });
    if (path.endsWith('/actions/runners')) return json({ total_count: 1, runners: [{ id: 6, name: 'hosted', os: 'linux', status: 'online', busy: false }] });
    if (path.endsWith('/environments')) return json({ total_count: 1, environments: [{ id: 7, name: 'production',
      deployment_branch_policy: { protected_branches: true, custom_branch_policies: false },
      protection_rules: [{ id: 9, type: 'required_reviewers', prevent_self_review: true }] }] });
    if (path.endsWith('/dependabot/alerts')) return json([{ number: 12, state: 'open',
      security_advisory: { ghsa_id: 'GHSA-test-test-test', severity: 'high', description: SECRET } }]);
    if (path.endsWith('/code-scanning/alerts')) return json([{ number: 13, state: 'open', rule: { id: 'js/insecure', severity: 'error' },
      most_recent_instance: { ref: 'refs/heads/main', message: { text: SECRET }, location: { snippet: SECRET } } }]);
    if (path.endsWith('/secret-scanning/alerts')) {
      assert.equal(address.searchParams.get('hide_secret'), 'true');
      assert.equal(headers.get('x-github-api-version'), '2026-03-10');
      return json([{ number: 14, state: 'open', secret_type: 'generic_api_key', validity: 'unknown' }]);
    }
    assert.fail(`Unexpected GitHub route: ${path}`);
  }
  if (address.hostname === 'dev.azure.com') {
    if (path.endsWith('/_apis/projects')) return json({ count: 1, value: [{ id: PROJECT, name: 'Cloud', visibility: 'private' }] });
    if (path.endsWith('/distributedtask/pools')) return json({ count: 1, value: [{ id: 21, name: 'agents', isHosted: true, poolType: 'automation' }] });
    if (path.endsWith('/git/repositories')) {
      const projectId = path.split('/')[2];
      return json({ value: [{ id: SECOND, name: 'app', defaultBranch: 'refs/heads/main', project: { id: projectId, visibility: 'private' } }] });
    }
    if (path.endsWith('/policy/configurations')) return json({ value: [{ id: 22, isEnabled: true, isBlocking: true,
      type: { id: 'minimum-reviewers', displayName: 'Minimum reviewers' },
      settings: { minimumApproverCount: 2, scope: [{ repositoryId: SECOND, refName: 'refs/heads/main', matchKind: 'Exact' }],
        filenamePatterns: ['*.ts'], arbitraryEndpoint: SECRET } }] });
    if (path.endsWith('/pipelines')) return json({ value: [{ id: 23, name: 'Build', revision: 1, configuration: { variables: { password: SECRET } } }] });
    if (path.endsWith('/distributedtask/environments')) return json({ value: [{ id: 24, name: 'production', description: SECRET }] });
    assert.fail(`Unexpected Azure DevOps route: ${path}`);
  }
  assert.fail('Unexpected provider');
};

function options(fetcher: typeof fetch = healthyFetch): CollectorOptions {
  return { fetch: fetcher, tokenProvider: { async getToken() { return TOKEN; } }, now: CLOCK, sleep: async () => undefined };
}

function dataset(results: CollectionResult[], id: string, scope?: string): CollectionResult {
  const result = results.find(item => item.id === id && (scope === undefined || scope === item.scope));
  assert.ok(result, `Missing dataset ${id} ${scope ?? ''}`);
  return result;
}

function assertSafe(results: CollectionResult[]): void {
  const serialized = JSON.stringify(results);
  assert.ok(!serialized.includes(TOKEN));
  assert.ok(!serialized.includes(SECRET));
  assertSafeEvidence(results);
  for (const result of results) {
    assert.equal(result.collectedAt, CLOCK().toISOString());
    assert.ok(result.records.every(record => typeof record.id === 'string' && record.id.length > 0));
    if (result.status !== 'complete') assert.ok(result.reason);
    if (['unavailable', 'not-configured'].includes(result.status)) assert.equal(result.records.length, 0);
  }
}

test('live collectors successfully collect mock metadata from all five providers and project only safe fields', async () => {
  const results = await collect(config(), options());
  for (const [id, scope] of [
    ['entra.organization', TENANT], ['entra.applications', TENANT], ['entra.servicePrincipals', TENANT],
    ['entra.applicationOwners', TENANT], ['entra.federatedCredentials', TENANT],
    ['entra.authenticationRegistration', TENANT], ['intune.devices', TENANT],
    ['m365.sharePointSettings', TENANT], ['entra.directoryRoleAssignmentScheduleInstances', TENANT],
    ['azure.resources', `/subscriptions/${SUB}`], ['azure.roleAssignments', `/subscriptions/${SUB}`],
    ['azure.policyCompliance', `/subscriptions/${SUB}`],
    ['azure.federatedCredentials', `/subscriptions/${SUB}`], ['defenderCloud.pricings', `/subscriptions/${SUB}`],
    ['defender.incidents', TENANT], ['defender.machines', TENANT], ['github.organizations', 'contoso'],
    ['github.repositories', 'contoso'], ['github.members', 'contoso'], ['github.rulesets', 'contoso/app'],
    ['github.secretScanningAlerts', 'contoso/app'], ['github.secretMetadata', 'contoso/app'],
    ['azureDevOps.projects', 'contoso'], ['azureDevOps.branchPolicies', `contoso/${PROJECT}`],
  ]) {
    assert.ok(id && scope);
    const result = dataset(results, id, scope);
    assert.equal(result.status, 'complete', `${id}: ${result.reason ?? ''} ${result.message ?? ''}`);
    assert.ok(result.records.length > 0);
  }
  const application = dataset(results, 'entra.applications').records[0];
  assert.deepEqual(application?.passwordCredentials, [{ keyId: 'key-1', displayName: 'legacy',
    startDateTime: '2025-01-01T00:00:00Z', endDateTime: '2027-01-01T00:00:00Z' }]);
  assert.deepEqual(application?.keyCredentials, [{ keyId: 'key-2', type: 'AsymmetricX509Cert' }]);
  assert.equal(dataset(results, 'entra.applicationOwners').records[0]?.parentId, APP);
  assert.equal(dataset(results, 'entra.servicePrincipalOwners').records[0]?.parentId, SP);
  assert.equal(dataset(results, 'entra.federatedCredentials').records[0]?.parentId, APP);
  assert.equal(dataset(results, 'entra.appRoleAssignments').records[0]?.principalId, SP);
  assert.equal(dataset(results, 'github.workflows', 'contoso/app').records[0]?.repository, 'contoso/app');
  assert.equal(dataset(results, 'github.workflows', 'contoso/app').records[0]?.full_name, 'contoso/app');
  assert.equal(dataset(results, 'azure.federatedCredentials').records[0]?.parentId, RESOURCE);
  assert.deepEqual(dataset(results, 'github.secretMetadata', 'contoso/app').records,
    [{ name: 'DEPLOYMENT_CONFIGURATION', id: 'DEPLOYMENT_CONFIGURATION', repository: 'contoso/app', full_name: 'contoso/app' }]);
  assert.equal(dataset(results, 'entra.groupMemberships').status, 'partial');
  assert.equal(dataset(results, 'entra.groupMemberships').reason, 'unsupported');
  for (const definition of COLLECTION_CATALOG.filter(item => item.manual)) {
    assert.equal(dataset(results, definition.id).status, 'unavailable');
    assert.equal(dataset(results, definition.id).reason, 'unsupported');
  }
  assertSafe(results);
});

test('disabled providers emit not-configured evidence and make no authentication or API requests', async () => {
  const results = await collect(config([]), {
    fetch: async () => assert.fail('disabled providers must not fetch'),
    tokenProvider: { async getToken() { assert.fail('disabled providers must not authenticate'); } },
    now: CLOCK,
  });
  assert.equal(results.length, COLLECTION_CATALOG.length);
  assert.ok(results.every(result => result.status === 'not-configured' && result.reason === 'not-configured'));
  assertSafe(results);
});

test('OData, ARM, GitHub Link, Azure DevOps header and ARG skip-token pagination all work', async () => {
  const seen: string[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const address = new URL(String(input));
    const path = address.pathname;
    seen.push(address.href);
    if (path === '/v1.0/users') {
      if (address.searchParams.has('$skiptoken')) return json({ value: [{ id: SECOND, userType: 'Guest' }] });
      const next = new URL(address);
      next.searchParams.set('$skiptoken', 'user-page-2');
      return json({ value: [{ id: USER, userType: 'Member' }], '@odata.nextLink': next.href });
    }
    if (path.endsWith('/roleAssignments')) {
      const id = `${path}/${address.searchParams.has('$skiptoken') ? SECOND : USER}`;
      if (address.searchParams.has('$skiptoken')) return json({ value: [{ id, properties: { principalId: USER } }] });
      const next = new URL(address);
      next.searchParams.set('$skiptoken', 'rbac-page-2');
      return json({ value: [{ id, properties: { principalId: SP } }], nextLink: next.href });
    }
    if (path.endsWith('/actions/workflows')) {
      if (address.searchParams.has('page')) return json({ total_count: 2, workflows: [{ id: 52, name: 'Deploy' }] });
      const next = new URL(address);
      next.searchParams.set('page', '2');
      return json({ total_count: 2, workflows: [{ id: 51, name: 'Build' }] }, 200, { link: `<${next.href}>; rel="next"` });
    }
    if (path.endsWith('/_apis/projects')) {
      if (address.searchParams.has('continuationToken')) return json({ value: [{ id: SECOND, name: 'Other', visibility: 'private' }] });
      return json({ value: [{ id: PROJECT, name: 'Cloud', visibility: 'private' }] }, 200, { 'x-ms-continuationtoken': 'project-page-2' });
    }
    if (path === '/providers/Microsoft.ResourceGraph/resources') {
      const body = JSON.parse(String(init?.body));
      if (body.query === ARG_POLICY_QUERY) return healthyFetch(input, init);
      const secondPage = body.options.$skipToken === 'arg-page-2';
      return json({
        count: 1, totalRecords: 2, resultTruncated: secondPage ? 'false' : 'true',
        ...(secondPage ? {} : { $skipToken: 'arg-page-2' }),
        data: [{ id: secondPage ? STORAGE : RESOURCE, subscriptionId: SUB,
          type: secondPage ? 'microsoft.storage/storageaccounts' : 'microsoft.managedidentity/userassignedidentities' }],
      });
    }
    return healthyFetch(input, init);
  };
  const results = await collect(config(), options(fetcher));
  for (const [id, scope] of [
    ['entra.users', TENANT], ['azure.roleAssignments', `/subscriptions/${SUB}`],
    ['github.workflows', 'contoso/app'], ['azureDevOps.projects', 'contoso'],
    ['azure.resources', `/subscriptions/${SUB}`],
  ]) {
    assert.ok(id && scope);
    const result = dataset(results, id, scope);
    assert.equal(result.status, 'complete', `${id}: ${result.reason ?? ''}`);
    assert.equal(result.records.length, 2);
  }
  assert.ok(seen.some(address => address.includes('continuationToken=project-page-2')));
  assertSafe(results);
});

test('first-page 403, 404 and missing authentication are unavailable, not successful empty or inferred licensing', async () => {
  for (const [status, expected] of [[403, 'permission-denied'], [404, 'not-found']] as const) {
    const results = await collect(config(['github']), options(async () => json({ error: SECRET, token: TOKEN }, status)));
    const repositories = dataset(results, 'github.repositories');
    assert.equal(repositories.status, 'unavailable');
    assert.equal(repositories.reason, expected);
    assert.equal(dataset(results, 'github.branchProtection').reason, 'dependency-unavailable');
    assert.ok(!results.some(result => result.reason === 'not-licensed'));
    assertSafe(results);
  }
  const results = await collect(config(['github']), {
    fetch: async () => assert.fail('missing auth must not send requests'),
    tokenProvider: { async getToken() { throw new Error(TOKEN); } }, now: CLOCK,
  });
  assert.equal(dataset(results, 'github.repositories').reason, 'authentication-failed');
  assertSafe(results);
});

test('403 fallback retains basic user inventory but explicitly marks missing sign-in activity partial', async () => {
  const results = await collect(config(['graph']), options(async (input, init) => {
    const address = new URL(String(input));
    if (address.pathname === '/v1.0/users') {
      return address.searchParams.get('$select')?.includes('signInActivity')
        ? json({ error: TOKEN }, 403) : json({ value: [{ id: USER, accountEnabled: true, userType: 'Member' }] });
    }
    return healthyFetch(input, init);
  }));
  const users = dataset(results, 'entra.users');
  assert.equal(users.status, 'partial');
  assert.equal(users.reason, 'permission-denied');
  assert.equal(users.records.length, 1);
  assert.equal(users.records[0]?.signInActivity, undefined);
  assertSafe(results);
});

test('a failed later page preserves records as partial and propagates parent incompleteness to children', async () => {
  const results = await collect(config(['graph']), options(async (input, init) => {
    const address = new URL(String(input));
    if (address.pathname === '/v1.0/applications') {
      if (address.searchParams.has('$skiptoken')) return json({ error: TOKEN }, 403);
      const next = new URL(address);
      next.searchParams.set('$skiptoken', 'denied');
      return json({ value: [{ id: APP, appId: SECOND }], '@odata.nextLink': next.href });
    }
    return healthyFetch(input, init);
  }));
  assert.equal(dataset(results, 'entra.applications').status, 'partial');
  assert.equal(dataset(results, 'entra.applications').reason, 'permission-denied');
  assert.equal(dataset(results, 'entra.applicationOwners').status, 'partial');
  assert.equal(dataset(results, 'entra.applicationOwners').reason, 'dependency-unavailable');
  assert.equal(dataset(results, 'entra.federatedCredentials').status, 'partial');
  assertSafe(results);
});

test('a later-page 429, a pagination loop, and page or record truncation remain explicit partial results', async () => {
  for (const mode of ['rate-limit', 'loop', 'page-limit', 'record-limit'] as const) {
    const selected = config(['graph']);
    if (mode === 'page-limit') selected.limits.maxPages = 1;
    if (mode === 'record-limit') selected.limits.maxRecords = 1;
    const results = await collect(selected, options(async (input, init) => {
      const address = new URL(String(input));
      if (address.pathname === '/v1.0/users') {
        if (address.searchParams.has('$skiptoken')) return json({ error: TOKEN }, 429);
        const next = new URL(address);
        if (mode !== 'loop') next.searchParams.set('$skiptoken', 'page-2');
        return json({ value: [{ id: USER }, ...(mode === 'record-limit' ? [{ id: SECOND }] : [])], '@odata.nextLink': next.href });
      }
      return healthyFetch(input, init);
    }));
    const users = dataset(results, 'entra.users');
    assert.equal(users.status, 'partial');
    assert.equal(users.records.length, 1);
    assert.equal(users.reason, mode === 'rate-limit' ? 'rate-limited' : mode === 'loop' ? 'invalid-response' : 'limit-reached');
    assertSafe(results);
  }
});

test('unapproved next links are rejected before another host receives a token', async () => {
  let external = 0;
  const results = await collect(config(['graph']), options(async (input, init) => {
    const address = new URL(String(input));
    if (address.hostname !== 'graph.microsoft.com') { external++; assert.fail('cross-host request'); }
    if (address.pathname === '/v1.0/users') return json({
      value: [{ id: USER }], '@odata.nextLink': 'https://attacker.invalid/collect',
    });
    return healthyFetch(input, init);
  }));
  assert.equal(external, 0);
  assert.equal(dataset(results, 'entra.users').status, 'partial');
  assert.equal(dataset(results, 'entra.users').reason, 'unsupported');
  assertSafe(results);
});

test('Graph organization tenant mismatch blocks all Microsoft collection and never exposes foreign records', async () => {
  const calls: string[] = [];
  const results = await collect(config(['graph', 'azure', 'defender', 'azureDevOps']), options(async input => {
    calls.push(String(input));
    assert.equal(new URL(String(input)).pathname, '/v1.0/organization');
    return json({ value: [{ id: SECOND, displayName: 'Wrong tenant' }] });
  }));
  assert.equal(calls.length, 1);
  for (const id of ['entra.organization', 'entra.users', 'entra.directoryRoleAssignmentScheduleInstances',
    'm365.sharePointSettings', 'azure.resources', 'azure.policyCompliance', 'defender.machines', 'azureDevOps.projects']) {
    assert.equal(dataset(results, id).status, 'unavailable');
    assert.equal(dataset(results, id).records.length, 0);
    assert.equal(dataset(results, id).reason, 'scope-mismatch');
  }
  assert.ok(!JSON.stringify(results).includes('Wrong tenant'));
  assertSafe(results);
});

test('ARM subscription tenant mismatch blocks subscription children and a Graph permission denial permits only verified ARM scope', async () => {
  for (const mismatch of [true, false]) {
    const requested: string[] = [];
    const results = await collect(config(['azure']), options(async (input, init) => {
      const address = new URL(String(input));
      requested.push(address.href);
      if (address.pathname === '/v1.0/organization') return json({ error: TOKEN }, 403);
      if (address.pathname === `/subscriptions/${SUB}` && mismatch) {
        return json({ id: address.pathname, subscriptionId: SUB, tenantId: SECOND });
      }
      return healthyFetch(input, init);
    }));
    const subscription = dataset(results, 'azure.subscriptions');
    assert.equal(subscription.status, mismatch ? 'unavailable' : 'complete');
    const resources = dataset(results, 'azure.resources');
    assert.equal(resources.status, mismatch ? 'unavailable' : 'complete');
    assert.equal(dataset(results, 'azure.managementGroups').status, 'unavailable');
    if (mismatch) {
      assert.equal(subscription.reason, 'scope-mismatch');
      assert.ok(!requested.some(address => address.includes('ResourceGraph')));
    }
    assertSafe(results);
  }
});

test('a hidden-secret endpoint that nevertheless returns a literal secret is failed closed', async () => {
  const results = await collect(config(['github']), options(async (input, init) => {
    const address = new URL(String(input));
    if (address.pathname.endsWith('/secret-scanning/alerts')) {
      assert.equal(address.searchParams.get('hide_secret'), 'true');
      return json([{ number: 1, state: 'open', secret: SECRET }]);
    }
    return healthyFetch(input, init);
  }));
  const alerts = dataset(results, 'github.secretScanningAlerts', 'contoso/app');
  assert.notEqual(alerts.status, 'complete');
  assert.equal(alerts.reason, 'invalid-response');
  assert.equal(alerts.records.length, 0);
  assertSafe(results);
});

test('request budget exhaustion is bounded and never produces complete child coverage', async () => {
  const selected = config(['graph', 'azure', 'defender', 'github', 'azureDevOps']);
  selected.limits.maxRequests = 3;
  let requests = 0;
  const results = await collect(selected, options(async (input, init) => {
    requests++;
    return healthyFetch(input, init);
  }));
  assert.equal(requests, 3);
  assert.equal(dataset(results, 'entra.applications').reason, 'limit-reached');
  assert.notEqual(dataset(results, 'entra.federatedCredentials').status, 'complete');
  assert.equal(dataset(results, 'github.repositories').status, 'unavailable');
  assertSafe(results);
});

test('ARG resultTruncated without a continuation and inconsistent total counts are partial, not complete', async () => {
  for (const body of [
    { data: [{ id: RESOURCE, subscriptionId: SUB }], count: 1, totalRecords: 2, resultTruncated: 'true' },
    { data: [{ id: RESOURCE, subscriptionId: SUB }], count: 1, totalRecords: 2, resultTruncated: 'false' },
  ]) {
    const results = await collect(config(['azure']), options(async (input, init) => {
      if (new URL(String(input)).pathname === '/providers/Microsoft.ResourceGraph/resources'
        && JSON.parse(String(init?.body)).query === ARG_RESOURCE_QUERY) return json(body);
      return healthyFetch(input, init);
    }));
    assert.equal(dataset(results, 'azure.resources').status, 'partial');
    assert.equal(dataset(results, 'azure.resources').reason, 'limit-reached');
    assert.equal(dataset(results, 'azure.federatedCredentials').status, 'partial');
    assertSafe(results);
  }
});

test('foreign subscription, repository and project evidence cannot seed child enumeration', async () => {
  const results = await collect(config(), options(async (input, init) => {
    const address = new URL(String(input));
    if (address.pathname === '/providers/Microsoft.ResourceGraph/resources'
      && JSON.parse(String(init?.body)).query === ARG_RESOURCE_QUERY) return json({
      data: [{ id: RESOURCE.replace(SUB, SECOND), subscriptionId: SECOND, type: 'microsoft.managedidentity/userassignedidentities' }],
      resultTruncated: 'false',
    });
    if (address.pathname === '/orgs/contoso/repos') return json([{ id: 1, full_name: 'unconfigured/foreign', default_branch: 'main' }]);
    if (address.pathname.endsWith('/git/repositories')) return json({
      value: [{ id: SECOND, name: 'foreign', project: { id: APP } }],
    });
    return healthyFetch(input, init);
  }));
  assert.notEqual(dataset(results, 'azure.resources').status, 'complete');
  assert.equal(dataset(results, 'azure.resources').records.length, 0);
  assert.equal(dataset(results, 'github.repositories').reason, 'scope-mismatch');
  assert.equal(dataset(results, 'github.repositories').records.length, 0);
  assert.equal(dataset(results, 'azureDevOps.repositories', `contoso/${PROJECT}`).reason, 'scope-mismatch');
  assert.equal(dataset(results, 'azureDevOps.repositories', `contoso/${PROJECT}`).records.length, 0);
  assertSafe(results);
});

test('echoed authentication tokens in allowlisted metadata are redacted', async () => {
  const results = await collect(config(['graph']), options(async (input, init) => {
    if (new URL(String(input)).pathname === '/v1.0/users') return json({ value: [{ id: USER, displayName: TOKEN }] });
    return healthyFetch(input, init);
  }));
  assert.equal(dataset(results, 'entra.users').records[0]?.displayName, '[REDACTED]');
  assertSafe(results);
});

test('credential-shaped content in a metadata field fails that collection without aborting other collectors', async () => {
  const results = await collect(config(['graph']), options(async (input, init) => {
    if (new URL(String(input)).pathname === '/v1.0/users') return json({
      value: [{ id: USER, displayName: 'https://example.invalid/file?sig=must-not-export' }],
    });
    return healthyFetch(input, init);
  }));
  assert.equal(dataset(results, 'entra.users').status, 'unavailable');
  assert.equal(dataset(results, 'entra.users').reason, 'invalid-response');
  assert.equal(dataset(results, 'entra.applications').status, 'complete');
  assertSafe(results);
});

test('catalog promotes SharePoint and policy states, adds assignment schedule instances, and retains explicit manual gaps', () => {
  assert.equal(COLLECTION_CATALOG.length, 76);
  assert.equal(new Set(COLLECTION_CATALOG.map(entry => entry.id)).size, 76);
  assert.equal(COLLECTION_CATALOG.filter(entry => !entry.manual).length, 60);
  assert.equal(COLLECTION_CATALOG.filter(entry => entry.manual).length, 16);
  for (const id of ['m365.sharePointSettings', 'entra.directoryRoleAssignmentScheduleInstances', 'azure.policyCompliance']) {
    assert.equal(COLLECTION_CATALOG.find(entry => entry.id === id)?.manual, undefined);
  }
  assert.ok(COLLECTION_CATALOG.find(entry => entry.id === 'm365.sharePointSettings')
    ?.permissions.includes('SharePointTenantSettings.Read.All'));
  assert.ok(COLLECTION_CATALOG.find(entry => entry.id === 'entra.directoryRoleAssignmentScheduleInstances')
    ?.permissions.some(permission => permission.includes('RoleAssignmentSchedule.Read.Directory')));
});

test('SharePoint settings use exactly one selected v1.0 object and preserve false, null, missing and nonboolean evidence', async () => {
  const cases: Array<{ input: JsonObject; expected: JsonObject }> = [
    { input: {}, expected: { id: 'sharepoint-settings' } },
    { input: { id: 'native-settings', isLegacyAuthProtocolsEnabled: false },
      expected: { id: 'native-settings', isLegacyAuthProtocolsEnabled: false } },
    { input: { isLegacyAuthProtocolsEnabled: null, isUnmanagedSyncAppForTenantRestricted: 'false', idleSessionSignOut: null },
      expected: { id: 'sharepoint-settings', isLegacyAuthProtocolsEnabled: null,
        isUnmanagedSyncAppForTenantRestricted: 'false', idleSessionSignOut: null } },
    {
      input: {
        isLegacyAuthProtocolsEnabled: false, isRequireAcceptingUserToMatchInvitedUserEnabled: true,
        isResharingByExternalUsersEnabled: null, sharingCapability: 'externalUserSharingOnly',
        sharingDomainRestrictionMode: 'blockList', sharingAllowedDomainList: [],
        sharingBlockedDomainList: ['blocked.invalid'],
        idleSessionSignOut: { isEnabled: true, signOutAfterInSeconds: 3600, warnAfterInSeconds: null, unselected: SECRET },
        allowedDomainGuidsForSyncApp: [SECRET], customSettings: { secret: SECRET },
      },
      expected: {
        id: 'sharepoint-settings', isLegacyAuthProtocolsEnabled: false,
        isRequireAcceptingUserToMatchInvitedUserEnabled: true, isResharingByExternalUsersEnabled: null,
        sharingCapability: 'externalUserSharingOnly', sharingDomainRestrictionMode: 'blockList',
        sharingAllowedDomainList: [], sharingBlockedDomainList: ['blocked.invalid'],
        idleSessionSignOut: { isEnabled: true, signOutAfterInSeconds: 3600, warnAfterInSeconds: null },
      },
    },
  ];
  for (const { input, expected } of cases) {
    let requests = 0;
    const results = await collect(config(['graph']), options(async (address, init) => {
      const parsed = new URL(String(address));
      if (parsed.pathname.startsWith('/v1.0/admin/sharepoint/')) {
        assert.equal(parsed.pathname, SHAREPOINT_PATH);
        assert.equal(init?.method, 'GET');
        assert.equal(init?.body, undefined);
        assert.deepEqual([...parsed.searchParams.keys()], ['$select']);
        assert.deepEqual(parsed.searchParams.get('$select')?.split(','), [
          'id', 'isLegacyAuthProtocolsEnabled', 'isRequireAcceptingUserToMatchInvitedUserEnabled',
          'isResharingByExternalUsersEnabled', 'isUnmanagedSyncAppForTenantRestricted',
          'sharingCapability', 'sharingDomainRestrictionMode', 'sharingAllowedDomainList',
          'sharingBlockedDomainList', 'idleSessionSignOut',
        ]);
        requests++;
        return json(input);
      }
      return healthyFetch(address, init);
    }));
    const settings = dataset(results, 'm365.sharePointSettings', TENANT);
    assert.equal(settings.status, 'complete');
    assert.equal(settings.source, SHAREPOINT_PATH);
    assert.equal(requests, 1);
    assert.deepEqual(settings.records, [expected]);
    assertSafe(results);
  }
});

test('SharePoint singleton rejects list/pagination envelopes and non-string domain entries without following links', async () => {
  for (const body of [
    [], { value: [] }, { isLegacyAuthProtocolsEnabled: false, '@odata.nextLink': 'https://attacker.invalid/data' },
    { isLegacyAuthProtocolsEnabled: true, nextLink: 'https://graph.microsoft.com/v1.0/sites' },
    { sharingAllowedDomainList: ['valid.invalid', 42] },
    { sharingBlockedDomainList: [null] },
  ]) {
    let requests = 0;
    const results = await collect(config(['graph']), options(async (input, init) => {
      if (new URL(String(input)).pathname === SHAREPOINT_PATH) { requests++; return json(body); }
      return healthyFetch(input, init);
    }));
    const settings = dataset(results, 'm365.sharePointSettings');
    assert.equal(settings.status, 'unavailable');
    assert.equal(settings.reason, 'invalid-response');
    assert.equal(settings.records.length, 0);
    assert.equal(requests, 1);
    assertSafe(results);
  }
});

test('role assignment schedule pages preserve native fields, explicit null end dates and missing dates distinctly', async () => {
  let pages = 0;
  const results = await collect(config(['graph']), options(async (input, init) => {
    const address = new URL(String(input));
    if (address.pathname !== SCHEDULE_PATH) return healthyFetch(input, init);
    pages++;
    assert.equal(init?.method, 'GET');
    assert.equal(address.searchParams.has('$expand'), false);
    assert.equal(address.searchParams.has('$top'), false);
    assert.deepEqual(address.searchParams.get('$select')?.split(','), [
      'id', 'principalId', 'roleDefinitionId', 'directoryScopeId', 'appScopeId', 'assignmentType',
      'memberType', 'startDateTime', 'endDateTime', 'roleAssignmentOriginId', 'roleAssignmentScheduleId',
    ]);
    if (address.searchParams.has('$skiptoken')) return json({
      value: [{ id: 'activated', principalId: USER, roleDefinitionId: SECOND,
        assignmentType: 'Activated', memberType: 'Direct', startDateTime: '2025-12-31T11:00:00Z',
        endDateTime: '2025-12-31T13:00:00Z' }],
    });
    const next = new URL(address);
    next.searchParams.set('$skiptoken', 'schedule-next');
    return json({ value: [
      { id: 'assigned', principalId: USER, roleDefinitionId: SECOND, directoryScopeId: '/', appScopeId: null,
        assignmentType: 'Assigned', memberType: 'Direct', startDateTime: '2025-12-01T00:00:00Z',
        endDateTime: null, roleAssignmentOriginId: 'origin', roleAssignmentScheduleId: 'schedule',
        principal: { password: SECRET }, activatedUsing: { secret: SECRET } },
      { id: 'unknown-end', principalId: SP, roleDefinitionId: SECOND, directoryScopeId: '/',
        assignmentType: 'Assigned', memberType: 'Group' },
    ], '@odata.nextLink': next.href });
  }));
  const schedules = dataset(results, 'entra.directoryRoleAssignmentScheduleInstances', TENANT);
  assert.equal(pages, 2);
  assert.equal(schedules.status, 'complete');
  assert.equal(schedules.records.length, 3);
  assert.equal(schedules.records[0]?.endDateTime, null);
  assert.ok(Object.hasOwn(schedules.records[0]!, 'endDateTime'));
  assert.equal(schedules.records[0]?.appScopeId, null);
  assert.equal(schedules.records[0]?.roleAssignmentOriginId, 'origin');
  assert.equal(schedules.records[0]?.roleAssignmentScheduleId, 'schedule');
  assert.equal(Object.hasOwn(schedules.records[1]!, 'endDateTime'), false);
  assert.equal(schedules.records[2]?.endDateTime, '2025-12-31T13:00:00Z');
  assertSafe(results);
});

test('new dataset 403, 404 and 429 responses are unavailable without licensing inference or unsafe fallback', async () => {
  for (const [status, reason] of [[403, 'permission-denied'], [404, 'not-found'], [429, 'rate-limited']] as const) {
    let rejectedCalls = 0;
    const results = await collect(config(['graph', 'azure']), options(async (input, init) => {
      const path = new URL(String(input)).pathname;
      if ([SHAREPOINT_PATH, SCHEDULE_PATH].includes(path)
        || (path === '/providers/Microsoft.ResourceGraph/resources' && JSON.parse(String(init?.body)).query === ARG_POLICY_QUERY)) {
        rejectedCalls++;
        return json({ error: { message: SECRET } }, status, { 'retry-after': '0' });
      }
      return healthyFetch(input, init);
    }));
    for (const id of ['m365.sharePointSettings', 'entra.directoryRoleAssignmentScheduleInstances', 'azure.policyCompliance']) {
      const result = dataset(results, id);
      assert.equal(result.status, 'unavailable');
      assert.equal(result.reason, reason);
      assert.equal(result.records.length, 0);
    }
    assert.equal(rejectedCalls, 3);
    assert.ok(!results.some(result => result.reason === 'not-licensed'));
    assertSafe(results);
  }
});

test('role-schedule and policy-state second-page failures preserve partial evidence', async () => {
  for (const [status, reason] of [[403, 'permission-denied'], [404, 'not-found'], [429, 'rate-limited']] as const) {
    const results = await collect(config(['graph', 'azure']), options(async (input, init) => {
      const address = new URL(String(input));
      if (address.pathname === SCHEDULE_PATH) {
        if (address.searchParams.has('$skiptoken')) return json({ error: TOKEN }, status);
        const next = new URL(address);
        next.searchParams.set('$skiptoken', 'schedule-next');
        return json({ value: [{ id: 'schedule-instance', endDateTime: null }], '@odata.nextLink': next.href });
      }
      if (address.pathname === '/providers/Microsoft.ResourceGraph/resources') {
        const body = JSON.parse(String(init?.body));
        if (body.query === ARG_POLICY_QUERY) return body.options.$skipToken
          ? json({ error: TOKEN }, status)
          : json({ data: [policyState()], count: 1, totalRecords: 2, resultTruncated: 'true', $skipToken: 'policy-next' });
      }
      return healthyFetch(input, init);
    }));
    for (const id of ['entra.directoryRoleAssignmentScheduleInstances', 'azure.policyCompliance']) {
      const result = dataset(results, id);
      assert.equal(result.status, 'partial');
      assert.equal(result.reason, reason);
      assert.equal(result.records.length, 1);
    }
    assertSafe(results);
  }
});

test('policy states retain native safe properties and derive stable unique IDs from the assessment tuple, not time or server IDs', async () => {
  const variants: Record<string, unknown>[] = [
    { policyDefinitionReferenceId: 'check' },
    { policyDefinitionReferenceId: 'check', resourceId: RESOURCE },
    { policyDefinitionReferenceId: 'check', policyAssignmentId: `${POLICY_ASSIGNMENT}-other` },
    { policyDefinitionReferenceId: 'check', policyDefinitionId: `${POLICY_DEFINITION}-other` },
    { policyDefinitionReferenceId: 'other' },
    { policyDefinitionReferenceId: 'Check' },
  ];
  const runs: CollectionResult[] = [];
  for (const updated of [false, true]) {
    const results = await collect(config(['azure']), options(async (input, init) => {
      if (new URL(String(input)).pathname === '/providers/Microsoft.ResourceGraph/resources'
        && JSON.parse(String(init?.body)).query === ARG_POLICY_QUERY) {
        return json({ count: variants.length, totalRecords: variants.length, resultTruncated: 'false',
          data: variants.map(properties => policyState({
            ...properties, timestamp: updated ? '2026-01-01T00:00:00Z' : '2025-12-31T12:00:00Z',
            complianceState: updated ? 'Compliant' : 'NonCompliant',
            effectiveParameters: SECRET, policyAssignmentParameters: SECRET,
            policyEvaluationDetails: { secret: SECRET }, expandedResource: { password: SECRET },
          }, { id: updated ? `${POLICY_SOURCE}-changed` : POLICY_SOURCE })),
        });
      }
      return healthyFetch(input, init);
    }));
    const states = dataset(results, 'azure.policyCompliance', `/subscriptions/${SUB}`);
    runs.push(states);
    assert.equal(states.status, 'complete');
    assert.equal(states.records.length, variants.length);
    assert.equal(new Set(states.records.map(record => record.id)).size, variants.length);
    assert.ok(states.records.every(record => /^policy-state-[0-9a-f]{64}$/.test(String(record.id))));
    assert.ok(states.records.every(record => record.sourceId === (updated ? `${POLICY_SOURCE}-changed` : POLICY_SOURCE)));
    assert.equal(states.source, '/providers/Microsoft.ResourceGraph/resources');
    const properties = states.records[0]?.properties as JsonObject;
    assert.deepEqual(Object.keys(properties).sort(), [
      'resourceId', 'policyAssignmentId', 'policyAssignmentName', 'policyAssignmentScope', 'policyDefinitionId',
      'policyDefinitionReferenceId', 'policySetDefinitionId', 'policyDefinitionAction', 'complianceState', 'timestamp',
    ].sort());
    assert.equal(properties.policySetDefinitionId, null);
    assert.equal(properties.resourceId, STORAGE);
    assertSafe(results);
  }
  assert.deepEqual(runs[0]?.records.map(record => record.id), runs[1]?.records.map(record => record.id));
});

test('policy-state IDs normalize ARM identifier case but preserve reference identity and absence in evidence', async () => {
  const ids: string[] = [];
  for (const reference of [undefined, null, '']) {
    const upperCase = reference === null;
    const results = await collect(config(['azure']), options(async (input, init) => {
      if (new URL(String(input)).pathname === '/providers/Microsoft.ResourceGraph/resources'
        && JSON.parse(String(init?.body)).query === ARG_POLICY_QUERY) return json({
        data: [policyState({
          resourceId: upperCase ? STORAGE.toUpperCase() : STORAGE,
          policyAssignmentId: upperCase ? POLICY_ASSIGNMENT.toUpperCase() : POLICY_ASSIGNMENT,
          policyDefinitionId: upperCase ? POLICY_DEFINITION.toUpperCase() : POLICY_DEFINITION,
          policyDefinitionReferenceId: reference,
        })], resultTruncated: 'false',
      });
      return healthyFetch(input, init);
    }));
    const record = dataset(results, 'azure.policyCompliance').records[0];
    assert.ok(record);
    ids.push(String(record.id));
    const properties = record.properties as JsonObject;
    assert.equal(properties.policyDefinitionReferenceId, reference);
    assert.equal(Object.hasOwn(properties, 'policyDefinitionReferenceId'), reference !== undefined);
    assertSafe(results);
  }
  assert.equal(new Set(ids).size, 1);
});

test('policy ARG continuation keeps the original query and approved subscription despite untrusted envelope fields', async () => {
  const bodies: Array<{ query: string; subscriptions: string[]; options: { $skipToken?: string } }> = [];
  const results = await collect(config(['azure']), options(async (input, init) => {
    if (new URL(String(input)).pathname === '/providers/Microsoft.ResourceGraph/resources') {
      const body = JSON.parse(String(init?.body));
      if (body.query === ARG_POLICY_QUERY) {
        bodies.push(body);
        return body.options.$skipToken
          ? json({ data: [policyState({ policyDefinitionReferenceId: 'second' })], resultTruncated: 'false', totalRecords: 2 })
          : json({ data: [policyState({ policyDefinitionReferenceId: 'first' })], resultTruncated: 'true', totalRecords: 2,
            $skipToken: 'policy-next', query: ARG_RESOURCE_QUERY, subscriptions: [SECOND],
            nextLink: 'https://attacker.invalid/secret' });
      }
    }
    return healthyFetch(input, init);
  }));
  const states = dataset(results, 'azure.policyCompliance');
  assert.equal(states.status, 'complete');
  assert.equal(states.records.length, 2);
  assert.equal(bodies.length, 2);
  assert.ok(bodies.every(body => body.query === ARG_POLICY_QUERY && JSON.stringify(body.subscriptions) === JSON.stringify([SUB])));
  assert.equal(bodies[1]?.options.$skipToken, 'policy-next');
  assertSafe(results);
});

test('policy-state foreign scope and malformed resource IDs are rejected before evidence acceptance', async () => {
  const invalid: Array<{ properties?: Record<string, unknown>; overrides?: Record<string, unknown>; reason: string }> = [
    { overrides: { subscriptionId: SECOND }, reason: 'scope-mismatch' },
    { properties: { resourceId: STORAGE.replace(SUB, SECOND) }, reason: 'scope-mismatch' },
    { overrides: { id: POLICY_SOURCE.replace(SUB, SECOND) }, reason: 'scope-mismatch' },
    { properties: { resourceId: `/subscriptions/${SUB}/../${SECOND}` }, reason: 'invalid-response' },
    { properties: { resourceId: `/subscriptions/${SUB}/%2e%2e/${SECOND}` }, reason: 'invalid-response' },
    { properties: { resourceId: `https://management.azure.com${STORAGE}` }, reason: 'invalid-response' },
    { properties: { resourceId: null }, reason: 'invalid-response' },
    { properties: { policyAssignmentId: null }, reason: 'invalid-response' },
    { properties: { policyDefinitionId: null }, reason: 'invalid-response' },
    { overrides: { type: 'microsoft.resources/deployments' }, reason: 'invalid-response' },
    { overrides: { subscriptionId: null }, reason: 'invalid-response' },
  ];
  for (const candidate of invalid) {
    const results = await collect(config(['azure']), options(async (input, init) => {
      if (new URL(String(input)).pathname === '/providers/Microsoft.ResourceGraph/resources'
        && JSON.parse(String(init?.body)).query === ARG_POLICY_QUERY) return json({
        data: [policyState(candidate.properties, candidate.overrides)], resultTruncated: 'false',
      });
      return healthyFetch(input, init);
    }));
    const states = dataset(results, 'azure.policyCompliance');
    assert.equal(states.status, 'unavailable');
    assert.equal(states.reason, candidate.reason);
    assert.equal(states.records.length, 0);
    assertSafe(results);
  }
});

test('policy page, record, response and request bounds, truncation, duplicate identities and looping cursors stay partial', async () => {
  for (const mode of ['pages', 'records', 'bytes', 'requests', 'truncated', 'duplicate', 'loop'] as const) {
    const selected = config(['azure']);
    if (mode === 'pages') selected.limits.maxPages = 1;
    if (mode === 'records') selected.limits.maxRecords = 1;
    if (mode === 'bytes') selected.limits.maxResponseBytes = 2048;
    if (mode === 'requests') selected.limits.maxRequests = 5;
    let calls = 0;
    const results = await collect(selected, options(async (input, init) => {
      if (new URL(String(input)).pathname === '/providers/Microsoft.ResourceGraph/resources'
        && JSON.parse(String(init?.body)).query === ARG_POLICY_QUERY) {
        calls++;
        const second = policyState({ policyDefinitionReferenceId: mode === 'duplicate' ? 'first' : 'second' });
        if (mode === 'records' || mode === 'duplicate') return json({
          data: [policyState({ policyDefinitionReferenceId: 'first' }), second], resultTruncated: 'false',
        });
        if (mode === 'bytes' && calls > 1) return json({ data: [second], padding: 'x'.repeat(4096) });
        return json({
          data: [calls === 1 ? policyState({ policyDefinitionReferenceId: 'first' }) : second],
          resultTruncated: 'true', ...(mode === 'truncated' ? {} : { $skipToken: 'repeated-cursor' }),
        });
      }
      return healthyFetch(input, init);
    }));
    const states = dataset(results, 'azure.policyCompliance');
    assert.equal(states.status, 'partial');
    assert.equal(states.reason, mode === 'duplicate' || mode === 'loop' ? 'invalid-response' : 'limit-reached');
    assert.equal(states.records.length, mode === 'loop' ? 2 : 1);
    assert.ok(calls <= 2);
    assertSafe(results);
  }
});

test('policy-state collection requires verified subscription tenant evidence even when Graph read-back is denied', async () => {
  for (const validTenant of [false, true]) {
    let policyCalls = 0;
    const results = await collect(config(['azure']), options(async (input, init) => {
      const address = new URL(String(input));
      if (address.pathname === '/v1.0/organization') return json({}, 403);
      if (address.pathname === `/subscriptions/${SUB}` && !validTenant) return json({
        id: `/subscriptions/${SUB}`, tenantId: SECOND, subscriptionId: SUB,
      });
      if (address.pathname === '/providers/Microsoft.ResourceGraph/resources'
        && JSON.parse(String(init?.body)).query === ARG_POLICY_QUERY) policyCalls++;
      return healthyFetch(input, init);
    }));
    const states = dataset(results, 'azure.policyCompliance');
    assert.equal(states.status, validTenant ? 'complete' : 'unavailable');
    assert.equal(policyCalls, validTenant ? 1 : 0);
    if (!validTenant) assert.equal(states.reason, 'scope-mismatch');
    assertSafe(results);
  }
});
