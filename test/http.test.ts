import assert from 'node:assert/strict';
import test from 'node:test';
import { ARG_POLICY_QUERY, ARG_RESOURCE_QUERY, CollectionError, GRAPH_SELECT, SafeHttpClient } from '../src/http.js';
import type { ResourceGraphQuery } from '../src/http.js';
import type { AssessmentConfig, Provider } from '../src/model.js';

const TENANT = '11111111-1111-4111-8111-111111111111';
const SUB = '22222222-2222-4222-8222-222222222222';
const OTHER_SUB = '33333333-3333-4333-8333-333333333333';
const PROJECT = '44444444-4444-4444-8444-444444444444';
const TOKEN = 'mock-credential-DO-NOT-EXPOSE';
const GRAPH = 'https://graph.microsoft.com/v1.0/users';
const ARG = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01';

function config(limits: Partial<AssessmentConfig['limits']> = {}): AssessmentConfig {
  return {
    scope: {
      tenantId: TENANT, subscriptionIds: [SUB, OTHER_SUB],
      githubOrganizations: ['contoso', 'fabrikam'], azureDevOpsOrganizations: ['contoso', 'fabrikam'],
    },
    sources: { graph: true, azure: true, defender: true, github: true, azureDevOps: true },
    auth: { azure: { mode: 'azure-cli' }, github: { tokenEnvironmentVariable: 'ASSESSMENT_GITHUB_TOKEN' } },
    limits: {
      maxPages: 5, maxRecords: 1000, maxRequests: 100, timeoutMs: 1000, maxRetries: 0,
      maxResponseBytes: 100_000, ...limits,
    },
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

const response = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
const hasReason = (reason: string) => (error: unknown): boolean =>
  error instanceof CollectionError && error.reason === reason && !String(error.stack).includes(TOKEN);

test('default-deny rejects writes, secrets, downloads, unapproved query shapes and scope changes before auth', async () => {
  let tokens = 0;
  let requests = 0;
  const client = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { tokens++; return TOKEN; } },
    fetch: async () => { requests++; return response({}); },
  });
  const forbidden: Array<[Provider, string, string?, unknown?]> = [
    ['graph', GRAPH, 'POST', {}], ['graph', GRAPH, 'PATCH', {}], ['graph', GRAPH, 'PUT', {}],
    ['graph', GRAPH, 'DELETE'], ['graph', GRAPH, 'HEAD'], ['graph', GRAPH, 'OPTIONS'],
    ['graph', 'https://graph.microsoft.com/v1.0/$batch', 'POST', {}],
    ['graph', `https://graph.microsoft.com/v1.0/users/${TENANT}/authentication/passwordMethods`],
    ['graph', 'https://graph.microsoft.com/v1.0/users?$expand=manager'],
    ['graph', 'https://graph.microsoft.com/v1.0/users?$select=passwordProfile'],
    ['graph', 'https://graph.microsoft.com/beta/users'],
    ['graph', 'https://graph.microsoft.com/v1.0/me/messages'],
    ['graph', 'https://graph.microsoft.com/v1.0/drives/one/items/two/content'],
    ['azure', `https://management.azure.com/subscriptions/${SUB}/resourceGroups/a/providers/Microsoft.KeyVault/vaults/b/secrets/c?api-version=2023-07-01`],
    ['azure', `https://management.azure.com/subscriptions/${SUB}/resourceGroups/a/providers/Microsoft.Storage/storageAccounts/b/listKeys?api-version=2023-05-01`],
    ['azure', 'https://example.vault.azure.net/secrets'],
    ['azure', 'https://management.azure.com/subscriptions?api-version=2022-12-01'],
    ['azure', `https://management.azure.com/subscriptions/${TENANT}?api-version=2022-12-01`],
    ['azure', ARG, 'GET'],
    ['azure', ARG, 'POST', { query: 'Resources', subscriptions: [SUB], options: {} }],
    ['azure', ARG, 'POST', { ...client.resourceGraphBody(SUB), managementGroups: ['root'] }],
    ['azure', ARG, 'POST', client.resourceGraphBody(TENANT)],
    ['github', 'https://api.github.com/repos/contoso/app/contents/.github/workflows/build.yml'],
    ['github', 'https://api.github.com/repos/contoso/app/git/blobs/abc'],
    ['github', 'https://api.github.com/repos/contoso/app/actions/artifacts/1/zip'],
    ['github', 'https://api.github.com/repos/contoso/app/actions/variables'],
    ['github', 'https://api.github.com/repos/contoso/app/actions/secrets/NAME'],
    ['github', 'https://api.github.com/repos/contoso/app/secret-scanning/alerts'],
    ['github', 'https://api.github.com/repos/contoso/app/secret-scanning/alerts?hide_secret=false'],
    ['github', 'https://api.github.com/repos/contoso/app/secret-scanning/alerts/1?hide_secret=true'],
    ['github', 'https://api.github.com/repos/contoso/app/secret-scanning/alerts?hide_secret=true&hide_secret=false'],
    ['github', 'https://api.github.com/repos/unknown/app/actions/workflows'],
    ['github', 'https://github.contoso.com/api/v3/orgs/contoso/repos'],
    ['azureDevOps', `https://dev.azure.com/contoso/${PROJECT}/_apis/serviceendpoint/endpoints?api-version=7.1`],
    ['azureDevOps', `https://dev.azure.com/contoso/${PROJECT}/_apis/distributedtask/variablegroups?api-version=7.1`],
    ['azureDevOps', `https://dev.azure.com/contoso/${PROJECT}/_apis/distributedtask/securefiles/1?download=true&api-version=7.1`],
    ['azureDevOps', `https://dev.azure.com/unknown/${PROJECT}/_apis/git/repositories?api-version=7.1`],
    ['defender', 'https://api.security.microsoft.com/api/advancedqueries/run', 'POST', {}],
    ['defender', 'https://api.security.microsoft.com/api/machineactions'],
    ['graph', 'http://graph.microsoft.com/v1.0/users'],
    ['graph', 'https://graph.microsoft.com.evil.example/v1.0/users'],
    ['graph', 'https://graph.microsoft.com@evil.example/v1.0/users'],
    ['graph', 'https://user:password@graph.microsoft.com/v1.0/users'],
    ['graph', 'https://graph.microsoft.com:444/v1.0/users'],
    ['graph', 'https://graph.microsoft.com/v1.0/a/../users'],
    ['graph', 'https://graph.microsoft.com/v1.0/a/%2e%2e/users'],
    ['graph', 'https://graph.microsoft.com/v1.0/a/%252e%252e/users'],
    ['graph', 'https://graph.microsoft.com\\evil.example/v1.0/users'],
    ['graph', 'https://graph.microsoft.com/v1.0/users#fragment'],
    ['graph', 'https://graph.microsoft.com/v1.0/users?access_token=leaked'],
  ];
  for (const [provider, address, method, body] of forbidden) {
    await assert.rejects(client.request(provider, address, { method, body }), CollectionError);
  }
  assert.equal(tokens, 0);
  assert.equal(requests, 0);
  assert.equal(client.requestCount, 0);
});

test('only the fixed, explicitly subscription-scoped Resource Graph POST is allowed', async () => {
  let captured: RequestInit | undefined;
  let calls = 0;
  const client = new SafeHttpClient(config(), {
    tokenProvider: { async getToken(provider) { assert.equal(provider, 'azure'); return TOKEN; } },
    fetch: async (_address, init) => {
      captured = init;
      return response({ data: [], count: 0, ...(calls++ === 0 ? { $skipToken: 'opaque-page-token' } : {}) });
    },
  });
  await client.request('azure', ARG, { method: 'POST', body: client.resourceGraphBody(SUB) });
  const body = client.resourceGraphBody(SUB, 'resources', 'opaque-page-token');
  await client.request('azure', ARG, { method: 'POST', body });
  assert.deepEqual(JSON.parse(String(captured?.body)), body);
  assert.equal(JSON.parse(String(captured?.body)).query, ARG_RESOURCE_QUERY);
  assert.equal(captured?.redirect, 'error');
  assert.equal(captured?.credentials, 'omit');
  assert.equal(captured?.method, 'POST');
  await assert.rejects(client.request('azure', ARG, {
    method: 'POST', body: { ...body, subscriptions: [SUB, OTHER_SUB] },
  }), hasReason('unsupported'));
  await assert.rejects(client.request('azure', ARG, {
    method: 'POST', body: { ...body, options: { resultFormat: 'objectArray', $top: 1000, allowPartialScopes: true } },
  }), hasReason('unsupported'));
});

test('continuations cannot change host, route, collection query, repository, project or subscription', async () => {
  let calls = 0;
  const client = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { calls++; return TOKEN; } },
    fetch: async () => response({ value: [] }),
  });
  const denied: Array<[Provider, string, string]> = [
    ['graph', `${GRAPH}?$select=id`, 'https://evil.example/v1.0/users?$select=id'],
    ['graph', GRAPH, 'https://graph.microsoft.com/v1.0/applications'],
    ['graph', `${GRAPH}?$select=id`, `${GRAPH}?$select=id,displayName&$skiptoken=x`],
    ['graph', `${GRAPH}?$top=100`, `${GRAPH}?$top=500&$skiptoken=x`],
    ['github', 'https://api.github.com/repos/contoso/app/actions/workflows?per_page=100',
      'https://api.github.com/repos/fabrikam/app/actions/workflows?per_page=100&page=2'],
    ['github', 'https://api.github.com/repos/contoso/app/secret-scanning/alerts?hide_secret=true',
      'https://api.github.com/repos/contoso/app/secret-scanning/alerts?page=2'],
    ['azureDevOps', `https://dev.azure.com/contoso/${PROJECT}/_apis/pipelines?api-version=7.1`,
      `https://dev.azure.com/contoso/${TENANT}/_apis/pipelines?api-version=7.1&continuationToken=2`],
    ['azure', `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`,
      `https://management.azure.com/subscriptions/${OTHER_SUB}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$skiptoken=2`],
  ];
  for (const [provider, initial, next] of denied) {
    await assert.rejects(client.request(provider, next, { continuationOf: initial }), CollectionError);
  }
  assert.equal(calls, 0);
  await client.request('graph', `${GRAPH}?$top=100&$skiptoken=opaque%2Bvalue`, { continuationOf: `${GRAPH}?$top=100` });
  assert.equal(calls, 1);
});

test('remote status errors, transport errors and token errors are redacted and never retried indiscriminately', async () => {
  for (const [status, reason] of [[401, 'authentication-failed'], [403, 'permission-denied'],
    [404, 'not-found'], [501, 'api-error']] as const) {
    let count = 0;
    const client = new SafeHttpClient(config({ maxRetries: 3 }), {
      tokenProvider: { async getToken() { return TOKEN; } },
      fetch: async () => { count++; return response({ error: { message: TOKEN } }, status); },
    });
    await assert.rejects(client.request('graph', GRAPH), hasReason(reason));
    assert.equal(count, 1);
  }
  const tokenFailure = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { throw new Error(`Credential failed: ${TOKEN}`); } },
    fetch: async () => { assert.fail('must not fetch without authentication'); },
  });
  await assert.rejects(tokenFailure.request('graph', GRAPH), hasReason('authentication-failed'));
  const transportFailure = new SafeHttpClient(config({ maxRetries: 3 }), {
    tokenProvider: { async getToken() { return TOKEN; } },
    fetch: async () => { throw new Error(`Transport returned ${TOKEN}`); },
  });
  await assert.rejects(transportFailure.request('graph', GRAPH), hasReason('api-error'));
});

test('redirects are rejected and remote bodies are never used as error messages', async () => {
  let calls = 0;
  const client = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { return TOKEN; } },
    fetch: async (_input, init) => {
      calls++;
      assert.equal(init?.redirect, 'error');
      return new Response(TOKEN, { status: 302, headers: { location: 'https://evil.example/steal' } });
    },
  });
  await assert.rejects(client.request('graph', GRAPH), hasReason('unsupported'));
  assert.equal(calls, 1);
});

test('429 and transient 5xx honor bounded Retry-After and the shared request budget', async () => {
  let calls = 0;
  const sleeps: number[] = [];
  const client = new SafeHttpClient(config({ maxRetries: 2, timeoutMs: 10_000 }), {
    tokenProvider: { async getToken() { return TOKEN; } },
    fetch: async () => {
      calls++;
      if (calls === 1) return response({ error: TOKEN }, 429, { 'retry-after': '2' });
      if (calls === 2) return response({ error: TOKEN }, 503);
      return response({ value: [] });
    },
    sleep: async milliseconds => { sleeps.push(milliseconds); },
  });
  assert.deepEqual((await client.request('graph', GRAPH)).body, { value: [] });
  assert.equal(calls, 3);
  assert.deepEqual(sleeps, [2000, 1000]);
  const limited = new SafeHttpClient(config({ maxRetries: 5, maxRequests: 1 }), {
    tokenProvider: { async getToken() { return TOKEN; } },
    fetch: async () => response({ error: TOKEN }, 429, { 'retry-after': '0' }),
    sleep: async () => assert.fail('budget must be checked before sleeping'),
  });
  await assert.rejects(limited.request('graph', GRAPH), hasReason('rate-limited'));
  await assert.rejects(limited.request('graph', GRAPH), hasReason('limit-reached'));
  const longRetry = new SafeHttpClient(config({ maxRetries: 5 }), {
    tokenProvider: { async getToken() { return TOKEN; } },
    fetch: async () => response({ error: TOKEN }, 429, { 'retry-after': '86400' }),
    sleep: async () => assert.fail('unbounded Retry-After must not be used'),
  });
  await assert.rejects(longRetry.request('graph', GRAPH), hasReason('rate-limited'));
});

test('HTTP-date Retry-After uses injected clock and retry exhaustion stays explicit', async () => {
  const sleeps: number[] = [];
  const client = new SafeHttpClient(config({ maxRetries: 1, timeoutMs: 10_000 }), {
    tokenProvider: { async getToken() { return TOKEN; } },
    now: () => new Date('2026-01-01T00:00:00Z'),
    sleep: async milliseconds => { sleeps.push(milliseconds); },
    fetch: async () => response({}, 429, { 'retry-after': 'Thu, 01 Jan 2026 00:00:03 GMT' }),
  });
  await assert.rejects(client.request('graph', GRAPH), hasReason('rate-limited'));
  assert.deepEqual(sleeps, [3000]);
  assert.equal(client.requestCount, 2);
});

test('timeout includes response streaming and cancels a stalled body', async () => {
  let cancelled = false;
  const client = new SafeHttpClient(config({ timeoutMs: 20 }), {
    tokenProvider: { async getToken() { return TOKEN; } },
    fetch: async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode('{"value":[')); },
      cancel() { cancelled = true; },
    }), { headers: { 'content-type': 'application/json' } }),
  });
  await assert.rejects(client.request('graph', GRAPH), hasReason('timeout'));
  assert.equal(cancelled, true);
});

test('timeout includes injected authentication that never resolves', async () => {
  const client = new SafeHttpClient(config({ timeoutMs: 20 }), {
    tokenProvider: { getToken: () => new Promise<string>(() => undefined) },
    fetch: async () => assert.fail('must not send a timed-out credential request'),
  });
  await assert.rejects(client.request('graph', GRAPH), hasReason('timeout'));
});

test('response bytes, JSON type and request count are bounded', async () => {
  for (const makeResponse of [
    () => response({ value: 'x'.repeat(100) }),
    () => new Response('{}', { headers: { 'content-type': 'application/json', 'content-length': '1000' } }),
  ]) {
    const client = new SafeHttpClient(config({ maxResponseBytes: 50 }), {
      tokenProvider: { async getToken() { return TOKEN; } }, fetch: async () => makeResponse(),
    });
    await assert.rejects(client.request('graph', GRAPH), hasReason('limit-reached'));
  }
  const html = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { return TOKEN; } },
    fetch: async () => new Response(TOKEN, { headers: { 'content-type': 'text/html' } }),
  });
  await assert.rejects(html.request('graph', GRAPH), hasReason('invalid-response'));
  const malformed = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { return TOKEN; } },
    fetch: async () => new Response(`{"${TOKEN}"`, { headers: { 'content-type': 'application/json' } }),
  });
  await assert.rejects(malformed.request('graph', GRAPH), hasReason('invalid-response'));
  const budget = new SafeHttpClient(config({ maxRequests: 1 }), {
    tokenProvider: { async getToken() { return TOKEN; } }, fetch: async () => response({ value: [] }),
  });
  await budget.request('graph', GRAPH);
  await assert.rejects(budget.request('graph', GRAPH), hasReason('limit-reached'));
  assert.equal(budget.requestCount, 1);
});

test('token echoes are redacted recursively before they become evidence', async () => {
  const client = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { return TOKEN; } }, fetch: async () => response({ value: [] }),
  });
  await client.request('graph', GRAPH);
  const projected = client.redact({ id: '1', displayName: TOKEN, nested: [{ name: `prefix ${TOKEN}` }] });
  assert.ok(!JSON.stringify(projected).includes(TOKEN));
  assert.deepEqual(projected, { id: '1', displayName: '[REDACTED]', nested: [{ name: 'prefix [REDACTED]' }] });
});

test('SharePoint singleton and role schedules require safe select lists and never allow writes, expansion or adjacent routes', async () => {
  let authCalls = 0;
  const calls: string[] = [];
  const client = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { authCalls++; return TOKEN; } },
    fetch: async input => { calls.push(String(input)); return response({}); },
  });
  const settings = 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings';
  const schedules = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances';
  const denied: Array<[string, string?]> = [
    [settings], [`${settings}?$select=allowedDomainGuidsForSyncApp`],
    [`${settings}?$select=id&$top=1`], [`${settings}?$select=id&$skiptoken=1`],
    [`${settings}?$select=id&$expand=sites`], [`${settings}/sites?$select=id`],
    [settings.replace('/v1.0/', '/beta/') + '?$select=id'],
    [`${settings}?$select=id`, 'PATCH'], [`${settings}?$select=id`, 'POST'],
    [`${settings}?$select=id`, 'DELETE'],
    [schedules], [`${schedules}?$select=id&$expand=principal`],
    [`${schedules}?$select=id,activatedUsing`], [`${schedules}?$select=id&$top=100`],
    [schedules.replace('roleAssignmentScheduleInstances', 'roleAssignmentScheduleRequests') + '?$select=id'],
    [schedules.replace('/v1.0/', '/beta/') + '?$select=id'],
    [`${schedules}?$select=id`, 'POST'],
  ];
  for (const [address, method] of denied) {
    await assert.rejects(client.request('graph', address, { method }), hasReason('unsupported'));
  }
  assert.equal(authCalls, 0);
  assert.deepEqual(calls, []);
  for (const [base, key] of [[settings, 'admin/sharepoint/settings'],
    [schedules, 'roleManagement/directory/roleAssignmentScheduleInstances']] as const) {
    const select = GRAPH_SELECT[key];
    assert.ok(select);
    await client.request('graph', `${base}?${new URLSearchParams({ $select: select })}`);
  }
  assert.equal(authCalls, 2);
  assert.ok(calls.every(address => !new URL(address).searchParams.has('$top')));
});

test('policy ARG permits only its named fixed metadata projection and rejects mutated queries before authentication', async () => {
  let authCalls = 0;
  const requests: RequestInit[] = [];
  const client = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { authCalls++; return TOKEN; } },
    fetch: async (_input, init) => { assert.ok(init); requests.push(init); return response({ data: [] }); },
  });
  const body = client.resourceGraphBody(SUB, 'policy-compliance');
  assert.equal(body.query, ARG_POLICY_QUERY);
  assert.throws(() => client.resourceGraphBody(SUB, 'custom' as ResourceGraphQuery), hasReason('unsupported'));
  const rejected: unknown[] = [
    { ...body, query: 'PolicyResources' },
    { ...body, query: `${ARG_POLICY_QUERY} | project properties` },
    { ...body, query: ARG_POLICY_QUERY.replace("'timestamp', properties.timestamp", "'parameters', properties.policyAssignmentParameters") },
    { ...body, query: ARG_POLICY_QUERY.replace('PolicyResources', 'Resources') },
    { ...body, query: ARG_POLICY_QUERY.replace('| order by', '| take 1 | order by') },
    { ...body, query: `${ARG_POLICY_QUERY} ` },
    { ...body, subscriptions: [] }, { ...body, subscriptions: [TENANT] },
    { ...body, subscriptions: [SUB, OTHER_SUB] }, { ...body, managementGroups: ['root'] },
    { ...body, facets: [{ expression: 'properties' }] },
    { ...body, options: { resultFormat: 'table', $top: 1000 } },
    { ...body, options: { resultFormat: 'objectArray', $top: 1001 } },
    { ...body, options: { resultFormat: 'objectArray', $top: 1000, allowPartialScopes: true } },
  ];
  for (const candidate of rejected) {
    await assert.rejects(client.request('azure', ARG, { method: 'POST', body: candidate }), hasReason('unsupported'));
  }
  assert.equal(authCalls, 0);
  assert.equal(requests.length, 0);
  await client.request('azure', ARG, { method: 'POST', body });
  assert.equal(authCalls, 1);
  const sent = JSON.parse(String(requests[0]?.body)) as { subscriptions: string[]; query: string };
  assert.deepEqual(sent.subscriptions, [SUB]);
  assert.equal(sent.query, ARG_POLICY_QUERY);
  assert.match(sent.query, /^PolicyResources \| where type =~ 'Microsoft\.PolicyInsights\/PolicyStates'/);
  assert.match(sent.query, /\| order by assessmentResourceId asc, assessmentAssignmentId asc,/);
  assert.match(sent.query, /\| project id, type, subscriptionId, resourceGroup, properties = bag_pack\(/);
  const projectedProperties = [...sent.query.matchAll(/'(\w+)', properties\.(\w+)/g)];
  assert.deepEqual(projectedProperties.map(match => [match[1], match[2]]), [
    'resourceId', 'policyAssignmentId', 'policyAssignmentName', 'policyAssignmentScope',
    'policyDefinitionId', 'policyDefinitionReferenceId', 'policySetDefinitionId',
    'policyDefinitionAction', 'complianceState', 'timestamp',
  ].map(field => [field, field]));
  assert.doesNotMatch(sent.query, /parameters|evaluationDetails|project\s+\*|extend\s+properties\b/i);
});

test('ARG cursors cannot change the fixed query or approved subscription, be invented, or be replayed after completion', async () => {
  let authCalls = 0;
  const client = new SafeHttpClient(config(), {
    tokenProvider: { async getToken() { authCalls++; return TOKEN; } },
    fetch: async (_input, init) => {
      const body = JSON.parse(String(init?.body));
      return response({
        data: [], resultTruncated: 'false',
        ...(body.options.$skipToken ? {} : {
          $skipToken: body.query === ARG_RESOURCE_QUERY ? 'resources-next' : 'policy-next',
        }),
      });
    },
  });
  await assert.rejects(client.request('azure', ARG, {
    method: 'POST', body: client.resourceGraphBody(SUB, 'policy-compliance', 'invented'),
  }), hasReason('scope-mismatch'));
  assert.equal(authCalls, 0);
  await client.request('azure', ARG, { method: 'POST', body: client.resourceGraphBody(SUB) });
  await assert.rejects(client.request('azure', ARG, {
    method: 'POST', body: client.resourceGraphBody(SUB, 'policy-compliance', 'resources-next'),
  }), hasReason('scope-mismatch'));
  await assert.rejects(client.request('azure', ARG, {
    method: 'POST', body: client.resourceGraphBody(OTHER_SUB, 'resources', 'resources-next'),
  }), hasReason('scope-mismatch'));
  assert.equal(authCalls, 1);
  await client.request('azure', ARG, { method: 'POST', body: client.resourceGraphBody(SUB, 'policy-compliance') });
  await assert.rejects(client.request('azure', ARG, {
    method: 'POST', body: client.resourceGraphBody(SUB, 'resources', 'policy-next'),
  }), hasReason('scope-mismatch'));
  assert.equal(authCalls, 2);
  await client.request('azure', ARG, { method: 'POST', body: client.resourceGraphBody(SUB, 'resources', 'resources-next') });
  await client.request('azure', ARG, { method: 'POST', body: client.resourceGraphBody(SUB, 'policy-compliance', 'policy-next') });
  assert.equal(authCalls, 4);
  await assert.rejects(client.request('azure', ARG, {
    method: 'POST', body: client.resourceGraphBody(SUB, 'policy-compliance', 'policy-next'),
  }), hasReason('scope-mismatch'));
  assert.equal(authCalls, 4);
});
