import assert from 'node:assert/strict';
import test from 'node:test';
import { parseConfig } from '../src/config.js';
import { assessLive, createAssessment, TOOL_VERSION } from '../src/engine.js';
import { DEFAULT_POLICY } from '../src/policy.js';
import { assertSafeEvidence, canonicalJson, recordKey, safeHttpsUrl } from '../src/safety.js';
import { parseInput, parseSnapshot } from '../src/validation.js';
import { collection, finding, input, scope, snapshot, tenant, timestamp } from './support.js';
import { readFile } from 'node:fs/promises';

test('configuration is strict, normalized, explicit, and uses bounded defaults', () => {
  const config = parseConfig({ scope: { ...scope, githubOrganizations: ['EXAMPLE-ORG', 'example-org'] } });
  assert.deepEqual(config.scope.githubOrganizations, ['example-org']);
  assert.equal(config.auth.azure.mode, 'azure-cli');
  assert.equal(config.limits.maxRetries, 3);
  assert.equal(config.sources.azure, false);
  assert.throws(() => parseConfig({ scope, surprise: true }), /invalid/);
  assert.throws(() => parseConfig({ scope, limits: { maxRequests: -1 } }), /invalid/);
  assert.throws(() => parseConfig({ scope, auth: { azure: { mode: 'client-secret' } } }), /invalid/);
});

test('live providers cannot silently broaden absent subscription and organization scopes', () => {
  assert.throws(() => parseConfig({ scope: { ...scope, subscriptionIds: [] }, sources: { azure: true } }), /subscriptionIds/);
  assert.throws(() => parseConfig({ scope: { ...scope, githubOrganizations: [] }, sources: { github: true } }), /githubOrganizations/);
  assert.throws(() => parseConfig({ scope: { ...scope, azureDevOpsOrganizations: [] }, sources: { azureDevOps: true } }), /azureDevOpsOrganizations/);
  assert.throws(() => parseConfig({ scope, auth: { azure: { mode: 'workload-identity' } } }), /clientId/);
  assert.throws(() => parseConfig({ scope, auth: { azure: { mode: 'azure-cli', clientId: tenant } } }), /not used/);
});

test('risk policy is configurable without mutating defaults or accepting duplicate permission rules', () => {
  const config = parseConfig({ scope, policy: { maxOwners: 7, weights: { broadScope: 0 } } });
  assert.equal(config.policy.maxOwners, 7);
  assert.equal(config.policy.weights.broadScope, 0);
  assert.notEqual(DEFAULT_POLICY.maxOwners, 7);
  const rule = DEFAULT_POLICY.permissionRules[0];
  assert.ok(rule);
  assert.throws(() => parseConfig({ scope, policy: { permissionRules: [rule, rule] } }), /invalid/);
});

test('secret-bearing inputs and prototype manipulation fail without echoing values', () => {
  for (const key of ['secretText', 'hint', 'clientSecret', 'authorization', 'privateKey', 'secret', 'access_token']) {
    assert.throws(() => assertSafeEvidence({ nested: { [key]: 'sensitive-sentinel' } }), error => {
      assert.ok(error instanceof Error);
      assert.ok(!error.message.includes('sensitive-sentinel'));
      return true;
    });
  }
  assert.throws(() => assertSafeEvidence(JSON.parse('{"__proto__":{"admin":true}}')), /prohibited/);
  assert.throws(() => assertSafeEvidence({ value: `ghp_${'a'.repeat(36)}` }), /Credential-shaped/);
  assert.throws(() => assertSafeEvidence({ value: 'https://example.invalid/?sig=secret-signature' }), /Credential-shaped/);
  assert.throws(() => assertSafeEvidence({ value: Number.NaN }), /finite JSON/);
  assertSafeEvidence({ passwordCredentials: [{ keyId: 'key-1', startDateTime: timestamp, endDateTime: timestamp }] });
});

test('input rejects bad chronology, out-of-scope data, missing identifiers, and hidden partial failure', () => {
  assert.throws(() => parseInput(input([collection('entra.users', [], { collectedAt: '2026-09-02T00:00:00.000Z' })])), /postdate/);
  assert.throws(() => parseInput(input([collection('entra.users', [], { scope: 'different-tenant' })])), /scope/);
  assert.throws(() => parseInput(input([collection('entra.users', [{ displayName: 'missing id' }])])), /stable/);
  assert.throws(() => parseInput(input([collection('entra.users', [], { status: 'partial' })])), /invalid/);
  assert.throws(() => parseInput(input([collection('entra.users', [{ id: 'u1' }], { status: 'unavailable', reason: 'permission-denied' })])), /invalid/);
});

test('duplicate identities fail but one owner of different applications is valid', () => {
  assert.throws(() => parseInput(input([collection(), collection()])), /Duplicate collection/);
  assert.throws(() => parseInput(input([collection('entra.users', [{ id: 'u1' }, { id: 'u1' }])])), /Duplicate evidence/);
  const result = parseInput(input([collection('entra.applicationOwners', [
    { id: 'owner-1', parentId: 'app-1' }, { id: 'owner-1', parentId: 'app-2' },
  ])]));
  assert.equal(result.collections[0]?.records.length, 2);
  assert.notEqual(recordKey({ id: 'a|b', parentId: 'c' }), recordKey({ id: 'a', parentId: 'b|c' }));
});

test('repository records and Azure resource subscriptions must match their declared scope', () => {
  assert.throws(() => parseInput(input([
    collection('github.repositories', [{ id: 'r', full_name: 'unapproved/repo' }], { provider: 'github', scope: 'example-org' }),
  ])), /Repository evidence/);
  assert.throws(() => parseInput(input([
    collection('azure.resources', [{ id: 'r', subscriptionId: tenant }], { provider: 'azure', scope: `/subscriptions/${scope.subscriptionIds[0]}` }),
  ])), /Azure resource evidence/);
  assert.throws(() => parseInput(input([
    collection('github.repositories', [{ id: 'r', full_name: 'example-org/../outside' }], { provider: 'github', scope: 'example-org' }),
  ])), /Repository evidence/);
  assert.throws(() => parseInput(input([
    collection('github.rulesets', [], { provider: 'github', scope: 'example-org/repo/../../outside' }),
  ])), /scope/);
  assert.throws(() => parseInput(input([
    collection('azure.policyCompliance', [{
      id: 'state', subscriptionId: scope.subscriptionIds[0]!,
      properties: { resourceId: `/subscriptions/${tenant}/resourceGroups/outside` },
    }], { provider: 'azure', scope: `/subscriptions/${scope.subscriptionIds[0]}` }),
  ])), /Policy evaluation evidence/);
});
test('snapshot validation ensures evidence provenance and graph integrity', () => {
  const value = snapshot([collection()], [finding()]);
  assert.deepEqual(parseSnapshot(value), value);
  value.findings[0]!.evidence[0]!.recordId = 'missing-user';
  assert.throws(() => parseSnapshot(value), /missing evidence/);
  const dangling = snapshot();
  dangling.graph.edges.push({
    id: 'edge-1', from: 'missing-1', to: 'missing-2', relationship: 'owns', confidence: 'potential',
    evidence: [{ collectionId: 'entra.users', scope: tenant }],
  });
  assert.throws(() => parseSnapshot(dangling), /endpoint nodes/);
  assert.throws(() => parseSnapshot(snapshot([collection()], [finding(), finding()])), /unique/);
});

test('canonical comparisons ignore collection order, not metadata changes', () => {
  assert.equal(canonicalJson({ b: [2, 1], a: 'value' }), canonicalJson({ a: 'value', b: [1, 2] }));
  assert.notEqual(canonicalJson({ a: null }), canonicalJson({}));
  assert.notEqual(canonicalJson({ id: 'u1', enabled: true }), canonicalJson({ id: 'u1', enabled: false }));
});

test('documentation URLs reject script protocols, credential queries and markdown injection', () => {
  assert.equal(safeHttpsUrl('https://learn.microsoft.com/en-us/graph/overview'), true);
  for (const value of ['javascript:alert(1)', 'https://user:pass@example.com/', 'https://example.com/<x>', 'https://example.com/\nfoo', 'https://example.com/?sig=value']) {
    assert.equal(safeHttpsUrl(value), false);
  }
});

test('engine adds explicit assessment gaps and validates source catalog rather than silently passing', t => {
  t.mock.method(globalThis, 'fetch', () => { throw new Error('Offline analysis must not use the network.'); });
  const result = createAssessment(input([collection('entra.users', [{ id: 'u1', accountEnabled: true }])]));
  assert.ok(result.collections.some(item => item.status === 'unavailable'));
  assert.ok(result.findings.some(item => item.status === 'unable-to-assess'));
  assert.equal(result.coverage.length, 10);
  assert.throws(() => createAssessment(input([collection('unknown.collector')])), /unknown collection/);
  assert.throws(() => createAssessment(input([collection('entra.users', [], { provider: 'github', scope: 'example-org' })])), /mismatched provider/);
});

test('engine coverage includes missing selected scopes and manual code-to-cloud controls', () => {
  const evidence = input([collection('azure.resources', [], { provider: 'azure', scope: `/subscriptions/${scope.subscriptionIds[0]}` })]);
  const extraSubscription = '33333333-3333-4333-8333-333333333333';
  evidence.scope = { ...scope, subscriptionIds: [...scope.subscriptionIds, extraSubscription] };
  const result = createAssessment(evidence);
  assert.equal(result.collections.find(item => item.id === 'azure.resources' && item.scope === `/subscriptions/${extraSubscription}`)?.status, 'unavailable');
  assert.ok((result.coverage.find(item => item.domain === 'code-to-cloud')?.unavailable ?? 0) > 0);
});

test('live orchestration with disabled sources remains valid, explicit and entirely offline', async () => {
  const config = parseConfig({ scope, sources: { graph: false, azure: false, defender: false, github: false, azureDevOps: false } });
  const result = await assessLive(config, {
    now: () => new Date(timestamp),
    tokenProvider: { getToken: async () => { throw new Error('Disabled providers must not authenticate.'); } },
    fetch: async () => { throw new Error('Disabled providers must not access the network.'); },
  });
  assert.ok(result.collections.every(item => item.status === 'not-configured' || item.status === 'unavailable'));
  assert.ok(result.findings.every(item => item.status !== 'fail' && item.status !== 'pass'));
  assert.ok(result.findings.some(item => item.status === 'unable-to-assess'));
});

test('reported tool version matches package and locked package metadata', async () => {
  const manifest: { version: string } = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  const lock: { version: string; packages: { '': { version: string } } } = JSON.parse(await readFile(new URL('../../package-lock.json', import.meta.url), 'utf8'));
  assert.equal(TOOL_VERSION, manifest.version);
  assert.equal(lock.version, manifest.version);
  assert.equal(lock.packages[''].version, manifest.version);
});
