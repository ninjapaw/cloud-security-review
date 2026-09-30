import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AuthenticationError, createTokenProvider, TOKEN_SCOPES,
} from '../src/auth.js';
import type { CredentialConfiguration } from '../src/auth.js';
import type { AssessmentConfig, Provider } from '../src/model.js';

const TENANT = '11111111-1111-4111-8111-111111111111';
const CLIENT = '22222222-2222-4222-8222-222222222222';
const TOKEN = 'opaque-mocked-credential-DO-NOT-LOG';
const NOW = Date.parse('2026-01-01T00:00:00Z');

function config(mode: AssessmentConfig['auth']['azure']['mode'] = 'azure-cli'): AssessmentConfig {
  return {
    scope: { tenantId: TENANT, subscriptionIds: [], githubOrganizations: [], azureDevOpsOrganizations: [] },
    sources: { graph: true, azure: true, defender: true, github: true, azureDevOps: true },
    auth: { azure: { mode, ...(mode === 'workload-identity' ? { clientId: CLIENT } : {}) },
      github: { tokenEnvironmentVariable: 'ASSESSMENT_GITHUB_TOKEN' } },
    limits: { maxPages: 5, maxRecords: 1000, maxRequests: 100, timeoutMs: 1000, maxRetries: 0, maxResponseBytes: 100_000 },
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

const reason = (expected: string) => (error: unknown): boolean =>
  error instanceof AuthenticationError && error.reason === expected
    && !String(error.stack).includes(TOKEN) && error.cause === undefined;

test('all Azure auth modes use one explicit credential and tenant-bound scopes, never a fallback chain', async () => {
  for (const mode of ['azure-cli', 'managed-identity', 'workload-identity'] as const) {
    const settings: CredentialConfiguration[] = [];
    const calls: Array<{ scope: string; tenantId: string | undefined }> = [];
    const provider = createTokenProvider(config(mode), {
      environment: {
        AZURE_TENANT_ID: TENANT, AZURE_FEDERATED_TOKEN_FILE: 'C:\\assessment\\oidc-token',
      },
      now: () => new Date(NOW),
      credentialFactory: (selectedMode, options) => {
        assert.equal(selectedMode, mode);
        settings.push(options);
        return {
          async getToken(scope, tokenOptions) {
            calls.push({ scope, tenantId: tokenOptions?.tenantId });
            return { token: TOKEN, expiresOnTimestamp: NOW + 3600_000 };
          },
        };
      },
    });
    for (const source of ['graph', 'azure', 'defender', 'azureDevOps'] as const) {
      assert.equal(await provider.getToken(source), TOKEN);
    }
    assert.equal(settings.length, 1);
    assert.equal(settings[0]?.tenantId, TENANT);
    assert.equal(settings[0]?.authorityHost, 'https://login.microsoftonline.com');
    assert.deepEqual(settings[0]?.additionallyAllowedTenants, []);
    assert.equal(settings[0]?.processTimeoutInMs, 1000);
    assert.deepEqual(calls.map(call => call.scope), Object.values(TOKEN_SCOPES));
    assert.ok(calls.every(call => call.tenantId === TENANT));
    assert.equal(calls.at(-1)?.scope, '499b84ac-1321-427f-aa17-267ca6975798/.default');
    if (mode === 'workload-identity') {
      assert.equal(settings[0]?.clientId, CLIENT);
      assert.equal(settings[0]?.tokenFilePath, 'C:\\assessment\\oidc-token');
    }
  }
});

test('GitHub token uses only the caller-configured environment variable and never initializes Azure credentials', async () => {
  const provider = createTokenProvider(config(), {
    environment: { ASSESSMENT_GITHUB_TOKEN: TOKEN, GITHUB_TOKEN: 'not-selected' },
    credentialFactory: () => assert.fail('Azure must not be initialized for GitHub-only authentication'),
  });
  assert.equal(await provider.getToken('github'), TOKEN);
  assert.equal(JSON.stringify(provider), '{}');
  const missing = createTokenProvider(config(), { environment: { GITHUB_TOKEN: TOKEN } });
  await assert.rejects(missing.getToken('github'), reason('authentication-failed'));
  const bad = createTokenProvider(config(), { environment: { ASSESSMENT_GITHUB_TOKEN: `${TOKEN}\r\nInjected: 1` } });
  await assert.rejects(bad.getToken('github'), reason('authentication-failed'));
});

test('in-memory token cache uses injected clock and SDK expiry, not decoded token claims', async () => {
  let calls = 0;
  let clock = NOW;
  const provider = createTokenProvider(config(), {
    environment: {}, now: () => new Date(clock),
    credential: {
      async getToken() { calls++; return { token: `${TOKEN}-${calls}`, expiresOnTimestamp: clock + 60_000 }; },
    },
  });
  assert.equal(await provider.getToken('graph'), `${TOKEN}-1`);
  assert.equal(await provider.getToken('graph'), `${TOKEN}-1`);
  clock += 31_000;
  assert.equal(await provider.getToken('graph'), `${TOKEN}-2`);
  assert.equal(calls, 2);
});

test('credential exception and constructor diagnostics cannot leak tokens or causes', async () => {
  const provider = createTokenProvider(config(), {
    environment: {},
    credential: { async getToken() { throw new Error(`Authorization failed with ${TOKEN}`); } },
  });
  await assert.rejects(provider.getToken('graph'), reason('authentication-failed'));
  const constructorFailure = createTokenProvider(config(), {
    environment: {},
    credentialFactory: () => { throw new Error(`Client secret ${TOKEN}`); },
  });
  await assert.rejects(constructorFailure.getToken('azure'), reason('authentication-failed'));
});

test('tenant mismatches and sovereign authority settings fail before credential initialization', async () => {
  for (const mode of ['managed-identity', 'workload-identity'] as const) {
    const provider = createTokenProvider(config(mode), {
      environment: { AZURE_TENANT_ID: CLIENT },
      credentialFactory: () => assert.fail('tenant mismatch must be rejected before credential initialization'),
    });
    await assert.rejects(provider.getToken('graph'), reason('scope-mismatch'));
  }
  const sovereign = createTokenProvider(config(), {
    environment: { AZURE_AUTHORITY_HOST: 'https://login.microsoftonline.us' },
    credentialFactory: () => assert.fail('unsupported cloud must not initialize a credential'),
  });
  await assert.rejects(sovereign.getToken('azure'), reason('unsupported'));
  let boundTenant: string | undefined;
  const explicitCli = createTokenProvider(config(), {
    environment: { AZURE_TENANT_ID: CLIENT }, now: () => new Date(NOW),
    credentialFactory: (_mode, options) => {
      boundTenant = options.tenantId;
      return { async getToken() { return { token: TOKEN, expiresOnTimestamp: NOW + 60_000 }; } };
    },
  });
  await explicitCli.getToken('graph');
  assert.equal(boundTenant, TENANT);
});

test('workload identity requires the selected client and existing federated-token file configuration', async () => {
  const provider = createTokenProvider(config('workload-identity'), {
    environment: {}, credentialFactory: () => assert.fail('no token file was configured'),
  });
  await assert.rejects(provider.getToken('graph'), reason('authentication-failed'));
  const selected = config('workload-identity');
  selected.auth.azure.clientId = undefined;
  let observed: CredentialConfiguration | undefined;
  const fromEnvironment = createTokenProvider(selected, {
    environment: { AZURE_CLIENT_ID: CLIENT, AZURE_FEDERATED_TOKEN_FILE: 'C:\\assessment\\existing-token-file' },
    now: () => new Date(NOW),
    credentialFactory: (_mode, options) => {
      observed = options;
      return { async getToken() { return { token: TOKEN, expiresOnTimestamp: NOW + 60_000 }; } };
    },
  });
  await fromEnvironment.getToken('graph');
  assert.equal(observed?.tenantId, TENANT);
  assert.equal(observed?.clientId, CLIENT);
});

test('credential acquisition timeout aborts the selected credential and remains sanitized', async () => {
  const selected = config();
  selected.limits.timeoutMs = 20;
  let signal: AbortSignal | undefined;
  const provider = createTokenProvider(selected, {
    environment: {},
    credential: {
      getToken(_scope, options) {
        signal = options?.abortSignal;
        return new Promise(() => undefined);
      },
    },
  });
  await assert.rejects(provider.getToken('graph'), reason('timeout'));
  assert.equal(signal?.aborted, true);
});

test('null, expired, invalid and unsupported credentials are not silently accepted', async () => {
  for (const token of [null, { token: TOKEN, expiresOnTimestamp: NOW - 1 },
    { token: '', expiresOnTimestamp: NOW + 1000 }, { token: 'bad\ntoken', expiresOnTimestamp: NOW + 1000 }]) {
    const provider = createTokenProvider(config(), {
      environment: {}, now: () => new Date(NOW),
      credential: { async getToken() { return token; } },
    });
    await assert.rejects(provider.getToken('graph'), reason('authentication-failed'));
  }
  await assert.rejects(createTokenProvider(config(), { environment: {} }).getToken('arbitrary' as Provider),
    reason('authentication-failed'));
});
