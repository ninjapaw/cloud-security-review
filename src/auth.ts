import {
  AzureCliCredential, ManagedIdentityCredential, WorkloadIdentityCredential,
} from '@azure/identity';
import type { AssessmentConfig, CollectionReason, Provider, TokenProvider } from './model.js';

export const TOKEN_SCOPES: Readonly<Record<Exclude<Provider, 'github'>, string>> = Object.freeze({
  graph: 'https://graph.microsoft.com/.default',
  azure: 'https://management.azure.com/.default',
  defender: 'https://api.security.microsoft.com/.default',
  azureDevOps: '499b84ac-1321-427f-aa17-267ca6975798/.default',
});

const PUBLIC_AUTHORITY = 'https://login.microsoftonline.com';
const GUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;

export class AuthenticationError extends Error {
  constructor(public readonly reason: Extract<CollectionReason,
    'authentication-failed' | 'scope-mismatch' | 'unsupported' | 'timeout'> = 'authentication-failed') {
    super({
      'authentication-failed': 'The explicitly configured credential could not acquire a token. No alternate credential or interactive login was attempted.',
      'scope-mismatch': 'The identity configuration does not match the configured tenant.',
      unsupported: 'Only public Azure and GitHub.com authentication endpoints are supported.',
      timeout: 'Credential acquisition exceeded the configured timeout.',
    }[reason]);
    this.name = 'AuthenticationError';
  }
}

export interface AzureTokenCredential {
  getToken(scope: string, options?: { abortSignal?: AbortSignal; tenantId?: string }):
    Promise<{ token: string; expiresOnTimestamp: number } | null>;
}

export interface CredentialConfiguration {
  tenantId: string;
  clientId?: string;
  tokenFilePath?: string;
  authorityHost: string;
  additionallyAllowedTenants: string[];
  processTimeoutInMs: number;
}

export interface AuthenticationOptions {
  credential?: AzureTokenCredential;
  credentialFactory?: (
    mode: AssessmentConfig['auth']['azure']['mode'], options: CredentialConfiguration,
  ) => AzureTokenCredential;
  environment?: Readonly<Record<string, string | undefined>>;
  now?: () => Date;
}

function defaultCredentialFactory(
  mode: AssessmentConfig['auth']['azure']['mode'], options: CredentialConfiguration,
): AzureTokenCredential {
  const common = {
    authorityHost: options.authorityHost,
    retryOptions: { maxRetries: 0 },
    loggingOptions: { allowLoggingAccountIdentifiers: false, enableUnsafeSupportLogging: false },
  };
  switch (mode) {
    case 'azure-cli':
      return new AzureCliCredential({
        ...common,
        tenantId: options.tenantId,
        additionallyAllowedTenants: [],
        processTimeoutInMs: options.processTimeoutInMs,
      });
    case 'managed-identity':
      return new ManagedIdentityCredential({ ...common, clientId: options.clientId });
    case 'workload-identity':
      return new WorkloadIdentityCredential({
        ...common,
        tenantId: options.tenantId,
        clientId: options.clientId,
        tokenFilePath: options.tokenFilePath,
        additionallyAllowedTenants: [],
      });
    default:
      throw new AuthenticationError();
  }
}

export function isUsableToken(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 64_000
    && /^[A-Za-z0-9._~+\/=-]+$/.test(value);
}

/**
 * Credentials are selected explicitly, never chained. Tokens stay in this closure;
 * SDK error messages and causes (which can contain credentials) never escape it.
 * Managed-identity tenant binding is additionally verified by the collectors.
 */
export function createTokenProvider(
  config: AssessmentConfig, options: AuthenticationOptions = {},
): TokenProvider {
  const environment = options.environment ?? process.env;
  const now = options.now ?? (() => new Date());
  const tenantId = config.scope.tenantId;
  const mode = config.auth.azure.mode;
  const githubVariable = config.auth.github.tokenEnvironmentVariable;
  const clientId = config.auth.azure.clientId;
  const timeoutMs = config.limits.timeoutMs;
  let credential = options.credential;
  const cache = new Map<Provider, { token: string; expiresOnTimestamp: number }>();

  function configuration(): CredentialConfiguration {
    if (!GUID.test(tenantId) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1
      || timeoutMs > 300_000 || (clientId !== undefined && !GUID.test(clientId))) {
      throw new AuthenticationError();
    }
    const authority = environment.AZURE_AUTHORITY_HOST?.replace(/\/$/, '');
    if (authority && authority.toLowerCase() !== PUBLIC_AUTHORITY) {
      throw new AuthenticationError('unsupported');
    }
    if (mode !== 'azure-cli' && environment.AZURE_TENANT_ID
      && environment.AZURE_TENANT_ID.toLowerCase() !== tenantId.toLowerCase()) {
      throw new AuthenticationError('scope-mismatch');
    }
    const settings: CredentialConfiguration = {
      tenantId, clientId, authorityHost: PUBLIC_AUTHORITY,
      additionallyAllowedTenants: [], processTimeoutInMs: timeoutMs,
    };
    if (mode === 'workload-identity') {
      settings.clientId = clientId ?? environment.AZURE_CLIENT_ID;
      settings.tokenFilePath = environment.AZURE_FEDERATED_TOKEN_FILE;
      if (!settings.clientId || !GUID.test(settings.clientId) || !settings.tokenFilePath) {
        throw new AuthenticationError();
      }
    }
    if (!['azure-cli', 'managed-identity', 'workload-identity'].includes(mode)) {
      throw new AuthenticationError();
    }
    return settings;
  }

  return {
    async getToken(provider: Provider): Promise<string> {
      if (provider === 'github') {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(githubVariable)) throw new AuthenticationError();
        const token = environment[githubVariable];
        if (!isUsableToken(token)) throw new AuthenticationError();
        return token;
      }
      const scope = TOKEN_SCOPES[provider];
      if (!scope) throw new AuthenticationError();
      const settings = configuration();
      const cached = cache.get(provider);
      if (cached && cached.expiresOnTimestamp > now().getTime() + 30_000) return cached.token;

      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        credential ??= (options.credentialFactory ?? defaultCredentialFactory)(mode, settings);
        const activeCredential = credential;
        const token = await Promise.race([
          activeCredential.getToken(scope, { tenantId, abortSignal: controller.signal }),
          new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
              controller.abort();
              reject(new AuthenticationError('timeout'));
            }, timeoutMs);
          }),
        ]);
        if (!token || !isUsableToken(token.token) || !Number.isFinite(token.expiresOnTimestamp)
          || token.expiresOnTimestamp <= now().getTime()) throw new AuthenticationError();
        cache.set(provider, { token: token.token, expiresOnTimestamp: token.expiresOnTimestamp });
        return token.token;
      } catch (error) {
        if (error instanceof AuthenticationError) throw error;
        throw new AuthenticationError();
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    },
  };
}
