import { AuthenticationError, createTokenProvider, isUsableToken } from './auth.js';
import type {
  AssessmentConfig, CollectionReason, CollectorOptions, JsonValue, Provider, TokenProvider,
} from './model.js';

const GUID = '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}';
const SUBSCRIPTION = new RegExp(`^/subscriptions/(${GUID})(/.*)?$`, 'i');
const ORG = '[A-Za-z0-9][A-Za-z0-9-]{0,49}';
const REPOSITORY = '[A-Za-z0-9_.-]{1,100}';
const PUBLIC_HOSTS: Readonly<Record<Provider, string>> = Object.freeze({
  graph: 'graph.microsoft.com',
  azure: 'management.azure.com',
  defender: 'api.security.microsoft.com',
  github: 'api.github.com',
  azureDevOps: 'dev.azure.com',
});
export const GITHUB_API_VERSION = '2026-03-10';

export const GRAPH_SELECT: Readonly<Record<string, string>> = Object.freeze({
  organization: 'id,displayName',
  users: 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity',
  groups: 'id,displayName,securityEnabled,mailEnabled,isAssignableToRole,groupTypes',
  applications: 'id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials',
  servicePrincipals: 'id,appId,displayName,servicePrincipalType,accountEnabled,appRoles,oauth2PermissionScopes,appOwnerOrganizationId,passwordCredentials,keyCredentials',
  oauth2PermissionGrants: 'id,clientId,resourceId,scope,consentType,principalId',
  'roleManagement/directory/roleDefinitions': 'id,displayName,templateId,isBuiltIn,isEnabled,rolePermissions',
  'roleManagement/directory/roleAssignments': 'id,principalId,roleDefinitionId,directoryScopeId,appScopeId',
  'roleManagement/directory/roleAssignmentScheduleInstances': 'id,principalId,roleDefinitionId,directoryScopeId,appScopeId,assignmentType,memberType,startDateTime,endDateTime,roleAssignmentOriginId,roleAssignmentScheduleId',
  'roleManagement/directory/roleEligibilityScheduleInstances': 'id,principalId,roleDefinitionId,directoryScopeId,startDateTime,endDateTime,memberType,roleEligibilityScheduleId',
  'reports/authenticationMethods/userRegistrationDetails': 'id,userPrincipalName,userDisplayName,userType,isAdmin,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered,lastUpdatedDateTime',
  'identity/conditionalAccess/policies': 'id,displayName,state,createdDateTime,modifiedDateTime,conditions,grantControls,sessionControls',
  'identityProtection/riskyUsers': 'id,userDisplayName,userPrincipalName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime,isDeleted,isProcessing',
  'auditLogs/signIns': 'id,createdDateTime,userId,userPrincipalName,appId,appDisplayName,riskLevelAggregated,riskLevelDuringSignIn,riskState,riskDetail,conditionalAccessStatus',
  'security/secureScores': 'id,createdDateTime,currentScore,maxScore,activeUserCount,licensedUserCount,controlScores',
  'security/secureScoreControlProfiles': 'id,title,service,controlCategory,maxScore,deprecated,isPreview,implementationCost,userImpact',
  subscribedSkus: 'id,skuId,skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits,servicePlans,appliesTo',
  'admin/sharepoint/settings': 'id,isLegacyAuthProtocolsEnabled,isRequireAcceptingUserToMatchInvitedUserEnabled,isResharingByExternalUsersEnabled,isUnmanagedSyncAppForTenantRestricted,sharingCapability,sharingDomainRestrictionMode,sharingAllowedDomainList,sharingBlockedDomainList,idleSessionSignOut',
  'deviceManagement/managedDevices': 'id,deviceName,azureADDeviceId,complianceState,operatingSystem,osVersion,managedDeviceOwnerType,managementAgent,lastSyncDateTime,enrolledDateTime,isEncrypted',
  'deviceManagement/deviceCompliancePolicies': 'id,displayName,createdDateTime,lastModifiedDateTime,version',
  'deviceManagement/deviceConfigurations': 'id,displayName,createdDateTime,lastModifiedDateTime,version',
});

export const ARG_RESOURCE_QUERY = [
  'Resources',
  "| project id, type, name, subscriptionId, resourceGroup, location,",
  "identity = bag_pack('type', identity.type, 'principalId', identity.principalId,",
  "'tenantId', identity.tenantId, 'userAssignedIdentities', identity.userAssignedIdentities),",
  "properties = bag_pack('publicNetworkAccess', properties.publicNetworkAccess,",
  "'allowBlobPublicAccess', properties.allowBlobPublicAccess,",
  "'allowSharedKeyAccess', properties.allowSharedKeyAccess,",
  "'supportsHttpsTrafficOnly', properties.supportsHttpsTrafficOnly,",
  "'minimumTlsVersion', properties.minimumTlsVersion,",
  "'enableRbacAuthorization', properties.enableRbacAuthorization,",
  "'enablePurgeProtection', properties.enablePurgeProtection,",
  "'enableSoftDelete', properties.enableSoftDelete,",
  "'httpsOnly', properties.httpsOnly, 'disableLocalAuth', properties.disableLocalAuth,",
  "'networkAcls', bag_pack('defaultAction', properties.networkAcls.defaultAction),",
  "'siteConfig', bag_pack('minTlsVersion', properties.siteConfig.minTlsVersion,",
  "'ftpsState', properties.siteConfig.ftpsState))",
  '| order by id asc',
].join(' ');

export const ARG_POLICY_QUERY = [
  'PolicyResources',
  "| where type =~ 'Microsoft.PolicyInsights/PolicyStates'",
  '| extend assessmentResourceId = tolower(tostring(properties.resourceId)),',
  'assessmentAssignmentId = tolower(tostring(properties.policyAssignmentId)),',
  'assessmentDefinitionId = tolower(tostring(properties.policyDefinitionId)),',
  'assessmentDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId)',
  '| order by assessmentResourceId asc, assessmentAssignmentId asc,',
  'assessmentDefinitionId asc, assessmentDefinitionReferenceId asc, id asc',
  '| project id, type, subscriptionId, resourceGroup,',
  "properties = bag_pack('resourceId', properties.resourceId,",
  "'policyAssignmentId', properties.policyAssignmentId,",
  "'policyAssignmentName', properties.policyAssignmentName,",
  "'policyAssignmentScope', properties.policyAssignmentScope,",
  "'policyDefinitionId', properties.policyDefinitionId,",
  "'policyDefinitionReferenceId', properties.policyDefinitionReferenceId,",
  "'policySetDefinitionId', properties.policySetDefinitionId,",
  "'policyDefinitionAction', properties.policyDefinitionAction,",
  "'complianceState', properties.complianceState, 'timestamp', properties.timestamp)",
].join(' ');

const ARG_QUERIES = Object.freeze({
  resources: ARG_RESOURCE_QUERY,
  'policy-compliance': ARG_POLICY_QUERY,
});
export type ResourceGraphQuery = keyof typeof ARG_QUERIES;

interface ResourceGraphContext {
  key: string;
  skipToken?: string;
}
interface RoutePolicy {
  cursors: string[];
  body?: string;
  resourceGraph?: ResourceGraphContext;
}

const MESSAGES: Readonly<Record<CollectionReason, string>> = Object.freeze({
  'permission-denied': 'The API denied access. Permissions or resource visibility must be reviewed; licensing was not inferred.',
  'authentication-failed': 'Authentication failed. No alternate credential, consent change, or interactive login was attempted.',
  'not-found': 'The API did not expose this endpoint or resource. Absence of a security control or a license was not inferred.',
  'not-licensed': 'A licensing limitation was explicitly established.',
  unsupported: 'The request or capability is outside the curated read-only public-cloud API allowlist.',
  'rate-limited': 'The API rate limit could not be satisfied within the configured retry bounds.',
  timeout: 'The request exceeded its timeout, including authentication, retry waits, and response reading.',
  'api-error': 'The remote API or transport failed. Remote error content was suppressed.',
  'invalid-response': 'The API returned an invalid or inconsistent metadata response.',
  'limit-reached': 'A configured collection, request, pagination, or response-size limit was reached.',
  'dependency-unavailable': 'Required parent inventory or tenant-binding evidence was incomplete or unavailable.',
  'not-configured': 'This provider or scope was not configured.',
  'scope-mismatch': 'The request or returned identity is outside the explicitly configured scope.',
});

export class CollectionError extends Error {
  constructor(public readonly reason: CollectionReason, public readonly status?: number) {
    super(MESSAGES[reason]);
    this.name = 'CollectionError';
  }
}

export function collectionError(error: unknown): CollectionError {
  if (error instanceof CollectionError) return new CollectionError(error.reason, error.status);
  if (error instanceof AuthenticationError) return new CollectionError(error.reason);
  return new CollectionError('api-error');
}

export interface HttpRequestOptions {
  method?: string;
  body?: unknown;
  continuationOf?: string;
}

export interface HttpResponse {
  body: unknown;
  headers: Headers;
  status: number;
}

type QueryRule = (value: string) => boolean;
type QueryRules = Record<string, QueryRule>;
const integer = (min: number, max: number): QueryRule =>
  value => /^\d+$/.test(value) && Number(value) >= min && Number(value) <= max;
const equal = (expected: string): QueryRule => value => value === expected;
const oneOf = (...values: string[]): QueryRule => value => values.includes(value);
const cursor: QueryRule = value => value.length > 0 && value.length <= 8192 && !/[\u0000-\u001f\u007f]/.test(value);
const graphPageRules: QueryRules = { $top: integer(1, 500), $skiptoken: cursor, $skipToken: cursor };
const armPageRules: QueryRules = { $skiptoken: cursor, $skipToken: cursor, skipToken: cursor };
const githubPageRules: QueryRules = {
  per_page: integer(1, 100), page: integer(1, 1_000_000),
  before: cursor, after: cursor,
};

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function checkQuery(url: URL, rules: QueryRules, required: string[] = []): void {
  const seen = new Set<string>();
  for (const [key, value] of url.searchParams) {
    if (seen.has(key) || !Object.hasOwn(rules, key) || !rules[key]?.(value)) {
      throw new CollectionError('unsupported');
    }
    seen.add(key);
  }
  if (required.some(key => !seen.has(key))) throw new CollectionError('unsupported');
}

function checkSelection(value: string, fields: string): boolean {
  const selected = value.split(',');
  const allowed = new Set(fields.split(','));
  return selected.length > 0 && new Set(selected).size === selected.length
    && selected.every(field => allowed.has(field));
}

function parsePublicUrl(provider: Provider, input: string): URL {
  if (typeof input !== 'string' || input.length > 24_000
    || !input.startsWith('https://') || /[\u0000-\u0020\u007f\\]/.test(input)) {
    throw new CollectionError('unsupported');
  }
  const rawPath = input.replace(/^https:\/\/[^/?#]+/, '').split(/[?#]/, 1)[0] ?? '';
  if (/(?:^|\/)\.{1,2}(?:\/|$)/.test(rawPath) || /%(?:2e|5c|25)/i.test(rawPath)) {
    throw new CollectionError('unsupported');
  }
  let url: URL;
  try { url = new URL(input); } catch { throw new CollectionError('unsupported'); }
  if (url.protocol !== 'https:' || url.hostname !== PUBLIC_HOSTS[provider]
    || url.port || url.username || url.password || url.hash) {
    throw new CollectionError('unsupported');
  }
  return url;
}

function graphRoute(url: URL): string[] {
  const path = url.pathname.replace(/^\/v1\.0\//, '');
  if (!url.pathname.startsWith('/v1.0/')) throw new CollectionError('unsupported');
  let fields = Object.hasOwn(GRAPH_SELECT, path) ? GRAPH_SELECT[path] : undefined;
  if (new RegExp(`^(?:applications|servicePrincipals)/${GUID}/owners$`).test(path)
    || new RegExp(`^groups/${GUID}/members$`).test(path)) {
    fields = 'id,displayName,userPrincipalName,userType,appId,servicePrincipalType';
  } else if (new RegExp(`^applications/${GUID}/federatedIdentityCredentials$`).test(path)) {
    fields = 'id,name,issuer,subject,audiences';
  } else if (new RegExp(`^servicePrincipals/${GUID}/appRoleAssignments$`).test(path)) {
    fields = 'id,principalId,principalType,resourceId,appRoleId,createdDateTime';
  }
  if (!fields) throw new CollectionError('unsupported');
  if (path === 'admin/sharepoint/settings') {
    checkQuery(url, { $select: value => checkSelection(value, fields) }, ['$select']);
    return [];
  }
  if (path === 'roleManagement/directory/roleAssignmentScheduleInstances') {
    checkQuery(url, { $select: value => checkSelection(value, fields), $skiptoken: cursor, $skipToken: cursor }, ['$select']);
    return ['$skiptoken', '$skipToken'];
  }
  const rules: QueryRules = { ...graphPageRules, $select: value => checkSelection(value, fields) };
  if (path === 'auditLogs/signIns') rules.$filter = equal("riskLevelAggregated ne 'none'");
  checkQuery(url, rules, path === 'auditLogs/signIns' ? ['$filter'] : []);
  return ['$skiptoken', '$skipToken'];
}

function statusError(status: number): CollectionError {
  return new CollectionError(
    status === 401 ? 'authentication-failed'
      : status === 403 ? 'permission-denied'
        : status === 404 ? 'not-found'
          : status === 429 ? 'rate-limited' : 'api-error',
    status,
  );
}

function discardBody(response: Response): void {
  // Cancellation failures are cleanup failures, never collection successes.
  if (response.body) void response.body.cancel().catch(() => undefined);
}

export class SafeHttpClient {
  private readonly subscriptions: Set<string>;
  private readonly githubOrganizations: Set<string>;
  private readonly adoOrganizations: Set<string>;
  private readonly limits: AssessmentConfig['limits'];
  private readonly fetcher: typeof globalThis.fetch;
  private readonly tokens: TokenProvider;
  private readonly now: () => Date;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly credentials = new Set<string>();
  private readonly resourceGraphContinuations = new Map<string, string>();
  private usedRequests = 0;

  constructor(config: AssessmentConfig, options: CollectorOptions = {}) {
    this.subscriptions = new Set(config.scope.subscriptionIds.map(id => id.toLowerCase()));
    this.githubOrganizations = new Set(config.scope.githubOrganizations.map(org => org.toLowerCase()));
    this.adoOrganizations = new Set(config.scope.azureDevOpsOrganizations.map(org => org.toLowerCase()));
    this.limits = { ...config.limits };
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.tokens = options.tokenProvider ?? createTokenProvider(config, { now: options.now });
    this.now = options.now ?? (() => new Date());
    this.sleep = options.sleep ?? (milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)));
    const caps: AssessmentConfig['limits'] = {
      maxPages: 100_000, maxRecords: 1_000_000, maxRequests: 1_000_000,
      timeoutMs: 300_000, maxRetries: 10, maxResponseBytes: 64 * 1024 * 1024,
    };
    for (const key of Object.keys(caps) as (keyof AssessmentConfig['limits'])[]) {
      const value = this.limits[key];
      if (!Number.isSafeInteger(value) || value < (key === 'maxRetries' ? 0 : 1) || value > caps[key]) {
        throw new CollectionError('limit-reached');
      }
    }
  }

  get requestCount(): number { return this.usedRequests; }
  get remainingRequests(): number { return Math.max(0, this.limits.maxRequests - this.usedRequests); }

  resourceGraphBody(
    subscriptionId: string, query: ResourceGraphQuery = 'resources', skipToken?: string,
  ): Record<string, unknown> {
    if (!Object.hasOwn(ARG_QUERIES, query)) throw new CollectionError('unsupported');
    return {
      subscriptions: [subscriptionId],
      query: ARG_QUERIES[query],
      options: {
        resultFormat: 'objectArray', $top: Math.min(1000, this.limits.maxRecords),
        ...(skipToken === undefined ? {} : { $skipToken: skipToken }),
      },
    };
  }

  redact(value: JsonValue): JsonValue {
    if (typeof value === 'string') {
      let text = value;
      for (const token of this.credentials) text = text.split(token).join('[REDACTED]');
      return text
        .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, '[REDACTED]')
        .replace(/\bBearer\s+\S+/gi, '[REDACTED]')
        .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]');
    }
    if (Array.isArray(value)) return value.map(entry => this.redact(entry));
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, this.redact(entry)]));
    }
    return value;
  }

  private azureRoute(url: URL, method: string, body: unknown): RoutePolicy {
    const path = url.pathname;
    if (path === '/providers/Microsoft.ResourceGraph/resources') {
      checkQuery(url, { 'api-version': equal('2022-10-01') }, ['api-version']);
      if (method !== 'POST' || !isObject(body)
        || Object.keys(body).sort().join(',') !== 'options,query,subscriptions'
        || !Object.values(ARG_QUERIES).includes(body.query as string) || !Array.isArray(body.subscriptions)
        || body.subscriptions.length !== 1 || typeof body.subscriptions[0] !== 'string'
        || !this.subscriptions.has(body.subscriptions[0].toLowerCase()) || !isObject(body.options)) {
        throw new CollectionError('unsupported');
      }
      const options = body.options;
      if (Object.keys(options).some(key => !['resultFormat', '$top', '$skipToken'].includes(key))
        || options.resultFormat !== 'objectArray' || options.$top !== Math.min(1000, this.limits.maxRecords)
        || (options.$skipToken !== undefined && (typeof options.$skipToken !== 'string' || !cursor(options.$skipToken)))) {
        throw new CollectionError('unsupported');
      }
      const query: ResourceGraphQuery = body.query === ARG_RESOURCE_QUERY ? 'resources' : 'policy-compliance';
      return {
        cursors: [],
        body: JSON.stringify(this.resourceGraphBody(body.subscriptions[0], query, options.$skipToken as string | undefined)),
        resourceGraph: {
          key: JSON.stringify([query, body.subscriptions[0].toLowerCase(), options.$top, options.resultFormat]),
          skipToken: options.$skipToken as string | undefined,
        },
      };
    }
    if (method !== 'GET' || body !== undefined) throw new CollectionError('unsupported');
    if (path === '/providers/Microsoft.Management/managementGroups') {
      checkQuery(url, { ...armPageRules, 'api-version': equal('2020-05-01') }, ['api-version']);
      return { cursors: Object.keys(armPageRules) };
    }
    const match = path.match(SUBSCRIPTION);
    if (!match?.[1] || !this.subscriptions.has(match[1].toLowerCase())) {
      throw new CollectionError('scope-mismatch');
    }
    const tail = match[2] ?? '';
    const versions: Record<string, string> = {
      '': '2022-12-01',
      '/providers/Microsoft.Authorization/roleAssignments': '2022-04-01',
      '/providers/Microsoft.Authorization/roleDefinitions': '2022-04-01',
      '/providers/Microsoft.Security/pricings': '2024-01-01',
      '/providers/Microsoft.Security/assessments': '2020-01-01',
      '/providers/Microsoft.Security/secureScores': '2020-01-01',
      '/providers/Microsoft.Security/regulatoryComplianceStandards': '2019-01-01-preview',
    };
    let version = Object.hasOwn(versions, tail) ? versions[tail] : undefined;
    if (/^\/resourceGroups\/[A-Za-z0-9_().-]{1,90}\/providers\/Microsoft\.ManagedIdentity\/userAssignedIdentities\/[A-Za-z0-9_-]{1,128}\/federatedIdentityCredentials$/.test(tail)) {
      version = '2023-01-31';
    }
    if (!version) throw new CollectionError('unsupported');
    checkQuery(url, { ...armPageRules, 'api-version': equal(version) }, ['api-version']);
    return { cursors: Object.keys(armPageRules) };
  }

  private githubRoute(url: URL): string[] {
    const orgRoute = url.pathname.match(new RegExp(`^/orgs/(${ORG})(/.*)?$`));
    const repoRoute = url.pathname.match(new RegExp(`^/repos/(${ORG})/(${REPOSITORY})(/.*)?$`));
    const org = orgRoute?.[1] ?? repoRoute?.[1];
    if (!org || !this.githubOrganizations.has(org.toLowerCase())) throw new CollectionError('scope-mismatch');
    let rules: QueryRules | undefined;
    if (orgRoute) {
      switch (orgRoute[2] ?? '') {
        case '': rules = {}; break;
        case '/members': rules = { ...githubPageRules, role: oneOf('member', 'admin') }; break;
        case '/outside_collaborators': rules = { ...githubPageRules }; break;
        case '/repos': rules = { ...githubPageRules, type: equal('all') }; break;
        case '/actions/secrets': rules = { ...githubPageRules }; break;
      }
    } else {
      const tail = repoRoute?.[3] ?? '';
      if (/^\/branches\/[^/]+\/protection$/.test(tail)) {
        let branch: string;
        try { branch = decodeURIComponent(tail.slice('/branches/'.length, -'/protection'.length)); }
        catch { throw new CollectionError('unsupported'); }
        if (!/^[A-Za-z0-9_./-]{1,250}$/.test(branch)
          || branch.split('/').some(part => !part || part === '.' || part === '..')) {
          throw new CollectionError('unsupported');
        }
        rules = {};
      } else if (/^\/rulesets\/[0-9]+$/.test(tail)) {
        rules = { includes_parents: equal('true') };
      } else {
        switch (tail) {
          case '/rulesets': rules = { ...githubPageRules, includes_parents: equal('true') }; break;
          case '/actions/permissions/workflow': rules = {}; break;
          case '/actions/workflows':
          case '/actions/runners':
          case '/actions/secrets':
          case '/environments':
          case '/dependabot/alerts':
          case '/code-scanning/alerts':
            rules = { ...githubPageRules }; break;
          case '/secret-scanning/alerts':
            rules = { ...githubPageRules, hide_secret: equal('true') }; break;
        }
      }
    }
    if (!rules) throw new CollectionError('unsupported');
    const required = repoRoute?.[3] === '/secret-scanning/alerts' ? ['hide_secret']
      : orgRoute?.[2] === '/members' ? ['role'] : [];
    checkQuery(url, rules, required);
    return ['page', 'before', 'after'];
  }

  private adoRoute(url: URL): string[] {
    const match = url.pathname.match(new RegExp(`^/(${ORG})/(?:(${GUID})/)?_apis/(.+)$`));
    if (!match?.[1] || !this.adoOrganizations.has(match[1].toLowerCase())) {
      throw new CollectionError('scope-mismatch');
    }
    const project = match[2];
    const endpoint = match[3];
    const permitted = project
      ? ['git/repositories', 'policy/configurations', 'pipelines', 'distributedtask/environments']
      : ['projects', 'distributedtask/pools'];
    if (!endpoint || !permitted.includes(endpoint)) throw new CollectionError('unsupported');
    const rules: QueryRules = { 'api-version': equal('7.1') };
    if (['projects', 'pipelines', 'distributedtask/environments', 'policy/configurations'].includes(endpoint)) {
      rules.$top = integer(1, 1000);
      rules.continuationToken = cursor;
    }
    checkQuery(url, rules, ['api-version']);
    return ['continuationToken'];
  }

  private prepare(provider: Provider, input: string, options: HttpRequestOptions):
    RoutePolicy & { url: URL; method: string } {
    const url = parsePublicUrl(provider, input);
    const method = (options.method ?? 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'POST') throw new CollectionError('unsupported');
    if (provider !== 'azure' && (method !== 'GET' || options.body !== undefined)) {
      throw new CollectionError('unsupported');
    }
    let result: RoutePolicy;
    switch (provider) {
      case 'graph': result = { cursors: graphRoute(url) }; break;
      case 'azure': result = this.azureRoute(url, method, options.body); break;
      case 'defender':
        if (!['/api/incidents', '/api/alerts', '/api/machines'].includes(url.pathname)) {
          throw new CollectionError('unsupported');
        }
        checkQuery(url, { $top: integer(1, 100), $skip: integer(0, 100_000_000), $skiptoken: cursor });
        result = { cursors: ['$skip', '$skiptoken'] };
        break;
      case 'github': result = { cursors: this.githubRoute(url) }; break;
      case 'azureDevOps': result = { cursors: this.adoRoute(url) }; break;
      default: throw new CollectionError('unsupported');
    }
    return { url, method, ...result };
  }

  private assertContinuation(provider: Provider, next: URL, baseline: string, cursors: string[]): void {
    const initial = this.prepare(provider, baseline, {}).url;
    if (initial.origin !== next.origin || initial.pathname !== next.pathname) {
      throw new CollectionError('scope-mismatch');
    }
    const stable = (url: URL): string => JSON.stringify([...url.searchParams]
      .filter(([key]) => !cursors.includes(key)).sort(([a], [b]) => a.localeCompare(b)));
    if (stable(initial) !== stable(next)) throw new CollectionError('scope-mismatch');
  }

  private async readJson(response: Response, signal: AbortSignal): Promise<unknown> {
    const contentType = response.headers.get('content-type');
    if (contentType && !/^application\/(?:[\w.+-]+\+)?json(?:;|$)/i.test(contentType)) {
      discardBody(response);
      throw new CollectionError('invalid-response');
    }
    const length = response.headers.get('content-length');
    if (length && /^\d+$/.test(length) && Number(length) > this.limits.maxResponseBytes) {
      discardBody(response);
      throw new CollectionError('limit-reached');
    }
    if (!response.body) throw new CollectionError('invalid-response');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    const cancel = (): void => { void reader.cancel().catch(() => undefined); };
    signal.addEventListener('abort', cancel, { once: true });
    try {
      while (true) {
        if (signal.aborted) throw new CollectionError('timeout');
        const result = await reader.read();
        if (result.done) break;
        bytes += result.value.byteLength;
        if (bytes > this.limits.maxResponseBytes) {
          cancel();
          throw new CollectionError('limit-reached');
        }
        chunks.push(result.value);
      }
      if (signal.aborted) throw new CollectionError('timeout');
      try {
        return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, bytes)));
      } catch {
        throw new CollectionError('invalid-response');
      }
    } finally {
      signal.removeEventListener('abort', cancel);
      reader.releaseLock();
    }
  }

  async request(provider: Provider, input: string, options: HttpRequestOptions = {}): Promise<HttpResponse> {
    // Every route, body, scope and continuation check precedes token acquisition.
    const prepared = this.prepare(provider, input, options);
    if (options.continuationOf) {
      this.assertContinuation(provider, prepared.url, options.continuationOf, prepared.cursors);
    }
    // ARG cursors are opaque: only the last cursor actually issued for this
    // fixed query and approved subscription may be sent back to the service.
    const graphContext = prepared.resourceGraph;
    if (graphContext?.skipToken !== undefined
      && this.resourceGraphContinuations.get(graphContext.key) !== graphContext.skipToken) {
      throw new CollectionError('scope-mismatch');
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async (): Promise<HttpResponse> => {
      for (let attempt = 0; ; attempt++) {
        if (controller.signal.aborted) throw new CollectionError('timeout');
        if (this.remainingRequests === 0) throw new CollectionError('limit-reached');
        this.usedRequests++;
        let token: string;
        try { token = await this.tokens.getToken(provider); }
        catch (error) {
          throw error instanceof AuthenticationError ? collectionError(error) : new CollectionError('authentication-failed');
        }
        if (controller.signal.aborted) throw new CollectionError('timeout');
        if (!isUsableToken(token)) throw new CollectionError('authentication-failed');
        if (!this.credentials.has(token) && this.credentials.size >= 128) throw new CollectionError('limit-reached');
        this.credentials.add(token);
        const headers: Record<string, string> = {
          Accept: 'application/json', Authorization: `Bearer ${token}`,
        };
        if (provider === 'github') {
          headers.Accept = 'application/vnd.github+json';
          headers['X-GitHub-Api-Version'] = GITHUB_API_VERSION;
          headers['User-Agent'] = 'cloud-security-review';
        }
        if (prepared.body) headers['Content-Type'] = 'application/json';
        const response = await this.fetcher(prepared.url.href, {
          method: prepared.method, body: prepared.body, headers,
          redirect: 'error', credentials: 'omit', cache: 'no-store', signal: controller.signal,
        });
        if (controller.signal.aborted) {
          discardBody(response);
          throw new CollectionError('timeout');
        }
        if (response.redirected || (response.url && response.url !== prepared.url.href)
          || (response.status >= 300 && response.status < 400)) {
          discardBody(response);
          throw new CollectionError('unsupported');
        }
        if (response.status === 200) {
          const body = await this.readJson(response, controller.signal);
          if (graphContext) {
            const next = isObject(body) ? body.$skipToken : undefined;
            if (typeof next === 'string' && cursor(next)) this.resourceGraphContinuations.set(graphContext.key, next);
            else this.resourceGraphContinuations.delete(graphContext.key);
          }
          return { body, headers: response.headers, status: response.status };
        }
        discardBody(response);
        const retryable = [429, 500, 502, 503, 504].includes(response.status);
        if (!retryable || attempt >= this.limits.maxRetries) throw statusError(response.status);
        const retryAfter = response.headers.get('retry-after');
        let delay = Math.min(500 * 2 ** attempt, 5000);
        if (retryAfter !== null) {
          const seconds = /^\d+(?:\.\d+)?$/.test(retryAfter) ? Number(retryAfter) : undefined;
          const parsed = seconds === undefined ? Date.parse(retryAfter) - this.now().getTime() : seconds * 1000;
          if (Number.isFinite(parsed)) delay = Math.max(0, parsed);
        }
        if (delay > Math.min(30_000, this.limits.timeoutMs) || this.remainingRequests === 0) {
          throw statusError(response.status);
        }
        await this.sleep(delay);
      }
    };
    try {
      return await Promise.race([
        run(),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new CollectionError('timeout'));
          }, this.limits.timeoutMs);
        }),
      ]);
    } catch (error) {
      throw controller.signal.aborted ? new CollectionError('timeout') : collectionError(error);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
}
