import { COLLECTION_CATALOG } from './catalog.js';
import { CollectionError, collectionError, GRAPH_SELECT, SafeHttpClient } from './http.js';
import { object, projectRecord } from './collectors/projection.js';
import { assertSafeEvidence } from './safety.js';
import type {
  AssessmentConfig, CollectionDefinition, CollectionReason, CollectionResult,
  CollectorOptions, JsonObject, Provider,
} from './model.js';

const GRAPH = 'https://graph.microsoft.com/v1.0/';
const ARM = 'https://management.azure.com';
const GITHUB = 'https://api.github.com';
const ADO = 'https://dev.azure.com';
const GUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const PAGE_SIZE = 100;
const DEFINITIONS = new Map(COLLECTION_CATALOG.map(definition => [definition.id, definition]));

interface PageSpec {
  id: string;
  scope: string;
  url: string;
  container?: string | 'array' | 'object';
  body?: Record<string, unknown>;
  idFrom?: string;
  syntheticId?: string;
  decorate?: JsonObject;
  validate?: (record: JsonObject, raw: Record<string, unknown>) => void;
  offsetPaging?: boolean;
}

const GRAPH_ROOTS: ReadonlyArray<readonly [string, string]> = [
  ['entra.users', 'users'], ['entra.groups', 'groups'],
  ['entra.applications', 'applications'], ['entra.servicePrincipals', 'servicePrincipals'],
  ['entra.oauth2PermissionGrants', 'oauth2PermissionGrants'],
  ['entra.directoryRoleDefinitions', 'roleManagement/directory/roleDefinitions'],
  ['entra.directoryRoleAssignments', 'roleManagement/directory/roleAssignments'],
  ['entra.directoryRoleAssignmentScheduleInstances', 'roleManagement/directory/roleAssignmentScheduleInstances'],
  ['entra.directoryRoleEligibility', 'roleManagement/directory/roleEligibilityScheduleInstances'],
  ['entra.authenticationRegistration', 'reports/authenticationMethods/userRegistrationDetails'],
  ['entra.conditionalAccess', 'identity/conditionalAccess/policies'],
  ['entra.riskyUsers', 'identityProtection/riskyUsers'],
  ['entra.riskySignIns', 'auditLogs/signIns'],
  ['m365.secureScores', 'security/secureScores'],
  ['m365.secureScoreControls', 'security/secureScoreControlProfiles'],
  ['m365.licenses', 'subscribedSkus'],
  ['m365.sharePointSettings', 'admin/sharepoint/settings'],
  ['intune.devices', 'deviceManagement/managedDevices'],
  ['intune.compliancePolicies', 'deviceManagement/deviceCompliancePolicies'],
  ['intune.configurationPolicies', 'deviceManagement/deviceConfigurations'],
];

const AZURE_ROOTS: ReadonlyArray<readonly [string, string, string]> = [
  ['azure.roleDefinitions', 'Microsoft.Authorization/roleDefinitions', '2022-04-01'],
  ['azure.roleAssignments', 'Microsoft.Authorization/roleAssignments', '2022-04-01'],
  ['defenderCloud.pricings', 'Microsoft.Security/pricings', '2024-01-01'],
  ['defenderCloud.assessments', 'Microsoft.Security/assessments', '2020-01-01'],
  ['defenderCloud.secureScores', 'Microsoft.Security/secureScores', '2020-01-01'],
  ['defenderCloud.regulatoryCompliance', 'Microsoft.Security/regulatoryComplianceStandards', '2019-01-01-preview'],
];

const GITHUB_CHILDREN: ReadonlyArray<readonly [string, string, string]> = [
  ['github.workflowPermissions', 'actions/permissions/workflow', 'object'],
  ['github.workflows', 'actions/workflows', 'workflows'],
  ['github.runners', 'actions/runners', 'runners'],
  ['github.environments', 'environments', 'environments'],
  ['github.dependabotAlerts', 'dependabot/alerts', 'array'],
  ['github.codeScanningAlerts', 'code-scanning/alerts', 'array'],
  ['github.secretScanningAlerts', 'secret-scanning/alerts', 'array'],
  ['github.secretMetadata', 'actions/secrets', 'secrets'],
];
const GITHUB_REPOSITORY_IDS = [
  'github.branchProtection', 'github.rulesets', ...GITHUB_CHILDREN.map(([id]) => id),
];
const ADO_CHILDREN: ReadonlyArray<readonly [string, string]> = [
  ['azureDevOps.repositories', 'git/repositories'],
  ['azureDevOps.branchPolicies', 'policy/configurations'],
  ['azureDevOps.pipelines', 'pipelines'],
  ['azureDevOps.environments', 'distributedtask/environments'],
];

function url(base: string, query: Record<string, string> = {}): string {
  const result = new URL(base);
  for (const [key, value] of Object.entries(query)) result.searchParams.set(key, value);
  return result.href;
}

function graphUrl(path: string, selection = GRAPH_SELECT[path]): string {
  return url(`${GRAPH}${path}`, {
    ...(selection ? { $select: selection } : {}),
    ...(['organization', 'subscribedSkus', 'admin/sharepoint/settings',
      'roleManagement/directory/roleAssignmentScheduleInstances'].includes(path) ? {} : { $top: String(PAGE_SIZE) }),
    ...(path === 'auditLogs/signIns' ? { $filter: "riskLevelAggregated ne 'none'" } : {}),
  });
}

function stableRecordId(value: unknown): string {
  if ((typeof value !== 'string' && typeof value !== 'number')
    || (typeof value === 'number' && !Number.isSafeInteger(value))
    || !String(value) || String(value).length > 4096 || /[\u0000-\u001f\u007f]/.test(String(value))) {
    throw new CollectionError('invalid-response');
  }
  return String(value);
}

function recordIdentity(record: JsonObject): string {
  return JSON.stringify([record.id, record.parentId ?? null, record.repository ?? null]);
}

function nextLink(value: unknown): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') throw new CollectionError('invalid-response');
  return value;
}

function githubNext(header: string | null): string | undefined {
  if (!header) return undefined;
  if (header.length > 32_000) throw new CollectionError('invalid-response');
  const links = [...header.matchAll(/<([^>]+)>\s*;\s*rel="([^"]+)"/g)];
  const next = links.filter(match => match[2]?.split(' ').includes('next'));
  if (next.length > 1 || (/\bnext\b/.test(header) && next.length === 0)) {
    throw new CollectionError('invalid-response');
  }
  return next[0]?.[1];
}

function canonicalPage(input: string, body?: Record<string, unknown>): string {
  const parsed = new URL(input);
  parsed.searchParams.sort();
  return `${parsed.href}\n${JSON.stringify(body ?? null)}`;
}

function subscriptionRecord(record: JsonObject, subscriptionId: string): void {
  const id = String(record.id ?? '');
  const match = /^\/subscriptions\/([^/]+)(?:\/|$)/i.exec(id);
  if (match?.[1] && match[1].toLowerCase() !== subscriptionId.toLowerCase()) {
    throw new CollectionError('scope-mismatch');
  }
}

function policySubscriptionRecord(record: JsonObject, subscriptionId: string): void {
  if (typeof record.subscriptionId !== 'string' || !GUID.test(record.subscriptionId)
    || typeof record.type !== 'string' || record.type.toLowerCase() !== 'microsoft.policyinsights/policystates') {
    throw new CollectionError('invalid-response');
  }
  if (record.subscriptionId.toLowerCase() !== subscriptionId.toLowerCase()) {
    throw new CollectionError('scope-mismatch');
  }
  const resourceId = object(record.properties).resourceId;
  if (typeof resourceId !== 'string' || /[\u0000-\u001f\u007f?#\\]/.test(resourceId)
    || /%(?:2e|2f|5c|25)/i.test(resourceId) || /(?:^|\/)\.{1,2}(?:\/|$)/.test(resourceId)) {
    throw new CollectionError('invalid-response');
  }
  const scope = /^\/subscriptions\/([^/]+)(?:\/|$)/i.exec(resourceId);
  if (!scope?.[1] || !GUID.test(scope[1])) throw new CollectionError('invalid-response');
  if (scope[1].toLowerCase() !== subscriptionId.toLowerCase()) throw new CollectionError('scope-mismatch');
  if (record.sourceId !== undefined) subscriptionRecord({ id: record.sourceId }, subscriptionId);
}

class Collector {
  private readonly client: SafeHttpClient;
  private readonly collectedAt: string;
  private readonly results = new Map<string, CollectionResult>();

  constructor(private readonly config: AssessmentConfig, options: CollectorOptions) {
    this.client = new SafeHttpClient(config, options);
    this.collectedAt = (options.now ?? (() => new Date()))().toISOString();
  }

  private result(
    id: string, scope: string, status: CollectionResult['status'] = 'complete', reason?: CollectionReason,
  ): CollectionResult {
    const definition = DEFINITIONS.get(id);
    if (!definition) throw new CollectionError('unsupported');
    return {
      id, provider: definition.provider, scope, status, collectedAt: this.collectedAt, records: [],
      ...(reason ? { reason, message: new CollectionError(reason).message } : {}),
    };
  }

  private add(result: CollectionResult): CollectionResult {
    this.results.set(JSON.stringify([result.id, result.scope]), result);
    return result;
  }

  private lookup(id: string, scope: string): CollectionResult {
    return this.results.get(JSON.stringify([id, scope])) ?? this.result(id, scope, 'unavailable', 'dependency-unavailable');
  }

  private incomplete(result: CollectionResult, error: CollectionError, progressed: boolean): CollectionResult {
    return {
      ...result, status: progressed || result.records.length ? 'partial' : 'unavailable',
      reason: error.reason, message: error.message,
    };
  }

  private dependency(id: string, scope: string, parent: CollectionResult): CollectionResult {
    return this.result(id, scope, parent.status === 'partial' ? 'partial' : 'unavailable',
      parent.reason === 'scope-mismatch' ? 'scope-mismatch' : 'dependency-unavailable');
  }

  private inherit(result: CollectionResult, parent: CollectionResult): CollectionResult {
    if (parent.status === 'complete') return result;
    if (result.status === 'complete') {
      return { ...result, status: 'partial', reason: 'dependency-unavailable',
        message: 'This child endpoint was read, but its parent inventory was incomplete; coverage is not exhaustive.' };
    }
    return { ...result, message: `${result.message ?? ''} Parent inventory was also incomplete.`.trim() };
  }

  private async pages(spec: PageSpec): Promise<CollectionResult> {
    let result = this.result(spec.id, spec.scope);
    let pageUrl = spec.url;
    let body = spec.body;
    const seenPages = new Set<string>();
    const seenRecords = new Set<string>();
    let pages = 0;
    let knownTotal: number | undefined;
    try {
      result.source = new URL(spec.url).pathname;
      while (true) {
        if (pages >= this.config.limits.maxPages) throw new CollectionError('limit-reached');
        const pageKey = canonicalPage(pageUrl, body);
        if (seenPages.has(pageKey)) throw new CollectionError('invalid-response');
        seenPages.add(pageKey);
        const response = await this.client.request(result.provider, pageUrl, {
          method: body ? 'POST' : 'GET', body,
          ...(pages > 0 && !body ? { continuationOf: spec.url } : {}),
        });
        const container = spec.container ?? 'value';
        const envelope = container === 'array' ? undefined : object(response.body);
        const records: unknown = container === 'array' ? response.body
          : container === 'object' ? [response.body] : envelope?.[container];
        if (!Array.isArray(records)) throw new CollectionError('invalid-response');
        if (envelope) {
          const total = envelope.totalRecords ?? envelope.total_count ?? envelope['@odata.count'];
          if (total !== undefined) {
            if (typeof total !== 'number' || !Number.isSafeInteger(total) || total < 0) {
              throw new CollectionError('invalid-response');
            }
            knownTotal = total;
          }
        }
        for (const raw of records) {
          if (result.records.length >= this.config.limits.maxRecords) throw new CollectionError('limit-reached');
          const rawObject = object(raw);
          const record = projectRecord(spec.id, raw);
          const identity = record.id ?? (spec.idFrom ? record[spec.idFrom] : undefined) ?? spec.syntheticId;
          record.id = stableRecordId(identity);
          spec.validate?.(record, rawObject);
          Object.assign(record, spec.decorate);
          const safeRecord = this.client.redact(record) as JsonObject;
          try { assertSafeEvidence(safeRecord); }
          catch { throw new CollectionError('invalid-response'); }
          const key = recordIdentity(safeRecord);
          if (seenRecords.has(key)) throw new CollectionError('invalid-response');
          seenRecords.add(key);
          result.records.push(safeRecord);
        }
        pages++;
        let next: string | undefined;
        if (body) {
          const skip = nextLink(envelope?.$skipToken);
          if (skip) {
            const options = object(body.options);
            body = { ...body, options: { ...options, $skipToken: skip } };
            next = spec.url;
          } else if (envelope?.resultTruncated === true || envelope?.resultTruncated === 'true') {
            throw new CollectionError('limit-reached');
          } else if (envelope?.resultTruncated !== undefined
            && envelope.resultTruncated !== false && envelope.resultTruncated !== 'false') {
            throw new CollectionError('invalid-response');
          }
        } else if (result.provider === 'github') {
          next = githubNext(response.headers.get('link'));
        } else if (result.provider === 'azureDevOps') {
          const continuation = response.headers.get('x-ms-continuationtoken');
          if (continuation) {
            const nextUrl = new URL(spec.url);
            nextUrl.searchParams.set('continuationToken', continuation);
            next = nextUrl.href;
          }
        } else {
          next = nextLink(envelope?.['@odata.nextLink'] ?? envelope?.nextLink);
          if (!next && spec.offsetPaging && records.length === PAGE_SIZE) {
            const nextUrl = new URL(spec.url);
            nextUrl.searchParams.set('$skip', String(pages * PAGE_SIZE));
            next = nextUrl.href;
          }
        }
        if (!next) {
          if (knownTotal !== undefined && knownTotal > result.records.length) {
            throw new CollectionError('limit-reached');
          }
          if (result.source) result.source = String(this.client.redact(result.source));
          return result;
        }
        if (result.records.length >= this.config.limits.maxRecords) throw new CollectionError('limit-reached');
        pageUrl = next;
      }
    } catch (error) {
      if (result.source) result.source = String(this.client.redact(result.source));
      return this.incomplete(result, collectionError(error), pages > 0 && result.records.length === 0);
    }
  }

  private async fanout(
    id: string, scope: string, parent: CollectionResult,
    selectParents: (record: JsonObject) => boolean,
    spec: (record: JsonObject) => PageSpec,
  ): Promise<CollectionResult> {
    if (parent.records.length === 0 && parent.status !== 'complete') return this.dependency(id, scope, parent);
    let result = this.result(id, scope);
    let successfulChildren = 0;
    let attempted = 0;
    const parents = parent.records.filter(selectParents);
    for (const record of parents) {
      if (this.client.remainingRequests === 0 || result.records.length >= this.config.limits.maxRecords) {
        result = this.incomplete(result, new CollectionError('limit-reached'), attempted > 0);
        break;
      }
      let child: CollectionResult;
      attempted++;
      try { child = await this.pages(spec(record)); }
      catch (error) { child = this.incomplete(this.result(id, scope), collectionError(error), false); }
      const room = this.config.limits.maxRecords - result.records.length;
      result.records.push(...child.records.slice(0, room));
      result.source ??= child.source;
      if (child.status === 'complete') successfulChildren++;
      else result = this.incomplete(result, new CollectionError(child.reason ?? 'api-error'), successfulChildren > 0);
      if (child.records.length > room) {
        result = this.incomplete(result, new CollectionError('limit-reached'), true);
        break;
      }
    }
    if (successfulChildren > 0 && result.status === 'unavailable') result.status = 'partial';
    return this.inherit(result, parent);
  }

  private async binding(): Promise<CollectionResult> {
    const tenant = this.config.scope.tenantId;
    const result = await this.pages({
      id: 'entra.organization', scope: tenant, url: graphUrl('organization'),
      validate: record => {
        if (String(record.id).toLowerCase() !== tenant.toLowerCase()) throw new CollectionError('scope-mismatch');
      },
    });
    if (result.reason === 'scope-mismatch') return { ...result, records: [], status: 'unavailable' };
    if (result.status !== 'complete') return { ...result, records: [], status: 'unavailable' };
    if (result.records.length !== 1) return this.result('entra.organization', tenant, 'unavailable', 'invalid-response');
    return result;
  }

  private async graph(binding: CollectionResult): Promise<void> {
    const scope = this.config.scope.tenantId;
    this.add(binding);
    if (binding.status !== 'complete') {
      for (const definition of COLLECTION_CATALOG.filter(item => item.provider === 'graph' && item.id !== binding.id && !item.manual)) {
        this.add(this.dependency(definition.id, scope, binding));
      }
      return;
    }
    for (const [id, path] of GRAPH_ROOTS) {
      let result = await this.pages({
        id, scope, url: graphUrl(path),
        ...(id === 'm365.sharePointSettings' ? {
          container: 'object', syntheticId: 'sharepoint-settings',
          validate: (_record: JsonObject, raw: Record<string, unknown>) => {
            if (['value', '@odata.nextLink', 'nextLink'].some(key => Object.hasOwn(raw, key))) {
              throw new CollectionError('invalid-response');
            }
          },
        } : {}),
      });
      if (id === 'entra.users' && result.status === 'unavailable' && result.reason === 'permission-denied') {
        const selection = GRAPH_SELECT.users?.split(',').filter(field => field !== 'signInActivity').join(',');
        const basic = await this.pages({ id, scope, url: graphUrl(path, selection) });
        result = basic.status === 'complete' ? {
          ...basic, status: 'partial', reason: 'permission-denied',
          message: 'Basic user inventory was collected, but sign-in activity was denied. Licensing was not inferred.',
        } : basic;
      }
      this.add(result);
    }
    const children: ReadonlyArray<readonly [string, string, string, string, string]> = [
      ['entra.groupMemberships', 'entra.groups', 'groups', 'members', ''],
      ['entra.applicationOwners', 'entra.applications', 'applications', 'owners', ''],
      ['entra.servicePrincipalOwners', 'entra.servicePrincipals', 'servicePrincipals', 'owners', ''],
      ['entra.federatedCredentials', 'entra.applications', 'applications', 'federatedIdentityCredentials', 'id,name,issuer,subject,audiences'],
      ['entra.appRoleAssignments', 'entra.servicePrincipals', 'servicePrincipals', 'appRoleAssignments', 'id,principalId,principalType,resourceId,appRoleId,createdDateTime'],
    ];
    for (const [id, parentId, resource, relationship, selection] of children) {
      const parent = this.lookup(parentId, scope);
      let result = await this.fanout(id, scope, parent, () => true, record => {
        const entityId = stableRecordId(record.id);
        if (!GUID.test(entityId)) throw new CollectionError('invalid-response');
        return {
          id, scope, url: graphUrl(`${resource}/${entityId}/${relationship}`, selection),
          decorate: { parentId: entityId },
          validate: child => {
            if (id === 'entra.appRoleAssignments' && typeof child.principalId === 'string'
              && child.principalId.toLowerCase() !== entityId.toLowerCase()) {
              throw new CollectionError('scope-mismatch');
            }
          },
        };
      });
      if (id === 'entra.groupMemberships' && parent.records.length > 0 && result.status === 'complete') {
        result = { ...result, status: 'partial', reason: 'unsupported',
          message: 'Graph v1.0 direct group membership has a documented service-principal omission limitation; membership coverage is not certified complete.' };
      }
      this.add(result);
    }
  }

  private async azure(binding: CollectionResult): Promise<void> {
    const tenant = this.config.scope.tenantId;
    const groups = binding.status === 'complete'
      ? await this.pages({
        id: 'azure.managementGroups', scope: tenant,
        url: url(`${ARM}/providers/Microsoft.Management/managementGroups`, { 'api-version': '2020-05-01' }),
        validate: record => {
          const properties = record.properties;
          if (properties && typeof properties === 'object' && !Array.isArray(properties)
            && typeof properties.tenantId === 'string' && properties.tenantId.toLowerCase() !== tenant.toLowerCase()) {
            throw new CollectionError('scope-mismatch');
          }
        },
      }) : this.dependency('azure.managementGroups', tenant, binding);
    this.add(groups);
    for (const subscriptionId of new Set(this.config.scope.subscriptionIds)) {
      const scope = `/subscriptions/${subscriptionId}`;
      const subscription = binding.reason === 'scope-mismatch'
        ? this.result('azure.subscriptions', scope, 'unavailable', 'scope-mismatch')
        : await this.pages({
          id: 'azure.subscriptions', scope, container: 'object',
          url: url(`${ARM}${scope}`, { 'api-version': '2022-12-01' }),
          validate: record => {
            if (typeof record.tenantId !== 'string' || typeof record.subscriptionId !== 'string') {
              throw new CollectionError('invalid-response');
            }
            if (record.tenantId.toLowerCase() !== tenant.toLowerCase()
              || record.subscriptionId.toLowerCase() !== subscriptionId.toLowerCase()
              || String(record.id).toLowerCase() !== scope.toLowerCase()) {
              throw new CollectionError('scope-mismatch');
            }
          },
        });
      this.add(subscription);
      if (subscription.status !== 'complete') {
        for (const id of ['azure.resources', 'azure.policyCompliance', 'azure.federatedCredentials', ...AZURE_ROOTS.map(([id]) => id)]) {
          this.add(this.dependency(id, scope, subscription));
        }
        continue;
      }
      const resources = this.add(await this.pages({
        id: 'azure.resources', scope, container: 'data',
        url: url(`${ARM}/providers/Microsoft.ResourceGraph/resources`, { 'api-version': '2022-10-01' }),
        body: this.client.resourceGraphBody(subscriptionId), decorate: { subscriptionId },
        validate: record => {
          if (typeof record.subscriptionId !== 'string' || typeof record.id !== 'string'
            || !record.id.toLowerCase().startsWith(`${scope.toLowerCase()}/`)) {
            throw new CollectionError('invalid-response');
          }
          if (record.subscriptionId.toLowerCase() !== subscriptionId.toLowerCase()) {
            throw new CollectionError('scope-mismatch');
          }
          subscriptionRecord(record, subscriptionId);
          const identity = record.identity;
          if (identity && typeof identity === 'object' && !Array.isArray(identity)
            && typeof identity.tenantId === 'string' && identity.tenantId
            && identity.tenantId.toLowerCase() !== tenant.toLowerCase()) throw new CollectionError('scope-mismatch');
        },
      }));
      this.add(await this.pages({
        id: 'azure.policyCompliance', scope, container: 'data',
        url: url(`${ARM}/providers/Microsoft.ResourceGraph/resources`, { 'api-version': '2022-10-01' }),
        body: this.client.resourceGraphBody(subscriptionId, 'policy-compliance'),
        decorate: { subscriptionId }, validate: record => policySubscriptionRecord(record, subscriptionId),
      }));
      for (const [id, resource, version] of AZURE_ROOTS) {
        this.add(await this.pages({
          id, scope, url: url(`${ARM}${scope}/providers/${resource}`, { 'api-version': version }),
          decorate: { subscriptionId }, validate: record => subscriptionRecord(record, subscriptionId),
        }));
      }
      this.add(await this.fanout('azure.federatedCredentials', scope, resources,
        record => String(record.type).toLowerCase() === 'microsoft.managedidentity/userassignedidentities',
        record => {
          const parentId = stableRecordId(record.id);
          const parts = parentId.match(/^\/subscriptions\/([^/]+)\/resourceGroups\/([^/]+)\/providers\/Microsoft\.ManagedIdentity\/userAssignedIdentities\/([^/]+)$/i);
          if (!parts?.[1] || !parts[2] || !parts[3] || parts[1].toLowerCase() !== subscriptionId.toLowerCase()) {
            throw new CollectionError('scope-mismatch');
          }
          const parentPath = `${scope}/resourceGroups/${encodeURIComponent(parts[2])}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${encodeURIComponent(parts[3])}`;
          return {
            id: 'azure.federatedCredentials', scope,
            url: url(`${ARM}${parentPath}/federatedIdentityCredentials`, { 'api-version': '2023-01-31' }),
            decorate: { parentId, subscriptionId }, validate: child => subscriptionRecord(child, subscriptionId),
          };
        }));
    }
  }

  private async defender(binding: CollectionResult): Promise<void> {
    const scope = this.config.scope.tenantId;
    for (const [id, path] of [
      ['defender.incidents', 'incidents'], ['defender.alerts', 'alerts'], ['defender.machines', 'machines'],
    ] as const) {
      this.add(binding.status === 'complete' ? await this.pages({
        id, scope, url: url(`https://api.security.microsoft.com/api/${path}`, { $top: String(PAGE_SIZE) }),
        offsetPaging: true, ...(id === 'defender.incidents' ? { idFrom: 'incidentId' } : {}),
        validate: record => {
          if (typeof record.aadTenantId === 'string' && record.aadTenantId.toLowerCase() !== scope.toLowerCase()) {
            throw new CollectionError('scope-mismatch');
          }
        },
      }) : this.dependency(id, scope, binding));
    }
  }

  private async githubRulesets(repository: string, parent: CollectionResult): Promise<CollectionResult> {
    const id = 'github.rulesets';
    const decorate = { repository, full_name: repository };
    let result = await this.pages({
      id, scope: repository, container: 'array',
      url: url(`${GITHUB}/repos/${repository}/rulesets`, { per_page: String(PAGE_SIZE), includes_parents: 'true' }),
      decorate,
    });
    const summaries = [...result.records];
    for (let index = 0; index < summaries.length; index++) {
      if (this.client.remainingRequests === 0) {
        result = this.incomplete(result, new CollectionError('limit-reached'), true);
        break;
      }
      const summary = summaries[index];
      if (!summary || !/^\d+$/.test(String(summary.id))) {
        result = this.incomplete(result, new CollectionError('invalid-response'), true);
        continue;
      }
      const detail = await this.pages({
        id, scope: repository, container: 'object',
        url: url(`${GITHUB}/repos/${repository}/rulesets/${String(summary.id)}`, { includes_parents: 'true' }),
        decorate, validate: record => {
          if (record.id !== summary.id) throw new CollectionError('invalid-response');
        },
      });
      if (detail.status === 'complete' && detail.records[0]) result.records[index] = detail.records[0];
      else result = this.incomplete(result, new CollectionError(detail.reason ?? 'api-error'), true);
    }
    return this.inherit(result, parent);
  }

  private async github(): Promise<void> {
    for (const organization of new Set(this.config.scope.githubOrganizations)) {
      this.add(await this.pages({
        id: 'github.organizations', scope: organization, container: 'object',
        url: `${GITHUB}/orgs/${organization}`,
        validate: record => {
          if (typeof record.login !== 'string' || record.login.toLowerCase() !== organization.toLowerCase()) {
            throw new CollectionError('scope-mismatch');
          }
        },
      }));
      const memberRoles: CollectionResult[] = [];
      for (const role of ['member', 'admin']) {
        memberRoles.push(await this.pages({
          id: 'github.members', scope: organization, container: 'array',
          url: url(`${GITHUB}/orgs/${organization}/members`, { per_page: String(PAGE_SIZE), role }),
          decorate: { role },
        }));
      }
      let members = this.result('github.members', organization);
      const memberIds = new Set<string>();
      for (const role of memberRoles) {
        for (const record of role.records) {
          if (members.records.length >= this.config.limits.maxRecords) {
            members = this.incomplete(members, new CollectionError('limit-reached'), true);
            break;
          }
          if (memberIds.has(String(record.id))) {
            members = this.incomplete(members, new CollectionError('invalid-response'), true);
            continue;
          }
          memberIds.add(String(record.id));
          members.records.push(record);
        }
        if (role.status !== 'complete') members = this.incomplete(members,
          new CollectionError(role.reason ?? 'api-error'), memberRoles.some(item => item.status === 'complete'));
      }
      this.add(members);
      this.add(await this.pages({
        id: 'github.outsideCollaborators', scope: organization, container: 'array',
        url: url(`${GITHUB}/orgs/${organization}/outside_collaborators`, { per_page: String(PAGE_SIZE) }),
      }));
      this.add(await this.pages({
        id: 'github.secretMetadata', scope: organization, container: 'secrets', idFrom: 'name',
        url: url(`${GITHUB}/orgs/${organization}/actions/secrets`, { per_page: String(PAGE_SIZE) }),
      }));
      const repositories = this.add(await this.pages({
        id: 'github.repositories', scope: organization, container: 'array',
        url: url(`${GITHUB}/orgs/${organization}/repos`, { per_page: String(PAGE_SIZE), type: 'all' }),
        validate: record => {
          if (typeof record.full_name !== 'string'
            || !new RegExp(`^${organization}/[A-Za-z0-9_.-]{1,100}$`, 'i').test(record.full_name)
            || record.full_name.split('/')[1] === '.' || record.full_name.split('/')[1] === '..') {
            throw new CollectionError('scope-mismatch');
          }
        },
      }));
      if (repositories.status !== 'complete') {
        for (const id of GITHUB_REPOSITORY_IDS.filter(id => id !== 'github.secretMetadata')) {
          this.add(this.dependency(id, organization, repositories));
        }
        const secrets = this.lookup('github.secretMetadata', organization);
        this.add(this.inherit(secrets, repositories));
      }
      if (repositories.records.length === 0) {
        for (const id of GITHUB_REPOSITORY_IDS.filter(id => id !== 'github.secretMetadata')) {
          this.add(repositories.status === 'complete' ? this.result(id, organization)
            : this.dependency(id, organization, repositories));
        }
        continue;
      }
      for (const record of repositories.records) {
        if (this.client.remainingRequests === 0) {
          for (const id of GITHUB_REPOSITORY_IDS.filter(id => id !== 'github.secretMetadata')) {
            this.add(this.result(id, organization, 'partial', 'limit-reached'));
          }
          const secrets = this.lookup('github.secretMetadata', organization);
          this.add({ ...secrets, status: 'partial', reason: 'limit-reached',
            message: 'Organization secret names were assessed separately; repository secret-name coverage stopped at the request limit.' });
          break;
        }
        const repository = String(record.full_name);
        const decorate = { repository, full_name: repository };
        const branch = typeof record.default_branch === 'string' && record.default_branch ? record.default_branch : undefined;
        const protection = branch ? await this.pages({
          id: 'github.branchProtection', scope: repository, container: 'object',
          url: `${GITHUB}/repos/${repository}/branches/${encodeURIComponent(branch)}/protection`,
          syntheticId: `${repository}/branches/${branch}/protection`, decorate: { ...decorate, branch },
        }) : this.result('github.branchProtection', repository, 'unavailable', 'dependency-unavailable');
        this.add(this.inherit(protection, repositories));
        this.add(await this.githubRulesets(repository, repositories));
        for (const [id, path, container] of GITHUB_CHILDREN) {
          const query: Record<string, string> = container === 'object' ? {} : { per_page: String(PAGE_SIZE) };
          if (id === 'github.secretScanningAlerts') query.hide_secret = 'true';
          const child = await this.pages({
            id, scope: repository, container, url: url(`${GITHUB}/repos/${repository}/${path}`, query),
            decorate,
            ...(id.endsWith('Alerts') ? { idFrom: 'number' } : {}),
            ...(id === 'github.secretMetadata' ? { idFrom: 'name' } : {}),
            ...(container === 'object' ? { syntheticId: `${repository}/${path}` } : {}),
            validate: (_record, raw) => {
              if (id === 'github.secretScanningAlerts' && raw.secret !== undefined
                && raw.secret !== null && raw.secret !== '') {
                throw new CollectionError('invalid-response');
              }
            },
          });
          this.add(this.inherit(child, repositories));
        }
      }
    }
  }

  private async ado(binding: CollectionResult): Promise<void> {
    for (const organization of new Set(this.config.scope.azureDevOpsOrganizations)) {
      if (binding.status !== 'complete') {
        for (const definition of COLLECTION_CATALOG.filter(item => item.provider === 'azureDevOps' && !item.manual)) {
          this.add(this.dependency(definition.id, organization, binding));
        }
        continue;
      }
      this.add(await this.pages({
        id: 'azureDevOps.agentPools', scope: organization,
        url: url(`${ADO}/${organization}/_apis/distributedtask/pools`, { 'api-version': '7.1' }),
      }));
      const projects = this.add(await this.pages({
        id: 'azureDevOps.projects', scope: organization,
        url: url(`${ADO}/${organization}/_apis/projects`, { 'api-version': '7.1', $top: String(PAGE_SIZE) }),
        validate: record => { if (!GUID.test(String(record.id))) throw new CollectionError('invalid-response'); },
      }));
      if (projects.records.length === 0) {
        for (const [id] of ADO_CHILDREN) this.add(projects.status === 'complete' ? this.result(id, organization)
          : this.dependency(id, organization, projects));
        continue;
      }
      for (const project of projects.records) {
        if (this.client.remainingRequests === 0) {
          for (const [id] of ADO_CHILDREN) this.add(this.result(id, organization, 'partial', 'limit-reached'));
          break;
        }
        const projectId = String(project.id);
        const scope = `${organization}/${projectId}`;
        for (const [id, path] of ADO_CHILDREN) {
          const child = await this.pages({
            id, scope, url: url(`${ADO}/${organization}/${projectId}/_apis/${path}`, {
              'api-version': '7.1', ...(path === 'git/repositories' ? {} : { $top: String(PAGE_SIZE) }),
            }),
            decorate: { projectId },
            validate: record => {
              const reference = record.project;
              if (reference && typeof reference === 'object' && !Array.isArray(reference)
                && reference.id !== undefined && String(reference.id).toLowerCase() !== projectId.toLowerCase()) {
                throw new CollectionError('scope-mismatch');
              }
            },
          });
          this.add(this.inherit(child, projects));
        }
      }
    }
  }

  private scopes(definition: CollectionDefinition): string[] {
    const { tenantId, subscriptionIds, githubOrganizations, azureDevOpsOrganizations } = this.config.scope;
    switch (definition.provider) {
      case 'graph': case 'defender': return [tenantId];
      case 'azure':
        return definition.id.startsWith('azure.managementGroup') || !subscriptionIds.length
          ? [tenantId] : [...new Set(subscriptionIds.map(id => `/subscriptions/${id}`))];
      case 'github': return githubOrganizations.length ? [...new Set(githubOrganizations)] : ['github'];
      case 'azureDevOps': return azureDevOpsOrganizations.length ? [...new Set(azureDevOpsOrganizations)] : ['azureDevOps'];
    }
  }

  async collect(): Promise<CollectionResult[]> {
    const enabled = { ...this.config.sources };
    if (!this.config.scope.githubOrganizations.length) enabled.github = false;
    if (!this.config.scope.azureDevOpsOrganizations.length) enabled.azureDevOps = false;
    for (const definition of COLLECTION_CATALOG) {
      if (!enabled[definition.provider]) {
        for (const scope of this.scopes(definition)) this.add(this.result(definition.id, scope, 'not-configured', 'not-configured'));
      }
    }
    // This single read-back is an authentication prerequisite even when Graph inventory is disabled.
    // ARM subscription tenant evidence can independently authorize subscription-only collection.
    const binding = enabled.graph || enabled.azure || enabled.defender || enabled.azureDevOps
      ? await this.binding() : this.result('entra.organization', this.config.scope.tenantId, 'not-configured', 'not-configured');
    const operations: Array<readonly [Provider, () => Promise<void>]> = [
      ['graph', () => this.graph(binding)], ['azure', () => this.azure(binding)],
      ['defender', () => this.defender(binding)], ['github', () => this.github()],
      ['azureDevOps', () => this.ado(binding)],
    ];
    for (const [provider, operation] of operations) {
      if (!enabled[provider]) continue;
      try { await operation(); }
      catch (error) {
        const failure = collectionError(error);
        for (const definition of COLLECTION_CATALOG.filter(item => item.provider === provider && !item.manual)) {
          for (const scope of this.scopes(definition)) {
            const existing = this.results.get(JSON.stringify([definition.id, scope]));
            this.add(existing ? this.incomplete(existing, failure, existing.status === 'complete')
              : this.result(definition.id, scope, 'unavailable', failure.reason));
          }
        }
      }
    }
    for (const definition of COLLECTION_CATALOG) {
      if (!enabled[definition.provider]) continue;
      if (definition.manual) {
        for (const scope of this.scopes(definition)) {
          const manual = this.result(definition.id, scope, 'unavailable', 'unsupported');
          manual.message = `${definition.title}. No corresponding endpoint was requested.`;
          this.add(manual);
        }
      } else if (![...this.results.values()].some(result => result.id === definition.id)) {
        for (const scope of this.scopes(definition)) this.add(this.result(definition.id, scope, 'not-configured', 'not-configured'));
      }
    }
    return [...this.results.values()].sort((left, right) => left.id.localeCompare(right.id) || left.scope.localeCompare(right.scope));
  }
}

export async function collect(
  config: AssessmentConfig, options: CollectorOptions = {},
): Promise<CollectionResult[]> {
  return new Collector(config, options).collect();
}
