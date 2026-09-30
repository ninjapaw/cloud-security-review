import { createHash } from 'node:crypto';
import { assertSafeEvidence } from '../safety.js';
import type {
  AnalysisResult, CollectionResult, Domain, EvidenceRef, Finding, GraphEdge, GraphNode,
  IdentityRisk, JsonObject, JsonValue, RiskFactor, RiskPolicy, Severity, ZeroTrustPrinciple,
} from '../model.js';

export const REFERENCES = {
  permissions: 'https://learn.microsoft.com/en-us/graph/permissions-reference',
  roles: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference',
  pim: 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure',
  groups: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept',
  registration: 'https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0',
  ca: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview',
  risk: 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks',
  dormant: 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts',
  credentials: 'https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration',
  credentialDates: 'https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0',
  owners: 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-app-owners',
  applications: 'https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals',
  appGrants: 'https://learn.microsoft.com/en-us/graph/api/resources/approleassignment?view=graph-rest-1.0',
  delegatedGrants: 'https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0',
  rbac: 'https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions',
  rbacConditions: 'https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-overview',
  rbacScope: 'https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview',
  identities: 'https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview',
  federation: 'https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust',
  adoFederation: 'https://learn.microsoft.com/en-us/azure/devops/pipelines/release/configure-workload-identity?view=azure-devops',
  secureScore: 'https://learn.microsoft.com/en-us/defender-xdr/microsoft-secure-score',
  sharePointSettings: 'https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0',
  sharePointGet: 'https://learn.microsoft.com/en-us/graph/api/sharepointsettings-get?view=graph-rest-1.0',
  sharePointIdle: 'https://learn.microsoft.com/en-us/graph/api/resources/idlesessionsignout?view=graph-rest-1.0',
  roleSchedules: 'https://learn.microsoft.com/en-us/graph/api/resources/unifiedroleassignmentscheduleinstance?view=graph-rest-1.0',
  roleSchedulesList: 'https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentscheduleinstances?view=graph-rest-1.0',
  policyCompliance: 'https://learn.microsoft.com/en-us/azure/governance/policy/samples/resource-graph-samples',
  policyEvaluation: 'https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data',
  policyEffects: 'https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-basics',
  policyDisabled: 'https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-disabled',
  policyManual: 'https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-manual',
  incidents: 'https://learn.microsoft.com/en-us/defender-xdr/api-list-incidents',
  alerts: 'https://learn.microsoft.com/en-us/defender-endpoint/api/get-alerts',
  machines: 'https://learn.microsoft.com/en-us/defender-endpoint/api/machine',
  intune: 'https://learn.microsoft.com/en-us/intune/intune-service/protect/device-compliance-get-started',
  defenderPlans: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction',
  defenderAssessments: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/review-security-recommendations',
  storage: 'https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations',
  keyVault: 'https://learn.microsoft.com/en-us/azure/key-vault/general/secure-key-vault',
  github2fa: 'https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization',
  githubBase: 'https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/setting-base-permissions-for-an-organization',
  githubSecurity: 'https://docs.github.com/en/code-security/getting-started/github-security-features',
  githubBranch: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches',
  githubRules: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets',
  githubToken: 'https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication',
  githubRunners: 'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions',
  githubEnvironment: 'https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments',
  githubOidc: 'https://docs.github.com/en/actions/reference/security/oidc',
  adoProjects: 'https://learn.microsoft.com/en-us/azure/devops/organizations/projects/about-projects?view=azure-devops',
  adoPolicies: 'https://learn.microsoft.com/en-us/azure/devops/repos/git/branch-policies?view=azure-devops',
  adoPipelines: 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview?view=azure-devops',
} as const;

export function object(value: JsonValue | undefined): JsonObject | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : undefined;
}
export function objects(value: JsonValue | undefined): JsonObject[] {
  return Array.isArray(value) ? value.flatMap((item) => object(item) ? [item as JsonObject] : []) : [];
}
export function text(value: JsonValue | undefined): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
export function number(value: JsonValue | undefined): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}
export function strings(value: JsonValue | undefined): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}
export function has(objectValue: JsonObject, field: string): boolean {
  return Object.hasOwn(objectValue, field);
}
export function identifier(value: JsonValue | undefined): string | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : text(value);
}
export function canonical(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b, 'en')).map(([key, item]) =>
    `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`;
}
export function stableId(kind: string, ...parts: unknown[]): string {
  return `${kind}:${createHash('sha256').update(canonical(parts)).digest('hex').slice(0, 24)}`;
}
export function uniqueEvidence(refs: EvidenceRef[]): EvidenceRef[] {
  return [...new Map(refs.map((ref) => [canonical(ref), ref])).values()]
    .sort((a, b) => canonical(a).localeCompare(canonical(b), 'en'));
}
export const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
export function maximumSeverity(a: Severity, b: Severity): Severity {
  return severityRank[a] >= severityRank[b] ? a : b;
}
export function date(value: JsonValue | undefined): number | undefined {
  if (typeof value !== 'string') return undefined;
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/i.exec(value);
  if (!parts) return undefined;
  const [year, month, day, hour, minute, second] = parts.slice(1, 7).map(Number);
  if (year === undefined || month === undefined || day === undefined || hour === undefined || minute === undefined || second === undefined) return undefined;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const maximumDay = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (!maximumDay || day < 1 || day > maximumDay || hour > 23 || minute > 59 || second > 59) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}
export const DAY = 86_400_000;
export function policyNumber(value: number, fallback: number): number {
  return Number.isFinite(value) && value >= 0 ? value : fallback;
}

export interface RecordRef {
  data: JsonObject;
  id: string;
  scope: string;
  collectionId: string;
  evidence: EvidenceRef[];
}
export interface Rule {
  id: string;
  domain: Domain;
  severity: Severity;
  title: string;
  recommendation: string;
  references: string[];
  zeroTrust: ZeroTrustPrinciple[];
}
export function rule(
  id: string, domain: Domain, severity: Severity, title: string, recommendation: string,
  reference: string | string[], zeroTrust: ZeroTrustPrinciple[] = ['least-privilege'],
): Rule {
  return { id, domain, severity, title, recommendation,
    references: typeof reference === 'string' ? [reference] : reference, zeroTrust };
}

interface Dataset {
  sources: CollectionResult[];
  records: RecordRef[];
  conflicting: boolean;
}
interface RiskState {
  id: string;
  scope: string;
  displayName: string;
  factors: Map<string, RiskFactor>;
  incomplete: boolean;
}
export interface Privilege {
  principalId: string;
  tenant: string;
  kind: 'directory' | 'api' | 'azure';
  capabilities: string[];
  severity: Severity;
  evidence: EvidenceRef[];
  delegated?: boolean;
  eligible?: boolean;
  conditional?: boolean;
  broad?: boolean;
  scope?: string;
  assignmentId?: string;
}
export interface OwnerRelationship {
  tenant: string;
  ownerId: string;
  ownedId: string;
  ownedType: 'application' | 'servicePrincipal';
  external: boolean;
  evidence: EvidenceRef[];
}
export interface RepositoryWeakness {
  repository: string;
  kind: 'branch' | 'workflow-token' | 'environment';
  target?: string;
  severity: Severity;
  evidence: EvidenceRef[];
}

export class Context {
  readonly findings = new Map<string, Finding>();
  readonly nodes = new Map<string, GraphNode>();
  readonly edges = new Map<string, GraphEdge>();
  readonly privileges: Privilege[] = [];
  readonly owners: OwnerRelationship[] = [];
  readonly repositoryWeaknesses: RepositoryWeakness[] = [];
  readonly now: number;
  private readonly datasets = new Map<string, Dataset>();
  private readonly byCollection = new Map<string, RecordRef[]>();
  private readonly byRecord = new Map<string, RecordRef[]>();
  private readonly risks = new Map<string, RiskState>();

  constructor(readonly collections: CollectionResult[], readonly policy: RiskPolicy, now: Date) {
    this.now = now.getTime();
    for (const collection of [...collections].sort((a, b) =>
      canonical([a.id, a.scope, a.status]).localeCompare(canonical([b.id, b.scope, b.status]), 'en'))) {
      const key = this.key(collection.id, collection.scope);
      const dataset = this.datasets.get(key) ?? { sources: [], records: [], conflicting: false };
      dataset.sources.push(collection);
      // An unavailable collector must not manufacture observed configuration from a stale/error body.
      if (collection.status === 'complete' || collection.status === 'partial') {
        for (const data of collection.records) {
          const id = identifier(data.id);
          if (!id) { dataset.conflicting = true; continue; }
          dataset.records.push({ data, id, scope: collection.scope, collectionId: collection.id,
            evidence: [{ collectionId: collection.id, scope: collection.scope, recordId: id }] });
        }
      }
      this.datasets.set(key, dataset);
    }
    for (const dataset of this.datasets.values()) {
      const seen = new Map<string, string>();
      const records = new Map<string, RecordRef>();
      for (const record of dataset.records) {
        const key = canonical([record.id, record.data.parentId, record.data.repository]);
        const value = canonical(record.data);
        if (seen.has(key) && seen.get(key) !== value) dataset.conflicting = true;
        seen.set(key, value);
        records.set(canonical([key, value]), record);
      }
      dataset.records = [...records.entries()].sort(([a], [b]) => a.localeCompare(b, 'en')).map(([, record]) => record);
      for (const record of dataset.records) {
        const collectionRecords = this.byCollection.get(record.collectionId) ?? [];
        collectionRecords.push(record);
        this.byCollection.set(record.collectionId, collectionRecords);
        const key = canonical([record.collectionId, record.scope, record.id.toLowerCase()]);
        const matches = this.byRecord.get(key) ?? [];
        matches.push(record);
        this.byRecord.set(key, matches);
      }
    }
  }

  private key(id: string, scope: string): string { return canonical([id, scope]); }

  private identityLabel(scope: string, id: string, type?: 'application' | 'identity'): {
    label: string; evidence: EvidenceRef[];
  } | undefined {
    const datasets = type === 'application' ? ['entra.applications']
      : type === 'identity' ? ['entra.users', 'entra.groups', 'entra.servicePrincipals']
        : ['entra.applications', 'entra.users', 'entra.groups', 'entra.servicePrincipals'];
    const matches = datasets.flatMap((dataset) => {
      const record = this.find(dataset, scope, id);
      return record ? [record] : [];
    });
    if (matches.length !== 1) return undefined;
    const record = matches[0]!;
    const label = text(record.data.displayName);
    if (!label || !label.trim()) return undefined;
    try {
      assertSafeEvidence(label);
    } catch {
      return undefined;
    }
    return { label, evidence: this.evidenceFor(record, 'displayName') };
  }

  records(id: string, scope?: string): RecordRef[] {
    return scope === undefined ? this.byCollection.get(id) ?? [] : this.datasets.get(this.key(id, scope))?.records ?? [];
  }

  complete(id: string, scope: string): boolean {
    const dataset = this.datasets.get(this.key(id, scope));
    return !!dataset && !dataset.conflicting && dataset.sources.length > 0
      && dataset.sources.every((source) => source.status === 'complete');
  }

  scopes(...prefixes: string[]): string[] {
    return [...new Set(this.collections.filter((source) => prefixes.some((prefix) => source.id.startsWith(prefix)))
      .map((source) => source.scope))].sort();
  }

  inventoryEvidence(id: string, scope: string): EvidenceRef[] {
    if (this.datasets.has(this.key(id, scope))) return [{ collectionId: id, scope }];
    const placeholder = this.datasets.get(this.key(id, 'assessment'));
    if (placeholder?.sources.every((source) =>
      (source.status === 'unavailable' || source.status === 'not-configured') && source.records.length === 0)) {
      return [{ collectionId: id, scope: 'assessment' }];
    }
    // Missing evidence is a check result, not a reference to an invented collection or a different tenant.
    return [];
  }

  find(id: string, scope: string, recordId: string): RecordRef | undefined {
    const records = this.byRecord.get(canonical([id, scope, recordId.toLowerCase()])) ?? [];
    return records.length === 1 ? records[0] : undefined;
  }

  evidenceFor(record: RecordRef, field: string): EvidenceRef[] {
    return record.evidence.map((ref) => ({ ...ref, field }));
  }

  emit(
    check: Rule, scope: string, resourceId: string, status: Finding['status'], description: string,
    evidence: EvidenceRef[], discriminator = '', severity = check.severity, confidence: Finding['confidence'] = 'high',
  ): Finding {
    const id = stableId('finding', check.id, scope, resourceId, discriminator);
    const previous = this.findings.get(id);
    const statusRank = { fail: 3, 'unable-to-assess': 2, informational: 1, pass: 0 };
    const finding: Finding = {
      id, checkId: check.id, domain: check.domain, severity: status === 'unable-to-assess' ? 'informational' : severity,
      status, title: check.title, description, resourceId, scope, evidence: uniqueEvidence(evidence),
      recommendation: check.recommendation, references: [...new Set(check.references)].sort(),
      zeroTrust: [...new Set(check.zeroTrust)].sort(), confidence,
    };
    if (previous) {
      const keepPrevious = statusRank[previous.status] > statusRank[status]
        || (previous.status === status && severityRank[previous.severity] > severityRank[finding.severity]);
      const kept = keepPrevious ? previous : finding;
      kept.evidence = uniqueEvidence([...previous.evidence, ...finding.evidence]);
      kept.references = [...new Set([...previous.references, ...finding.references])].sort();
      this.findings.set(id, kept);
      return kept;
    }
    this.findings.set(id, finding);
    return finding;
  }

  require(check: Rule, scope: string, ids: string[], resourceId = scope, evidence: EvidenceRef[] = []): boolean {
    const missing = ids.filter((id) => !this.complete(id, scope));
    if (missing.length === 0) return true;
    this.emit(check, scope, resourceId, 'unable-to-assess',
      `Complete, unambiguous evidence is required from: ${missing.join(', ')}. Unavailable, partial, missing or conflicting inventories are not a pass and cannot establish absence.`,
      [...evidence, ...missing.flatMap((id) => this.inventoryEvidence(id, scope))], 'coverage');
    return false;
  }

  node(type: string, scope: string, resourceId: string, evidence: EvidenceRef[], properties: JsonObject = {}): string {
    const id = stableId('node', type, scope, resourceId);
    const existing = this.nodes.get(id);
    const name = type === 'application' || type === 'identity' ? this.identityLabel(scope, resourceId, type) : undefined;
    this.nodes.set(id, { id, type, label: name?.label ?? existing?.label ?? resourceId,
      properties: { ...existing?.properties, scope, resourceId, ...properties },
      evidence: uniqueEvidence([...(existing?.evidence ?? []), ...evidence, ...(name?.evidence ?? [])]) });
    return id;
  }

  principal(scope: string, id: string, evidence: EvidenceRef[], kind?: string): string {
    return this.node('identity', scope, id.toLowerCase(), evidence, kind ? { kind } : {});
  }

  edge(from: string, to: string, relationship: string, evidence: EvidenceRef[],
    confidence: GraphEdge['confidence'] = 'confirmed', discriminator = ''): void {
    const id = stableId('edge', from, to, relationship, discriminator);
    const existing = this.edges.get(id);
    this.edges.set(id, { id, from, to, relationship, confidence,
      evidence: uniqueEvidence([...(existing?.evidence ?? []), ...evidence]) });
  }

  identity(scope: string, id: string, incomplete = false): void {
    const key = this.key(scope, id.toLowerCase());
    const previous = this.risks.get(key);
    this.risks.set(key, previous ? { ...previous, incomplete: previous.incomplete || incomplete }
      : { id, scope, displayName: this.identityLabel(scope, id)?.label ?? id, factors: new Map(), incomplete });
  }

  incomplete(scope: string, id: string): void { this.identity(scope, id, true); }

  factor(scope: string, id: string, name: keyof RiskPolicy['weights'], explanation: string, evidence: EvidenceRef[]): void {
    this.identity(scope, id);
    const risk = this.risks.get(this.key(scope, id.toLowerCase()))!;
    const existing = risk.factors.get(name);
    const weight = Math.min(100, policyNumber(this.policy.weights[name], 0));
    const explanations = new Set([...(existing?.explanation.split('\n') ?? []), explanation]);
    risk.factors.set(name, { name, weight, explanation: [...explanations].sort().join('\n'),
      evidence: uniqueEvidence([...(existing?.evidence ?? []), ...evidence]) });
  }

  addPrivilege(privilege: Privilege): void {
    this.privileges.push(privilege);
    this.identity(privilege.tenant, privilege.principalId, privilege.conditional === true);
    if (privilege.eligible) return;
    const factor = privilege.kind === 'directory' ? 'directoryPrivilege' : privilege.kind === 'api' ? 'apiPrivilege' : 'azurePrivilege';
    if (severityRank[privilege.severity] >= severityRank.medium) {
      this.factor(privilege.tenant, privilege.principalId, factor,
        `${privilege.delegated ? 'Delegated, user-dependent ' : ''}${privilege.kind} capability: ${privilege.capabilities.join(', ')}.${privilege.conditional ? ' Effective restrictions require manual validation.' : ''}`,
        privilege.evidence);
    }
    if (privilege.broad) this.factor(privilege.tenant, privilege.principalId, 'broadScope',
      `Azure assignment includes broad scope ${privilege.scope}; the scope does not prove access to every resource or data plane.`, privilege.evidence);
  }

  result(): AnalysisResult {
    const azureScopes = this.scopes('azure.roleAssignments', 'azure.roleDefinitions');
    const identityRisks: IdentityRisk[] = [...this.risks.values()].map((risk) => {
      const factors = [...risk.factors.values()].sort((a, b) => a.name.localeCompare(b.name, 'en'));
      const unknownPrivilegeInputs = ['entra.directoryRoleAssignments', 'entra.directoryRoleDefinitions',
        'entra.directoryRoleAssignmentScheduleInstances', 'entra.appRoleAssignments', 'entra.oauth2PermissionGrants', 'entra.groupMemberships']
        .some((dataset) => !this.complete(dataset, risk.scope))
        || !azureScopes.length || azureScopes.some((scope) =>
          !this.complete('azure.roleAssignments', scope) || !this.complete('azure.roleDefinitions', scope));
      return { identityId: `${risk.scope}/${risk.id}`, displayName: risk.displayName,
        score: Math.min(100, Math.max(0, Math.round(factors.reduce((sum, factor) => sum + factor.weight, 0)))),
        factors, incomplete: risk.incomplete || unknownPrivilegeInputs,
        caveat: 'Advisory, capped prioritization score, not exploitability or a probability. Factors may overlap; zero means no classified factors observed, not safe. Uncollected controls and effective authorization can change the assessment. Federation never cancels observed privilege or persistent-credential risk.' };
    }).sort((a, b) => b.score - a.score || a.identityId.localeCompare(b.identityId, 'en'));
    return {
      findings: [...this.findings.values()].sort((a, b) => a.id.localeCompare(b.id, 'en')),
      graph: { nodes: [...this.nodes.values()].sort((a, b) => a.id.localeCompare(b.id, 'en')),
        edges: [...this.edges.values()].sort((a, b) => a.id.localeCompare(b.id, 'en')) },
      identityRisks,
    };
  }
}

export function sameId(a: string | undefined, b: string | undefined): boolean {
  return a !== undefined && b !== undefined && a.toLowerCase() === b.toLowerCase();
}

export function matchesAction(pattern: string, action: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i').test(action);
}

export function azureScopeKind(scope: string): 'tenant' | 'management-group' | 'subscription' | 'resource-group' | 'resource' | 'unknown' {
  if (scope === '/') return 'tenant';
  if (/^\/providers\/Microsoft\.Management\/managementGroups\/[^/]+$/i.test(scope)) return 'management-group';
  if (/^\/subscriptions\/[^/]+$/i.test(scope)) return 'subscription';
  if (/^\/subscriptions\/[^/]+\/resourceGroups\/[^/]+$/i.test(scope)) return 'resource-group';
  if (/^\/subscriptions\/[^/]+\/(?:resourceGroups\/[^/]+\/)?providers\/[^/]+\/[^/]+\/[^/]+/i.test(scope)) return 'resource';
  return 'unknown';
}

export function withinAzureScope(resourceId: string, assignmentScope: string): boolean {
  const resource = resourceId.toLowerCase().replace(/\/$/, '');
  const scope = assignmentScope.toLowerCase().replace(/\/$/, '');
  if (scope === '') return assignmentScope === '/' && resource.startsWith('/subscriptions/');
  return resource === scope || resource.startsWith(`${scope}/`);
}
