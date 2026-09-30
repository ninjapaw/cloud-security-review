export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export interface JsonObject { [key: string]: JsonValue }

export const PROVIDERS = ['graph', 'azure', 'defender', 'github', 'azureDevOps'] as const;
export type Provider = typeof PROVIDERS[number];
export const DOMAINS = [
  'entra', 'workload-identities', 'microsoft365', 'defender-xdr', 'intune',
  'azure', 'defender-cloud', 'azure-devops', 'github', 'code-to-cloud',
] as const;
export type Domain = typeof DOMAINS[number];
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const;
export type Severity = typeof SEVERITIES[number];
export type ZeroTrustPrinciple = 'verify-explicitly' | 'least-privilege' | 'assume-breach';

export interface AssessmentScope {
  tenantId: string;
  subscriptionIds: string[];
  githubOrganizations: string[];
  azureDevOpsOrganizations: string[];
}

export interface PermissionRiskRule {
  resourceAppId: string;
  permissionId: string;
  permissionType: 'application' | 'delegated';
  severity: Severity;
  capabilities: string[];
  rationale: string;
  reference: string;
}

export interface RiskPolicy {
  expiringWithinDays: number;
  maxCredentialLifetimeDays: number;
  staleCredentialDays: number;
  maxOwners: number;
  dormantUserDays: number;
  permissionRules: PermissionRiskRule[];
  weights: {
    directoryPrivilege: number;
    apiPrivilege: number;
    azurePrivilege: number;
    broadScope: number;
    persistentCredential: number;
    externalOwner: number;
    missingOwner: number;
    credentialHygiene: number;
    privilegeCombination: number;
    codeToCloud: number;
  };
}

export interface AssessmentConfig {
  scope: AssessmentScope;
  sources: Record<Provider, boolean>;
  auth: {
    azure: {
      mode: 'azure-cli' | 'managed-identity' | 'workload-identity';
      clientId?: string;
    };
    github: { tokenEnvironmentVariable: string };
  };
  limits: {
    maxPages: number;
    maxRecords: number;
    maxRequests: number;
    timeoutMs: number;
    maxRetries: number;
    maxResponseBytes: number;
  };
  policy: RiskPolicy;
}

export type CollectionStatus = 'complete' | 'partial' | 'unavailable' | 'not-configured';
export type CollectionReason =
  | 'permission-denied' | 'authentication-failed' | 'not-found' | 'not-licensed'
  | 'unsupported' | 'rate-limited' | 'timeout' | 'api-error' | 'invalid-response'
  | 'limit-reached' | 'dependency-unavailable' | 'not-configured' | 'scope-mismatch';

export interface CollectionDefinition {
  id: string;
  provider: Provider;
  domain: Domain;
  title: string;
  permissions: string[];
  references: string[];
  manual?: boolean;
}

export interface CollectionResult {
  id: string;
  provider: Provider;
  scope: string;
  status: CollectionStatus;
  collectedAt: string;
  records: JsonObject[];
  reason?: CollectionReason;
  message?: string;
  /** Sanitized public API path only; never authorization headers or raw error bodies. */
  source?: string;
}

export interface EvidenceRef {
  collectionId: string;
  scope: string;
  recordId?: string;
  field?: string;
}

export interface Finding {
  id: string;
  checkId: string;
  domain: Domain;
  severity: Severity;
  status: 'fail' | 'pass' | 'unable-to-assess' | 'informational';
  title: string;
  description: string;
  resourceId: string;
  scope: string;
  evidence: EvidenceRef[];
  recommendation: string;
  references: string[];
  zeroTrust: ZeroTrustPrinciple[];
  confidence: 'high' | 'medium' | 'low';
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  properties: JsonObject;
  evidence: EvidenceRef[];
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  relationship: string;
  confidence: 'confirmed' | 'potential';
  evidence: EvidenceRef[];
}

export interface RelationshipGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface RiskFactor {
  name: string;
  weight: number;
  explanation: string;
  evidence: EvidenceRef[];
}

export interface IdentityRisk {
  identityId: string;
  displayName: string;
  score: number;
  factors: RiskFactor[];
  incomplete: boolean;
  caveat: string;
}

export interface AnalysisResult {
  findings: Finding[];
  graph: RelationshipGraph;
  identityRisks: IdentityRisk[];
}

export interface AssessmentInput {
  schemaVersion: '1.0';
  scope: AssessmentScope;
  collectedAt: string;
  collections: CollectionResult[];
}

export interface CoverageEntry {
  domain: Domain;
  complete: number;
  partial: number;
  unavailable: number;
  notConfigured: number;
}

export interface AssessmentSnapshot extends AssessmentInput, AnalysisResult {
  kind: 'cloud-security-assessment';
  toolVersion: string;
  assessmentId: string;
  policy: RiskPolicy;
  coverage: CoverageEntry[];
}

export interface TokenProvider {
  getToken(provider: Provider): Promise<string>;
}

export interface CollectorOptions {
  tokenProvider?: TokenProvider;
  fetch?: typeof globalThis.fetch;
  now?: () => Date;
  sleep?: (milliseconds: number) => Promise<void>;
}

export interface SnapshotChange {
  kind: 'added' | 'removed' | 'changed' | 'indeterminate';
  collectionId: string;
  scope: string;
  recordId: string;
  parentId?: string;
  repository?: string;
  fields: string[];
  securityImpact: 'potential-increase' | 'potential-decrease' | 'review-required' | 'unknown';
  description: string;
}

export interface AssessmentDiff {
  kind: 'cloud-security-assessment-diff';
  schemaVersion: '1.0';
  previousAssessmentId: string;
  currentAssessmentId: string;
  changes: SnapshotChange[];
  findings: { new: string[]; resolved: string[]; persistent: string[]; indeterminate: string[] };
  caveat: string;
}
