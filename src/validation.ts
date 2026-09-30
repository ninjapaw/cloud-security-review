import { z } from 'zod';
import { DOMAINS, PROVIDERS, SEVERITIES } from './model.js';
import type {
  AssessmentInput, AssessmentSnapshot, JsonValue, RiskPolicy,
} from './model.js';
import {
  AssessmentError, assertSafeEvidence, collectionKey, recordId, recordKey, safeHttpsUrl,
} from './safety.js';

const text = z.string().min(1).max(20_000);
const date = z.string().datetime({ offset: true });
const guid = z.string().regex(/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i).transform(value => value.toLowerCase());
const https = z.string().max(4096).refine(safeHttpsUrl, 'An HTTPS documentation URL is required.');
const json: z.ZodType<JsonValue> = z.lazy(() => z.union([
  z.null(), z.boolean(), z.number().finite(), z.string(),
  z.array(json), z.record(z.string(), json),
]));
const object = z.record(z.string(), json);
const distinctNames = (pattern: RegExp) => z.array(z.string().regex(pattern))
  .max(1000).transform(values => [...new Set(values.map(value => value.toLowerCase()))].sort());

export const scopeSchema = z.object({
  tenantId: guid,
  subscriptionIds: z.array(guid).max(1000).transform(values => [...new Set(values)].sort()),
  githubOrganizations: distinctNames(/^[a-z0-9](?:[a-z0-9-]{0,38})$/i),
  azureDevOpsOrganizations: distinctNames(/^[a-z0-9](?:[a-z0-9-]{0,49})$/i),
}).strict();

export const permissionRuleSchema = z.object({
  resourceAppId: guid,
  permissionId: guid,
  permissionType: z.enum(['application', 'delegated']),
  severity: z.enum(SEVERITIES),
  capabilities: z.array(text).min(1).max(50),
  rationale: text,
  reference: https,
}).strict();

export const weightsSchema = z.object({
  directoryPrivilege: z.number().int().min(0).max(100),
  apiPrivilege: z.number().int().min(0).max(100),
  azurePrivilege: z.number().int().min(0).max(100),
  broadScope: z.number().int().min(0).max(100),
  persistentCredential: z.number().int().min(0).max(100),
  externalOwner: z.number().int().min(0).max(100),
  missingOwner: z.number().int().min(0).max(100),
  credentialHygiene: z.number().int().min(0).max(100),
  privilegeCombination: z.number().int().min(0).max(100),
  codeToCloud: z.number().int().min(0).max(100),
}).strict();

export const policySchema = z.object({
  expiringWithinDays: z.number().int().min(1).max(365),
  maxCredentialLifetimeDays: z.number().int().min(1).max(3650),
  staleCredentialDays: z.number().int().min(1).max(3650),
  maxOwners: z.number().int().min(1).max(100),
  dormantUserDays: z.number().int().min(1).max(3650),
  permissionRules: z.array(permissionRuleSchema).max(10000),
  weights: weightsSchema,
}).strict().superRefine((value, ctx) => {
  const keys = value.permissionRules.map(rule => `${rule.resourceAppId}/${rule.permissionType}/${rule.permissionId}`);
  if (new Set(keys).size !== keys.length) {
    ctx.addIssue({ code: 'custom', path: ['permissionRules'], message: 'Duplicate permission rules are not permitted.' });
  }
});

const collectionSchema = z.object({
  id: text,
  provider: z.enum(PROVIDERS),
  scope: text.transform(value => value.toLowerCase()),
  status: z.enum(['complete', 'partial', 'unavailable', 'not-configured']),
  collectedAt: date,
  records: z.array(object).max(1_000_000),
  reason: z.enum([
    'permission-denied', 'authentication-failed', 'not-found', 'not-licensed',
    'unsupported', 'rate-limited', 'timeout', 'api-error', 'invalid-response',
    'limit-reached', 'dependency-unavailable', 'not-configured', 'scope-mismatch',
  ]).optional(),
  message: text.optional(),
  source: z.string().max(4096).optional(),
}).strict().superRefine((value, ctx) => {
  if (['unavailable', 'not-configured'].includes(value.status) && value.records.length) {
    ctx.addIssue({ code: 'custom', path: ['records'], message: 'Unavailable collections cannot contain records.' });
  }
  if (value.status !== 'complete' && !value.reason) {
    ctx.addIssue({ code: 'custom', path: ['reason'], message: 'Incomplete collection requires an explicit reason.' });
  }
});

const inputFields = {
  schemaVersion: z.literal('1.0'),
  scope: scopeSchema,
  collectedAt: date,
  collections: z.array(collectionSchema).max(100_000),
};
const inputSchema = z.object(inputFields).strict();
const evidenceSchema = z.object({
  collectionId: text,
  scope: text.transform(value => value.toLowerCase()),
  recordId: text.optional(),
  field: text.optional(),
}).strict();
const findingSchema = z.object({
  id: text,
  checkId: text,
  domain: z.enum(DOMAINS),
  severity: z.enum(SEVERITIES),
  status: z.enum(['fail', 'pass', 'unable-to-assess', 'informational']),
  title: text,
  description: text,
  resourceId: text,
  scope: text,
  evidence: z.array(evidenceSchema),
  recommendation: text,
  references: z.array(https),
  zeroTrust: z.array(z.enum(['verify-explicitly', 'least-privilege', 'assume-breach'])),
  confidence: z.enum(['high', 'medium', 'low']),
}).strict();
const graphSchema = z.object({
  nodes: z.array(z.object({
    id: text, type: text, label: text, properties: object, evidence: z.array(evidenceSchema),
  }).strict()),
  edges: z.array(z.object({
    id: text, from: text, to: text, relationship: text,
    confidence: z.enum(['confirmed', 'potential']), evidence: z.array(evidenceSchema),
  }).strict()),
}).strict();
const snapshotSchema = z.object({
  ...inputFields,
  kind: z.literal('cloud-security-assessment'),
  toolVersion: text,
  assessmentId: text,
  policy: policySchema,
  findings: z.array(findingSchema),
  graph: graphSchema,
  identityRisks: z.array(z.object({
    identityId: text,
    displayName: text,
    score: z.number().min(0).max(100),
    factors: z.array(z.object({
      name: text, weight: z.number().min(0).max(100), explanation: text, evidence: z.array(evidenceSchema),
    }).strict()),
    incomplete: z.boolean(),
    caveat: text,
  }).strict()),
  coverage: z.array(z.object({
    domain: z.enum(DOMAINS),
    complete: z.number().int().nonnegative(),
    partial: z.number().int().nonnegative(),
    unavailable: z.number().int().nonnegative(),
    notConfigured: z.number().int().nonnegative(),
  }).strict()),
}).strict();

export function validate<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  assertSafeEvidence(value);
  const result = schema.safeParse(value);
  if (!result.success) {
    // Schema diagnostics can contain input values; only report structural paths and codes.
    const issues = result.error.issues.slice(0, 8).map(issue => `${issue.path.join('.') || '<root>'}: ${issue.code}`);
    throw new AssessmentError('invalid-input', `${label} is invalid (${issues.join('; ')}).`);
  }
  return result.data;
}

function validateCollections(input: AssessmentInput): void {
  const keys = new Set<string>();
  for (const collection of input.collections) {
    const key = collectionKey(collection.id, collection.scope);
    if (keys.has(key)) {
      throw new AssessmentError('duplicate-collection', 'Duplicate collection id and scope in evidence.');
    }
    keys.add(key);
    const records = collection.records.map(recordKey);
    if (new Set(records).size !== records.length) {
      throw new AssessmentError('duplicate-record', 'Duplicate evidence record identity within a collection.');
    }
    if (Date.parse(collection.collectedAt) > Date.parse(input.collectedAt)) {
      throw new AssessmentError('invalid-time', 'Collection evidence cannot postdate the assessment timestamp.');
    }
    const scope = collection.scope.toLowerCase();
    const sourceParts = scope.split('/');
    const sourceScopeValid = sourceParts.length <= 2 && sourceParts.every(part =>
      /^[a-z0-9_.-]+$/.test(part) && part !== '.' && part !== '..');
    const allowed = collection.provider === 'graph' || collection.provider === 'defender'
      ? scope === input.scope.tenantId
      : collection.provider === 'azure'
        ? scope === input.scope.tenantId
          || input.scope.subscriptionIds.some(id => scope === `/subscriptions/${id}`)
          || scope.startsWith('/providers/microsoft.management/managementgroups/')
        : sourceScopeValid
          && (collection.provider === 'github' ? input.scope.githubOrganizations : input.scope.azureDevOpsOrganizations)
            .some(org => scope === org || scope.startsWith(`${org}/`));
    if (!allowed && !(collection.records.length === 0 && collection.status !== 'complete' && scope === 'assessment')) {
      throw new AssessmentError('scope-mismatch', 'A collection falls outside the explicitly selected assessment scope.');
    }
    for (const record of collection.records) {
      if (collection.provider === 'github') {
        const repository = record.full_name ?? record.repository;
        if (typeof repository === 'string') {
          const normalized = repository.toLowerCase();
          const parts = normalized.split('/');
          const owner = parts[0];
          const repositoryName = parts[1];
          if (parts.length !== 2 || !repositoryName || !/^[a-z0-9_.-]{1,100}$/.test(repositoryName)
            || repositoryName === '.' || repositoryName === '..'
            || !owner || !input.scope.githubOrganizations.includes(owner)
            || (collection.id === 'github.repositories' && owner !== scope)
            || (typeof record.repository === 'string' && normalized !== scope)) {
            throw new AssessmentError('scope-mismatch', 'Repository evidence does not match its approved organization and collection scope.');
          }
        }
      }
      if (['azure.resources', 'azure.policyCompliance'].includes(collection.id) && typeof record.subscriptionId === 'string'
        && `/subscriptions/${record.subscriptionId.toLowerCase()}` !== scope) {
        throw new AssessmentError('scope-mismatch', 'Azure resource evidence does not match its selected subscription.');
      }
      if (collection.id === 'azure.policyCompliance') {
        const properties = record.properties;
        if (properties && typeof properties === 'object' && !Array.isArray(properties)
          && typeof properties.resourceId === 'string') {
          const resource = properties.resourceId.toLowerCase();
          if (resource !== scope && !resource.startsWith(`${scope}/`)) {
            throw new AssessmentError('scope-mismatch', 'Azure Policy evaluation evidence refers to a resource outside its selected subscription.');
          }
        }
      }
    }
  }
}

export function parseInput(value: unknown): AssessmentInput {
  const input = validate(inputSchema, value, 'Assessment input');
  validateCollections(input);
  return input;
}

export function parsePolicy(value: unknown): RiskPolicy {
  return validate(policySchema, value, 'Risk policy');
}

export function parseSnapshot(value: unknown): AssessmentSnapshot {
  const snapshot = validate(snapshotSchema, value, 'Assessment snapshot');
  validateCollections(snapshot);
  const inventories = new Map(snapshot.collections.map(collection => [
    collectionKey(collection.id, collection.scope), new Set(collection.records.map(recordId)),
  ]));
  const evidence = [
    ...snapshot.findings.flatMap(finding => finding.evidence),
    ...snapshot.graph.nodes.flatMap(node => node.evidence),
    ...snapshot.graph.edges.flatMap(edge => edge.evidence),
    ...snapshot.identityRisks.flatMap(risk => risk.factors.flatMap(factor => factor.evidence)),
  ];
  for (const ref of evidence) {
    const records = inventories.get(collectionKey(ref.collectionId, ref.scope));
    if (!records || (ref.recordId !== undefined && !records.has(ref.recordId))) {
      throw new AssessmentError('invalid-evidence-reference', 'A finding or relationship references missing evidence.');
    }
  }
  for (const ids of [
    snapshot.findings.map(finding => finding.id),
    snapshot.graph.nodes.map(node => node.id),
    snapshot.graph.edges.map(edge => edge.id),
    snapshot.identityRisks.map(risk => risk.identityId),
    snapshot.coverage.map(entry => entry.domain),
  ]) {
    if (new Set(ids).size !== ids.length) {
      throw new AssessmentError('duplicate-analysis-id', 'Analysis identifiers must be unique.');
    }
  }
  const nodes = new Set(snapshot.graph.nodes.map(node => node.id));
  if (snapshot.graph.edges.some(edge => !nodes.has(edge.from) || !nodes.has(edge.to))) {
    throw new AssessmentError('invalid-relationship', 'Relationship graph has an edge without its endpoint nodes.');
  }
  return snapshot;
}
