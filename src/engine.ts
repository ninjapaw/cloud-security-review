import { randomUUID } from 'node:crypto';
import { analyze } from './analysis.js';
import { COLLECTION_CATALOG } from './catalog.js';
import { DOMAINS, SEVERITIES } from './model.js';
import type {
  AssessmentConfig, AssessmentInput, AssessmentSnapshot, CollectionDefinition, CollectionResult,
  CollectorOptions, CoverageEntry, Finding, RiskPolicy,
} from './model.js';
import { DEFAULT_POLICY } from './policy.js';
import { AssessmentError, collectionKey, stableId } from './safety.js';
import { parseInput, parsePolicy, parseSnapshot } from './validation.js';

export const TOOL_VERSION = '0.2.0';
const correlationInputs = new Set([
  'entra.applications', 'entra.servicePrincipals', 'entra.federatedCredentials',
  'azure.roleAssignments', 'azure.roleDefinitions', 'github.repositories',
  'github.branchProtection', 'github.rulesets',
]);

function missingScopes(definition: CollectionDefinition, input: AssessmentInput): string[] {
  if (definition.provider === 'graph' || definition.provider === 'defender') return [input.scope.tenantId];
  if (definition.provider === 'azure') {
    if (definition.id === 'azure.managementGroups') return [input.scope.tenantId];
    return input.scope.subscriptionIds.length ? input.scope.subscriptionIds.map(id => `/subscriptions/${id}`) : ['assessment'];
  }
  if (definition.provider === 'github') {
    const organizations = input.scope.githubOrganizations;
    if (['github.organizations', 'github.members', 'github.outsideCollaborators', 'github.repositories'].includes(definition.id)) {
      return organizations.length ? organizations : ['assessment'];
    }
    const repositories = input.collections.filter(collection => collection.id === 'github.repositories')
      .flatMap(collection => collection.records.flatMap(record => typeof record.full_name === 'string' ? [record.full_name] : []));
    return repositories.length ? [...new Set(repositories)] : organizations.length ? organizations : ['assessment'];
  }
  const organizations = input.scope.azureDevOpsOrganizations;
  if (['azureDevOps.projects', 'azureDevOps.agentPools'].includes(definition.id)) {
    return organizations.length ? organizations : ['assessment'];
  }
  const projects = input.collections.filter(collection => collection.id === 'azureDevOps.projects')
    .flatMap(collection => collection.records.map(record => `${collection.scope}/${String(record.id)}`));
  return projects.length ? [...new Set(projects)] : organizations.length ? organizations : ['assessment'];
}

function normalizeCoverage(input: AssessmentInput): CollectionResult[] {
  const catalog = new Map(COLLECTION_CATALOG.map(definition => [definition.id, definition]));
  for (const collection of input.collections) {
    if (catalog.get(collection.id)?.provider !== collection.provider) {
      throw new AssessmentError('unknown-collection', 'Evidence has an unknown collection or mismatched provider.');
    }
  }
  const present = new Set(input.collections.map(collection => collectionKey(collection.id, collection.scope)));
  const missing: CollectionResult[] = COLLECTION_CATALOG
    .flatMap(definition => missingScopes(definition, input)
      .filter(scope => !present.has(collectionKey(definition.id, scope))
        && !input.collections.some(collection => collection.id === definition.id
          && collection.scope === 'assessment' && collection.status === 'not-configured'))
      .map(scope => ({
      id: definition.id,
      provider: definition.provider,
      scope,
      status: 'unavailable' as const,
      collectedAt: input.collectedAt,
      records: [],
      reason: definition.manual ? 'unsupported' as const : 'dependency-unavailable' as const,
      message: definition.manual
        ? 'This capability requires separate, authorized manual evidence; this version does not collect it.'
        : 'No evidence for this collection was supplied. This is not evidence that the control is absent or secure.',
    })));
  return [...input.collections, ...missing].sort((a, b) => `${a.id}\0${a.scope}`.localeCompare(`${b.id}\0${b.scope}`));
}

function coverageFindings(collections: CollectionResult[]): Finding[] {
  const catalog = new Map(COLLECTION_CATALOG.map(definition => [definition.id, definition]));
  return collections.filter(collection => collection.status !== 'complete').map(collection => {
    const definition = catalog.get(collection.id);
    if (!definition) throw new AssessmentError('unknown-collection', 'Collection definition is missing.');
    return {
      id: stableId('coverage', collection.id, collection.scope),
      checkId: `coverage.${collection.id}`,
      domain: definition.domain,
      severity: 'informational',
      status: 'unable-to-assess',
      title: `${definition.title}: ${collection.status === 'partial' ? 'partial evidence' : 'unable to assess'}`,
      description: collection.message ?? `Evidence is ${collection.status} (${collection.reason}). No security pass is inferred.`,
      resourceId: collection.id,
      scope: collection.scope,
      evidence: [{ collectionId: collection.id, scope: collection.scope }],
      recommendation: definition.manual
        ? 'Arrange an authorized manual review for this capability. Do not interpret the gap as a passing control.'
        : `Review the collection reason, selected scope, licensing and documented read-only permissions before reassessing. Required permissions: ${definition.permissions.join(', ') || 'see linked documentation'}.`,
      references: definition.references,
      zeroTrust: ['verify-explicitly'],
      confidence: 'high',
    };
  });
}

function summarizeCoverage(collections: CollectionResult[]): CoverageEntry[] {
  const catalog = new Map(COLLECTION_CATALOG.map(definition => [definition.id, definition]));
  return DOMAINS.map(domain => {
    const entries = collections.filter(collection => domain === 'code-to-cloud'
      ? correlationInputs.has(collection.id) || catalog.get(collection.id)?.domain === domain
      : catalog.get(collection.id)?.domain === domain);
    return {
      domain,
      complete: entries.filter(entry => entry.status === 'complete').length,
      partial: entries.filter(entry => entry.status === 'partial').length,
      unavailable: entries.filter(entry => entry.status === 'unavailable').length,
      notConfigured: entries.filter(entry => entry.status === 'not-configured').length,
    };
  });
}

export function createAssessment(
  rawInput: AssessmentInput,
  rawPolicy: RiskPolicy = DEFAULT_POLICY,
  assessmentId: string = randomUUID(),
): AssessmentSnapshot {
  const input = parseInput(rawInput);
  const policy = parsePolicy(rawPolicy);
  const collections = normalizeCoverage(input);
  const analysis = analyze(collections, policy, new Date(input.collectedAt));
  const statusOrder = { fail: 0, 'unable-to-assess': 1, informational: 2, pass: 3 };
  const findings = [...analysis.findings, ...coverageFindings(collections)].sort((a, b) =>
    statusOrder[a.status] - statusOrder[b.status]
    || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
    || a.id.localeCompare(b.id));
  return parseSnapshot({
    ...input,
    kind: 'cloud-security-assessment',
    toolVersion: TOOL_VERSION,
    assessmentId,
    policy,
    collections,
    findings,
    graph: analysis.graph,
    identityRisks: analysis.identityRisks,
    coverage: summarizeCoverage(collections),
  });
}

export async function assessLive(config: AssessmentConfig, options: CollectorOptions = {}): Promise<AssessmentSnapshot> {
  const { collect } = await import('./collectors.js');
  const collections = await collect(config, options);
  const now = options.now ?? (() => new Date());
  return createAssessment({
    schemaVersion: '1.0',
    scope: config.scope,
    collectedAt: now().toISOString(),
    collections,
  }, config.policy);
}
