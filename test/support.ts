import type { AssessmentInput, AssessmentSnapshot, CollectionResult, Finding, JsonObject } from '../src/model.js';
import { DEFAULT_POLICY } from '../src/policy.js';

export const tenant = '11111111-1111-4111-8111-111111111111';
export const subscription = '22222222-2222-4222-8222-222222222222';
export const timestamp = '2026-09-01T12:00:00.000Z';
export const scope = {
  tenantId: tenant, subscriptionIds: [subscription],
  githubOrganizations: ['example-org'], azureDevOpsOrganizations: ['example-org'],
};

export function collection(id = 'entra.users', records: JsonObject[] = [], patch: Partial<CollectionResult> = {}): CollectionResult {
  return { id, provider: 'graph', scope: tenant, status: 'complete', collectedAt: timestamp, records, ...patch };
}

export function input(collections = [collection()]): AssessmentInput {
  return { schemaVersion: '1.0', scope, collectedAt: timestamp, collections };
}

export function finding(patch: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1', checkId: 'test.check', domain: 'entra', severity: 'high', status: 'fail',
    title: 'Example risk', description: 'Evidence-supported test condition.', resourceId: 'user-1',
    scope: tenant, evidence: [{ collectionId: 'entra.users', scope: tenant }],
    recommendation: 'Review the observed state.', references: ['https://learn.microsoft.com/en-us/graph/overview'],
    zeroTrust: ['least-privilege'], confidence: 'high', ...patch,
  };
}

export function snapshot(collections = [collection()], findings: Finding[] = []): AssessmentSnapshot {
  return {
    ...input(collections), kind: 'cloud-security-assessment', assessmentId: 'test-assessment', toolVersion: '0.1.0',
    policy: structuredClone(DEFAULT_POLICY), findings, graph: { nodes: [], edges: [] }, identityRisks: [], coverage: [],
  };
}
