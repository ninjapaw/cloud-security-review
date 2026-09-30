import type { AnalysisResult, CollectionResult, RiskPolicy } from './model.js';
import { Context } from './analysis/context.js';
import { analyzeIdentity } from './analysis/identity.js';
import { analyzeAccess } from './analysis/access.js';
import { analyzeWorkloads, analyzePrivilegeCombinations } from './analysis/workloads.js';
import { analyzePosture } from './analysis/posture.js';
import { analyzeDevelopment } from './analysis/development.js';
import { analyzeFederation } from './analysis/federation.js';
import { analyzeSharePoint } from './analysis/sharepoint.js';
import { analyzeRoleSchedules } from './analysis/schedules.js';
import { analyzePolicyCompliance } from './analysis/policy-compliance.js';

/** Pure, offline evaluation: no authentication, network requests, secret retrieval or remediation. */
export function analyze(collections: CollectionResult[], policy: RiskPolicy, now: Date): AnalysisResult {
  const context = new Context(collections, policy, now);
  analyzeRoleSchedules(context);
  analyzeIdentity(context);
  analyzeAccess(context);
  analyzeWorkloads(context);
  analyzePosture(context);
  analyzeSharePoint(context);
  analyzePolicyCompliance(context);
  analyzeDevelopment(context);
  analyzeFederation(context);
  analyzePrivilegeCombinations(context);
  return context.result();
}
