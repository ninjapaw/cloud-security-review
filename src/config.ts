import { z } from 'zod';
import type { AssessmentConfig } from './model.js';
import { DEFAULT_POLICY } from './policy.js';
import { AssessmentError } from './safety.js';
import { parsePolicy, permissionRuleSchema, scopeSchema, validate, weightsSchema } from './validation.js';

const configSchema = z.object({
  scope: scopeSchema,
  sources: z.object({
    graph: z.boolean().default(true),
    azure: z.boolean().default(false),
    defender: z.boolean().default(false),
    github: z.boolean().default(false),
    azureDevOps: z.boolean().default(false),
  }).strict().default({ graph: true, azure: false, defender: false, github: false, azureDevOps: false }),
  auth: z.object({
    azure: z.object({
      mode: z.enum(['azure-cli', 'managed-identity', 'workload-identity']).default('azure-cli'),
      clientId: z.string().uuid().optional(),
    }).strict().default({ mode: 'azure-cli' }),
    github: z.object({
      tokenEnvironmentVariable: z.string().regex(/^[A-Z][A-Z0-9_]{0,127}$/).default('GITHUB_TOKEN'),
    }).strict().default({ tokenEnvironmentVariable: 'GITHUB_TOKEN' }),
  }).strict().default({ azure: { mode: 'azure-cli' }, github: { tokenEnvironmentVariable: 'GITHUB_TOKEN' } }),
  limits: z.object({
    maxPages: z.number().int().min(1).max(10000).default(100),
    maxRecords: z.number().int().min(1).max(1_000_000).default(10000),
    maxRequests: z.number().int().min(1).max(100000).default(5000),
    timeoutMs: z.number().int().min(100).max(300000).default(30000),
    maxRetries: z.number().int().min(0).max(5).default(3),
    maxResponseBytes: z.number().int().min(1024).max(32 * 1024 * 1024).default(4 * 1024 * 1024),
  }).strict().prefault({}),
  policy: z.object({
    expiringWithinDays: z.number().int().min(1).max(365).optional(),
    maxCredentialLifetimeDays: z.number().int().min(1).max(3650).optional(),
    staleCredentialDays: z.number().int().min(1).max(3650).optional(),
    maxOwners: z.number().int().min(1).max(100).optional(),
    dormantUserDays: z.number().int().min(1).max(3650).optional(),
    permissionRules: z.array(permissionRuleSchema).max(10000).optional(),
    weights: weightsSchema.partial().optional(),
  }).strict().default({}),
}).strict();

export function parseConfig(value: unknown): AssessmentConfig {
  const parsed = validate(configSchema, value, 'Configuration');
  if (parsed.sources.azure && parsed.scope.subscriptionIds.length === 0) {
    throw new AssessmentError('missing-scope', 'Azure collection requires explicitly approved subscriptionIds.');
  }
  if (parsed.sources.github && parsed.scope.githubOrganizations.length === 0) {
    throw new AssessmentError('missing-scope', 'GitHub collection requires explicitly approved githubOrganizations.');
  }
  if (parsed.sources.azureDevOps && parsed.scope.azureDevOpsOrganizations.length === 0) {
    throw new AssessmentError('missing-scope', 'Azure DevOps collection requires explicitly approved azureDevOpsOrganizations.');
  }
  if (parsed.auth.azure.mode === 'azure-cli' && parsed.auth.azure.clientId) {
    throw new AssessmentError('invalid-auth-config', 'clientId is not used by Azure CLI authentication.');
  }
  if (parsed.auth.azure.mode === 'workload-identity' && !parsed.auth.azure.clientId) {
    throw new AssessmentError('invalid-auth-config', 'Workload identity authentication requires an explicit clientId.');
  }
  const policy = parsePolicy({
    ...DEFAULT_POLICY,
    ...parsed.policy,
    weights: { ...DEFAULT_POLICY.weights, ...parsed.policy.weights },
  });
  return { ...parsed, policy };
}
