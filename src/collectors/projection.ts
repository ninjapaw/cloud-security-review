import { createHash } from 'node:crypto';
import { CollectionError } from '../http.js';
import type { JsonObject, JsonValue } from '../model.js';

type Rule = true | Shape | readonly [Rule];
interface Shape { [field: string]: Rule }
const fields = (...names: string[]): Shape => Object.fromEntries(names.map(name => [name, true]));
const credential = fields('keyId', 'displayName', 'startDateTime', 'endDateTime', 'type', 'usage');
const owner = fields('id', 'displayName', 'userPrincipalName', 'userType', 'appId', 'servicePrincipalType', '@odata.type');
const githubUser = fields('id', 'login', 'type', 'site_admin');
const azureResource = fields('id', 'name', 'type', 'location', 'subscriptionId', 'resourceGroup');
const policyScope = fields('repositoryId', 'refName', 'matchKind');
const rolePermission = {
  actions: [true], notActions: [true], dataActions: [true], notDataActions: [true],
} satisfies Shape;

const SHAPES: Readonly<Record<string, Shape>> = {
  'entra.organization': fields('id', 'displayName'),
  'entra.users': {
    ...fields('id', 'displayName', 'userPrincipalName', 'accountEnabled', 'userType', 'createdDateTime'),
    signInActivity: fields('lastSignInDateTime', 'lastNonInteractiveSignInDateTime', 'lastSuccessfulSignInDateTime'),
  },
  'entra.groups': {
    ...fields('id', 'displayName', 'securityEnabled', 'mailEnabled', 'isAssignableToRole'), groupTypes: [true],
  },
  'entra.groupMemberships': owner,
  'entra.applications': {
    ...fields('id', 'appId', 'displayName', 'signInAudience', 'createdDateTime'),
    passwordCredentials: [credential], keyCredentials: [credential],
  },
  'entra.servicePrincipals': {
    ...fields('id', 'appId', 'displayName', 'servicePrincipalType', 'accountEnabled', 'appOwnerOrganizationId'),
    appRoles: [{
      ...fields('id', 'displayName', 'value', 'isEnabled'), allowedMemberTypes: [true],
    }],
    oauth2PermissionScopes: [fields('id', 'type', 'value', 'isEnabled', 'adminConsentDisplayName')],
    passwordCredentials: [credential], keyCredentials: [credential],
  },
  'entra.applicationOwners': owner,
  'entra.servicePrincipalOwners': owner,
  'entra.federatedCredentials': { ...fields('id', 'name', 'issuer', 'subject'), audiences: [true] },
  'entra.appRoleAssignments': fields('id', 'principalId', 'principalType', 'resourceId', 'appRoleId', 'createdDateTime'),
  'entra.oauth2PermissionGrants': fields('id', 'clientId', 'resourceId', 'scope', 'consentType', 'principalId'),
  'entra.directoryRoleDefinitions': {
    ...fields('id', 'displayName', 'templateId', 'isBuiltIn', 'isEnabled'),
    rolePermissions: [{ allowedResourceActions: [true], excludedResourceActions: [true], condition: true }],
  },
  'entra.directoryRoleAssignments': fields('id', 'principalId', 'roleDefinitionId', 'directoryScopeId', 'appScopeId'),
  'entra.directoryRoleAssignmentScheduleInstances': fields('id', 'principalId', 'roleDefinitionId',
    'directoryScopeId', 'appScopeId', 'assignmentType', 'memberType', 'startDateTime', 'endDateTime',
    'roleAssignmentOriginId', 'roleAssignmentScheduleId'),
  'entra.directoryRoleEligibility': fields('id', 'principalId', 'roleDefinitionId', 'directoryScopeId',
    'startDateTime', 'endDateTime', 'memberType', 'roleEligibilityScheduleId'),
  'entra.authenticationRegistration': {
    ...fields('id', 'userPrincipalName', 'userDisplayName', 'userType', 'isAdmin',
      'isMfaRegistered', 'isMfaCapable', 'isPasswordlessCapable', 'lastUpdatedDateTime'),
    methodsRegistered: [true],
  },
  'entra.conditionalAccess': {
    ...fields('id', 'displayName', 'state', 'createdDateTime', 'modifiedDateTime'),
    conditions: {
      users: {
        includeUsers: [true], excludeUsers: [true], includeGroups: [true], excludeGroups: [true],
        includeRoles: [true], excludeRoles: [true],
      },
      applications: {
        includeApplications: [true], excludeApplications: [true], includeUserActions: [true],
        applicationFilter: fields('mode', 'rule'), includeAuthenticationContextClassReferences: [true],
      },
      clientAppTypes: [true], signInRiskLevels: [true], userRiskLevels: [true],
      servicePrincipalRiskLevels: [true],
      clientApplications: {
        includeServicePrincipals: [true], excludeServicePrincipals: [true],
        servicePrincipalFilter: fields('mode', 'rule'),
      },
      platforms: { includePlatforms: [true], excludePlatforms: [true] },
      locations: { includeLocations: [true], excludeLocations: [true] },
      devices: { deviceFilter: fields('mode', 'rule') },
      authenticationFlows: fields('transferMethods'),
    },
    grantControls: {
      operator: true, builtInControls: [true], customAuthenticationFactors: [true],
      termsOfUse: [true], authenticationStrength: fields('id', 'displayName', 'policyType', 'requirementsSatisfied'),
    },
    sessionControls: {
      signInFrequency: fields('isEnabled', 'type', 'value', 'authenticationType', 'frequencyInterval'),
      persistentBrowser: fields('isEnabled', 'mode'),
      applicationEnforcedRestrictions: fields('isEnabled'),
      cloudAppSecurity: fields('isEnabled', 'cloudAppSecurityType'),
      disableResilienceDefaults: true,
    },
  },
  'entra.riskyUsers': fields('id', 'userDisplayName', 'userPrincipalName', 'riskLevel', 'riskState',
    'riskDetail', 'riskLastUpdatedDateTime', 'isDeleted', 'isProcessing'),
  'entra.riskySignIns': fields('id', 'createdDateTime', 'userId', 'userPrincipalName', 'appId',
    'appDisplayName', 'riskLevelAggregated', 'riskLevelDuringSignIn', 'riskState', 'riskDetail', 'conditionalAccessStatus'),
  'm365.secureScores': {
    ...fields('id', 'createdDateTime', 'currentScore', 'maxScore', 'activeUserCount', 'licensedUserCount'),
    controlScores: [fields('controlName', 'score', 'controlCategory')],
  },
  'm365.secureScoreControls': fields('id', 'title', 'service', 'controlCategory', 'maxScore',
    'deprecated', 'isPreview', 'implementationCost', 'userImpact'),
  'm365.licenses': {
    ...fields('id', 'skuId', 'skuPartNumber', 'capabilityStatus', 'consumedUnits', 'appliesTo'),
    prepaidUnits: fields('enabled', 'suspended', 'warning', 'lockedOut'),
    servicePlans: [fields('servicePlanId', 'servicePlanName', 'provisioningStatus', 'appliesTo')],
  },
  'm365.sharePointSettings': {
    ...fields('id', 'isLegacyAuthProtocolsEnabled', 'isRequireAcceptingUserToMatchInvitedUserEnabled',
      'isResharingByExternalUsersEnabled', 'isUnmanagedSyncAppForTenantRestricted',
      'sharingCapability', 'sharingDomainRestrictionMode'),
    sharingAllowedDomainList: [true], sharingBlockedDomainList: [true],
    idleSessionSignOut: fields('isEnabled', 'signOutAfterInSeconds', 'warnAfterInSeconds'),
  },
  'intune.devices': fields('id', 'deviceName', 'azureADDeviceId', 'complianceState',
    'operatingSystem', 'osVersion', 'managedDeviceOwnerType', 'managementAgent', 'lastSyncDateTime',
    'enrolledDateTime', 'isEncrypted'),
  'intune.compliancePolicies': fields('id', 'displayName', 'createdDateTime', 'lastModifiedDateTime', 'version', '@odata.type'),
  'intune.configurationPolicies': fields('id', 'displayName', 'createdDateTime', 'lastModifiedDateTime', 'version', '@odata.type'),
  'defender.incidents': fields('id', 'incidentId', 'incidentName', 'severity', 'status', 'classification',
    'determination', 'createdTime', 'lastUpdateTime', 'redirectIncidentId'),
  'defender.alerts': fields('id', 'incidentId', 'title', 'severity', 'status', 'classification', 'determination',
    'category', 'detectionSource', 'machineId', 'aadTenantId', 'alertCreationTime', 'lastUpdateTime'),
  'defender.machines': fields('id', 'aadDeviceId', 'computerDnsName', 'osPlatform', 'osBuild',
    'onboardingStatus', 'healthStatus', 'riskScore', 'exposureLevel', 'isAadJoined',
    'firstSeen', 'lastSeen', 'rbacGroupId'),
  'azure.managementGroups': {
    ...fields('id', 'name', 'type'),
    properties: { ...fields('displayName', 'tenantId'), details: { parent: fields('id', 'name', 'displayName') } },
  },
  'azure.subscriptions': {
    ...fields('id', 'subscriptionId', 'tenantId', 'displayName', 'state', 'authorizationSource'),
    subscriptionPolicies: fields('locationPlacementId', 'quotaId', 'spendingLimit'),
  },
  'azure.resources': {
    ...azureResource,
    identity: fields('type', 'principalId', 'tenantId'),
    properties: {
      ...fields('publicNetworkAccess', 'allowBlobPublicAccess', 'allowSharedKeyAccess',
        'supportsHttpsTrafficOnly', 'minimumTlsVersion', 'enableRbacAuthorization',
        'enablePurgeProtection', 'enableSoftDelete', 'httpsOnly', 'disableLocalAuth'),
      networkAcls: fields('defaultAction'), siteConfig: fields('minTlsVersion', 'ftpsState'),
    },
  },
  'azure.policyCompliance': {
    ...fields('id', 'type', 'subscriptionId', 'resourceGroup'),
    properties: fields('resourceId', 'policyAssignmentId', 'policyAssignmentName', 'policyAssignmentScope',
      'policyDefinitionId', 'policyDefinitionReferenceId', 'policySetDefinitionId',
      'policyDefinitionAction', 'complianceState', 'timestamp'),
  },
  'azure.roleDefinitions': {
    ...fields('id', 'name', 'type'),
    properties: {
      ...fields('roleName', 'roleType'), assignableScopes: [true], permissions: [rolePermission],
    },
  },
  'azure.roleAssignments': {
    ...fields('id', 'name', 'type'),
    properties: fields('principalId', 'principalType', 'roleDefinitionId', 'scope', 'condition', 'conditionVersion'),
  },
  'azure.federatedCredentials': {
    ...fields('id', 'name', 'type'), properties: { ...fields('issuer', 'subject'), audiences: [true] },
  },
  'defenderCloud.pricings': {
    ...fields('id', 'name', 'type'),
    properties: {
      ...fields('pricingTier', 'subPlan', 'freeTrialRemainingTime', 'enforce', 'inherited'),
      extensions: [fields('name', 'isEnabled')],
    },
  },
  'defenderCloud.assessments': {
    ...fields('id', 'name', 'type'),
    properties: {
      displayName: true, status: fields('code', 'cause', 'firstEvaluationDate', 'statusChangeDate'),
      resourceDetails: fields('id', 'source'),
      metadata: fields('severity', 'assessmentType', 'policyDefinitionId'),
    },
  },
  'defenderCloud.secureScores': {
    ...fields('id', 'name', 'type'),
    properties: { ...fields('displayName', 'weight'), score: fields('max', 'current', 'percentage') },
  },
  'defenderCloud.regulatoryCompliance': {
    ...fields('id', 'name', 'type'),
    properties: fields('state', 'passedControls', 'failedControls', 'skippedControls', 'unsupportedControls'),
  },
  'github.organizations': fields('id', 'login', 'name', 'two_factor_requirement_enabled',
    'default_repository_permission', 'members_can_create_repositories', 'members_can_create_public_repositories'),
  'github.members': githubUser,
  'github.outsideCollaborators': githubUser,
  'github.repositories': {
    ...fields('id', 'name', 'full_name', 'visibility', 'private', 'archived', 'disabled', 'fork', 'default_branch'),
    owner: githubUser,
    security_and_analysis: {
      advanced_security: fields('status'), secret_scanning: fields('status'),
      secret_scanning_push_protection: fields('status'), dependabot_security_updates: fields('status'),
      secret_scanning_validity_checks: fields('status'), code_security: fields('status'),
      secret_protection: fields('status'),
    },
  },
  'github.branchProtection': {
    required_status_checks: { strict: true, contexts: [true], checks: [fields('context', 'app_id')] },
    required_pull_request_reviews: fields('dismiss_stale_reviews', 'require_code_owner_reviews',
      'required_approving_review_count', 'require_last_push_approval'),
    enforce_admins: fields('enabled'), required_signatures: fields('enabled'),
    required_linear_history: fields('enabled'), allow_force_pushes: fields('enabled'),
    allow_deletions: fields('enabled'), required_conversation_resolution: fields('enabled'),
    block_creations: fields('enabled'), lock_branch: fields('enabled'),
    restrictions: { users: [githubUser], teams: [fields('id', 'name', 'slug')], apps: [fields('id', 'slug', 'name')] },
  },
  'github.rulesets': {
    ...fields('id', 'name', 'target', 'source_type', 'source', 'enforcement'),
    bypass_actors: [fields('actor_id', 'actor_type', 'bypass_mode')],
    conditions: { ref_name: { include: [true], exclude: [true] } },
    rules: [{
      type: true,
      parameters: {
        ...fields('required_approving_review_count', 'dismiss_stale_reviews_on_push',
          'require_code_owner_review', 'require_last_push_approval', 'required_review_thread_resolution',
          'strict_required_status_checks_policy', 'do_not_enforce_on_create', 'operator', 'pattern',
          'negate', 'name'),
        required_status_checks: [fields('context', 'integration_id')],
        allowed_merge_methods: [true],
      },
    }],
  },
  'github.workflowPermissions': fields('default_workflow_permissions', 'can_approve_pull_request_reviews'),
  'github.workflows': fields('id', 'name', 'path', 'state', 'created_at', 'updated_at'),
  'github.runners': {
    ...fields('id', 'name', 'os', 'status', 'busy'), labels: [fields('id', 'name', 'type')],
  },
  'github.environments': {
    ...fields('id', 'name', 'created_at', 'updated_at', 'can_admins_bypass'),
    deployment_branch_policy: fields('protected_branches', 'custom_branch_policies'),
    protection_rules: [{
      ...fields('id', 'type', 'wait_timer', 'prevent_self_review'),
      reviewers: [{ type: true, reviewer: { ...githubUser, ...fields('name', 'slug') } }],
    }],
  },
  'github.dependabotAlerts': {
    ...fields('id', 'number', 'state', 'created_at', 'updated_at', 'fixed_at', 'dismissed_at', 'dismissed_reason'),
    dependency: { package: fields('ecosystem', 'name'), ...fields('manifest_path', 'scope', 'relationship') },
    security_advisory: fields('ghsa_id', 'cve_id', 'severity', 'epss_percentage', 'epss_percentile'),
    security_vulnerability: {
      severity: true, package: fields('ecosystem', 'name'), first_patched_version: fields('identifier'),
    },
  },
  'github.codeScanningAlerts': {
    ...fields('id', 'number', 'state', 'created_at', 'updated_at', 'fixed_at', 'dismissed_at', 'dismissed_reason'),
    rule: fields('id', 'severity', 'security_severity_level'),
    tool: fields('name', 'version'),
    most_recent_instance: fields('ref', 'state', 'commit_sha', 'environment', 'category'),
  },
  'github.secretScanningAlerts': fields('id', 'number', 'state', 'secret_type', 'secret_type_display_name',
    'validity', 'created_at', 'updated_at', 'resolved_at', 'resolution', 'push_protection_bypassed',
    'publicly_leaked', 'multi_repo'),
  'github.secretMetadata': fields('name'),
  'azureDevOps.projects': fields('id', 'name', 'state', 'visibility', 'revision', 'lastUpdateTime'),
  'azureDevOps.repositories': {
    ...fields('id', 'name', 'defaultBranch', 'isDisabled', 'isFork'),
    project: fields('id', 'name', 'visibility', 'state'),
  },
  'azureDevOps.branchPolicies': {
    ...fields('id', 'revision', 'isEnabled', 'isBlocking', 'isDeleted'),
    type: fields('id', 'displayName'),
    settings: {
      ...fields('minimumApproverCount', 'creatorVoteCounts', 'allowDownvotes', 'resetOnSourcePush',
        'requireVoteOnLastIteration', 'blockLastPusherVote', 'buildDefinitionId', 'validDuration',
        'manualQueueOnly', 'queueOnSourceUpdateOnly'),
      scope: [policyScope], requiredReviewerIds: [true], filenamePatterns: [true],
    },
  },
  'azureDevOps.pipelines': fields('id', 'name', 'folder', 'revision'),
  'azureDevOps.environments': {
    ...fields('id', 'name', 'createdOn', 'lastModifiedOn'),
    project: fields('id', 'name'), resources: [fields('id', 'name', 'type')],
  },
  'azureDevOps.agentPools': fields('id', 'name', 'poolType', 'isHosted', 'autoProvision', 'autoSize', 'size'),
};

export function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new CollectionError('invalid-response');
  }
  return value as Record<string, unknown>;
}

function pick(value: unknown, rule: Rule): JsonValue {
  if (value === null) return null;
  if (rule === true) {
    if (typeof value === 'string' || typeof value === 'boolean'
      || (typeof value === 'number' && Number.isFinite(value))) return value;
    throw new CollectionError('invalid-response');
  }
  if (Array.isArray(rule)) {
    if (!Array.isArray(value)) throw new CollectionError('invalid-response');
    const item = rule[0];
    if (item === undefined) throw new CollectionError('invalid-response');
    return value.map(entry => pick(entry, item));
  }
  const source = object(value);
  const result: JsonObject = {};
  for (const [key, childRule] of Object.entries(rule)) {
    if (Object.hasOwn(source, key)) result[key] = pick(source[key], childRule);
  }
  return result;
}

function policyRecordIdentity(record: JsonObject): void {
  const properties = object(record.properties);
  const identity = ['resourceId', 'policyAssignmentId', 'policyDefinitionId'].map(field => {
    const value = properties[field];
    if (typeof value !== 'string' || !value.startsWith('/') || value.length > 4096
      || /[\u0000-\u001f\u007f?#\\]/.test(value)) throw new CollectionError('invalid-response');
    return value.toLowerCase().replace(/\/$/, '');
  });
  const reference = properties.policyDefinitionReferenceId;
  if (reference !== undefined && reference !== null
    && (typeof reference !== 'string' || reference.length > 4096 || /[\u0000-\u001f\u007f]/.test(reference))) {
    throw new CollectionError('invalid-response');
  }
  if (record.id !== undefined && record.id !== null) {
    if ((typeof record.id !== 'string' && typeof record.id !== 'number')
      || (typeof record.id === 'number' && !Number.isSafeInteger(record.id))) {
      throw new CollectionError('invalid-response');
    }
    record.sourceId = record.id;
  }
  // State timestamps and server IDs can change or repeat; the assessed
  // resource/assignment/definition/reference tuple identifies the observation.
  record.id = `policy-state-${createHash('sha256')
    .update(JSON.stringify([...identity, reference ?? ''])).digest('hex')}`;
}

export function projectRecord(collectionId: string, value: unknown): JsonObject {
  const shape = SHAPES[collectionId];
  if (!shape) throw new CollectionError('unsupported');
  const projected = pick(object(value), shape) as JsonObject;
  if (collectionId === 'azure.policyCompliance') policyRecordIdentity(projected);
  if (collectionId === 'm365.sharePointSettings') {
    for (const field of ['sharingAllowedDomainList', 'sharingBlockedDomainList']) {
      const domains = projected[field];
      if (Array.isArray(domains) && domains.some(domain => typeof domain !== 'string')) {
        throw new CollectionError('invalid-response');
      }
    }
  }
  if (collectionId === 'azure.resources') {
    const rawIdentity = object(value).identity;
    if (rawIdentity !== null && typeof rawIdentity === 'object' && !Array.isArray(rawIdentity)) {
      const map = (rawIdentity as Record<string, unknown>).userAssignedIdentities;
      if (map !== undefined && map !== null) {
        const identities = object(map);
        const safe: JsonObject = {};
        for (const [id, identity] of Object.entries(identities)) {
          if (!/^\/subscriptions\/[0-9a-f-]{36}\/resourceGroups\/[^/?#\\]+\/providers\/Microsoft\.ManagedIdentity\/userAssignedIdentities\/[^/?#\\]+$/i.test(id)) {
            throw new CollectionError('invalid-response');
          }
          safe[id] = pick(identity, fields('principalId', 'clientId'));
        }
        const projectedIdentity = projected.identity;
        if (projectedIdentity !== null && typeof projectedIdentity === 'object' && !Array.isArray(projectedIdentity)) {
          projectedIdentity.userAssignedIdentities = safe;
        }
      }
    }
  }
  return projected;
}
