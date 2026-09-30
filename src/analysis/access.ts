import type { EvidenceRef, PermissionRiskRule, Severity } from '../model.js';
import {
  Context, REFERENCES as R, azureScopeKind, canonical, has, matchesAction, maximumSeverity,
  object, objects, rule, sameId, strings, text, withinAzureScope, type RecordRef,
} from './context.js';
import { groupMembers } from './identity.js';

const checks = {
  application: rule('WORKLOAD.API.APPLICATION', 'workload-identities', 'high', 'Classified application API permission',
    'Review the documented app-only capability and business need. Reduce grants and validate API-specific restrictions.', [R.permissions, R.appGrants]),
  delegated: rule('WORKLOAD.API.DELEGATED', 'workload-identities', 'high', 'Classified delegated API consent',
    'Review consent scope, user authorization and resource-specific restrictions; delegated consent is not app-only access.', [R.permissions, R.delegatedGrants]),
  unknown: rule('WORKLOAD.API.UNCLASSIFIED', 'workload-identities', 'informational', 'API permission capability is unresolved',
    'Resolve the exact resource service principal and permission identifier. Add a documented, resource-specific policy rule or review manually.', [R.permissions, R.appGrants, R.delegatedGrants]),
  azure: rule('AZURE.RBAC.CAPABILITY', 'azure', 'high', 'Potential Azure RBAC control capability',
    'Review allowed actions minus per-block exclusions, assignment scope, conditions and deny assignments. Prefer narrowly scoped access.', [R.rbac, R.rbacConditions, R.rbacScope]),
  azureUnknown: rule('AZURE.RBAC.UNCLASSIFIED', 'azure', 'informational', 'Azure role capability requires review',
    'Collect the exact role definition and assignment restrictions. Display names and unknown permissions cannot establish safe or effective access.', R.rbac),
  broad: rule('AZURE.RBAC.BROAD_SCOPE', 'azure', 'high', 'Privileged Azure assignment has a broad scope',
    'Validate hierarchy and restrictions, then consider resource or resource-group scope instead of broad inherited control.', [R.rbac, R.rbacScope]),
  identity: rule('AZURE.IDENTITY.ASSOCIATION', 'azure', 'informational', 'Azure resource identity association',
    'Review managed-identity permissions and the identities of people or workloads able to use the associated resource.', R.identities),
};

function matchingPermissionRules(ctx: Context, resourceAppId: string, permissionId: string, type: 'application' | 'delegated'): PermissionRiskRule[] {
  return ctx.policy.permissionRules.filter((entry) => sameId(entry.resourceAppId, resourceAppId)
    && sameId(entry.permissionId, permissionId) && entry.permissionType === type)
    .sort((a, b) => canonical(a).localeCompare(canonical(b), 'en'));
}

function classifyGrant(ctx: Context, grant: RecordRef, client: RecordRef, resource: RecordRef,
  permissionId: string, permissionType: 'application' | 'delegated', discriminator: string): void {
  const resourceAppId = text(resource.data.appId);
  const evidence = [...grant.evidence, ...client.evidence, ...resource.evidence];
  const rules = resourceAppId ? matchingPermissionRules(ctx, resourceAppId, permissionId, permissionType) : [];
  const clientNode = ctx.principal(grant.scope, client.id, client.evidence, 'servicePrincipal');
  const resourceNode = ctx.principal(grant.scope, resource.id, resource.evidence, 'resourceServicePrincipal');
  const permissionNode = ctx.node('api-permission', grant.scope,
    `${resource.id.toLowerCase()}/${permissionType}/${permissionId.toLowerCase()}`, resource.evidence,
    { permissionId, permissionType, ...(resourceAppId ? { resourceAppId } : {}) });
  ctx.edge(permissionNode, resourceNode, 'permission-exposed-by', resource.evidence);
  ctx.edge(clientNode, permissionNode, permissionType === 'application' ? 'application-permission-grant' : 'delegated-consent',
    evidence, 'confirmed', grant.id);
  if (rules.length === 0) {
    ctx.emit(checks.unknown, grant.scope, client.id, 'unable-to-assess',
      `The ${permissionType} permission ${permissionId} on resource service principal ${resource.id} is not classified by a documented resource-and-ID rule. No inference is made from its name.`,
      evidence, `${grant.id}/${discriminator}`);
    ctx.incomplete(grant.scope, client.id);
    return;
  }
  const severity = rules.reduce<Severity>((maximum, entry) => maximumSeverity(maximum, entry.severity), 'informational');
  const capabilities = [...new Set(rules.flatMap((entry) => entry.capabilities))].sort();
  const rationale = [...new Set(rules.map((entry) => entry.rationale))].sort().join(' ');
  const base = permissionType === 'application' ? checks.application : checks.delegated;
  const check = { ...base, references: [...base.references, ...rules.map((entry) => entry.reference)] };
  const consentType = permissionType === 'delegated' ? text(grant.data.consentType) : undefined;
  const consentDescription = permissionType === 'delegated'
    ? ` Consent type: ${consentType ?? 'not visible'}. ${consentType === 'AllPrincipals'
      ? 'Tenant-wide user consent does not remove the signed-in user authorization requirement.'
      : 'The authorized user context must also be validated.'}` : '';
  ctx.emit(check, grant.scope, client.id, severity === 'informational' ? 'informational' : 'fail',
    `${rationale}${consentDescription} Classification is bound to resource application ID ${resourceAppId}, permission ID ${permissionId} and type ${permissionType}; it is not proof of effective access.`,
    evidence, `${grant.id}/${discriminator}`, severity, permissionType === 'delegated' ? 'medium' : 'high');
  ctx.addPrivilege({ principalId: client.id, tenant: grant.scope, kind: 'api', capabilities, severity,
    evidence, delegated: permissionType === 'delegated', conditional: permissionType === 'delegated', assignmentId: grant.id });
}

function applicationGrants(ctx: Context, scope: string): void {
  ctx.require(checks.application, scope, ['entra.appRoleAssignments', 'entra.servicePrincipals']);
  for (const grant of ctx.records('entra.appRoleAssignments', scope)) {
    const principalId = text(grant.data.principalId);
    const parentId = text(grant.data.parentId);
    const resourceId = text(grant.data.resourceId);
    const permissionId = text(grant.data.appRoleId);
    const client = principalId ? ctx.find('entra.servicePrincipals', scope, principalId) : undefined;
    const resource = resourceId ? ctx.find('entra.servicePrincipals', scope, resourceId) : undefined;
    const matches = resource && permissionId ? objects(resource.data.appRoles).filter((permission) => sameId(text(permission.id), permissionId)) : [];
    if (!principalId || !sameId(principalId, parentId) || !client || !resource || !permissionId || matches.length !== 1) {
      ctx.emit(checks.unknown, scope, grant.id, 'unable-to-assess',
        'An app-only grant needs a matching client principal/parent, resource service principal and unique appRoleId exposed by that resource. Unresolved and default all-zero app roles are not classified as powerful API grants.',
        grant.evidence, 'application');
      if (principalId) ctx.incomplete(scope, principalId);
      continue;
    }
    const allowed = strings(matches[0]!.allowedMemberTypes);
    if (allowed.length && !allowed.includes('Application')) {
      ctx.emit(checks.unknown, scope, grant.id, 'unable-to-assess',
        'The resolved app role does not declare Application as an allowed member type. This inconsistency needs validation.', [...grant.evidence, ...resource.evidence], 'application');
      ctx.incomplete(scope, principalId);
      continue;
    }
    classifyGrant(ctx, grant, client, resource, permissionId, 'application', permissionId);
  }
}

function delegatedGrants(ctx: Context, scope: string): void {
  ctx.require(checks.delegated, scope, ['entra.oauth2PermissionGrants', 'entra.servicePrincipals']);
  for (const grant of ctx.records('entra.oauth2PermissionGrants', scope)) {
    const clientId = text(grant.data.clientId);
    const resourceId = text(grant.data.resourceId);
    const client = clientId ? ctx.find('entra.servicePrincipals', scope, clientId) : undefined;
    const resource = resourceId ? ctx.find('entra.servicePrincipals', scope, resourceId) : undefined;
    const claimValues = text(grant.data.scope)?.trim().split(/\s+/).filter(Boolean) ?? [];
    const consentType = text(grant.data.consentType);
    const validConsent = consentType === 'AllPrincipals' || (consentType === 'Principal' && !!text(grant.data.principalId));
    if (!client || !resource || !claimValues.length || !validConsent) {
      ctx.emit(checks.unknown, scope, grant.id, 'unable-to-assess',
        'The delegated grant lacks a unique client/resource mapping, scope claims or valid consent/user context.', grant.evidence, 'delegated');
      if (clientId) ctx.incomplete(scope, clientId);
      continue;
    }
    for (const claim of [...new Set(claimValues)].sort()) {
      const definitions = objects(resource.data.oauth2PermissionScopes).filter((definition) => definition.value === claim);
      const permissionId = definitions.length === 1 ? text(definitions[0]!.id) : undefined;
      if (!permissionId) {
        ctx.emit(checks.unknown, scope, client.id, 'unable-to-assess',
          'A delegated scope claim could not be resolved unambiguously to a permission ID in the resource service principal oauth2PermissionScopes. A familiar permission name is not a risk classification.',
          [...grant.evidence, ...resource.evidence], `${grant.id}/delegated/${claim}`);
        ctx.incomplete(scope, client.id);
        continue;
      }
      classifyGrant(ctx, grant, client, resource, permissionId, 'delegated', permissionId);
    }
  }
}

interface AzureCapabilities { capabilities: string[]; severity: Severity; restrictionsUnknown: boolean }

const controlOperations: [string, string, Severity][] = [
  ['Microsoft.Authorization/roleAssignments/write', 'azure-role-assignment-write', 'critical'],
  ['Microsoft.Authorization/roleDefinitions/write', 'azure-role-definition-write', 'high'],
  ['Microsoft.Compute/virtualMachines/write', 'azure-compute-write', 'high'],
  ['Microsoft.Web/sites/write', 'azure-application-host-write', 'high'],
  ['Microsoft.Storage/storageAccounts/listKeys/action', 'storage-account-key-access', 'high'],
  ['Microsoft.KeyVault/vaults/accessPolicies/write', 'key-vault-access-policy-write', 'high'],
  ['Microsoft.ManagedIdentity/userAssignedIdentities/assign/action', 'managed-identity-attach', 'high'],
  ['Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write', 'managed-identity-federation-write', 'high'],
];
const dataOperations: [string, string, Severity][] = [
  ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read', 'storage-blob-data-read', 'medium'],
  ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write', 'storage-blob-data-write', 'high'],
  ['Microsoft.KeyVault/vaults/secrets/getSecret/action', 'key-vault-secret-read', 'high'],
  ['Microsoft.KeyVault/vaults/secrets/setSecret/action', 'key-vault-secret-write', 'high'],
];

export function azureCapabilities(definition: RecordRef): AzureCapabilities {
  const properties = object(definition.data.properties);
  const permissions = objects(properties?.permissions);
  let restrictionsUnknown = !permissions.length;
  const capabilities = new Set<string>();
  let severity: Severity = 'informational';
  for (const permission of permissions) {
    for (const [allowKey, denyKey, operations] of [
      ['actions', 'notActions', controlOperations], ['dataActions', 'notDataActions', dataOperations],
    ] as const) {
      const allow = strings(permission[allowKey]);
      const deny = strings(permission[denyKey]);
      // Absent dataActions means no data-plane grant; a visible grant with missing exclusions is only potential.
      if (allow.length && !Array.isArray(permission[denyKey])) restrictionsUnknown = true;
      if (allowKey === 'actions' && !Array.isArray(permission[allowKey])) restrictionsUnknown = true;
      if (permission.condition !== undefined && permission.condition !== null) restrictionsUnknown = true;
      for (const [operation, capability, impact] of operations) {
        if (allow.some((pattern) => matchesAction(pattern, operation))
          && !deny.some((pattern) => matchesAction(pattern, operation))) {
          capabilities.add(capability);
          severity = maximumSeverity(severity, impact);
        }
      }
    }
  }
  return { capabilities: [...capabilities].sort(), severity, restrictionsUnknown };
}

export function azurePrincipalTenant(ctx: Context, source: RecordRef, principalId: string): string | undefined {
  const matchingScopes = new Set(['entra.servicePrincipals', 'entra.users', 'entra.groups'].flatMap((dataset) =>
    ctx.records(dataset).filter((record) => sameId(record.id, principalId)).map((record) => record.scope)));
  const subscription = ctx.records('azure.subscriptions', source.scope);
  const tenants = new Set(subscription.map((record) => text(record.data.tenantId) ?? text(object(record.data.properties)?.tenantId)).filter(Boolean));
  if (tenants.size === 1) {
    const tenant = [...tenants][0]!;
    return matchingScopes.size === 0 || matchingScopes.has(tenant) ? tenant : undefined;
  }
  return matchingScopes.size === 1 ? [...matchingScopes][0] : undefined;
}

function azureAssignments(ctx: Context, scope: string): void {
  ctx.require(checks.azure, scope, ['azure.roleAssignments', 'azure.roleDefinitions']);
  for (const assignment of ctx.records('azure.roleAssignments', scope)) {
    const properties = object(assignment.data.properties);
    const principalId = text(properties?.principalId);
    const definitionId = text(properties?.roleDefinitionId);
    const assignmentScope = text(properties?.scope);
    const definitions = definitionId ? ctx.records('azure.roleDefinitions').filter((record) => sameId(record.id, definitionId)) : [];
    const distinctDefinitions = [...new Map(definitions.map((definition) => [canonical(definition.data), definition])).values()];
    const definition = distinctDefinitions.length === 1 ? distinctDefinitions[0] : undefined;
    const tenant = principalId ? azurePrincipalTenant(ctx, assignment, principalId) : undefined;
    if (!principalId || !definition || !properties || !assignmentScope) {
      ctx.emit(checks.azureUnknown, scope, assignment.id, 'unable-to-assess',
        'The assignment does not resolve to an exact, unambiguous role-definition resource ID, principal ID and assignment scope. Role display names are not classified.', assignment.evidence);
      if (principalId) ctx.incomplete(tenant ?? scope, principalId);
      continue;
    }
    const evidence = [...assignment.evidence, ...definition.evidence];
    const principalScope = tenant ?? scope;
    const principal = ctx.principal(principalScope, principalId, assignment.evidence);
    const role = ctx.node('azure-role', definition.scope, definition.id.toLowerCase(), definition.evidence);
    const binding = ctx.node('azure-role-assignment', scope, assignment.id.toLowerCase(), assignment.evidence);
    const target = ctx.node('azure-scope', scope, assignmentScope.toLowerCase(), assignment.evidence,
      { scopeKind: azureScopeKind(assignmentScope) });
    ctx.edge(principal, binding, 'azure-role-assignment', assignment.evidence);
    ctx.edge(binding, role, 'role-definition', evidence);
    ctx.edge(binding, target, 'assignment-scope', assignment.evidence);
    const classified = azureCapabilities(definition);
    const scopeKind = azureScopeKind(assignmentScope);
    const explicitCondition = !!text(properties.condition);
    const restrictionsUnknown = classified.restrictionsUnknown || !has(properties, 'condition') || scopeKind === 'unknown';
    if (!classified.capabilities.length) {
      ctx.emit(checks.azureUnknown, scope, assignment.id, 'unable-to-assess',
        'No operation modeled by the initial capability set remains after per-permission-block exclusions. Other actions may still be significant. This is not a safe-role or effective-access conclusion.',
        evidence);
      ctx.incomplete(principalScope, principalId);
      continue;
    }
    const broad = ['tenant', 'management-group', 'subscription'].includes(scopeKind);
    const severity = explicitCondition || restrictionsUnknown ? 'medium' : classified.severity;
    const restrictionDescription = explicitCondition ? 'An assignment condition is present and has not been evaluated.'
      : restrictionsUnknown ? 'One or more exclusion lists, scope details or condition fields are not visible.'
        : 'Visible exclusions have been subtracted per permission block and no assignment condition is recorded.';
    ctx.emit(checks.azure, scope, assignment.id, 'fail',
      `Potential capabilities: ${classified.capabilities.join(', ')} at ${scopeKind} scope ${assignmentScope}. ${restrictionDescription} `
      + 'Deny assignments, PIM activation, resource-specific authorization and other effective restrictions are not evaluated; this is potential control, not proven access or exploitability.',
      evidence, '', severity, explicitCondition || restrictionsUnknown ? 'low' : 'medium');
    if (broad) ctx.emit(checks.broad, scope, assignment.id, 'fail',
      `A role with modeled control/data capabilities is assigned at ${scopeKind} scope. ${restrictionDescription} Management-group descendants are not invented from subscription names.`,
      evidence, '', severity, 'medium');
    ctx.addPrivilege({ principalId, tenant: principalScope, kind: 'azure', ...classified, severity,
      evidence, conditional: true, broad, scope: assignmentScope, assignmentId: assignment.id });
    if (!tenant) ctx.incomplete(principalScope, principalId);
    for (const resource of ctx.records('azure.resources')) {
      const resourceTenants = new Set(ctx.records('azure.subscriptions', resource.scope)
        .map((subscription) => text(subscription.data.tenantId) ?? text(object(subscription.data.properties)?.tenantId)).filter(Boolean));
      const provenTenantScope = scopeKind !== 'tenant'
        || (tenant !== undefined && resourceTenants.size === 1 && resourceTenants.has(tenant));
      if (provenTenantScope && withinAzureScope(resource.id, assignmentScope) && scopeKind !== 'management-group' && scopeKind !== 'unknown') {
        ctx.edge(binding, ctx.node('azure-resource', resource.scope, resource.id.toLowerCase(), resource.evidence),
          'potential-control-within-scope', [...evidence, ...resource.evidence], 'potential');
      }
    }
    if (tenant) for (const member of groupMembers(ctx, tenant, principalId)) {
      const inheritedEvidence = [...evidence, ...member.evidence];
      ctx.edge(ctx.principal(tenant, member.id, member.evidence), binding,
        'potential-group-azure-role', inheritedEvidence, 'potential');
      ctx.addPrivilege({ principalId: member.id, tenant, kind: 'azure', ...classified, severity,
        evidence: inheritedEvidence, conditional: true, broad, scope: assignmentScope, assignmentId: assignment.id });
    }
  }
}

function azureResources(ctx: Context, scope: string): void {
  for (const resource of ctx.records('azure.resources', scope)) {
    const node = ctx.node('azure-resource', scope, resource.id.toLowerCase(), resource.evidence,
      { resourceType: text(resource.data.type) ?? 'unknown' });
    const identity = object(resource.data.identity);
    const associations: { principalId: string; identityResource?: string }[] = [];
    const systemPrincipal = text(identity?.principalId);
    if (systemPrincipal) associations.push({ principalId: systemPrincipal });
    const properties = object(resource.data.properties);
    if (text(resource.data.type)?.toLowerCase() === 'microsoft.managedidentity/userassignedidentities') {
      const principalId = text(properties?.principalId);
      if (principalId) associations.push({ principalId });
    }
    for (const [identityResource, value] of Object.entries(object(identity?.userAssignedIdentities) ?? {})) {
      const principalId = text(object(value)?.principalId);
      if (principalId) associations.push({ principalId, identityResource });
      else {
        const matches = ctx.records('azure.resources').filter((record) => sameId(record.id, identityResource));
        const resolved = matches.length === 1 ? text(object(matches[0]!.data.properties)?.principalId) : undefined;
        if (resolved) associations.push({ principalId: resolved, identityResource });
      }
      ctx.edge(node, ctx.node('azure-resource', scope, identityResource.toLowerCase(), resource.evidence),
        'associated-user-assigned-identity', resource.evidence);
    }
    for (const association of associations) {
      const tenant = azurePrincipalTenant(ctx, resource, association.principalId);
      const explicitTenant = text(identity?.tenantId);
      if (!tenant || (explicitTenant && !sameId(explicitTenant, tenant))) {
        ctx.emit(checks.identity, scope, resource.id, 'unable-to-assess',
          'A principal ID is observed on the resource, but its tenant/service-principal association cannot be resolved unambiguously.', resource.evidence, association.principalId);
        continue;
      }
      const sp = ctx.find('entra.servicePrincipals', tenant, association.principalId);
      const evidence = [...resource.evidence, ...(sp?.evidence ?? [])];
      ctx.edge(node, ctx.principal(tenant, association.principalId, evidence, 'managedIdentity'),
        'uses-managed-identity', evidence);
      ctx.emit(checks.identity, scope, resource.id, 'informational',
        `An exact principal-ID relationship associates this resource with identity ${association.principalId}. Resource administrators may be able to use its identity; no successful token use or privilege escalation is asserted.`,
        evidence, association.principalId);
    }
  }
}

export function analyzeAccess(ctx: Context): void {
  for (const scope of ctx.scopes('entra.')) {
    applicationGrants(ctx, scope);
    delegatedGrants(ctx, scope);
  }
  for (const scope of ctx.scopes('azure.resources')) azureResources(ctx, scope);
  for (const scope of ctx.scopes('azure.roleAssignments', 'azure.roleDefinitions')) azureAssignments(ctx, scope);
}
