import type { PermissionRiskRule, RiskPolicy, Severity } from './model.js';

// Resource ID: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps
export const MICROSOFT_GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';
const permissionReference = 'https://learn.microsoft.com/en-us/graph/permissions-reference';

// Identifiers and application/delegated semantics verified against Microsoft's reference.
const permissions: [string, string, string, Severity, string[], string][] = [
  ['rolemanagementreadwritedirectory', '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8', 'd01b97e9-cbc0-49fe-810a-750afd5527a3', 'critical',
    ['directory-role-management'], 'Can manage directory RBAC settings and directory role membership.'],
  ['approleassignmentreadwriteall', '06b708a9-e830-4db3-a914-8e69da51d44f', '84bccea3-f856-4a8a-967b-dbe0a3d53a64', 'critical',
    ['application-permission-grants'], 'Can manage application permission grants to APIs, including Microsoft Graph.'],
  ['applicationreadwriteall', '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9', 'bdfbf15f-ee85-4955-8675-146e8e5296b5', 'high',
    ['application-control'], 'Can create, update and delete applications and service principals; this is not by itself permission to grant Microsoft Graph application permissions.'],
  ['directoryreadwriteall', '19dbc75e-c2e2-444c-a770-ec69d8559fc7', 'c5366453-9fb0-48a5-a156-24f0c49a4b84', 'high',
    ['directory-data-write'], 'Can modify directory data such as users and groups; this does not imply all directory administrative permissions.'],
  ['userreadwriteall', '741f803b-c850-494e-b5df-cde7c675a1ca', '204e0828-b5ca-4ad8-b9f3-f32a958e7cc4', 'high',
    ['user-profile-write'], 'Can update user profile properties within the documented permission boundaries; not a blanket authentication-method administration grant.'],
  ['groupreadwriteall', '62a82d76-70ea-41e2-9197-370581804d09', '4e46008b-f24c-477d-8fff-7bb4ec7aafe0', 'high',
    ['group-management'], 'Can create and modify groups and memberships; role-assignable groups have additional authorization requirements.'],
  ['devicemanagementconfigurationreadwriteall', '9241abd9-d0e6-425a-bd4f-47ba86e767a4', '0883f392-0a7a-443d-8c76-16a6d39c7b63', 'high',
    ['device-policy-write'], 'Can modify Intune device configuration and compliance policies and their assignments.'],
  ['policyreadwriteauthenticationmethod', '29c18626-4985-4dcd-85c0-193eef327366', '7e823077-d88e-468f-a337-e18f1f0e6c7c', 'high',
    ['authentication-policy-write'], 'Can modify tenant authentication method policies.'],
  ['policyreadwriteconditionalaccess', '01c0a623-fc9b-48e9-b794-0756f8e8f067', 'ad902697-1014-4ef5-81ef-2b4301988e8c', 'high',
    ['conditional-access-write'], 'Can modify Conditional Access policies.'],
  ['mailread', '810c84a8-4a9e-49e6-bf7d-12d183f40d01', '570282fd-fa5c-430d-a7fd-fc8dc98a9dca', 'high',
    ['sensitive-mail-read'], 'Application access can read mail across mailboxes, subject to service-side restrictions; delegated access reads the signed-in user mailbox.'],
  ['filesreadall', '01d4889c-1287-42c6-ac1f-5d1e02578ef6', 'df85f4d6-205c-4ac5-a5ea-6bf408dba283', 'high',
    ['sensitive-files-read'], 'Application access can read files across site collections; delegated access is limited to files accessible to the signed-in user.'],
  ['sitesreadall', '332a536c-c7ef-4017-ab91-336970924f0d', '205e70e5-aba6-4c52-a976-6d2d46c48043', 'high',
    ['sensitive-sites-read'], 'Can read site collection documents and list items; delegated access also depends on the signed-in user.'],
];

const permissionRules: PermissionRiskRule[] = permissions.flatMap(
  ([anchor, application, delegated, severity, capabilities, rationale]) =>
    (['application', 'delegated'] as const).map((permissionType) => ({
      resourceAppId: MICROSOFT_GRAPH_APP_ID,
      permissionId: permissionType === 'application' ? application : delegated,
      permissionType,
      severity,
      capabilities: [...capabilities],
      rationale: rationale + (permissionType === 'delegated'
        ? ' Delegated consent is not app-only access: a signed-in user and applicable user privileges are also required.'
        : ' This classification concerns app-only permission capability, not proof that an operation succeeds.'),
      reference: `${permissionReference}#${anchor}`,
    })),
);

export const DEFAULT_POLICY: RiskPolicy = {
  expiringWithinDays: 30,
  maxCredentialLifetimeDays: 180,
  staleCredentialDays: 90,
  maxOwners: 3,
  dormantUserDays: 90,
  permissionRules,
  weights: {
    directoryPrivilege: 25,
    apiPrivilege: 20,
    azurePrivilege: 20,
    broadScope: 10,
    persistentCredential: 8,
    externalOwner: 10,
    missingOwner: 6,
    credentialHygiene: 8,
    privilegeCombination: 15,
    codeToCloud: 15,
  },
};
