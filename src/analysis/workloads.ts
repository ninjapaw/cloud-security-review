import type { EvidenceRef, RiskPolicy } from '../model.js';
import {
  Context, DAY, REFERENCES as R, canonical, date, object, objects, policyNumber, rule, sameId,
  severityRank, text, uniqueEvidence, type RecordRef,
} from './context.js';

const checks = {
  dates: rule('WORKLOAD.CREDENTIAL.DATES', 'workload-identities', 'informational', 'Credential metadata needs validation',
    'Collect key IDs and valid start/end metadata without retrieving credential values. Confirm missing or contradictory dates manually.', [R.credentials, R.credentialDates]),
  expired: rule('WORKLOAD.CREDENTIAL.EXPIRED', 'workload-identities', 'medium', 'Expired credential metadata remains registered',
    'Confirm dependencies and remove expired credential metadata in a separate approved remediation process.', [R.credentials, R.credentialDates]),
  expiring: rule('WORKLOAD.CREDENTIAL.EXPIRING', 'workload-identities', 'medium', 'Active credential is nearing expiration',
    'Review expiry with the workload owner and plan a controlled rotation or credentialless migration; do not retrieve the value.', R.credentials),
  lifetime: rule('WORKLOAD.CREDENTIAL.LIFETIME', 'workload-identities', 'medium', 'Credential validity interval exceeds policy',
    'Use a shorter validity interval or a supported managed identity/federation design after reviewing workload requirements.', R.credentials),
  old: rule('WORKLOAD.CREDENTIAL.OLD', 'workload-identities', 'low', 'Old active credential needs review',
    'Confirm credential lifecycle and rotation practices. A validity start date is not necessarily the creation or last-use date.', [R.credentials, R.credentialDates]),
  multiple: rule('WORKLOAD.CREDENTIAL.MULTIPLE_ACTIVE', 'workload-identities', 'low', 'Multiple active credentials observed',
    'Validate whether overlapping credentials are intentional for rotation and retire unnecessary persistent authentication paths.', R.credentials),
  secret: rule('WORKLOAD.CREDENTIAL.CLIENT_SECRET', 'workload-identities', 'low', 'Client-secret migration opportunity',
    'Consider managed identity or workload identity federation where supported. Federation does not disable an existing secret.', [R.credentials, R.federation]),
  owners: rule('WORKLOAD.OWNERSHIP.MISSING', 'workload-identities', 'medium', 'No owners in a complete ownership inventory',
    'Validate accountability and assign appropriate owners manually if needed. No listed owners does not mean no administrator can manage the identity.', R.owners),
  managedAccountability: rule('WORKLOAD.OWNERSHIP.RESOURCE_ACCOUNTABILITY', 'workload-identities', 'informational', 'Managed-identity resource accountability requires review',
    'Review the responsible team and effective resource-level RBAC for the managed identity and its associated resources. Do not assign application-owner risk solely because directory service-principal owners are absent.', [R.identities, R.rbac]),
  ownerCount: rule('WORKLOAD.OWNERSHIP.EXCESSIVE', 'workload-identities', 'low', 'Owner count exceeds assessment policy',
    'Review owner purpose and retain the least set needed for accountability and operation; ownership is a potential control relationship.', R.owners),
  external: rule('WORKLOAD.OWNERSHIP.EXTERNAL', 'workload-identities', 'medium', 'External or guest owner relationship',
    'Validate the external owner, home organization and business need, and review controls for the owned workload.', [R.owners, R.applications]),
  ownerPrivilege: rule('WORKLOAD.OWNERSHIP.PRIVILEGED', 'workload-identities', 'high', 'Owner is linked to a privileged workload',
    'Review owner authentication and application/service-principal management capabilities. Validate the exact credential and consent controls before claiming effective control.', [R.owners, R.permissions, R.roles, R.rbac]),
  ownerCombination: rule('WORKLOAD.OWNERSHIP.COMBINATION', 'workload-identities', 'high', 'Privileged identity also owns a privileged workload',
    'Review separation of duties and owner/PIM controls across both privilege relationships.', [R.owners, R.roles]),
  combined: rule('WORKLOAD.PRIVILEGE.COMBINATION', 'workload-identities', 'high', 'High-impact privilege combination',
    'Prioritize a capability-based least-privilege review across the matched directory, API and Azure relationships. Validate restrictions and runtime authorization.', [R.permissions, R.roles, R.rbac]),
  audience: rule('WORKLOAD.APPLICATION.AUDIENCE', 'workload-identities', 'informational', 'Application accepts identities outside its home tenant',
    'Validate supported account types, consent restrictions and tenant validation against the application business requirements.', R.applications),
};

export function linkedServicePrincipals(ctx: Context, application: RecordRef): RecordRef[] {
  const appId = text(application.data.appId);
  if (!appId) return [];
  const apps = ctx.records('entra.applications', application.scope).filter((entry) => sameId(text(entry.data.appId), appId));
  if (apps.length !== 1) return [];
  return ctx.records('entra.servicePrincipals', application.scope).filter((entry) => sameId(text(entry.data.appId), appId));
}

function factorTargets(ctx: Context, target: RecordRef, kind: 'application' | 'servicePrincipal'): RecordRef[] {
  return kind === 'application' ? [target, ...linkedServicePrincipals(ctx, target)] : [target];
}

function factor(ctx: Context, target: RecordRef, kind: 'application' | 'servicePrincipal',
  name: keyof RiskPolicy['weights'], explanation: string, evidence: EvidenceRef[]): void {
  for (const identity of factorTargets(ctx, target, kind)) {
    ctx.factor(identity.scope, identity.id, name, explanation, [...evidence, ...identity.evidence]);
  }
}

function credentials(ctx: Context, scope: string): void {
  for (const [dataset, kind] of [['entra.applications', 'application'], ['entra.servicePrincipals', 'servicePrincipal']] as const) {
    if (dataset === 'entra.applications') ctx.require(checks.dates, scope, [dataset]);
    for (const target of ctx.records(dataset, scope)) {
      const active = new Map<string, EvidenceRef[]>();
      let secretActive = false;
      const entity = kind === 'application'
        ? ctx.node('application', scope, target.id.toLowerCase(), target.evidence)
        : ctx.principal(scope, target.id, target.evidence, 'servicePrincipal');
      for (const [property, credentialType] of [['passwordCredentials', 'secret'], ['keyCredentials', 'certificate']] as const) {
        if (!Array.isArray(target.data[property])) {
          if (kind === 'servicePrincipal' && target.data.servicePrincipalType === 'ManagedIdentity') continue;
          ctx.emit(checks.dates, scope, target.id, 'unable-to-assess',
            `${property} metadata was not returned. Missing metadata is not an empty credential inventory.`, target.evidence, property);
          for (const identity of factorTargets(ctx, target, kind)) ctx.incomplete(scope, identity.id);
          continue;
        }
        const unique = new Map(objects(target.data[property]).map((credential) => [canonical(credential), credential]));
        const keyCounts = new Map<string, number>();
        for (const credential of unique.values()) {
          const keyId = text(credential.keyId)?.toLowerCase();
          if (keyId) keyCounts.set(keyId, (keyCounts.get(keyId) ?? 0) + 1);
        }
        for (const credential of unique.values()) {
          const keyId = text(credential.keyId);
          const start = date(credential.startDateTime);
          const end = date(credential.endDateTime);
          const evidence = ctx.evidenceFor(target, keyId ? `${property}.${keyId}` : property);
          if (!keyId) {
            ctx.emit(checks.dates, scope, target.id, 'unable-to-assess',
              'A credential has no stable keyId; it cannot be safely deduplicated or dated for lifecycle scoring.', evidence, property);
            for (const identity of factorTargets(ctx, target, kind)) ctx.incomplete(scope, identity.id);
            continue;
          }
          const duplicateKey = (keyCounts.get(keyId.toLowerCase()) ?? 0) > 1;
          const credentialId = `${property}/${keyId}`;
          const credentialNode = ctx.node('credential', scope, `${target.id}/${credentialId}`, evidence,
            { credentialType });
          ctx.edge(entity, credentialNode, 'has-credential-metadata', evidence);
          if (duplicateKey || start === undefined || end === undefined || end <= start || !Number.isFinite(ctx.now)) {
            ctx.emit(checks.dates, scope, target.id, 'unable-to-assess',
              'The credential has missing, invalid, conflicting or reversed validity metadata. Creation time, activation, age and expiration are not fabricated.', evidence, credentialId);
            for (const identity of factorTargets(ctx, target, kind)) ctx.incomplete(scope, identity.id);
            continue;
          }
          const isActive = start <= ctx.now && end > ctx.now;
          if (isActive) {
            active.set(credentialId, evidence);
            if (credentialType === 'secret') secretActive = true;
          }
          const lifecycle: { check: typeof checks.expired; applies: boolean; description: string }[] = [
            { check: checks.expired, applies: end <= ctx.now,
              description: 'The registered credential validity end is in the past. This expired credential is not counted as an active authentication path.' },
            { check: checks.expiring, applies: isActive && end - ctx.now <= policyNumber(ctx.policy.expiringWithinDays, 30) * DAY,
              description: `The active credential expires within ${policyNumber(ctx.policy.expiringWithinDays, 30)} days.` },
            { check: checks.lifetime, applies: end - start > policyNumber(ctx.policy.maxCredentialLifetimeDays, 180) * DAY,
              description: `The configured validity interval exceeds ${policyNumber(ctx.policy.maxCredentialLifetimeDays, 180)} days. ${start > ctx.now ? 'Activation is in the future and it is not counted as currently active.' : ''}` },
            { check: checks.old, applies: isActive && ctx.now - start > policyNumber(ctx.policy.staleCredentialDays, 90) * DAY,
              description: `The active credential validity start is older than ${policyNumber(ctx.policy.staleCredentialDays, 90)} days. This is validity age, not measured credential creation or last use.` },
          ];
          for (const item of lifecycle.filter((item) => item.applies)) {
            ctx.emit(item.check, scope, target.id, 'fail', item.description, evidence, credentialId);
            factor(ctx, target, kind, 'credentialHygiene', item.description, evidence);
          }
        }
      }
      if (active.size) factor(ctx, target, kind, 'persistentCredential',
        'At least one dated persistent credential is currently within its validity interval; actual use has not been measured.',
        [...active.values()].flat());
      if (active.size > 1) ctx.emit(checks.multiple, scope, target.id, 'fail',
        `At least ${active.size} distinct credential metadata entries are currently valid. Future and expired entries are excluded; overlapping rotation can be legitimate.`,
        [...active.values()].flat());
      if (secretActive) ctx.emit(checks.secret, scope, target.id, 'informational',
        'At least one client secret is currently within its validity interval. Consider a supported credentialless design; existing federation does not remove this persistent authentication path.',
        [...active.values()].flat());
    }
  }
}

function externalOwner(ctx: Context, scope: string, owner: RecordRef): boolean | undefined {
  const user = ctx.find('entra.users', scope, owner.id);
  const userType = text(owner.data.userType) ?? text(user?.data.userType);
  if (userType?.toLowerCase() === 'guest') return true;
  if (userType?.toLowerCase() === 'member') return false;
  const sp = ctx.find('entra.servicePrincipals', scope, owner.id);
  const homeTenant = text(owner.data.appOwnerOrganizationId) ?? text(sp?.data.appOwnerOrganizationId);
  if (homeTenant) return !sameId(scope, homeTenant);
  return undefined;
}

function ownership(ctx: Context, scope: string): void {
  for (const [dataset, ownerDataset, kind] of [
    ['entra.applications', 'entra.applicationOwners', 'application'],
    ['entra.servicePrincipals', 'entra.servicePrincipalOwners', 'servicePrincipal'],
  ] as const) {
    const complete = ctx.require(checks.owners, scope, [dataset, ownerDataset]);
    const allOwners = ctx.records(ownerDataset, scope);
    const validParents = allOwners.every((owner) => !!text(owner.data.parentId));
    for (const target of ctx.records(dataset, scope)) {
      const owners = [...new Map(allOwners.filter((owner) => sameId(text(owner.data.parentId), target.id))
        .map((owner) => [owner.id.toLowerCase(), owner])).values()];
      const targetNode = kind === 'application' ? ctx.node('application', scope, target.id.toLowerCase(), target.evidence)
        : ctx.principal(scope, target.id, target.evidence);
      const managedIdentity = kind === 'servicePrincipal' && target.data.servicePrincipalType === 'ManagedIdentity';
      if (managedIdentity) {
        const associations = [...ctx.edges.values()].filter((edge) =>
          edge.relationship === 'uses-managed-identity' && edge.to === targetNode);
        ctx.emit(checks.managedAccountability, scope, target.id, 'unable-to-assess',
          'This service principal is explicitly a ManagedIdentity with resource-managed lifecycle and administration. An absent directory-owner list is not an ownerless-application risk. '
          + (associations.length
            ? `${associations.length} resource association(s) are evidenced by exact principal IDs. `
            : 'No resource association has been resolved from the supplied evidence. ')
          + 'Responsible-team accountability and effective resource-level administration still require review.',
          [...target.evidence, ...associations.flatMap((association) => association.evidence)]);
        ctx.incomplete(scope, target.id);
      }
      if (owners.length === 0) {
        if (managedIdentity) continue;
        if (complete && validParents) {
          const evidence = [...target.evidence, ...ctx.inventoryEvidence(ownerDataset, scope)];
          ctx.emit(checks.owners, scope, target.id, 'fail',
            `The complete ${kind} ownership inventory contains no owners for this object. This concerns recorded accountability, not absence of administrative control.`,
            evidence, kind);
          factor(ctx, target, kind, 'missingOwner', 'No owner is recorded in a complete ownership inventory.', evidence);
        } else {
          ctx.emit(checks.owners, scope, target.id, 'unable-to-assess',
            'An empty observed owner set cannot establish ownerlessness because the object/ownership inventory is incomplete, ambiguous or has unresolved parents.',
            [...target.evidence, ...ctx.inventoryEvidence(ownerDataset, scope)], kind);
          for (const identity of factorTargets(ctx, target, kind)) ctx.incomplete(scope, identity.id);
        }
      } else {
        if (owners.length > policyNumber(ctx.policy.maxOwners, 3)) ctx.emit(checks.ownerCount, scope, target.id, 'fail',
          `At least ${owners.length} distinct owners exceed the configured threshold ${policyNumber(ctx.policy.maxOwners, 3)}. This is a review threshold, not proof of misuse.`,
          [...target.evidence, ...owners.flatMap((owner) => owner.evidence)], kind);
        for (const owner of owners) {
          const knownUser = ctx.find('entra.users', scope, owner.id);
          const knownPrincipal = ctx.find('entra.servicePrincipals', scope, owner.id);
          const evidence = [...owner.evidence, ...target.evidence, ...(knownUser?.evidence ?? []), ...(knownPrincipal?.evidence ?? [])];
          const external = externalOwner(ctx, scope, owner);
          ctx.edge(ctx.principal(scope, owner.id, owner.evidence), targetNode, 'potential-owner-control', evidence, 'potential');
          ctx.owners.push({ tenant: scope, ownerId: owner.id, ownedId: target.id, ownedType: kind, external: external === true, evidence });
          if (external === true) {
            ctx.emit(checks.external, scope, target.id, 'fail',
              'An owner is explicitly a guest or is a service principal with a different application home organization. Ownership is a potential management/control relationship, not proven impersonation or exploitability.',
              evidence, `${kind}/${owner.id}`);
            factor(ctx, target, kind, 'externalOwner', 'A documented guest/external owner relationship exists.', evidence);
          } else if (external === undefined) {
            ctx.emit(checks.external, scope, target.id, 'unable-to-assess',
              'Owner type or home-organization evidence is insufficient to determine whether this owner is internal. Names and user principal-name strings are not used as externality heuristics.',
              evidence, `${kind}/${owner.id}`);
            for (const identity of factorTargets(ctx, target, kind)) ctx.incomplete(scope, identity.id);
          }
        }
      }
      if (kind === 'application' && ['AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount', 'PersonalMicrosoftAccount'].includes(text(target.data.signInAudience) ?? '')) {
        ctx.emit(checks.audience, scope, target.id, 'informational',
          `The application explicitly declares signInAudience ${String(target.data.signInAudience)}. This is an audience/consent review item, not proof that an external actor has access.`, target.evidence);
      }
    }
  }
}

export function analyzeWorkloads(ctx: Context): void {
  for (const scope of ctx.scopes('entra.')) {
    credentials(ctx, scope);
    ownership(ctx, scope);
  }
}

export function analyzePrivilegeCombinations(ctx: Context): void {
  const principals = new Map(ctx.privileges.filter((privilege) => !privilege.eligible && !privilege.delegated)
    .map((privilege) => [canonical([privilege.tenant, privilege.principalId.toLowerCase()]), privilege]));
  for (const principal of principals.values()) {
    const privileges = ctx.privileges.filter((privilege) => privilege.tenant === principal.tenant
      && sameId(privilege.principalId, principal.principalId) && !privilege.eligible && !privilege.delegated);
    const impactful = privileges.filter((privilege) => severityRank[privilege.severity] >= 2);
    const kinds = new Set(impactful.map((privilege) => privilege.kind));
    const capabilities = new Set(impactful.flatMap((privilege) => privilege.capabilities));
    const consentCombination = capabilities.has('application-control') && capabilities.has('application-permission-grants');
    if (kinds.size < 2 && !consentCombination) continue;
    const evidence = uniqueEvidence(impactful.flatMap((privilege) => privilege.evidence));
    const explanation = consentCombination
      ? 'Application-management and application-permission-grant capabilities are combined on the same stable identity.'
      : `The same stable identity has modeled capabilities in ${[...kinds].sort().join(', ')} authorization planes.`;
    ctx.emit(checks.combined, principal.tenant, principal.principalId, 'fail',
      `${explanation} This can increase potential impact, but assignments, exclusions, ownership and runtime authorization must still be validated. No exploitable attack path is asserted.`,
      evidence, '', consentCombination ? 'critical' : 'high', 'medium');
    ctx.factor(principal.tenant, principal.principalId, 'privilegeCombination', explanation, evidence);
  }
  for (const owner of ctx.owners) {
    const app = owner.ownedType === 'application' ? ctx.find('entra.applications', owner.tenant, owner.ownedId) : undefined;
    const targets = owner.ownedType === 'application' && app ? linkedServicePrincipals(ctx, app).map((sp) => sp.id) : [owner.ownedId];
    const privileges = ctx.privileges.filter((privilege) => privilege.tenant === owner.tenant
      && targets.some((id) => sameId(id, privilege.principalId)) && !privilege.eligible && !privilege.delegated
      && severityRank[privilege.severity] >= 2);
    if (!privileges.length) continue;
    const links = app ? linkedServicePrincipals(ctx, app).flatMap((sp) => [...sp.evidence, ...app.evidence]) : [];
    const evidence = [...owner.evidence, ...links, ...privileges.flatMap((privilege) => privilege.evidence)];
    ctx.emit(checks.ownerPrivilege, owner.tenant, owner.ownerId, 'fail',
      'The owner relationship and workload privilege resolve through exact object/application IDs. The owner may have management influence over this workload; ownership alone is not proof of credential use, impersonation or exploitable control.',
      evidence, `${owner.ownedType}/${owner.ownedId}`, 'high', 'medium');
    ctx.factor(owner.tenant, owner.ownerId, 'privilegeCombination',
      'Ownership creates potential management influence over a workload with modeled privilege.', evidence);
    ctx.incomplete(owner.tenant, owner.ownerId);
    if (ctx.privileges.some((privilege) => privilege.tenant === owner.tenant && sameId(privilege.principalId, owner.ownerId)
      && privilege.kind === 'directory' && !privilege.eligible && !privilege.delegated)) {
      ctx.emit(checks.ownerCombination, owner.tenant, owner.ownerId, 'fail',
        'An observed directory-privileged identity also owns a workload with modeled privileges. Review separation of duties; this remains a potential-control combination, not an exploitable path.',
        [...evidence, ...ctx.privileges.filter((privilege) => privilege.tenant === owner.tenant && sameId(privilege.principalId, owner.ownerId))
          .flatMap((privilege) => privilege.evidence)], `${owner.ownedType}/${owner.ownedId}`, 'high', 'medium');
    }
  }
  for (const app of ctx.records('entra.applications')) {
    for (const sp of linkedServicePrincipals(ctx, app)) {
      for (const privilege of ctx.privileges.filter((privilege) => privilege.tenant === sp.scope
        && sameId(privilege.principalId, sp.id) && !privilege.eligible && severityRank[privilege.severity] >= 2)) {
        const name = privilege.kind === 'api' ? 'apiPrivilege' : privilege.kind === 'directory' ? 'directoryPrivilege' : 'azurePrivilege';
        ctx.factor(app.scope, app.id, name,
          `Associated service principal ${sp.id} has ${privilege.delegated ? 'delegated, user-dependent ' : ''}${privilege.kind} capabilities.`,
          [...app.evidence, ...sp.evidence, ...privilege.evidence]);
        if (privilege.conditional) ctx.incomplete(app.scope, app.id);
      }
    }
  }
  const inputs = ['entra.applications', 'entra.servicePrincipals', 'entra.applicationOwners',
    'entra.servicePrincipalOwners', 'entra.directoryRoleAssignments', 'entra.directoryRoleDefinitions',
    'entra.directoryRoleEligibility', 'entra.directoryRoleAssignmentScheduleInstances', 'entra.appRoleAssignments', 'entra.oauth2PermissionGrants',
    'entra.federatedCredentials', 'entra.groups', 'entra.groupMemberships'];
  for (const dataset of ['entra.applications', 'entra.servicePrincipals']) {
    for (const identity of ctx.records(dataset)) {
      const azureScopes = ctx.scopes('azure.roleAssignments', 'azure.roleDefinitions');
      const federationScopes = ctx.scopes('azure.federatedCredentials', 'azure.resources');
      const incomplete = inputs.some((input) => !ctx.complete(input, identity.scope))
        || !azureScopes.length || azureScopes.some((scope) =>
          !ctx.complete('azure.roleAssignments', scope) || !ctx.complete('azure.roleDefinitions', scope))
        || !federationScopes.length || federationScopes.some((scope) => !ctx.complete('azure.federatedCredentials', scope));
      if (incomplete) ctx.incomplete(identity.scope, identity.id);
    }
  }
}
