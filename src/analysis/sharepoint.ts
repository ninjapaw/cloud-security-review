import {
  Context, REFERENCES as R, number, object, rule, strings, text, type RecordRef, type Rule,
} from './context.js';

const DATASET = 'm365.sharePointSettings';
const references = [R.sharePointSettings, R.sharePointGet];
const sharingStates = new Set(['disabled', 'externalUserSharingOnly', 'externalUserAndGuestSharing', 'existingExternalUserSharingOnly']);
const ceiling = 'These are tenant-level ceilings/settings, not evidence of effective site/item sharing, publicly shared files, or a successful bypass.';
const checks = {
  inventory: rule('M365.SHAREPOINT.INVENTORY', 'microsoft365', 'informational', 'SharePoint tenant settings evidence',
    'Collect the unique tenant settings object through the documented read-only API; missing fields are not default values.', references, ['verify-explicitly']),
  legacy: rule('M365.SHAREPOINT.LEGACY_AUTH', 'microsoft365', 'high', 'SharePoint legacy-authentication setting',
    'Review legacy-client requirements and plan to disable legacy protocols where appropriate; assess actual authentication and Conditional Access separately.', references, ['verify-explicitly']),
  anonymous: rule('M365.SHAREPOINT.ANONYMOUS_LINKS', 'microsoft365', 'medium', 'SharePoint anonymous-link sharing ceiling',
    'Review the business need for anonymous links and validate site/item sharing and link settings before assessing actual exposure.', references, ['least-privilege', 'assume-breach']),
  invitation: rule('M365.SHAREPOINT.INVITATION_IDENTITY', 'microsoft365', 'medium', 'SharePoint invitation acceptance identity',
    'When external sharing is applicable, review whether accepting users must match invited accounts. This setting does not control anonymous links.', references, ['verify-explicitly']),
  resharing: rule('M365.SHAREPOINT.EXTERNAL_RESHARING', 'microsoft365', 'medium', 'SharePoint external-user resharing',
    'Review whether guests should reshare content they do not own, alongside site/item permissions and external collaboration requirements.', references),
  sync: rule('M365.SHAREPOINT.UNMANAGED_SYNC', 'microsoft365', 'informational', 'SharePoint sync-client restriction review',
    'Review sync restrictions against the organization device policy. This property is not a complete managed-device or Conditional Access assessment.', references, ['verify-explicitly']),
  domains: rule('M365.SHAREPOINT.DOMAIN_RESTRICTIONS', 'microsoft365', 'informational', 'SharePoint external-sharing domain restriction review',
    'Validate configured domain restrictions against approved collaboration needs; no universal allow-list policy is assumed.', references),
  idle: rule('M365.SHAREPOINT.IDLE_SESSION', 'microsoft365', 'informational', 'SharePoint idle-session sign-out review',
    'Review idle-session sign-out and warning intervals against user/device requirements. No universal inactivity timeout is imposed.', [R.sharePointSettings, R.sharePointIdle], ['verify-explicitly']),
};

function booleanSetting(ctx: Context, settings: RecordRef, check: Rule, field: string, riskValue: boolean,
  explanation: string, extraFields: string[] = []): void {
  const value = settings.data[field];
  const evidence = [field, ...extraFields].flatMap((name) => ctx.evidenceFor(settings, name));
  if (typeof value !== 'boolean') {
    ctx.emit(check, settings.scope, settings.id, 'unable-to-assess',
      `${field} is missing, null or not boolean; no configured/default value is inferred. ${ceiling}`, evidence);
    return;
  }
  const risky = value === riskValue;
  ctx.emit(check, settings.scope, settings.id, risky ? 'fail' : ctx.complete(DATASET, settings.scope) ? 'pass' : 'informational',
    `${field} is explicitly ${value}. ${explanation} ${ceiling}`, evidence, '', risky ? check.severity : 'informational');
}

function sharingRelevant(ctx: Context, settings: RecordRef, check: Rule, state: string | undefined): boolean {
  if (!state || !sharingStates.has(state)) {
    ctx.emit(check, settings.scope, settings.id, 'unable-to-assess',
      'The external-sharing capability is missing, null or unrecognized; applicability of this sharing-dependent control cannot be established.',
      ctx.evidenceFor(settings, 'sharingCapability'));
    return false;
  }
  if (state === 'disabled') {
    ctx.emit(check, settings.scope, settings.id, 'informational',
      `External sharing is explicitly disabled at the tenant ceiling, so this sharing-dependent control is not flagged as a current weakness. Its own configuration is not inferred. ${ceiling}`,
      ctx.evidenceFor(settings, 'sharingCapability'), '', 'informational');
    return false;
  }
  return true;
}

function domainRestrictions(ctx: Context, settings: RecordRef, sharing: string | undefined): void {
  if (!sharingRelevant(ctx, settings, checks.domains, sharing)) return;
  const mode = text(settings.data.sharingDomainRestrictionMode);
  const evidence = [...ctx.evidenceFor(settings, 'sharingCapability'), ...ctx.evidenceFor(settings, 'sharingDomainRestrictionMode')];
  if (mode === 'none') {
    ctx.emit(checks.domains, settings.scope, settings.id, 'informational',
      `This setting applies no external-sharing domain restriction. Review approved collaboration boundaries; a domain allow-list is not assumed mandatory. ${ceiling}`, evidence);
    return;
  }
  if (mode !== 'allowList' && mode !== 'blockList') {
    ctx.emit(checks.domains, settings.scope, settings.id, 'unable-to-assess',
      'The domain-restriction mode is missing, null or unrecognized. No allow/block behavior is inferred.', evidence);
    return;
  }
  const field = mode === 'allowList' ? 'sharingAllowedDomainList' : 'sharingBlockedDomainList';
  const values = settings.data[field];
  const domains = strings(values);
  if (!Array.isArray(values) || domains.length !== values.length || domains.some((domain) => !domain.trim())) {
    ctx.emit(checks.domains, settings.scope, settings.id, 'unable-to-assess',
      `${mode} is recorded but its active domain list is missing or malformed. An unknown list is not an empty list or evidence of restricted sharing.`,
      [...evidence, ...ctx.evidenceFor(settings, field)]);
    return;
  }
  ctx.emit(checks.domains, settings.scope, settings.id, 'informational',
    `${mode} is configured with ${new Set(domains.map((domain) => domain.toLowerCase())).size} distinct domain entries. `
    + `Review the list and its applicability, including empty-list behavior; configuration presence is not a protection pass. ${ceiling}`,
    [...evidence, ...ctx.evidenceFor(settings, field)]);
}

function idleSessions(ctx: Context, settings: RecordRef): void {
  const idle = object(settings.data.idleSessionSignOut);
  const evidence = ctx.evidenceFor(settings, 'idleSessionSignOut');
  if (!idle || typeof idle.isEnabled !== 'boolean') {
    ctx.emit(checks.idle, settings.scope, settings.id, 'unable-to-assess',
      'The idle-session policy or explicit enabled state is missing or malformed; no timeout or default is inferred.', evidence);
    return;
  }
  if (idle.isEnabled === false) {
    ctx.emit(checks.idle, settings.scope, settings.id, 'informational',
      'This SharePoint idle-session sign-out policy is explicitly disabled. Review the need for this control and other session protections; no organization-wide timeout requirement is invented.', evidence);
    return;
  }
  const signOut = number(idle.signOutAfterInSeconds);
  const warning = number(idle.warnAfterInSeconds);
  if (signOut === undefined || warning === undefined || !Number.isSafeInteger(signOut) || !Number.isSafeInteger(warning)
    || signOut <= 0 || warning < 0 || warning >= signOut) {
    ctx.emit(checks.idle, settings.scope, settings.id, 'unable-to-assess',
      'Idle sign-out is enabled, but a valid positive sign-out interval and a nonnegative, earlier warning interval are not both visible. No timing effectiveness is assumed.', evidence);
    return;
  }
  ctx.emit(checks.idle, settings.scope, settings.id, 'informational',
    `The tenant records idle sign-out after ${signOut} seconds and a warning after ${warning} seconds. These are configured intervals, not evidence of enforcement for every client/device or compliance with an invented timeout policy.`, evidence);
}

export function analyzeSharePoint(ctx: Context): void {
  for (const scope of ctx.scopes(DATASET)) {
    const complete = ctx.require(checks.inventory, scope, [DATASET]);
    const records = ctx.records(DATASET, scope);
    const settings = records.length === 1 && records[0]!.id === 'sharepoint-settings' ? records[0] : undefined;
    if (!settings) {
      if (complete || records.length) ctx.emit(checks.inventory, scope, scope, 'unable-to-assess',
        'The unique sharepoint-settings singleton is missing, ambiguous or has an unexpected identifier; absent data is not a secure configuration.',
        [...ctx.inventoryEvidence(DATASET, scope), ...records.flatMap((record) => record.evidence)], 'singleton');
      continue;
    }
    booleanSetting(ctx, settings, checks.legacy, 'isLegacyAuthProtocolsEnabled', true,
      'Permitting legacy protocols is a potential authentication weakness; it does not prove a client can authenticate or bypass another control.');
    const sharing = text(settings.data.sharingCapability);
    const sharingEvidence = ctx.evidenceFor(settings, 'sharingCapability');
    if (!sharing || !sharingStates.has(sharing)) ctx.emit(checks.anonymous, scope, settings.id, 'unable-to-assess',
      'sharingCapability is missing, null or unrecognized, including unknownFutureValue. Anonymous-link permission cannot be established.', sharingEvidence);
    else {
      const anonymous = sharing === 'externalUserAndGuestSharing';
      ctx.emit(checks.anonymous, scope, settings.id, anonymous ? 'fail' : complete ? 'pass' : 'informational',
        `The tenant reports sharingCapability=${sharing}. ${anonymous
          ? 'This ceiling permits links that do not require sign-in, creating potential exposure; no publicly shared content is observed.'
          : 'This ceiling does not permit anonymous external links; this is a limited configuration observation only.'} ${ceiling}`,
        sharingEvidence, '', anonymous ? 'medium' : 'informational');
    }
    if (sharingRelevant(ctx, settings, checks.invitation, sharing)) booleanSetting(ctx, settings, checks.invitation,
      'isRequireAcceptingUserToMatchInvitedUserEnabled', false,
      'This controls account matching for sharing-invitation acceptance, not anonymous links or every site/item authorization.', ['sharingCapability']);
    if (sharingRelevant(ctx, settings, checks.resharing, sharing)) booleanSetting(ctx, settings, checks.resharing,
      'isResharingByExternalUsersEnabled', true,
      'This permits or restricts guests resharing content they do not own; actual sharing events and item permissions are not evaluated.', ['sharingCapability']);
    const sync = settings.data.isUnmanagedSyncAppForTenantRestricted;
    ctx.emit(checks.sync, scope, settings.id, typeof sync === 'boolean' ? 'informational' : 'unable-to-assess',
      typeof sync === 'boolean'
        ? `Sync is ${sync ? 'restricted by this setting to PCs joined to specific domains' : 'not restricted by this specific domain-joined-PC setting'}. Allowed domains, device compliance and other access policies require review; no universal restriction requirement is assumed.`
        : 'The sync restriction state is missing, null or not boolean; no client/device-control state is inferred.',
      ctx.evidenceFor(settings, 'isUnmanagedSyncAppForTenantRestricted'));
    domainRestrictions(ctx, settings, sharing);
    idleSessions(ctx, settings);
  }
}
