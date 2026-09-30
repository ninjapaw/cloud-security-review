import type { JsonObject, Severity } from '../model.js';
import {
  Context, DAY, REFERENCES as R, date, identifier, number, object, objects, rule, sameId, strings, text,
  type RecordRef, type Rule,
} from './context.js';

const checks = {
  score: rule('M365.SECURESCORE.CONTROL', 'microsoft365', 'medium', 'Microsoft Secure Score improvement opportunity',
    'Validate the exact improvement action, applicability and current service configuration; score deltas are not proof of comprehensive product policy coverage.', R.secureScore),
  m365Coverage: rule('M365.POLICY.COVERAGE', 'microsoft365', 'informational', 'Microsoft 365 product policies need additional evidence',
    'Review Exchange, Teams, and SharePoint site/item and effective-access policies with product-specific evidence. License inventory, Secure Score and selected SharePoint tenant settings are not full coverage.', [R.secureScore, R.sharePointSettings], ['verify-explicitly']),
  incident: rule('DEFENDER.XDR.INCIDENT', 'defender-xdr', 'high', 'Open Defender XDR incident',
    'Triage the incident with the responsible response team and correlate supported entity identifiers; incident metadata does not prove compromise.', R.incidents, ['assume-breach']),
  alert: rule('DEFENDER.XDR.ALERT', 'defender-xdr', 'high', 'Open Defender alert',
    'Investigate the alert in context and validate its classification before response.', R.alerts, ['assume-breach']),
  machine: rule('DEFENDER.ENDPOINT.POSTURE', 'defender-xdr', 'medium', 'Endpoint sensor or risk posture requires review',
    'Validate onboarding state, sensor health and device risk in Defender for Endpoint. A single property is not fleet-wide coverage.', R.machines, ['assume-breach', 'verify-explicitly']),
  compliance: rule('INTUNE.DEVICE.COMPLIANCE', 'intune', 'medium', 'Intune device compliance posture',
    'Review the reported noncompliance and assigned policies; compliance status alone does not establish Conditional Access enforcement.', R.intune, ['verify-explicitly']),
  stale: rule('INTUNE.DEVICE.STALE', 'intune', 'low', 'Intune device has not recently synchronized',
    'Validate device lifecycle and management health before relying on old compliance information.', R.intune, ['verify-explicitly']),
  intunePolicies: rule('INTUNE.POLICY.INVENTORY', 'intune', 'medium', 'Intune policy inventory and assignment boundary',
    'Review compliance/configuration policies and their device/group assignments. An inventory does not prove assignment or effective application.', R.intune, ['verify-explicitly']),
  deviceMatch: rule('ENDPOINT.INVENTORY.MATCH', 'intune', 'medium', 'Intune and Defender device inventory correlation',
    'Validate device IDs, operating-system support, onboarding scope and recent reporting. An unmatched inventory row is not proof that a device lacks protection.', [R.intune, R.machines], ['verify-explicitly']),
  storageAnonymous: rule('AZURE.STORAGE.ANONYMOUS_CAPABILITY', 'azure', 'medium', 'Storage account permits blob anonymous-access configuration',
    'Review actual container access levels and, where not needed, plan to disallow anonymous blob access. Account-level permission alone does not prove public data.', R.storage),
  storageHttps: rule('AZURE.STORAGE.HTTPS', 'azure', 'high', 'Storage HTTPS-only configuration',
    'Require secure transfer where supported and verify client compatibility in an approved change process.', R.storage, ['verify-explicitly']),
  storageTls: rule('AZURE.STORAGE.TLS', 'azure', 'medium', 'Storage minimum TLS configuration',
    'Review client compatibility and require TLS 1.2 or stronger under the organization policy.', R.storage, ['verify-explicitly']),
  storageKey: rule('AZURE.STORAGE.SHARED_KEY', 'azure', 'low', 'Storage shared-key access capability',
    'Review shared-key use and consider Entra-based authorization; verify workload compatibility before changing access.', R.storage),
  network: rule('AZURE.NETWORK.PUBLIC_CONFIGURATION', 'azure', 'medium', 'Potential public network accessibility',
    'Validate firewall, private endpoint, perimeter, route and authentication controls. Public-network settings do not prove reachable or anonymous access.', [R.storage, R.keyVault], ['assume-breach']),
  purge: rule('AZURE.KEYVAULT.PURGE_PROTECTION', 'azure', 'medium', 'Key Vault purge-protection configuration',
    'Review recovery requirements and plan purge protection where appropriate.', R.keyVault, ['assume-breach']),
  softDelete: rule('AZURE.KEYVAULT.SOFT_DELETE', 'azure', 'high', 'Key Vault soft-delete configuration',
    'Review and enable supported deletion recovery controls in an approved change process.', R.keyVault, ['assume-breach']),
  vaultRbac: rule('AZURE.KEYVAULT.AUTHORIZATION', 'azure', 'low', 'Key Vault authorization model review',
    'Review vault access-policy administration and evaluate Azure RBAC migration for appropriate separation of duties.', [R.keyVault, R.rbac]),
  plan: rule('DEFENDER.CLOUD.PLAN', 'defender-cloud', 'medium', 'Defender for Cloud plan and workload coverage review',
    'Evaluate workload requirements, existing protections, resource overrides, plan capabilities and cost. The assessment does not require every paid plan.', R.defenderPlans, ['assume-breach']),
  assessment: rule('DEFENDER.CLOUD.ASSESSMENT', 'defender-cloud', 'medium', 'Unhealthy Defender for Cloud assessment',
    'Validate the recommendation applicability and resource context before planning remediation.', R.defenderAssessments),
  regulatory: rule('DEFENDER.CLOUD.REGULATORY', 'defender-cloud', 'medium', 'Failed regulatory-compliance assessment',
    'Review the recorded assessment against the relevant standard; platform assessment status is not a compliance certification.', R.defenderAssessments),
};

function microsoft365(ctx: Context, scope: string): void {
  ctx.require(checks.score, scope, ['m365.secureScores', 'm365.secureScoreControls']);
  const scores = ctx.records('m365.secureScores', scope);
  const dated = scores.map((score) => ({ score, at: date(score.data.createdDateTime) }));
  const valid = dated.every((item) => item.at !== undefined && Number.isFinite(ctx.now) && item.at <= ctx.now);
  const latest = valid ? [...dated].sort((a, b) => (b.at! - a.at!) || a.score.id.localeCompare(b.score.id))[0]?.score : undefined;
  if (!latest && scores.length) ctx.emit(checks.score, scope, scope, 'unable-to-assess',
    'Score snapshots cannot be ordered by valid historical observation dates; the analyzer will not fabricate freshness or combine scores from different snapshots.', scores.flatMap((score) => score.evidence));
  if (latest) {
    if (!Array.isArray(latest.data.controlScores)) ctx.emit(checks.score, scope, latest.id, 'unable-to-assess',
      'The score snapshot has no controlScores metadata; a total score cannot establish individual control completion.', latest.evidence);
    for (const scored of objects(latest.data.controlScores)) {
      const controlId = text(scored.controlName);
      const profile = controlId ? ctx.find('m365.secureScoreControls', scope, controlId) : undefined;
      const achieved = number(scored.score);
      const maximum = number(profile?.data.maxScore);
      if (!controlId || !profile || achieved === undefined || maximum === undefined || maximum <= 0
        || achieved < 0 || achieved > maximum || profile.data.deprecated === true) {
        ctx.emit(checks.score, scope, controlId ?? latest.id, 'unable-to-assess',
          'The control score does not resolve to a current profile with a valid positive maximum and bounded achieved score. Applicability is not fabricated.',
          [...latest.evidence, ...(profile?.evidence ?? [])], controlId ?? 'profile');
        continue;
      }
      if (achieved < maximum) ctx.emit(checks.score, scope, controlId, 'fail',
        `The latest resolvable score reports ${achieved} of ${maximum} available points for this control. Confirm applicability and actual service configuration; this is a scored improvement opportunity, not proof of every underlying policy state.`,
        [...latest.evidence, ...profile.evidence]);
    }
  }
  ctx.emit(checks.m365Coverage, scope, scope, 'unable-to-assess',
    'Secure Score, licenses and selected SharePoint tenant settings do not establish complete Exchange Online, Teams, SharePoint site/item or effective-user policy coverage. Tenant sharing controls are assessed separately when available; product-specific controls and entitlements still require validation.',
    [...ctx.inventoryEvidence('m365.secureScores', scope), ...ctx.inventoryEvidence('m365.licenses', scope),
      ...ctx.inventoryEvidence('m365.sharePointSettings', scope)]);
}

function defenderXdr(ctx: Context, scope: string): void {
  for (const [dataset, check, openStates] of [
    ['defender.incidents', checks.incident, ['active', 'inprogress']],
    ['defender.alerts', checks.alert, ['new', 'inprogress', 'active']],
  ] as const) {
    ctx.require(check, scope, [dataset]);
    for (const event of ctx.records(dataset, scope)) {
      const status = text(event.data.status)?.toLowerCase();
      const reportedSeverity = text(event.data.severity)?.toLowerCase();
      const severity: Severity | undefined = reportedSeverity === 'high' ? 'high'
        : reportedSeverity === 'medium' ? 'medium' : reportedSeverity === 'low' ? 'low'
          : reportedSeverity === 'informational' ? 'informational' : undefined;
      if (openStates.some((state) => state === status)) {
        ctx.emit(check, scope, event.id, severity === undefined ? 'unable-to-assess'
          : severity === 'informational' ? 'informational' : 'fail',
        severity === undefined
          ? 'The service reports an open event, but its vendor severity is missing or unrecognized. Priority requires manual assessment; no severity is fabricated.'
          : 'The service explicitly reports an open security event. Triage state and vendor severity are evidence, not independent confirmation of compromise.',
        event.evidence, '', severity ?? 'informational');
      } else if (!['resolved', 'redirected'].includes(status ?? '')) {
        ctx.emit(check, scope, event.id, 'unable-to-assess', 'An open/resolved state could not be determined from this event.', event.evidence);
      }
      const node = ctx.node(dataset === 'defender.incidents' ? 'incident' : 'alert', scope, event.id, event.evidence);
      const incidentId = identifier(event.data.incidentId);
      const incident = incidentId ? ctx.find('defender.incidents', scope, incidentId) : undefined;
      if (incident && dataset === 'defender.alerts') ctx.edge(node,
        ctx.node('incident', scope, incident.id, incident.evidence), 'alert-in-incident', [...event.evidence, ...incident.evidence]);
      const machineId = text(event.data.machineId);
      const machine = machineId ? ctx.find('defender.machines', scope, machineId) : undefined;
      if (machine && dataset === 'defender.alerts') ctx.edge(node,
        ctx.node('endpoint', scope, machine.id, machine.evidence), 'alert-on-machine', [...event.evidence, ...machine.evidence]);
    }
  }
  ctx.require(checks.machine, scope, ['defender.machines']);
  for (const machine of ctx.records('defender.machines', scope)) {
    ctx.node('endpoint', scope, machine.id, machine.evidence);
    const observations: string[] = [];
    const onboarding = text(machine.data.onboardingStatus)?.toLowerCase();
    const health = text(machine.data.healthStatus)?.toLowerCase();
    if (onboarding && ['canbeonboarded', 'offboarded'].includes(onboarding)) observations.push(`onboardingStatus=${onboarding}`);
    if (health && ['inactive', 'impairedcommunication', 'nosensordata', 'nosensordataimpairedcommunication'].includes(health)) observations.push(`healthStatus=${health}`);
    if (['high', 'medium'].includes(text(machine.data.riskScore)?.toLowerCase() ?? '')) observations.push(`riskScore=${String(machine.data.riskScore)}`);
    if (['high', 'medium'].includes(text(machine.data.exposureLevel)?.toLowerCase() ?? '')) observations.push(`exposureLevel=${String(machine.data.exposureLevel)}`);
    if (observations.length) ctx.emit(checks.machine, scope, machine.id, 'fail',
      `Recorded endpoint indicators: ${observations.join(', ')}. Confirm reporting freshness, supported platform and actual sensor state.`, machine.evidence);
    else if (!onboarding || !health || ['insufficientinfo', 'unsupported'].includes(onboarding) || health === 'unknown') ctx.emit(checks.machine, scope, machine.id, 'unable-to-assess',
      'Onboarding or sensor-health metadata is unavailable; device presence alone does not prove protection.', machine.evidence);
  }
}

function endpoints(ctx: Context, scope: string): void {
  ctx.require(checks.compliance, scope, ['intune.devices']);
  const devices = ctx.records('intune.devices', scope);
  for (const device of devices) {
    const state = text(device.data.complianceState)?.toLowerCase();
    const node = ctx.node('managed-device', scope, device.id, device.evidence);
    if (state === 'noncompliant' || state === 'ingraceperiod') ctx.emit(checks.compliance, scope, device.id, 'fail',
      `Intune explicitly reports complianceState=${state}. This is not a conclusion about device access enforcement or compromise.`, device.evidence, '', state === 'noncompliant' ? 'medium' : 'low');
    else if (state === 'compliant') ctx.emit(checks.compliance, scope, device.id, 'informational',
      'Intune reports this device compliant. Applicable policy assignments, freshness and access enforcement still require validation; no fleet-wide pass is inferred.',
      device.evidence, '', 'informational');
    else ctx.emit(checks.compliance, scope, device.id, 'unable-to-assess',
      'The device has no conclusive compliant/noncompliant status in the supplied evidence.', device.evidence);
    const lastSync = date(device.data.lastSyncDateTime);
    if (lastSync === undefined || !Number.isFinite(ctx.now) || lastSync > ctx.now) ctx.emit(checks.stale, scope, device.id, 'unable-to-assess',
      'A valid historical synchronization date is unavailable; no age is fabricated.', device.evidence);
    else if (ctx.now - lastSync > 30 * DAY) ctx.emit(checks.stale, scope, device.id, 'fail',
      'The device last synchronized more than 30 days before assessment time; current posture may differ.', device.evidence);

    const deviceId = text(device.data.azureADDeviceId);
    const complete = ctx.complete('intune.devices', scope) && ctx.complete('defender.machines', scope);
    const matches = deviceId ? ctx.records('defender.machines', scope)
      .filter((machine) => sameId(text(machine.data.aadDeviceId), deviceId)) : [];
    const intuneMatches = deviceId ? devices.filter((candidate) => sameId(text(candidate.data.azureADDeviceId), deviceId)) : [];
    if (!complete || !deviceId || matches.length > 1 || intuneMatches.length > 1) {
      ctx.emit(checks.deviceMatch, scope, device.id, 'unable-to-assess',
        'Complete inventories and unique matching Entra device IDs are required for this correlation. Device names are not used, and an unmatched partial inventory is not a coverage failure.',
        [...device.evidence, ...ctx.inventoryEvidence('defender.machines', scope)]);
    } else if (matches.length === 1) {
      const machine = matches[0]!;
      ctx.edge(node, ctx.node('endpoint', scope, machine.id, machine.evidence),
        'same-entra-device-id', [...device.evidence, ...machine.evidence]);
      const userId = text(device.data.userId);
      const user = userId && ctx.complete('entra.users', scope) ? ctx.find('entra.users', scope, userId) : undefined;
      if (user) ctx.edge(ctx.principal(scope, user.id, user.evidence), node,
        'reported-primary-user', [...user.evidence, ...device.evidence]);
    } else if (['windows', 'macos', 'mac os', 'linux'].includes(text(device.data.operatingSystem)?.toLowerCase() ?? '')) {
      ctx.emit(checks.deviceMatch, scope, device.id, 'fail',
        'No matching Defender machine appears in the complete inventories for this supported-platform device ID. This is an inventory correlation gap, not proof the device is unprotected.',
        [...device.evidence, ...ctx.inventoryEvidence('defender.machines', scope)]);
    }
  }
  for (const dataset of ['intune.compliancePolicies', 'intune.configurationPolicies']) {
    const complete = ctx.require(checks.intunePolicies, scope, ['intune.devices', dataset]);
    if (complete && devices.length && !ctx.records(dataset, scope).length) ctx.emit(checks.intunePolicies, scope, scope, 'fail',
      `Managed devices are present but the complete ${dataset} inventory is empty. This does not establish per-device effective settings or absence of other management controls.`,
      [...ctx.inventoryEvidence(dataset, scope), ...devices.flatMap((device) => device.evidence)], dataset);
    else if (ctx.records(dataset, scope).length) ctx.emit(checks.intunePolicies, scope, scope, 'informational',
      `${dataset} records exist; effective assignments, exclusions and deployment are not proven by inventory presence.`,
      ctx.inventoryEvidence(dataset, scope), dataset, 'informational');
  }
}

function booleanControl(ctx: Context, resource: RecordRef, properties: JsonObject, property: string, check: Rule, secureValue: boolean, limitation: string): void {
  const value = properties[property];
  const evidence = ctx.evidenceFor(resource, `properties.${property}`);
  if (typeof value !== 'boolean') ctx.emit(check, resource.scope, resource.id, 'unable-to-assess',
    `${property} is not explicitly visible. Defaults and permissions failures are not converted into configuration.`, evidence);
  else ctx.emit(check, resource.scope, resource.id, value === secureValue
    ? ctx.complete('azure.resources', resource.scope) ? 'pass' : 'informational' : 'fail',
  `The resource explicitly reports ${property}=${value}. ${limitation}`, evidence);
}

function resourcePosture(ctx: Context, scope: string): void {
  for (const resource of ctx.records('azure.resources', scope)) {
    const type = text(resource.data.type)?.toLowerCase();
    const properties = object(resource.data.properties) ?? {};
    if (type === 'microsoft.storage/storageaccounts') {
      booleanControl(ctx, resource, properties, 'allowBlobPublicAccess', checks.storageAnonymous, false,
        'Permitting anonymous container configuration is not evidence that any blob is publicly readable.');
      booleanControl(ctx, resource, properties, 'supportsHttpsTrafficOnly', checks.storageHttps, true,
        'This is only the recorded secure-transfer setting, not a complete transport-security assessment.');
      booleanControl(ctx, resource, properties, 'allowSharedKeyAccess', checks.storageKey, false,
        'This is an authorization capability, not evidence that keys were disclosed or used.');
      const tls = text(properties.minimumTlsVersion);
      if (tls === 'TLS1_0' || tls === 'TLS1_1') ctx.emit(checks.storageTls, scope, resource.id, 'fail',
        `The account explicitly permits minimum TLS ${tls}.`, ctx.evidenceFor(resource, 'properties.minimumTlsVersion'));
      else if (!tls) ctx.emit(checks.storageTls, scope, resource.id, 'unable-to-assess',
        'The configured minimum TLS version is not visible.', resource.evidence);
    }
    if (type === 'microsoft.keyvault/vaults') {
      booleanControl(ctx, resource, properties, 'enablePurgeProtection', checks.purge, true, 'Validate actual recovery requirements and retention separately.');
      booleanControl(ctx, resource, properties, 'enableSoftDelete', checks.softDelete, true, 'This describes the observed deletion-recovery setting only.');
      if (properties.enableRbacAuthorization === false) ctx.emit(checks.vaultRbac, scope, resource.id, 'informational',
        'This vault explicitly uses the access-policy authorization model. Review management-plane ability to change access policies; this is not a requirement that every vault use RBAC.', resource.evidence);
      else if (typeof properties.enableRbacAuthorization !== 'boolean') ctx.emit(checks.vaultRbac, scope, resource.id, 'unable-to-assess',
        'The vault authorization model is not explicitly visible.', resource.evidence);
    }
    if (type === 'microsoft.keyvault/vaults' || type === 'microsoft.storage/storageaccounts') {
      const publicAccess = text(properties.publicNetworkAccess)?.toLowerCase();
      const defaultAction = text(object(properties.networkAcls)?.defaultAction)?.toLowerCase();
      if (publicAccess === 'enabled' && defaultAction === 'allow') ctx.emit(checks.network, scope, resource.id, 'fail',
        'Public network access is enabled and the network ACL default action is Allow. This is potentially broad network accessibility; endpoint reachability, data authorization and anonymous access are not proven.',
        ctx.evidenceFor(resource, 'properties.networkAcls'));
      else if (!publicAccess || (publicAccess === 'enabled' && !defaultAction)) ctx.emit(checks.network, scope, resource.id, 'unable-to-assess',
        'Public-network/firewall metadata is insufficient to determine network restrictions. Missing settings are not treated as defaults.', resource.evidence);
    }
    if (type === 'microsoft.network/networksecuritygroups') {
      for (const securityRule of objects(properties.securityRules)) {
        const config = object(securityRule.properties);
        const sources = [text(config?.sourceAddressPrefix), ...strings(config?.sourceAddressPrefixes)].filter(Boolean);
        const ports = [text(config?.destinationPortRange), ...strings(config?.destinationPortRanges)].filter(Boolean);
        if (config?.access !== 'Allow' || config.direction !== 'Inbound' || !sources.some((source) => ['*', 'Internet', '0.0.0.0/0', '::/0'].includes(source!))) continue;
        const widePort = ports.some((port) => port === '*' || port === '22' || port === '3389'
          || (/^\d+-\d+$/.test(port!) && [22, 3389].some((target) => {
            const [low, high] = port!.split('-').map(Number);
            return low !== undefined && high !== undefined && low <= target && high >= target;
          })));
        if (widePort) ctx.emit(checks.network, scope, resource.id, 'fail',
          'An NSG rule explicitly allows Internet/wildcard inbound traffic to an administration port or all ports. Rule priority, NSG association, routing and host controls require validation; no reachable service is asserted.',
          resource.evidence, text(securityRule.id) ?? text(securityRule.name) ?? 'nsg', 'high', 'medium');
      }
    }
  }
}

const planWorkloads: Record<string, string[]> = {
  virtualmachines: ['microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachinescalesets', 'microsoft.hybridcompute/machines'],
  storageaccounts: ['microsoft.storage/storageaccounts'],
  keyvaults: ['microsoft.keyvault/vaults'],
  containers: ['microsoft.containerservice/managedclusters'],
  sqlservers: ['microsoft.sql/servers'],
  appservices: ['microsoft.web/sites'],
};

function defenderCloud(ctx: Context, scope: string): void {
  ctx.require(checks.plan, scope, ['defenderCloud.pricings', 'azure.resources']);
  for (const plan of ctx.records('defenderCloud.pricings', scope)) {
    const properties = object(plan.data.properties);
    const tier = text(properties?.pricingTier)?.toLowerCase();
    const name = (text(plan.data.name) ?? plan.id.split('/').at(-1) ?? '').toLowerCase();
    const resourceTypes = planWorkloads[name];
    const workloads = resourceTypes ? ctx.records('azure.resources', scope).filter((resource) => resourceTypes.includes(text(resource.data.type)?.toLowerCase() ?? '')) : [];
    if (tier === 'free' && workloads.length) ctx.emit(checks.plan, scope, plan.id, 'informational',
      'A Free pricing tier is explicitly reported for a plan with corresponding workload types present. Evaluate paid-plan capabilities, resource overrides, alternative controls, requirements and cost; Free does not mean every workload is unprotected and paid plans are not universally mandatory.',
      [...plan.evidence, ...workloads.flatMap((workload) => workload.evidence)], 'tier', 'low');
    else if (!tier || !['free', 'standard'].includes(tier)) ctx.emit(checks.plan, scope, plan.id, 'unable-to-assess',
      'The plan pricing tier is not explicitly recognized.', plan.evidence, 'tier');
    else if (tier === 'free' && resourceTypes && !ctx.complete('azure.resources', scope)) ctx.emit(checks.plan, scope, plan.id, 'unable-to-assess',
      'The workload inventory is incomplete, so a Free-tier plan cannot be declared irrelevant or fully applicable.', plan.evidence, 'workloads');
    const coverage = text(properties?.resourcesCoverageStatus);
    if (coverage === 'PartiallyCovered' || coverage === 'NotCovered') ctx.emit(checks.plan, scope, plan.id, 'fail',
      `The service reports resourcesCoverageStatus=${coverage}. Review eligible resources, overrides and exemptions before a protection conclusion.`, plan.evidence, 'coverage');
    else if (tier === 'standard' && !coverage) ctx.emit(checks.plan, scope, plan.id, 'unable-to-assess',
      'Standard pricing is recorded but per-resource coverage is not visible. Enabling a plan is not proof all resources are protected.', plan.evidence, 'coverage');
  }
  for (const [dataset, check] of [
    ['defenderCloud.assessments', checks.assessment], ['defenderCloud.regulatoryCompliance', checks.regulatory],
  ] as const) {
    ctx.require(check, scope, [dataset]);
    for (const assessment of ctx.records(dataset, scope)) {
      const properties = object(assessment.data.properties);
      const code = text(object(properties?.status)?.code) ?? text(properties?.state);
      if (code === 'Unhealthy' || code === 'Failed') {
        const rawSeverity = text(object(properties?.metadata)?.severity)?.toLowerCase();
        ctx.emit(check, scope, assessment.id, 'fail',
          `Defender for Cloud explicitly reports ${code}. Applicability, exemptions and current resource configuration require validation.`,
          assessment.evidence, '', rawSeverity === 'high' ? 'high' : rawSeverity === 'low' ? 'low' : 'medium');
      } else if (!code) ctx.emit(check, scope, assessment.id, 'unable-to-assess',
        'The assessment status is not visible.', assessment.evidence);
      const resourceId = text(object(properties?.resourceDetails)?.id);
      const resource = resourceId ? ctx.find('azure.resources', scope, resourceId) : undefined;
      if (resource) ctx.edge(ctx.node('cloud-assessment', scope, assessment.id, assessment.evidence),
        ctx.node('azure-resource', scope, resource.id.toLowerCase(), resource.evidence),
        'assessment-of-resource', [...assessment.evidence, ...resource.evidence]);
    }
  }
}

export function analyzePosture(ctx: Context): void {
  for (const scope of ctx.scopes('m365.')) microsoft365(ctx, scope);
  for (const scope of ctx.scopes('defender.')) defenderXdr(ctx, scope);
  for (const scope of ctx.scopes('intune.')) endpoints(ctx, scope);
  for (const scope of ctx.scopes('azure.resources')) resourcePosture(ctx, scope);
  for (const scope of ctx.scopes('defenderCloud.')) defenderCloud(ctx, scope);
}
