import type {
  AssessmentDiff, AssessmentScope, AssessmentSnapshot, CollectionResult, Finding, JsonObject, JsonValue, SnapshotChange,
} from './model.js';
import { AssessmentError, canonicalJson, collectionKey, recordId, recordKey } from './safety.js';
import { parseSnapshot } from './validation.js';
import { date as evidenceDate, object } from './analysis/context.js';

function fieldChanges(before: JsonObject, after: JsonObject): string[] {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter(key => canonicalJson(before[key]) !== canonicalJson(after[key])).sort();
}

function leaves(value: JsonValue | undefined, prefix = ''): Map<string, JsonValue> {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return new Map(Object.entries(value).flatMap(([key, child]) => [...leaves(child, `${prefix}.${key}`)]));
  }
  return value === undefined ? new Map() : new Map([[prefix, value]]);
}

function policyTimestamp(record: JsonObject, collection: CollectionResult): number | undefined {
  const properties = object(record.properties);
  const timestamp = evidenceDate(properties?.timestamp);
  const observed = evidenceDate(collection.collectedAt);
  return timestamp !== undefined && observed !== undefined && timestamp <= observed ? timestamp : undefined;
}

function policyIdentity(record: JsonObject): string | undefined {
  const properties = object(record.properties);
  if (!properties) return undefined;
  const identifiers = [properties.resourceId, properties.policyAssignmentId, properties.policyDefinitionId];
  if (!identifiers.every(value => typeof value === 'string' && value.length > 0)) return undefined;
  return canonicalJson([...identifiers, properties.policyDefinitionReferenceId ?? null, properties.policySetDefinitionId ?? null]);
}

function policyStateValues(record: JsonObject): JsonObject {
  const properties = object(record.properties);
  if (!properties) return record;
  const values = Object.fromEntries(Object.entries(record).filter(([key]) => key !== 'sourceId'));
  return { ...values, properties: Object.fromEntries(Object.entries(properties).filter(([key]) => key !== 'timestamp')) };
}

function sharePointImpact(before: JsonObject, after: JsonObject): SnapshotChange['securityImpact'] {
  const impacts = new Set<SnapshotChange['securityImpact']>();
  const ceilings = ['disabled', 'existingExternalUserSharingOnly', 'externalUserSharingOnly', 'externalUserAndGuestSharing'];
  const beforeCeiling = typeof before.sharingCapability === 'string' ? ceilings.indexOf(before.sharingCapability) : -1;
  const afterCeiling = typeof after.sharingCapability === 'string' ? ceilings.indexOf(after.sharingCapability) : -1;
  if (beforeCeiling >= 0 && afterCeiling >= 0 && beforeCeiling !== afterCeiling) {
    impacts.add(afterCeiling > beforeCeiling ? 'potential-increase' : 'potential-decrease');
  }
  const checkBoolean = (key: string, enabledIsRestrictive: boolean): void => {
    const oldValue = before[key];
    const value = after[key];
    if (typeof oldValue !== 'boolean' || typeof value !== 'boolean' || oldValue === value) return;
    impacts.add(value === enabledIsRestrictive ? 'potential-decrease' : 'potential-increase');
  };
  checkBoolean('isLegacyAuthProtocolsEnabled', false);
  checkBoolean('isUnmanagedSyncAppForTenantRestricted', true);
  if (beforeCeiling > 0 && afterCeiling > 0) {
    checkBoolean('isRequireAcceptingUserToMatchInvitedUserEnabled', true);
    checkBoolean('isResharingByExternalUsersEnabled', false);
  }
  return impacts.size === 1 ? [...impacts][0] ?? 'review-required' : 'review-required';
}

function securityImpact(
  collectionId: string, kind: SnapshotChange['kind'], before?: JsonObject, after?: JsonObject,
): SnapshotChange['securityImpact'] {
  if (kind === 'indeterminate') return 'unknown';
  if (/federatedCredentials$/i.test(collectionId)) return 'review-required';
  if (new Set([
    'entra.directoryRoleAssignments', 'entra.directoryRoleEligibility', 'entra.appRoleAssignments',
    'entra.oauth2PermissionGrants', 'entra.applicationOwners', 'entra.servicePrincipalOwners',
    'azure.roleAssignments', 'azure.managementGroupRoleAssignments', 'github.outsideCollaborators',
  ]).has(collectionId)) {
    if (kind === 'added') return 'potential-increase';
    if (kind === 'removed') return 'potential-decrease';
  }
  if (!before || !after) return 'review-required';
  if (collectionId === 'm365.sharePointSettings') return sharePointImpact(before, after);
  if (collectionId === 'azure.policyCompliance') {
    const oldProperties = object(before.properties);
    const newProperties = object(after.properties);
    if (!oldProperties || !newProperties || !policyIdentity(before) || policyIdentity(before) !== policyIdentity(after)) {
      return 'review-required';
    }
    const oldEffect = typeof oldProperties.policyDefinitionAction === 'string' ? oldProperties.policyDefinitionAction.toLowerCase() : undefined;
    const effect = typeof newProperties.policyDefinitionAction === 'string' ? newProperties.policyDefinitionAction.toLowerCase() : undefined;
    if (!oldEffect || oldEffect !== effect || effect === 'disabled') return 'review-required';
    if (oldProperties.complianceState === 'NonCompliant' && newProperties.complianceState === 'Compliant') return 'potential-decrease';
    if (oldProperties.complianceState === 'Compliant' && newProperties.complianceState === 'NonCompliant') return 'potential-increase';
    return 'review-required';
  }
  if (collectionId === 'azure.roleAssignments') {
    const previous = leaves(before);
    const current = leaves(after);
    const oldScope = previous.get('.properties.scope');
    const newScope = current.get('.properties.scope');
    if (typeof oldScope === 'string' && typeof newScope === 'string') {
      const from = oldScope.toLowerCase().replace(/\/+$/, '');
      const to = newScope.toLowerCase().replace(/\/+$/, '');
      const oldRole = previous.get('.properties.roleDefinitionId');
      const newRole = current.get('.properties.roleDefinitionId');
      const oldPrincipal = previous.get('.properties.principalId');
      const newPrincipal = current.get('.properties.principalId');
      const sameConstraints = canonicalJson(previous.get('.properties.condition')) === canonicalJson(current.get('.properties.condition'));
      if (oldRole !== undefined && oldRole === newRole && oldPrincipal !== undefined && oldPrincipal === newPrincipal && sameConstraints) {
        if (from.startsWith(`${to}/`)) return 'potential-increase';
        if (to.startsWith(`${from}/`)) return 'potential-decrease';
      }
    }
  }
  for (const key of ['passwordCredentials', 'keyCredentials']) {
    const previous = before[key];
    const current = after[key];
    if (Array.isArray(previous) && Array.isArray(current)) {
      const ids = (values: JsonValue[]) => new Set(values.flatMap(value =>
        value && !Array.isArray(value) && typeof value === 'object' && typeof value.keyId === 'string' ? [value.keyId] : []));
      const oldIds = ids(previous);
      const newIds = ids(current);
      if ([...newIds].some(id => !oldIds.has(id))) return 'potential-increase';
      if ([...oldIds].some(id => !newIds.has(id))) return 'potential-decrease';
    }
  }
  const previous = leaves(before);
  const current = leaves(after);
  const impacts = new Set<SnapshotChange['securityImpact']>();
  for (const [path, oldValue] of previous) {
    const value = current.get(path);
    if (value === undefined || canonicalJson(value) === canonicalJson(oldValue)) continue;
    if ((oldValue === 'disabled' && value === 'enabled') || (oldValue === 'Free' && value === 'Standard')) {
      impacts.add('potential-decrease');
    } else if ((oldValue === 'enabled' && value === 'disabled') || (oldValue === 'Standard' && value === 'Free')) {
      impacts.add('potential-increase');
    } else if (/\.publicNetworkAccess$/.test(path)) {
      if (value === 'Enabled') impacts.add('potential-increase');
      if (value === 'Disabled') impacts.add('potential-decrease');
    } else if (/\.(two_factor_requirement_enabled|enableRbacAuthorization|enablePurgeProtection|enableSoftDelete|supportsHttpsTrafficOnly)$/.test(path)) {
      if (value === true && oldValue === false) impacts.add('potential-decrease');
      if (value === false && oldValue === true) impacts.add('potential-increase');
    } else if (/\.(allowBlobPublicAccess|allowSharedKeyAccess)$/.test(path)) {
      if (value === true && oldValue === false) impacts.add('potential-increase');
      if (value === false && oldValue === true) impacts.add('potential-decrease');
    }
  }
  return impacts.size === 1 ? [...impacts][0] ?? 'review-required' : 'review-required';
}

function compareCollections(
  before: CollectionResult | undefined, after: CollectionResult | undefined, toolChanged: boolean,
): SnapshotChange[] {
  const collection = after ?? before;
  if (!collection) return [];
  const changes: SnapshotChange[] = [];
  const base = { collectionId: collection.id, scope: collection.scope };
  if (before?.status !== after?.status || before?.reason !== after?.reason) {
    changes.push({
      ...base,
      recordId: '[collection]',
      kind: 'changed',
      fields: ['collectionStatus'],
      securityImpact: 'unknown',
      description: `Evidence availability changed from ${before?.status ?? 'missing'} to ${after?.status ?? 'missing'}. This is not a security-control change.`,
    });
  }
  const oldRecords = new Map((before?.records ?? []).map(record => [recordKey(record), record]));
  const newRecords = new Map((after?.records ?? []).map(record => [recordKey(record), record]));
  for (const key of [...new Set([...oldRecords.keys(), ...newRecords.keys()])].sort()) {
    const oldRecord = oldRecords.get(key);
    const newRecord = newRecords.get(key);
    let kind: SnapshotChange['kind'];
    let fields: string[];
    let description: string;
    if (oldRecord && newRecord) {
      let policyComparable = true;
      if (collection.id === 'azure.policyCompliance' && before && after) {
        const previousTimestamp = policyTimestamp(oldRecord, before);
        const currentTimestamp = policyTimestamp(newRecord, after);
        policyComparable = previousTimestamp !== undefined && currentTimestamp !== undefined && currentTimestamp >= previousTimestamp
          && policyIdentity(oldRecord) !== undefined && policyIdentity(oldRecord) === policyIdentity(newRecord);
      }
      fields = fieldChanges(
        collection.id === 'azure.policyCompliance' && policyComparable ? policyStateValues(oldRecord) : oldRecord,
        collection.id === 'azure.policyCompliance' && policyComparable ? policyStateValues(newRecord) : newRecord,
      );
      if (!fields.length) continue;
      const omitted = fields.some(field => !(field in oldRecord) || !(field in newRecord));
      kind = omitted || toolChanged || !policyComparable ? 'indeterminate' : 'changed';
      description = kind === 'indeterminate'
        ? 'Record evidence changed, but omitted fields, collector-version changes or inconsistent evaluation identity/timing prevent a reliable posture conclusion.'
        : collection.id === 'azure.policyCompliance'
          ? 'Last-reported Azure Policy evaluation metadata changed. This is not real-time proof of resource protection or malicious intent.'
          : 'Observed metadata changed. Validate business intent and actual effective access; no malicious intent is inferred.';
    } else if (newRecord) {
      kind = before?.status === 'complete' && !toolChanged ? 'added' : 'indeterminate';
      fields = ['record'];
      description = kind === 'added'
        ? 'A record was observed that was absent from the complete previous inventory.'
        : 'A record is now visible; incomplete previous evidence prevents claiming it was newly created.';
    } else {
      kind = after?.status === 'complete' && !toolChanged ? 'removed' : 'indeterminate';
      fields = ['record'];
      description = kind === 'removed'
        ? 'A previously observed record is absent from the complete current inventory.'
        : 'A previously observed record is no longer visible; incomplete evidence prevents claiming it was deleted.';
    }
    changes.push({
      ...base, kind, recordId: recordId(newRecord ?? oldRecord ?? {}), fields,
      ...(typeof (newRecord ?? oldRecord)?.parentId === 'string'
        ? { parentId: String((newRecord ?? oldRecord)?.parentId) } : {}),
      ...(typeof (newRecord ?? oldRecord)?.repository === 'string'
        ? { repository: String((newRecord ?? oldRecord)?.repository) } : {}),
      securityImpact: securityImpact(collection.id, kind, oldRecord, newRecord), description,
    });
  }
  return changes;
}

function findingKey(finding: Finding): string {
  return JSON.stringify([finding.id, finding.checkId, finding.scope, finding.resourceId]);
}

function evidenceComplete(finding: Finding, collections: Map<string, CollectionResult>): boolean {
  return finding.evidence.length > 0 && finding.evidence.every(ref =>
    collections.get(collectionKey(ref.collectionId, ref.scope))?.status === 'complete');
}

export function assertComparableScope(previous: AssessmentScope, current: AssessmentScope): void {
  if (canonicalJson(previous) !== canonicalJson(current)) {
    throw new AssessmentError('scope-mismatch', 'Snapshots must use the same tenant, subscriptions and source-control organizations.');
  }
}

export function compareSnapshots(previousValue: AssessmentSnapshot, currentValue: AssessmentSnapshot): AssessmentDiff {
  const previous = parseSnapshot(previousValue);
  const current = parseSnapshot(currentValue);
  assertComparableScope(previous.scope, current.scope);
  if (Date.parse(previous.collectedAt) > Date.parse(current.collectedAt)) {
    throw new AssessmentError('invalid-time-order', 'Previous assessment cannot be newer than the current assessment.');
  }
  const before = new Map(previous.collections.map(collection => [collectionKey(collection.id, collection.scope), collection]));
  const after = new Map(current.collections.map(collection => [collectionKey(collection.id, collection.scope), collection]));
  const toolChanged = previous.toolVersion !== current.toolVersion;
  const comparablePolicy = !toolChanged && canonicalJson(previous.policy) === canonicalJson(current.policy);
  const changes = [...new Set([...before.keys(), ...after.keys()])].sort()
    .flatMap(key => compareCollections(before.get(key), after.get(key), toolChanged));
  const oldFindings = new Map(previous.findings.map(finding => [findingKey(finding), finding]));
  const newFindings = new Map(current.findings.map(finding => [findingKey(finding), finding]));
  const findings: AssessmentDiff['findings'] = { new: [], resolved: [], persistent: [], indeterminate: [] };
  for (const [key, finding] of newFindings) {
    if (finding.status !== 'fail') continue;
    if (oldFindings.get(key)?.status === 'fail') findings.persistent.push(finding.id);
    else if (comparablePolicy && evidenceComplete(finding, before) && evidenceComplete(finding, after)) findings.new.push(finding.id);
    else findings.indeterminate.push(finding.id);
  }
  for (const [key, finding] of oldFindings) {
    if (finding.status !== 'fail' || newFindings.get(key)?.status === 'fail') continue;
    const replacement = newFindings.get(key);
    if (comparablePolicy && replacement?.status === 'pass'
      && evidenceComplete(replacement, after) && evidenceComplete(finding, before)) {
      findings.resolved.push(finding.id);
    } else {
      findings.indeterminate.push(finding.id);
    }
  }
  for (const values of Object.values(findings)) values.sort();
  return {
    kind: 'cloud-security-assessment-diff',
    schemaVersion: '1.0',
    previousAssessmentId: previous.assessmentId,
    currentAssessmentId: current.assessmentId,
    changes,
    findings,
    caveat: 'Changes are observations, not evidence of malicious intent. Scores are advisory. Resolution requires an explicit passing recheck with comparable policy and complete evidence; missing findings, denied access and removed scope are never treated as remediation.',
  };
}
