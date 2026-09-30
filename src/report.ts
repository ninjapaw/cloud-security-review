import { COLLECTION_CATALOG } from './catalog.js';
import { SEVERITIES } from './model.js';
import type {
  AssessmentDiff, AssessmentSnapshot, CollectionReason, CollectionStatus, Domain,
  EvidenceRef, Finding, JsonObject, JsonValue, Provider, Severity,
} from './model.js';
import { canonicalJson, safeHttpsUrl, stableId } from './safety.js';

export function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char] ?? char);
}

function markdown(value: unknown): string {
  return String(value).replace(/\\/g, '\\\\').replace(/[&<>]/g, escapeHtml)
    .replace(/([|`*_[\]#])/g, '\\$1').replace(/[\r\n]+/g, ' ');
}

function get(object: JsonObject, ...path: string[]): JsonValue | undefined {
  let value: JsonValue | undefined = object;
  for (const key of path) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    value = value[key];
  }
  return value;
}

export interface RepositoryCoverage {
  repository: string;
  secretScanning: string;
  pushProtection: string;
  dependabotUpdates: string;
  codeScanning: string;
}

function capability(value: JsonValue | undefined): string {
  if (value === 'enabled') return 'Enabled';
  if (value === 'disabled') return 'Disabled';
  return 'Unable to Assess';
}

export function repositoryCoverage(snapshot: AssessmentSnapshot): RepositoryCoverage[] {
  return snapshot.collections.filter(collection => collection.id === 'github.repositories')
    .flatMap(collection => collection.records.map(record => {
      const repository = typeof record.full_name === 'string' ? record.full_name : `${collection.scope}/${String(record.id)}`;
      const codeScanning = snapshot.collections.find(item =>
        item.id === 'github.codeScanningAlerts' && item.scope.toLowerCase() === repository.toLowerCase());
      return {
        repository,
        secretScanning: capability(get(record, 'security_and_analysis', 'secret_scanning', 'status')),
        pushProtection: capability(get(record, 'security_and_analysis', 'secret_scanning_push_protection', 'status')),
        dependabotUpdates: capability(get(record, 'security_and_analysis', 'dependabot_security_updates', 'status')),
        codeScanning: codeScanning?.reason === 'not-licensed' ? 'Not licensed/available'
          : codeScanning?.status === 'complete' ? 'Available (API readable; deployment unverified)'
            : codeScanning?.status === 'partial' ? 'Unable to Assess (partial evidence)' : 'Unable to Assess',
      };
    })).sort((a, b) => a.repository.localeCompare(b.repository));
}

export function repositoryCoverageTotals(repos: RepositoryCoverage[]): {
  control: string; enabled: number; disabled: number; unknown: number; total: number; state: string;
}[] {
  return (['secretScanning', 'pushProtection', 'dependabotUpdates'] as const).map(control => {
    const enabled = repos.filter(repo => repo[control] === 'Enabled').length;
    const disabled = repos.filter(repo => repo[control] === 'Disabled').length;
    const unknown = repos.length - enabled - disabled;
    return {
      control, enabled, disabled, unknown, total: repos.length,
      state: enabled && disabled ? 'Partially deployed'
        : repos.length && enabled === repos.length ? 'Enabled'
          : repos.length && disabled === repos.length ? 'Disabled' : 'Unable to Assess',
    };
  });
}

export function assessmentSummary(snapshot: AssessmentSnapshot): {
  risks: number; passes: number; unableToAssess: number; incompleteCollections: number;
} {
  return {
    risks: snapshot.findings.filter(finding => finding.status === 'fail').length,
    passes: snapshot.findings.filter(finding => finding.status === 'pass').length,
    unableToAssess: snapshot.findings.filter(finding => finding.status === 'unable-to-assess').length,
    incompleteCollections: snapshot.collections.filter(collection => collection.status !== 'complete').length,
  };
}

function evidenceText(finding: Finding): string {
  return finding.evidence.map(ref =>
    `${ref.collectionId} (${ref.scope})${ref.recordId ? ` #${ref.recordId}` : ''}${ref.field ? ` / ${ref.field}` : ''}`).join('; ');
}

function tenantDisplayName(snapshot: AssessmentSnapshot): string | undefined {
  const names = new Set(snapshot.collections.filter(collection =>
    collection.id === 'entra.organization' && collection.scope === snapshot.scope.tenantId)
    .flatMap(collection => collection.records.flatMap(record =>
      typeof record.id === 'string' && record.id.toLowerCase() === snapshot.scope.tenantId
        && typeof record.displayName === 'string' && record.displayName.trim()
        ? [record.displayName] : [])));
  return names.size === 1 ? [...names][0] : undefined;
}

export interface RecommendationGroup {
  id: string;
  checkId: string;
  domain: Domain;
  title: string;
  severity: Severity;
  confidence: Finding['confidence'];
  recommendation: string;
  findingIds: string[];
  targets: { scope: string; resourceId: string; label?: string }[];
  evidence: EvidenceRef[];
}

export function groupedRecommendations(snapshot: AssessmentSnapshot): RecommendationGroup[] {
  const groups = new Map<string, RecommendationGroup>();
  const policyTargets = new Map<string, string>();
  for (const collection of snapshot.collections.filter(item => item.id === 'azure.policyCompliance')) {
    for (const record of collection.records) {
      const resource = get(record, 'properties', 'resourceId');
      const assignment = get(record, 'properties', 'policyAssignmentName') ?? get(record, 'properties', 'policyAssignmentId');
      if ((typeof record.id === 'string' || typeof record.id === 'number') && typeof resource === 'string') {
        policyTargets.set(JSON.stringify([collection.scope, String(record.id)]),
          `${resource}${typeof assignment === 'string' ? ` (${assignment})` : ''}`);
      }
    }
  }
  const confidenceRank = { high: 0, medium: 1, low: 2 };
  const risks = snapshot.findings.filter(finding => finding.status === 'fail').sort((a, b) =>
    SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id, 'en'));
  for (const finding of risks) {
    const id = stableId('recommendation', finding.domain, finding.checkId, finding.recommendation);
    let group = groups.get(id);
    if (!group) {
      group = {
        id, checkId: finding.checkId, domain: finding.domain, title: finding.title,
        severity: finding.severity, confidence: finding.confidence, recommendation: finding.recommendation,
        findingIds: [], targets: [], evidence: [],
      };
      groups.set(id, group);
    }
    if (confidenceRank[finding.confidence] > confidenceRank[group.confidence]) group.confidence = finding.confidence;
    group.findingIds.push(finding.id);
    const label = finding.checkId.startsWith('AZURE.POLICY.')
      ? policyTargets.get(JSON.stringify([finding.scope, finding.resourceId])) : undefined;
    group.targets.push({ scope: finding.scope, resourceId: finding.resourceId, ...(label ? { label } : {}) });
    group.evidence.push(...finding.evidence);
  }
  for (const group of groups.values()) {
    group.findingIds = [...new Set(group.findingIds)].sort();
    group.targets = [...new Map(group.targets.map(target => [canonicalJson(target), target])).values()]
      .sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b), 'en'));
    group.evidence = [...new Map(group.evidence.map(ref => [canonicalJson(ref), ref])).values()]
      .sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b), 'en'));
  }
  return [...groups.values()].sort((a, b) =>
    SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
    || b.targets.length - a.targets.length || a.id.localeCompare(b.id, 'en'));
}

export interface EvidenceGap {
  collectionId: string;
  provider: Provider;
  title: string;
  status: CollectionStatus;
  reason?: CollectionReason;
  scopes: string[];
  messages: string[];
  permissions: string[];
  manual: boolean;
  nextStep: string;
}

function gapNextStep(reason: CollectionReason | undefined, manual: boolean): string {
  if (manual) return 'Arrange a separate authorized metadata-only review. Extra API privileges will not automate this unsupported capability.';
  switch (reason) {
    case 'not-configured':
      return 'Confirm approval for this source and scope before opting in. No access was requested.';
    case 'permission-denied':
      return 'Have the authorized owner review the documented read permissions for this scope only. A denied request does not establish licensing.';
    case 'authentication-failed':
      return 'Check the existing selected credential and tenant binding. No alternate credential or interactive login was attempted.';
    case 'scope-mismatch':
      return 'Correct the approved tenant, subscription or organization mapping. Do not broaden permissions to bypass a scope mismatch.';
    case 'not-found':
      return 'Verify API support and resource visibility. A 404 does not prove that a control is disabled or a license is missing.';
    case 'not-licensed':
      return 'Confirm the documented entitlement with the product owner; no purchase or license change is assumed.';
    case 'rate-limited':
    case 'timeout':
    case 'limit-reached':
      return 'Use a smaller approved scope or review bounded collection budgets, then reassess. Partial evidence cannot establish absence.';
    case 'dependency-unavailable':
      return 'Obtain the missing prerequisite inventories or supply reviewed offline evidence for the same scope.';
    case 'invalid-response':
      return 'Review the documented metadata contract with sanitized diagnostics. Do not export raw payloads or bypass validation.';
    case 'unsupported':
      return 'Check support in the snapshot tool version and use a supported metadata source. Do not bypass the request allowlist.';
    case 'api-error':
      return 'Review service availability and API support before retrying within the configured bounds.';
    default:
      return 'Review the evidence gap before drawing a posture conclusion. No security pass is inferred.';
  }
}

export function evidenceGaps(snapshot: AssessmentSnapshot): EvidenceGap[] {
  const catalog = new Map(COLLECTION_CATALOG.map(definition => [definition.id, definition]));
  const groups = new Map<string, EvidenceGap>();
  for (const collection of snapshot.collections) {
    if (collection.status === 'complete') continue;
    const key = JSON.stringify([collection.id, collection.provider, collection.status, collection.reason]);
    let group = groups.get(key);
    if (!group) {
      const definition = catalog.get(collection.id);
      const manual = definition?.manual === true;
      group = {
        collectionId: collection.id, provider: collection.provider, title: definition?.title ?? collection.id,
        status: collection.status, ...(collection.reason ? { reason: collection.reason } : {}),
        scopes: [], messages: [], permissions: [...(definition?.permissions ?? [])], manual,
        nextStep: gapNextStep(collection.reason, manual),
      };
      groups.set(key, group);
    }
    group.scopes.push(collection.scope);
    if (collection.message) group.messages.push(collection.message);
  }
  for (const group of groups.values()) {
    group.scopes = [...new Set(group.scopes)].sort();
    group.messages = [...new Set(group.messages)].sort();
  }
  return [...groups.values()].sort((a, b) =>
    `${a.provider}\0${a.collectionId}\0${a.status}\0${a.reason ?? ''}`
      .localeCompare(`${b.provider}\0${b.collectionId}\0${b.status}\0${b.reason ?? ''}`, 'en'));
}

function candidates(groups: RecommendationGroup[]): { quick: RecommendationGroup[]; strategic: RecommendationGroup[] } {
  // No collection establishes implementation effort; only expired metadata is singled out for a cleanup review.
  const quick = groups.filter(group => group.checkId === 'WORKLOAD.CREDENTIAL.EXPIRED').slice(0, 10);
  const ids = new Set(quick.map(group => group.id));
  return { quick, strategic: groups.filter(group => !ids.has(group.id)).slice(0, 10) };
}

export function renderMarkdown(snapshot: AssessmentSnapshot): string {
  const summary = assessmentSummary(snapshot);
  const tenantName = tenantDisplayName(snapshot);
  const repos = repositoryCoverage(snapshot);
  const recommendations = groupedRecommendations(snapshot);
  const priority = candidates(recommendations);
  const gaps = evidenceGaps(snapshot);
  const lines = [
    '# Microsoft cloud security assessment',
    '',
    `Assessment: ${markdown(snapshot.assessmentId)} | UTC: ${markdown(snapshot.collectedAt)}`,
    `Tenant: ${tenantName ? `${markdown(tenantName)} (${markdown(snapshot.scope.tenantId)})` : markdown(snapshot.scope.tenantId)} | Engine: ${markdown(snapshot.toolVersion)}`,
    '',
    '**READ-ONLY. No remediation was executed. This report is sensitive tenant metadata.**',
    '',
    `${summary.risks} observed risks; ${summary.passes} explicitly passing checks; ${summary.unableToAssess} checks unable to assess; ${summary.incompleteCollections} incomplete or unconfigured collections.`,
    '',
    'No findings is not a security pass. Inventory completeness is not effective control coverage. Scores prioritize review, not compliance certification or proof of exploitability. Licensing, consent, API limits and manual controls remain explicit.',
    '',
    '## Priorities',
    '',
    '| Severity | Observed risks |',
    '| --- | ---: |',
    ...SEVERITIES.map(severity => `| ${severity} | ${snapshot.findings.filter(finding => finding.status === 'fail' && finding.severity === severity).length} |`),
    '',
    '## Grouped recommendations',
    '',
    `${recommendations.length} review actions consolidate ${summary.risks} observed risks. Groups preserve distinct affected targets and all individual findings below.`,
    'Sorted by highest observed severity, then distinct logical targets (including resource/policy evaluation pairs, not necessarily distinct physical assets). This is not a measure of exploitability, implementation effort or permission to remediate. Confidence is the lowest among grouped findings.',
    '',
    ...recommendations.flatMap(group => [
      `### ${markdown(group.title)} (${group.severity})`,
      '',
      `${markdown(group.checkId)} | ${group.targets.length} distinct targets | ${group.findingIds.length} findings | Confidence: ${group.confidence}`,
      '',
      markdown(group.recommendation),
      '',
      ...group.targets.map(target => `- ${markdown(target.scope)}: ${markdown(target.label ?? target.resourceId)}${target.label ? ` [evidence target: ${markdown(target.resourceId)}]` : ''}`),
      '',
    ]),
    ...(recommendations.length ? [] : ['No failing checks to consolidate. Unassessed controls still require review.', '']),
    '## Inventory collection outcomes',
    '',
    'Counts refer to collection/scope pairs, not percentages of protected resources. Code-to-cloud reuses its prerequisite inventories.',
    '',
    '| Domain | Complete | Partial | Unavailable | Not configured |',
    '| --- | ---: | ---: | ---: | ---: |',
    ...snapshot.coverage.map(entry => `| ${entry.domain} | ${entry.complete} | ${entry.partial} | ${entry.unavailable} | ${entry.notConfigured} |`),
    '',
    '## Evidence gaps and next steps',
    '',
    'Read permissions below are documentation, not access requests. Confirm authorization for the selected source and scope; do not grant all listed permissions or elevate access to bypass an unsupported API. Manual controls stay separate.',
    '',
    '| Source / collection | Status / reason | Scopes | Next evidence step | Documented read access |',
    '| --- | --- | --- | --- | --- |',
    ...gaps.map(gap => `| ${markdown(`${gap.provider} / ${gap.collectionId}`)} | ${markdown(`${gap.status} / ${gap.reason ?? 'unspecified'}`)} | ${markdown(gap.scopes.join('; '))} | ${markdown(`${gap.nextStep} ${gap.messages.join(' ')}`)} | ${markdown(gap.manual ? 'Manual review; no API grant requested' : gap.permissions.join('; ') || 'Review API documentation; no grant requested')} |`),
    ...(gaps.length ? [] : ['| No collection gaps recorded | Complete caller-visible inventories | Selected scope | Effective security coverage still requires check evidence | No access requested |']),
    '',
    '## Repository security-control coverage',
    '',
    'The denominator is observed repositories only; inaccessible repositories are unknown. An empty alert list does not prove scanning is enabled. HTTP 403/404 is not proof of missing licensing.',
    '',
    '| Repository | Secret scanning | Push protection | Dependabot security updates | Code scanning |',
    '| --- | --- | --- | --- | --- |',
    ...repos.map(repo => `| ${markdown(repo.repository)} | ${repo.secretScanning} | ${repo.pushProtection} | ${repo.dependabotUpdates} | ${repo.codeScanning} |`),
    ...(repos.length ? [] : ['| No repository evidence | Unable to Assess | Unable to Assess | Unable to Assess | Unable to Assess |']),
    '',
    ...repositoryCoverageTotals(repos).map(entry =>
      `- ${entry.control}: ${entry.state}; ${entry.enabled}/${entry.total} observed repositories enabled; ${entry.disabled} disabled; ${entry.unknown} unknown.`),
    '',
    '## Workload identity prioritization',
    '',
    'Scores are advisory and capped at 100. A zero score with incomplete evidence is not low risk. Federation does not cancel other privileges or prove that stored credentials were removed.',
    '',
    '| Identity | Score | Incomplete evidence | Contributing factors |',
    '| --- | ---: | --- | --- |',
    ...[...snapshot.identityRisks].sort((a, b) => b.score - a.score || a.identityId.localeCompare(b.identityId))
      .map(risk => `| ${markdown(risk.displayName)} (${markdown(risk.identityId)}) | ${risk.score} | ${risk.incomplete ? 'Yes' : 'No'} | ${markdown(risk.factors.map(factor => `${factor.name}: +${factor.weight} (${factor.explanation})`).join('; '))} |`),
    '',
    '## Candidate quick wins',
    '',
    'Only expired-credential metadata cleanup is nominated here. Validate dependencies, retention and ownership first; effort and safety are not measured. These are review candidates, never automatic remediations.',
    ...priority.quick.map(group => `- **${markdown(group.title)} (${group.targets.length} distinct targets):** ${markdown(group.recommendation)}`),
    ...(priority.quick.length ? [] : ['No evidence-supported candidates identified. Unassessed controls still require review.']),
    '',
    '## Strategic improvements',
    '',
    'Up to 10 consolidated priorities are shown here; the complete list is in Grouped recommendations.',
    ...priority.strategic.map(group => `- **${markdown(group.title)} (${group.targets.length} distinct targets):** ${markdown(group.recommendation)}`),
    '- Close evidence gaps, validate effective access and role conditions, then reassess with the same scope and risk policy.',
    '- Review identity lifecycle, least-privilege boundaries, workload federation, and source-control-to-runtime trust together.',
    '',
    '## Capability opportunities and context',
    '',
    'These are observed configuration or improvement opportunities, not failed controls or purchasing requirements. Validate licensing, existing alternatives and business requirements.',
    ...snapshot.findings.filter(finding => finding.status === 'informational')
      .map(finding => `- **${markdown(finding.title)}:** ${markdown(finding.description)} ${markdown(finding.recommendation)}`),
    '',
    '## Relationship evidence',
    '',
    `${snapshot.graph.nodes.length} nodes and ${snapshot.graph.edges.length} edges are included in assessment.json. Confirmed relationships describe observed metadata, not confirmed exploitation; potential relationships require validation.`,
    '',
    '## Findings',
    '',
  ];
  for (const finding of snapshot.findings) {
    lines.push(
      `### ${markdown(finding.title)}`,
      '',
      `**${finding.status} / ${finding.severity}** | ${finding.domain} | Confidence: ${finding.confidence}`,
      '',
      `Check: ${markdown(finding.checkId)} | Target: ${markdown(finding.resourceId)} | Scope: ${markdown(finding.scope)}`,
      '',
      markdown(finding.description),
      '',
      `Recommendation: ${markdown(finding.recommendation)}`,
      '',
      `Evidence: ${markdown(evidenceText(finding) || 'No supporting records; manual validation required.')}`,
      '',
      `Zero Trust: ${finding.zeroTrust.join(', ') || 'Not mapped'}`,
      '',
      ...finding.references.filter(safeHttpsUrl).map(reference =>
        `- [Documentation](${reference.replace(/\(/g, '%28').replace(/\)/g, '%29')})`),
      '',
    );
  }
  return `${lines.join('\n')}\n`;
}

export function renderHtml(snapshot: AssessmentSnapshot): string {
  const summary = assessmentSummary(snapshot);
  const tenantName = tenantDisplayName(snapshot);
  const repos = repositoryCoverage(snapshot);
  const recommendations = groupedRecommendations(snapshot);
  const priorities = candidates(recommendations);
  const gaps = evidenceGaps(snapshot);
  const recommendationRows = recommendations.map(group => `<li class="recommendation">
<h3>${escapeHtml(group.title)}</h3><p><strong>${group.severity}</strong> | ${group.targets.length} distinct targets | ${group.findingIds.length} findings | confidence ${group.confidence}</p>
<p>${escapeHtml(group.recommendation)}</p><p>Check: ${escapeHtml(group.checkId)} | <a href="#finding-${encodeURIComponent(group.findingIds[0] ?? '')}">First supporting finding</a></p>
<details><summary>Show all affected targets</summary><ul>${group.targets.map(target =>
    `<li>${escapeHtml(target.scope)}: ${escapeHtml(target.label ?? target.resourceId)}${target.label ? ` <small>(evidence target: ${escapeHtml(target.resourceId)})</small>` : ''}</li>`).join('')}</ul></details></li>`).join('');
  const gapRows = gaps.map(gap => `<tr><th scope="row">${escapeHtml(gap.provider)}<br>${escapeHtml(gap.collectionId)}</th>
<td>${escapeHtml(gap.status)}<br>${escapeHtml(gap.reason ?? 'unspecified')}</td><td>${escapeHtml(gap.scopes.join('; '))}</td>
<td>${escapeHtml(gap.nextStep)}${gap.messages.length ? `<p>${escapeHtml(gap.messages.join(' '))}</p>` : ''}</td>
<td>${escapeHtml(gap.manual ? 'Manual review; no API grant requested' : gap.permissions.join('; ') || 'Review API documentation; no grant requested')}</td></tr>`).join('');
  const repositoryRows = repos.map(repo =>
    `<tr><th scope="row">${escapeHtml(repo.repository)}</th><td>${escapeHtml(repo.secretScanning)}</td><td>${escapeHtml(repo.pushProtection)}</td><td>${escapeHtml(repo.dependabotUpdates)}</td><td>${escapeHtml(repo.codeScanning)}</td></tr>`).join('');
  const repositoryTotals = repositoryCoverageTotals(repos).map(entry =>
    `<li>${escapeHtml(entry.control)}: ${entry.state}; ${entry.enabled}/${entry.total} observed repositories enabled; ${entry.disabled} disabled; ${entry.unknown} unknown.</li>`).join('');
  const priorityList = (findings: Finding[]) => findings.length ? `<ul>${findings.map(finding =>
    `<li><strong>${escapeHtml(finding.title)}:</strong> ${escapeHtml(finding.recommendation)}</li>`).join('')}</ul>`
    : '<p>No evidence-supported candidates identified; unassessed controls still require review.</p>';
  const groupedPriorityList = (groups: RecommendationGroup[]) => groups.length ? `<ul>${groups.map(group =>
    `<li><strong>${escapeHtml(group.title)} (${group.targets.length} distinct targets):</strong> ${escapeHtml(group.recommendation)}</li>`).join('')}</ul>`
    : '<p>No evidence-supported candidates identified; unassessed controls still require review.</p>';
  const rows = snapshot.coverage.map(entry =>
    `<tr><th scope="row">${escapeHtml(entry.domain)}</th><td>${entry.complete}</td><td>${entry.partial}</td><td>${entry.unavailable}</td><td>${entry.notConfigured}</td></tr>`).join('');
  const findings = snapshot.findings.map(finding => `<article id="finding-${escapeHtml(finding.id)}" class="${finding.status === 'fail' ? 'risk' : 'other'}">
<h3>${escapeHtml(finding.title)}</h3><p class="badge">${finding.status} / ${finding.severity} / confidence ${finding.confidence}</p>
<p><strong>Target:</strong> ${escapeHtml(finding.resourceId)} <strong>Scope:</strong> ${escapeHtml(finding.scope)}</p>
<p>${escapeHtml(finding.description)}</p><p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
<p class="evidence"><strong>Evidence:</strong> ${escapeHtml(evidenceText(finding))}</p>
<p>Check: ${escapeHtml(finding.checkId)} | Zero Trust: ${escapeHtml(finding.zeroTrust.join(', '))}</p>
<ul>${finding.references.filter(safeHttpsUrl).map(reference =>
    `<li><a href="${escapeHtml(reference)}" rel="noreferrer noopener">Documentation</a></li>`).join('')}</ul></article>`).join('');
  const identities = [...snapshot.identityRisks].sort((a, b) => b.score - a.score).map(risk =>
    `<tr><th scope="row">${escapeHtml(risk.displayName)}</th><td>${risk.score}</td><td>${risk.incomplete ? 'Yes' : 'No'}</td><td>${escapeHtml(risk.factors.map(factor => `${factor.name}: +${factor.weight} - ${factor.explanation}`).join('; '))}</td></tr>`).join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>Microsoft cloud security assessment</title>
<style>
:root{font-family:system-ui,sans-serif;color:#182638;background:#f3f6fa;line-height:1.6}
body{max-width:1160px;margin:auto;padding:2rem;overflow-wrap:anywhere}h1,h2,h3{line-height:1.25}
h1{font-size:2.2rem}.notice,article,table{background:#fff;border:1px solid #c9d4e2;border-radius:6px}
.notice{padding:1.2rem;border-left:6px solid #2764ad}.stats{font-size:1.15rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{text-align:left;vertical-align:top;padding:.65rem;border-bottom:1px solid #c9d4e2;overflow-wrap:anywhere}
thead{background:#e5edf7}article{padding:1.2rem;margin:1rem 0;overflow-wrap:anywhere}.risk{border-left:6px solid #b53b32}
.other{border-left:6px solid #5f7691}.badge{font-weight:700}.evidence{font-size:.9rem;color:#334a63}
.recommendation{padding:1rem;margin:1rem 0;background:white;border:1px solid #c9d4e2;border-radius:6px;overflow-wrap:anywhere}
.recommendations{list-style:none;padding:0}.table-scroll{max-width:100%;overflow-x:auto}.gap-table{min-width:760px}
summary{cursor:pointer;font-weight:600}nav{display:flex;flex-wrap:wrap;gap:1rem;padding:1rem 0}
a{color:#164d90}@media(max-width:640px){body{padding:1rem}th,td{padding:.4rem;font-size:.85rem}}
@media print{body{background:white;padding:0}article{break-inside:avoid}a{color:inherit}}
</style></head><body><main>
<h1>Microsoft cloud security assessment</h1>
<p>Assessment ${escapeHtml(snapshot.assessmentId)} | ${escapeHtml(snapshot.collectedAt)} | v${escapeHtml(snapshot.toolVersion)}</p>
<p>Tenant: ${tenantName ? `${escapeHtml(tenantName)} (${escapeHtml(snapshot.scope.tenantId)})` : escapeHtml(snapshot.scope.tenantId)}</p>
<nav aria-label="Report sections"><a href="#recommendations">Recommendations</a><a href="#evidence-gaps">Evidence gaps</a><a href="#findings">Individual findings</a></nav>
<div class="notice"><strong>Read-only assessment. No remediation executed.</strong>
<p class="stats">${summary.risks} observed risks; ${summary.passes} explicit passes; ${summary.unableToAssess} checks unable to assess.</p>
<p>${summary.incompleteCollections} collection gaps remain. No findings is not a security pass. Scores are advisory, not certification or proof of exploitability. Treat this report as sensitive tenant metadata.</p></div>
<h2 id="recommendations">Grouped recommendations</h2><p>${recommendations.length} review actions consolidate ${summary.risks} observed risks. All distinct targets and individual findings are retained.</p>
<p>Sorted by highest observed severity, then distinct logical targets, including resource/policy evaluation pairs rather than necessarily distinct physical assets. This is not a measure of exploitability, implementation effort or permission to remediate. Group confidence is the lowest among its findings.</p>
${recommendations.length ? `<ul class="recommendations">${recommendationRows}</ul>` : '<p>No failing checks to consolidate. Unassessed controls still require review.</p>'}
<h2>Inventory collection outcomes</h2><p>Collection/scope counts are not percentages of protected resources.</p>
<table><thead><tr><th>Domain</th><th>Complete</th><th>Partial</th><th>Unavailable</th><th>Not configured</th></tr></thead><tbody>${rows}</tbody></table>
<h2 id="evidence-gaps">Evidence gaps and next steps</h2><p>Read permissions are documentation, not access requests. Confirm scope and authorization. Do not grant every permission or bypass unsupported APIs.</p>
<div class="table-scroll" role="region" aria-label="Evidence gaps table" tabindex="0"><table class="gap-table"><thead><tr><th>Source / collection</th><th>Status / reason</th><th>Scopes</th><th>Next evidence step</th><th>Documented read access</th></tr></thead><tbody>${gapRows || '<tr><td colspan="5">No collection gaps recorded. Complete caller-visible inventories do not prove effective security coverage.</td></tr>'}</tbody></table></div>
<h2>Repository security-control coverage</h2>
<p>The denominator is observed repositories only. Inaccessible repositories are unknown. API availability or an empty alert list does not prove that scanning is enabled; a 403/404 does not prove missing licensing.</p>
<table><thead><tr><th>Repository</th><th>Secret scanning</th><th>Push protection</th><th>Dependabot security updates</th><th>Code scanning</th></tr></thead><tbody>${repositoryRows || '<tr><td colspan="5">Unable to Assess: no repository evidence.</td></tr>'}</tbody></table><ul>${repositoryTotals}</ul>
<h2>Workload identity priorities</h2><p>Scores are capped at 100. Missing evidence cannot establish low risk. All factors and provenance remain in the JSON snapshot.</p>
<table><thead><tr><th>Identity</th><th>Score</th><th>Incomplete</th><th>Factors</th></tr></thead><tbody>${identities}</tbody></table>
<h2>Candidate quick wins</h2><p>Only expired-credential metadata cleanup is nominated. Validate dependencies, retention and ownership first; effort and safety are not measured. No automatic remediation.</p>${groupedPriorityList(priorities.quick)}
<h2>Strategic improvements</h2><p>Up to 10 consolidated priorities are shown here; all actions are in Grouped recommendations.</p>${groupedPriorityList(priorities.strategic)}
<p>Close evidence gaps, validate effective access and role conditions, then reassess with the same scope and risk policy.</p>
<h2>Capability opportunities and context</h2><p>These are not failed controls or purchasing requirements. Validate licensing, existing alternatives and business requirements.</p>${priorityList(snapshot.findings.filter(finding => finding.status === 'informational'))}
<h2>Relationships</h2><p>${snapshot.graph.nodes.length} nodes and ${snapshot.graph.edges.length} edges are retained in the JSON snapshot. Potential control is not confirmed exploitation.</p>
<h2 id="findings">Findings and assessment gaps</h2>${findings}
<footer>Full inventory, relationship graph and evidence: assessment.json. Repository coverage and review priorities: report.md. No remote assets, scripts, telemetry or uploads are used by this report.</footer>
</main></body></html>\n`;
}

export function renderDiffMarkdown(diff: AssessmentDiff): string {
  return [
    '# Security-relevant assessment changes',
    '',
    `${markdown(diff.previousAssessmentId)} -> ${markdown(diff.currentAssessmentId)}`,
    '',
    markdown(diff.caveat),
    '',
    `Findings: ${diff.findings.new.length} new against a comparable baseline, ${diff.findings.resolved.length} explicitly resolved, ${diff.findings.persistent.length} persistent, ${diff.findings.indeterminate.length} indeterminate.`,
    '',
    '| Change | Collection / scope | Record | Fields | Potential impact | Explanation |',
    '| --- | --- | --- | --- | --- | --- |',
    ...diff.changes.map(change =>
      `| ${change.kind} | ${markdown(`${change.collectionId} / ${change.scope}`)} | ${markdown(change.recordId)}${change.parentId ? ` (parent: ${markdown(change.parentId)})` : ''}${change.repository ? ` (${markdown(change.repository)})` : ''} | ${markdown(change.fields.join(', '))} | ${change.securityImpact} | ${markdown(change.description)} |`),
    '',
  ].join('\n');
}
