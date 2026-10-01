import { z } from 'zod';
import { DOMAINS, PROVIDERS, SEVERITIES } from './model.js';
import type { AssessmentSnapshot, Finding, Provider } from './model.js';
import { assessmentSummary, escapeHtml, escapeMarkdown, groupedRecommendations } from './report.js';
import type { RecommendationGroup } from './report.js';
import { AssessmentError, safeHttpsUrl, stableId } from './safety.js';
import { validate } from './validation.js';

export const MAX_SNAPSHOT_BYTES = 50 * 1024 * 1024;
export const MAX_PROFILE_BYTES = 256 * 1024;
export const REPORT_SECTIONS = ['recommendations', 'findings', 'notes'] as const;
export const FINDING_STATUSES = ['fail', 'unable-to-assess', 'informational', 'pass'] as const;
export const PRESET_NAMES = ['executive', 'technical', 'code-to-cloud'] as const;
export type ReportSection = typeof REPORT_SECTIONS[number];
export type ReportPreset = typeof PRESET_NAMES[number];

export const SECTION_LABELS: Record<ReportSection, string> = {
  recommendations: 'What should we address first?',
  findings: 'What supports these conclusions?',
  notes: 'What context has the analyst added?',
};

const unique = <T>(values: T[]): boolean => new Set(values).size === values.length;
const recipeSchema = z.object({
  kind: z.literal('cloud-security-report-recipe'),
  schemaVersion: z.literal('1.0'),
  title: z.string().trim().min(1).max(120),
  domains: z.array(z.enum(DOMAINS)).max(DOMAINS.length).refine(unique),
  severities: z.array(z.enum(SEVERITIES)).max(SEVERITIES.length).refine(unique),
  statuses: z.array(z.enum(FINDING_STATUSES)).max(FINDING_STATUSES.length).refine(unique),
  scope: z.string().min(1).max(4096).nullable(),
  sections: z.array(z.enum(REPORT_SECTIONS)).max(REPORT_SECTIONS.length).refine(unique),
  includeEvidence: z.boolean(),
  findingLimit: z.number().int().min(1).max(500),
}).strict();

const notesSchema = z.object({
  kind: z.literal('cloud-security-report-notes'),
  schemaVersion: z.literal('1.0'),
  assessmentId: z.string().min(1).max(1000),
  author: z.string().max(120),
  text: z.string().max(10000),
}).strict();

export type ReportRecipe = z.infer<typeof recipeSchema>;
export type ReportNotes = z.infer<typeof notesSchema>;

export function parseRecipe(value: unknown): ReportRecipe {
  return validate(recipeSchema, value, 'Report recipe');
}

export function parseNotes(value: unknown, assessmentId: string): ReportNotes {
  const notes = validate(notesSchema, value, 'Analyst notes');
  if (notes.assessmentId !== assessmentId) {
    throw new AssessmentError('notes-scope-mismatch', 'These analyst notes belong to a different assessment. They were not applied.');
  }
  return notes;
}

export function parseReportJson(contents: string, limit = MAX_SNAPSHOT_BYTES): unknown {
  if (new TextEncoder().encode(contents).byteLength > limit) {
    throw new AssessmentError('input-limit', 'The selected JSON file exceeds its supported size limit.');
  }
  try {
    return JSON.parse(contents);
  } catch {
    throw new AssessmentError('invalid-json', 'The selected file is not valid JSON. Its contents have not been logged.');
  }
}

export function emptyNotes(assessmentId: string): ReportNotes {
  return {
    kind: 'cloud-security-report-notes', schemaVersion: '1.0', assessmentId, author: '', text: '',
  };
}

export function presetRecipe(preset: ReportPreset): ReportRecipe {
  const recipe: ReportRecipe = {
    kind: 'cloud-security-report-recipe', schemaVersion: '1.0',
    title: 'Technical security assessment',
    domains: [...DOMAINS], severities: [...SEVERITIES], statuses: [...FINDING_STATUSES],
    scope: null, sections: [...REPORT_SECTIONS], includeEvidence: true, findingLimit: 250,
  };
  if (preset === 'executive') {
    recipe.title = 'Executive security brief';
    recipe.severities = ['critical', 'high', 'medium'];
    recipe.statuses = ['fail'];
    recipe.sections = ['recommendations', 'notes'];
    recipe.includeEvidence = false;
    recipe.findingLimit = 25;
  } else if (preset === 'code-to-cloud') {
    recipe.title = 'Code-to-cloud security review';
    recipe.domains = ['code-to-cloud', 'github', 'azure-devops', 'workload-identities', 'azure', 'defender-cloud'];
    recipe.statuses = ['fail', 'unable-to-assess', 'informational'];
    recipe.findingLimit = 100;
  }
  return recipe;
}

export function findingScopes(snapshot: AssessmentSnapshot): string[] {
  return [...new Set(snapshot.findings.map(finding => finding.scope))].sort();
}

export interface ReportView {
  source: {
    assessmentId: string;
    tenantId: string;
    collectedAt: string;
    toolVersion: string;
    subscriptionCount: number;
    githubOrganizationCount: number;
    azureDevOpsOrganizationCount: number;
    findingCount: number;
    totals: ReturnType<typeof assessmentSummary>;
  };
  recipe: ReportRecipe;
  recipeId: string;
  matchedCount: number;
  shownCount: number;
  excludedCount: number;
  limitedCount: number;
  selectedTotals: ReturnType<typeof assessmentSummary>;
  recommendations: RecommendationGroup[];
  findings: Finding[];
  notes?: ReportNotes;
  coverage: {
    provider: Provider;
    complete: number;
    partial: number;
    unavailable: number;
    notConfigured: number;
  }[];
}

/** Takes an already validated snapshot. Selection never edits evidence or reruns risk scoring. */
export function buildReportView(snapshot: AssessmentSnapshot, rawRecipe: ReportRecipe, rawNotes?: ReportNotes): ReportView {
  const recipe = parseRecipe(rawRecipe);
  const notes = rawNotes ? parseNotes(rawNotes, snapshot.assessmentId) : undefined;
  if (recipe.scope !== null && !findingScopes(snapshot).includes(recipe.scope)) {
    throw new AssessmentError('report-scope-mismatch', 'The recipe selects a finding scope absent from this assessment. Choose an available scope or all scopes.');
  }
  const matched = snapshot.findings.filter(finding =>
    recipe.domains.includes(finding.domain) && recipe.severities.includes(finding.severity)
    && recipe.statuses.includes(finding.status) && (recipe.scope === null || finding.scope === recipe.scope))
    .sort((a, b) => FINDING_STATUSES.indexOf(a.status) - FINDING_STATUSES.indexOf(b.status)
      || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id, 'en'));
  const selected = matched.slice(0, recipe.findingLimit);
  const selection = { ...snapshot, findings: selected };
  const recommendations = recipe.sections.includes('recommendations') ? groupedRecommendations(selection)
    .map(group => ({ ...group, evidence: recipe.includeEvidence ? group.evidence.map(ref => ({ ...ref })) : [] })) : [];
  const findings = recipe.sections.includes('findings') ? selected.map(finding => ({
    ...finding, evidence: recipe.includeEvidence ? finding.evidence.map(ref => ({ ...ref })) : [],
    references: recipe.includeEvidence ? [...finding.references] : [], zeroTrust: [...finding.zeroTrust],
  })) : [];
  return {
    source: {
      assessmentId: snapshot.assessmentId, tenantId: snapshot.scope.tenantId,
      collectedAt: snapshot.collectedAt, toolVersion: snapshot.toolVersion,
      subscriptionCount: snapshot.scope.subscriptionIds.length,
      githubOrganizationCount: snapshot.scope.githubOrganizations.length,
      azureDevOpsOrganizationCount: snapshot.scope.azureDevOpsOrganizations.length,
      findingCount: snapshot.findings.length, totals: assessmentSummary(snapshot),
    },
    recipe, recipeId: stableId('report-recipe', JSON.stringify(recipe)),
    matchedCount: matched.length, shownCount: selected.length,
    excludedCount: snapshot.findings.length - matched.length, limitedCount: matched.length - selected.length,
    selectedTotals: assessmentSummary(selection), recommendations, findings,
    ...(recipe.sections.includes('notes') && notes ? { notes: { ...notes } } : {}),
    coverage: PROVIDERS.map(provider => {
      const entries = snapshot.collections.filter(collection => collection.provider === provider);
      return {
        provider,
        complete: entries.filter(entry => entry.status === 'complete').length,
        partial: entries.filter(entry => entry.status === 'partial').length,
        unavailable: entries.filter(entry => entry.status === 'unavailable').length,
        notConfigured: entries.filter(entry => entry.status === 'not-configured').length,
      };
    }),
  };
}

function filters(view: ReportView): string[] {
  return [
    `Domains: ${view.recipe.domains.join(', ') || 'none'}`,
    `Severities: ${view.recipe.severities.join(', ') || 'none'}`,
    `Statuses: ${view.recipe.statuses.join(', ') || 'none'}`,
    `Finding scope: ${view.recipe.scope ?? 'all source finding scopes'}`,
    `Limit: ${view.recipe.findingLimit} findings, sorted by status, severity and stable identifier`,
    `Optional sections: ${view.recipe.sections.join(', ') || 'none'}`,
    `Evidence references: ${view.recipe.includeEvidence ? 'included for selected content' : 'omitted'}`,
  ];
}

function evidenceText(finding: Finding): string {
  return finding.evidence.map(ref => `${ref.collectionId} (${ref.scope})${ref.recordId ? ` #${ref.recordId}` : ''}${ref.field ? ` / ${ref.field}` : ''}`).join('; ');
}

function recommendationsHtml(view: ReportView): string {
  return view.recommendations.length ? view.recommendations.map(group => `<article>
<h3>${escapeHtml(group.title)}</h3><p><strong>${group.severity}</strong> | ${group.targets.length} distinct targets | ${group.findingIds.length} findings | confidence ${group.confidence}</p>
<p>${escapeHtml(group.recommendation)}</p><p>Check: ${escapeHtml(group.checkId)}</p>
<ul>${group.targets.map(target => `<li>${escapeHtml(target.scope)}: ${escapeHtml(target.label ?? target.resourceId)}</li>`).join('')}</ul>
${view.recipe.includeEvidence ? `<p class="evidence">Finding references: ${group.findingIds.map(escapeHtml).join(', ')}</p>` : ''}</article>`).join('')
    : '<p>No failing findings are included by this recipe. This is not a security pass.</p>';
}

function findingsHtml(view: ReportView): string {
  return view.findings.length ? view.findings.map(finding => `<article>
<h3>${escapeHtml(finding.title)}</h3><p><strong>${finding.status} / ${finding.severity}</strong> | ${finding.domain} | confidence ${finding.confidence}</p>
<p>Target: ${escapeHtml(finding.resourceId)} | Scope: ${escapeHtml(finding.scope)}</p>
<p>${escapeHtml(finding.description)}</p><p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
<p>Check: ${escapeHtml(finding.checkId)} | Zero Trust: ${escapeHtml(finding.zeroTrust.join(', ') || 'not mapped')}</p>
${view.recipe.includeEvidence ? `<p class="evidence">Evidence: ${escapeHtml(evidenceText(finding) || 'No record references; manual validation required.')}</p>
<ul>${finding.references.filter(safeHttpsUrl).map(reference => `<li><a href="${escapeHtml(reference)}" rel="noopener noreferrer">Documentation</a></li>`).join('')}</ul>` : ''}</article>`).join('')
    : '<p>No findings are included by this recipe. Review the exclusions and source coverage before drawing conclusions.</p>';
}

function notesHtml(notes?: ReportNotes): string {
  return notes?.text.trim() ? `<article><p><strong>Analyst commentary, not collected evidence.</strong> Author: ${escapeHtml(notes.author || 'not specified')}</p>
<div class="notes">${escapeHtml(notes.text)}</div></article>` : '<p>No analyst commentary was supplied.</p>';
}

export function renderRecipeHtml(view: ReportView): string {
  const parts: Record<ReportSection, string> = {
    recommendations: recommendationsHtml(view), findings: findingsHtml(view), notes: notesHtml(view.notes),
  };
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>${escapeHtml(view.recipe.title)}</title><style>
:root{font-family:system-ui,sans-serif;color:#192b37;background:#fff;line-height:1.6}
body{max-width:1000px;margin:auto;padding:2rem;overflow-wrap:anywhere}h1,h2,h3{line-height:1.25}
h1{font-size:2.15rem}h2{margin-top:2.2rem}article{padding:1.1rem;margin:1rem 0;border:1px solid #cbd8dc;border-left:4px solid #087c78;border-radius:5px}
.notice{background:#eef8f7;border:1px solid #99cfca;padding:1rem;border-radius:5px}.evidence,footer{font-size:.85rem;color:#40555f}
.notes{white-space:pre-wrap}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border-bottom:1px solid #cbd8dc;padding:.55rem;text-align:left}
thead{background:#edf3f4}a{color:#096660}@media(max-width:600px){body{padding:1rem}th,td{font-size:.8rem;padding:.3rem}}
@media print{@page{margin:15mm}body{padding:0;font-size:10pt}article{break-inside:avoid}h2,h3{break-after:avoid}thead{display:table-header-group}a{color:inherit}}
</style></head><body><main>
<h1>${escapeHtml(view.recipe.title)}</h1>
<p>Assessment: ${escapeHtml(view.source.assessmentId)} | Tenant: ${escapeHtml(view.source.tenantId)}<br>
Evidence as of ${escapeHtml(view.source.collectedAt)} | Assessment engine ${escapeHtml(view.source.toolVersion)} | Recipe ${view.recipeId}</p>
<div class="notice"><strong>Read-only assessment. No remediation executed.</strong>
<p>This is a configured view of an existing assessment, not a new assessment or a risk-policy change. Source findings, severity and scores have not been edited.</p>
<p>Source totals: ${view.source.totals.risks} risks; ${view.source.totals.unableToAssess} checks unable to assess; ${view.source.totals.incompleteCollections} incomplete collection/scope pairs.</p>
<p>${view.shownCount} findings selected from ${view.matchedCount} matches and ${view.source.findingCount} source findings.
${view.excludedCount} excluded by filters; ${view.limitedCount} additional matches omitted by the limit.</p>
<p>Selected: ${view.selectedTotals.risks} risks, ${view.selectedTotals.unableToAssess} unable to assess, ${view.selectedTotals.passes} explicit passes.
No findings is not a security pass. Filters are not automatic de-identification; review every export before sharing.</p></div>
<h2>Selection and scope disclosure</h2><ul>${filters(view).map(filter => `<li>${escapeHtml(filter)}</li>`).join('')}</ul>
<p>The original assessment selected ${view.source.subscriptionCount} subscriptions, ${view.source.githubOrganizationCount} GitHub organizations and ${view.source.azureDevOpsOrganizationCount} Azure DevOps organizations. A finding-scope filter does not recalculate cross-platform risk scores.</p>
<h2>Source evidence coverage</h2><p>This unfiltered coverage summary cannot be removed by a recipe. Counts describe collection/scope pairs in the caller's view, not protected assets. Inaccessible or unsupported controls remain unknown; licenses are not inferred from access failures. Consult the restricted source snapshot for gap details.</p>
<table><thead><tr><th>Source</th><th>Complete</th><th>Partial</th><th>Unavailable</th><th>Not configured</th></tr></thead>
<tbody>${view.coverage.map(entry => `<tr><th scope="row">${entry.provider}</th><td>${entry.complete}</td><td>${entry.partial}</td><td>${entry.unavailable}</td><td>${entry.notConfigured}</td></tr>`).join('')}</tbody></table>
${view.recipe.sections.map(section => `<section><h2>${SECTION_LABELS[section]}</h2>${parts[section]}</section>`).join('')}
<footer>Report Studio presentation only. Imported evidence is not signed or independently authenticated by this view. Raw inventory, hidden findings and relationship datasets are not embedded. Analyst notes are separate assertions, not assessment evidence. Treat this report as sensitive.</footer>
</main></body></html>\n`;
}

export function renderRecipeMarkdown(view: ReportView): string {
  const md = escapeMarkdown;
  const lines = [
    `# ${md(view.recipe.title)}`, '',
    `Assessment: ${md(view.source.assessmentId)} | Tenant: ${md(view.source.tenantId)}`,
    `Evidence as of ${md(view.source.collectedAt)} | Assessment engine ${md(view.source.toolVersion)} | Recipe ${view.recipeId}`, '',
    '**READ-ONLY. No remediation executed. This is a configured view, not a new assessment or a risk-policy change.**', '',
    `Source totals: ${view.source.totals.risks} risks; ${view.source.totals.unableToAssess} checks unable to assess; ${view.source.totals.incompleteCollections} incomplete collection/scope pairs.`,
    `${view.shownCount} findings selected from ${view.matchedCount} matches and ${view.source.findingCount} source findings. ${view.excludedCount} excluded by filters; ${view.limitedCount} additional matches omitted by the limit.`,
    `Selected: ${view.selectedTotals.risks} risks, ${view.selectedTotals.unableToAssess} unable to assess, ${view.selectedTotals.passes} explicit passes.`,
    'No findings is not a security pass. Filters are not automatic de-identification; review every export before sharing.', '',
    '## Selection and scope disclosure', '',
    ...filters(view).map(filter => `- ${md(filter)}`), '',
    `The original assessment selected ${view.source.subscriptionCount} subscriptions, ${view.source.githubOrganizationCount} GitHub organizations and ${view.source.azureDevOpsOrganizationCount} Azure DevOps organizations. A finding-scope filter does not recalculate cross-platform risk scores.`, '',
    '## Source evidence coverage', '',
    'This unfiltered summary cannot be removed. Counts describe collection/scope pairs, not protected assets. Unknown controls remain unknown; licenses are not inferred from access failures. Consult the restricted source snapshot for gap details.', '',
    '| Source | Complete | Partial | Unavailable | Not configured |',
    '| --- | ---: | ---: | ---: | ---: |',
    ...view.coverage.map(entry => `| ${entry.provider} | ${entry.complete} | ${entry.partial} | ${entry.unavailable} | ${entry.notConfigured} |`), '',
  ];
  for (const section of view.recipe.sections) {
    lines.push(`## ${SECTION_LABELS[section]}`, '');
    if (section === 'recommendations') {
      for (const group of view.recommendations) {
        lines.push(`### ${md(group.title)}`, '', `**${group.severity}** | ${group.targets.length} distinct targets | ${group.findingIds.length} findings | confidence ${group.confidence}`,
          '', md(group.recommendation), '', `Check: ${md(group.checkId)}`, '',
          ...group.targets.map(target => `- ${md(target.scope)}: ${md(target.label ?? target.resourceId)}`), '');
        if (view.recipe.includeEvidence) lines.push(`Finding references: ${md(group.findingIds.join(', '))}`, '');
      }
      if (!view.recommendations.length) lines.push('No failing findings are included by this recipe. This is not a security pass.', '');
    } else if (section === 'findings') {
      for (const finding of view.findings) {
        lines.push(`### ${md(finding.title)}`, '', `**${finding.status} / ${finding.severity}** | ${finding.domain} | confidence ${finding.confidence}`,
          '', `Target: ${md(finding.resourceId)} | Scope: ${md(finding.scope)}`,
          '', md(finding.description), '', `Recommendation: ${md(finding.recommendation)}`,
          '', `Check: ${md(finding.checkId)} | Zero Trust: ${md(finding.zeroTrust.join(', ') || 'not mapped')}`, '');
        if (view.recipe.includeEvidence) lines.push(
          `Evidence: ${md(evidenceText(finding) || 'No record references; manual validation required.')}`, '',
          ...finding.references.filter(safeHttpsUrl).map(reference =>
            `- [Documentation](${reference.replace(/\(/g, '%28').replace(/\)/g, '%29')})`), '');
      }
      if (!view.findings.length) lines.push('No findings are included. Review exclusions and source coverage before drawing conclusions.', '');
    } else {
      lines.push(view.notes?.text.trim()
        ? `**Analyst commentary, not collected evidence.** Author: ${md(view.notes.author || 'not specified')}\n\n${view.notes.text.split(/\r?\n/).map(md).join('\n\n')}`
        : 'No analyst commentary was supplied.', '');
    }
  }
  lines.push('Imported evidence is not signed or independently authenticated by this view. Raw inventory, hidden findings and relationship datasets are not embedded. Treat this report as sensitive.', '');
  return lines.join('\n');
}
