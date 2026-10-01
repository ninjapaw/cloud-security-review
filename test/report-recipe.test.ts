import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import type { ReportRecipe } from '../src/report-recipe.js';
import {
  buildReportView, emptyNotes, findingScopes, MAX_PROFILE_BYTES, parseNotes, parseRecipe,
  parseReportJson, presetRecipe, PRESET_NAMES, renderRecipeHtml, renderRecipeMarkdown, SECTION_LABELS,
} from '../src/report-recipe.js';
import { stableId } from '../src/safety.js';
import { parseSnapshot } from '../src/validation.js';
import { collection, finding, snapshot, tenant } from './support.js';

function evidence() {
  return parseSnapshot(snapshot([
    collection('entra.users', [{ id: 'user-1', displayName: 'RAW-INVENTORY-NOT-FOR-EXPORT' }]),
    collection('entra.riskyUsers', [], { status: 'unavailable', reason: 'permission-denied' }),
  ], [
    finding({ id: 'high', resourceId: 'user-1', title: 'Observed priority', description: 'INCLUDED-FINDING' }),
    finding({ id: 'low', severity: 'low', title: 'EXCLUDED-LOW-FINDING', description: 'EXCLUDED-LOW-DESCRIPTION' }),
    finding({ id: 'unknown', status: 'unable-to-assess', severity: 'informational', title: 'Collection gap' }),
    finding({ id: 'pass', status: 'pass', severity: 'informational', title: 'Explicit pass' }),
  ]));
}

test('portable SHA-256 preserves existing stable identifiers exactly', () => {
  const cases = [[], ['one'], ['tenant', 'scope', 'record'], ['Cr\u00e9dit', '\ud83d\udc3e', '\ud800'], ['a|b', 'c'], ['a', 'b|c']];
  for (const parts of cases) {
    assert.equal(stableId(...parts), createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 24));
  }
});

test('all presets are strict valid recipes with independent arrays and no assessment data', () => {
  for (const name of PRESET_NAMES) {
    const recipe = presetRecipe(name);
    assert.deepEqual(parseRecipe(recipe), recipe);
    assert.equal(recipe.kind, 'cloud-security-report-recipe');
    assert.equal(recipe.scope, null);
    assert.ok(!JSON.stringify(recipe).includes('assessmentId'));
  }
  const altered = presetRecipe('technical');
  altered.domains.pop();
  altered.sections.reverse();
  assert.notDeepEqual(altered, presetRecipe('technical'));
  assert.deepEqual(presetRecipe('executive').sections, ['recommendations', 'notes']);
});

test('recipe validation rejects executable extensions, duplicates, wrong versions and invalid limits', () => {
  const recipe = presetRecipe('technical');
  const invalid = [
    { ...recipe, schemaVersion: '2.0' },
    { ...recipe, sections: ['findings', 'findings'] },
    { ...recipe, sections: ['arbitrary-html'] },
    { ...recipe, domains: ['not-a-domain'] },
    { ...recipe, statuses: ['secure'] },
    { ...recipe, findingLimit: 0 },
    { ...recipe, findingLimit: 501 },
    { ...recipe, findingLimit: 1.5 },
    { ...recipe, title: ' ' },
    { ...recipe, script: 'DO-NOT-ECHO-CUSTOM-CODE' },
  ];
  for (const value of invalid) {
    assert.throws(() => parseRecipe(value), error => {
      assert.ok(error instanceof Error);
      assert.ok(!error.message.includes('DO-NOT-ECHO'));
      return true;
    });
  }
});

test('configured views never mutate findings, source scope or risk policy', () => {
  const original = evidence();
  const before = structuredClone(original);
  const recipe = presetRecipe('technical');
  const view = buildReportView(original, recipe);
  view.findings[0]!.description = 'changed display copy';
  view.findings[0]!.references.push('https://example.invalid/');
  view.findings[0]!.evidence[0]!.scope = 'display-only-change';
  view.recommendations[0]!.evidence[0]!.scope = 'another-display-only-change';
  view.recipe.domains.pop();
  assert.deepEqual(original, before);
  assert.deepEqual(recipe, presetRecipe('technical'));
  assert.equal(view.source.toolVersion, original.toolVersion);
});

test('filtered and limited content is physically omitted while mandatory source disclosures remain', () => {
  const source = evidence();
  source.graph.nodes.push({ id: 'unselected-node', type: 'test', label: 'RAW-GRAPH-NOT-FOR-EXPORT', properties: {}, evidence: [] });
  const recipe: ReportRecipe = {
    ...presetRecipe('technical'), severities: ['high'], statuses: ['fail'], findingLimit: 1,
  };
  const view = buildReportView(source, recipe);
  assert.equal(view.shownCount, 1);
  assert.equal(view.matchedCount, 1);
  assert.equal(view.excludedCount, 3);
  assert.equal(view.source.totals.risks, 2);
  assert.equal(view.source.totals.unableToAssess, 1);
  assert.equal(view.source.totals.incompleteCollections, 1);
  assert.equal(view.coverage.find(row => row.provider === 'graph')?.unavailable, 1);
  for (const rendered of [JSON.stringify(view), renderRecipeHtml(view), renderRecipeMarkdown(view)]) {
    assert.ok(!rendered.includes('EXCLUDED-LOW'));
    assert.ok(!rendered.includes('RAW-INVENTORY'));
    assert.ok(!rendered.includes('RAW-GRAPH'));
    assert.ok(rendered.includes('INCLUDED-FINDING'));
    assert.ok(rendered.includes(tenant));
  }
  for (const rendered of [renderRecipeHtml(view), renderRecipeMarkdown(view)]) {
    assert.ok(rendered.includes('No findings is not a security pass'));
    assert.ok(rendered.includes('3 excluded by filters'));
    assert.ok(rendered.includes('Source evidence coverage'));
    assert.ok(rendered.includes(source.collectedAt));
  }
});

test('zero selected domains or sections cannot hide evidence gaps or imply a security pass', () => {
  const view = buildReportView(evidence(), { ...presetRecipe('technical'), domains: [], sections: [] });
  assert.equal(view.shownCount, 0);
  assert.deepEqual(view.findings, []);
  assert.deepEqual(view.recommendations, []);
  for (const rendered of [renderRecipeHtml(view), renderRecipeMarkdown(view)]) {
    assert.ok(rendered.includes('Domains: none'));
    assert.ok(rendered.includes('Optional sections: none'));
    assert.ok(rendered.includes('1 incomplete collection/scope pairs'));
    assert.ok(rendered.includes('Source evidence coverage'));
  }
});

test('limit disclosure distinguishes matches omitted by the cap from excluded filters', () => {
  const view = buildReportView(evidence(), { ...presetRecipe('technical'), findingLimit: 1 });
  assert.equal(view.matchedCount, 4);
  assert.equal(view.shownCount, 1);
  assert.equal(view.excludedCount, 0);
  assert.equal(view.limitedCount, 3);
  assert.equal(view.findings[0]?.id, 'high');
  assert.ok(renderRecipeHtml(view).includes('3 additional matches omitted by the limit'));
});

test('scope filtering is exact and unavailable scopes are explicit errors, never an all-scope fallback', () => {
  const source = evidence();
  source.findings.push(finding({ id: 'another-scope', scope: 'example-org/repo', domain: 'github', title: 'OTHER-SCOPE-FINDING' }));
  assert.deepEqual(findingScopes(source), [tenant, 'example-org/repo'].sort());
  const view = buildReportView(source, { ...presetRecipe('technical'), scope: tenant });
  assert.ok(!renderRecipeHtml(view).includes('OTHER-SCOPE-FINDING'));
  assert.throws(() => buildReportView(source, { ...presetRecipe('technical'), scope: 'missing' }), /scope absent/);
});

test('evidence-reference switch removes references from both report formats without editing the source', () => {
  const source = evidence();
  source.collections[0]!.records.push({ id: 'REFERENCE-ONLY-IDENTIFIER' });
  source.findings[0]!.evidence = [{ collectionId: 'entra.users', scope: tenant, recordId: 'REFERENCE-ONLY-IDENTIFIER' }];
  source.findings[0]!.references = ['https://example.invalid/reference-only-doc'];
  const view = buildReportView(source, { ...presetRecipe('technical'), includeEvidence: false });
  for (const rendered of [renderRecipeHtml(view), renderRecipeMarkdown(view)]) {
    assert.ok(!rendered.includes('REFERENCE-ONLY-IDENTIFIER'));
    assert.ok(!rendered.includes('reference-only-doc'));
    assert.ok(rendered.includes('Evidence references: omitted'));
  }
  assert.equal(source.findings[0]!.evidence[0]?.recordId, 'REFERENCE-ONLY-IDENTIFIER');
});

test('section ordering is preserved in both exports and in the recipe identifier', () => {
  const source = evidence();
  const notes = { ...emptyNotes(source.assessmentId), author: 'Reviewer', text: 'Manual follow-up required.' };
  const recipe: ReportRecipe = { ...presetRecipe('technical'), sections: ['notes', 'findings', 'recommendations'] };
  const view = buildReportView(source, recipe, notes);
  for (const rendered of [renderRecipeHtml(view), renderRecipeMarkdown(view)]) {
    assert.ok(rendered.indexOf(SECTION_LABELS.notes) < rendered.indexOf(SECTION_LABELS.findings));
    assert.ok(rendered.indexOf(SECTION_LABELS.findings) < rendered.indexOf(SECTION_LABELS.recommendations));
  }
  assert.notEqual(view.recipeId, buildReportView(source, { ...recipe, sections: [...recipe.sections].reverse() }, notes).recipeId);
  assert.equal(view.recipeId, buildReportView(source, recipe, notes).recipeId);
});

test('analyst notes are separate, bound to an assessment, and excluded when their section is disabled', () => {
  const source = evidence();
  const notes = { ...emptyNotes(source.assessmentId), text: 'SEPARATE-ANALYST-COMMENTARY' };
  assert.deepEqual(parseNotes(notes, source.assessmentId), notes);
  assert.throws(() => parseNotes(notes, 'different-assessment'), /different assessment/);
  const included = buildReportView(source, presetRecipe('technical'), notes);
  const excluded = buildReportView(source, { ...presetRecipe('technical'), sections: ['findings'] }, notes);
  assert.ok(renderRecipeHtml(included).includes('Analyst commentary, not collected evidence'));
  assert.ok(!JSON.stringify(source).includes(notes.text));
  assert.ok(!JSON.stringify(included.recipe).includes(notes.text));
  assert.ok(!JSON.stringify(excluded).includes(notes.text));
  assert.throws(() => parseNotes({ ...notes, text: `ghp_${'X'.repeat(36)}` }, source.assessmentId), /Credential-shaped/);
});

test('all free text remains escaped; exported HTML has no scripts, remote assets or embedded inventory', () => {
  const malicious = '<img src=x onerror="alert(1)"> [click](javascript:alert(1))';
  const source = evidence();
  source.findings[0]!.title = malicious;
  const notes = { ...emptyNotes(source.assessmentId), author: malicious, text: malicious };
  const view = buildReportView(source, { ...presetRecipe('technical'), title: malicious }, notes);
  const html = renderRecipeHtml(view);
  const markdown = renderRecipeMarkdown(view);
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<script'));
  assert.ok(!html.includes('<link'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes("default-src 'none'"));
  assert.ok(html.includes('@media print'));
  assert.ok(!markdown.includes('[click](javascript:'));
  assert.ok(!markdown.includes('<img'));
});

test('malformed or excessive JSON is rejected without echoing file contents', () => {
  assert.throws(() => parseReportJson('{"private": NEVER-ECHO-THIS }'), error => {
    assert.ok(error instanceof Error);
    assert.ok(!error.message.includes('NEVER-ECHO'));
    return true;
  });
  assert.throws(() => parseReportJson(' '.repeat(MAX_PROFILE_BYTES + 1), MAX_PROFILE_BYTES), /size limit/);
  assert.deepEqual(parseReportJson('{"schemaVersion":"1.0"}'), { schemaVersion: '1.0' });
});
