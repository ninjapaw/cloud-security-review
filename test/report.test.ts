import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assessmentSummary, evidenceGaps, groupedRecommendations, renderDiffMarkdown,
  renderHtml, renderMarkdown, repositoryCoverage, repositoryCoverageTotals,
} from '../src/report.js';
import { compareSnapshots } from '../src/diff.js';
import { collection, finding, snapshot, subscription, tenant } from './support.js';

test('HTML and Markdown reports escape untrusted labels without executable content', () => {
  const malicious = '<img src=x onerror="alert(1)"> [click](javascript:alert(1)) | extra';
  const value = snapshot([collection()], [finding({ title: malicious, description: malicious, resourceId: malicious })]);
  const html = renderHtml(value);
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<script'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes("default-src 'none'"));
  assert.ok(html.includes('name="referrer" content="no-referrer"'));
  const md = renderMarkdown(value);
  assert.ok(!md.includes('<img'));
  assert.ok(!md.includes('[click](javascript:'));
  assert.ok(md.includes('\\| extra'));
});

test('reports do not equate missing evidence or zero scores with security', () => {
  const value = snapshot([
    collection('entra.users', [], { status: 'unavailable', reason: 'permission-denied' }),
  ], [finding({ status: 'unable-to-assess' })]);
  value.identityRisks.push({
    identityId: 'sp-1', displayName: 'Unknown service principal', score: 0,
    factors: [], incomplete: true, caveat: 'Not enough evidence.',
  });
  assert.deepEqual(assessmentSummary(value), { risks: 0, passes: 0, unableToAssess: 1, incompleteCollections: 1 });
  assert.ok(renderMarkdown(value).includes('zero score with incomplete evidence is not low risk'));
  assert.ok(renderHtml(value).includes('No findings is not a security pass'));
});

test('repository coverage separates explicit disabled, unknown, and API availability', () => {
  const value = snapshot([
    collection('github.repositories', [
      { id: 1, full_name: 'example-org/one', security_and_analysis: { secret_scanning: { status: 'enabled' }, secret_scanning_push_protection: { status: 'disabled' } } },
      { id: 2, full_name: 'example-org/two' },
    ], { provider: 'github', scope: 'example-org' }),
    collection('github.codeScanningAlerts', [], { provider: 'github', scope: 'example-org/one' }),
    collection('github.codeScanningAlerts', [], { provider: 'github', scope: 'example-org/two', status: 'unavailable', reason: 'permission-denied' }),
  ]);
  const repos = repositoryCoverage(value);
  assert.equal(repos[0]?.secretScanning, 'Enabled');
  assert.equal(repos[0]?.pushProtection, 'Disabled');
  assert.match(repos[0]?.codeScanning ?? '', /^Available/);
  assert.equal(repos[1]?.secretScanning, 'Unable to Assess');
  assert.equal(repos[1]?.codeScanning, 'Unable to Assess');
  assert.ok(renderMarkdown(value).includes('1/2 observed repositories enabled'));
  assert.ok(renderHtml(value).includes('1/2 observed repositories enabled'));
  assert.equal(repositoryCoverageTotals(repos)[0]?.state, 'Unable to Assess');
  repos[1]!.secretScanning = 'Disabled';
  assert.equal(repositoryCoverageTotals(repos)[0]?.state, 'Partially deployed');
});

test('finding documentation links are allowlisted by scheme and evidence is included', () => {
  const value = snapshot([collection()], [finding({ references: ['javascript:alert(1)', 'https://learn.microsoft.com/en-us/graph/overview'] })]);
  assert.ok(!renderHtml(value).includes('href="javascript:'));
  assert.ok(!renderMarkdown(value).includes('Documentation](javascript:'));
  assert.ok(renderHtml(value).includes('entra.users'));
  assert.ok(renderMarkdown(value).includes('least-privilege'));
});

test('change reports preserve indeterminate findings and do not infer malice', () => {
  const diff = compareSnapshots(snapshot([collection()], [finding()]), snapshot());
  const md = renderDiffMarkdown(diff);
  assert.ok(md.includes('0 explicitly resolved'));
  assert.ok(md.includes('1 indeterminate'));
  assert.ok(md.includes('not evidence of malicious intent'));
});

test('recommendations consolidate repeated checks without losing distinct targets or evidence', () => {
  const first = finding({ id: 'a', resourceId: 'one', severity: 'medium' });
  const second = finding({ id: 'b', resourceId: 'two', severity: 'high', confidence: 'low' });
  const anotherScope = finding({ id: 'c', resourceId: 'one', scope: 'different-scope' });
  const sameTarget = finding({ id: 'd', resourceId: 'one' });
  const ignored = [
    finding({ id: 'pass', status: 'pass' }),
    finding({ id: 'unknown', status: 'unable-to-assess' }),
    finding({ id: 'opportunity', status: 'informational' }),
  ];
  const value = snapshot([collection()], [first, second, anotherScope, sameTarget, ...ignored]);
  const original = structuredClone(value);
  const groups = groupedRecommendations(value);
  assert.equal(groups.length, 1);
  assert.equal(groups[0]?.targets.length, 3);
  assert.deepEqual(groups[0]?.findingIds, ['a', 'b', 'c', 'd']);
  assert.equal(groups[0]?.severity, 'high');
  assert.equal(groups[0]?.confidence, 'low');
  assert.equal(groups[0]?.evidence.length, 1);
  assert.deepEqual(value, original);
  assert.deepEqual(groupedRecommendations({ ...value, findings: [...value.findings].reverse() }), groups);
  assert.ok(renderMarkdown(value).includes('1 review actions consolidate 4 observed risks'));
  assert.ok(renderHtml(value).includes('3 distinct targets'));
  assert.ok(renderHtml(value).includes('id="finding-a"'));
});

test('different checks or recommendations remain separate even with identical titles', () => {
  const value = snapshot([collection()], [
    finding({ id: 'a', severity: 'low' }),
    finding({ id: 'b', checkId: 'different.check', severity: 'critical' }),
    finding({ id: 'c', recommendation: 'Review a different control.', severity: 'medium' }),
  ]);
  const groups = groupedRecommendations(value);
  assert.equal(groups.length, 3);
  assert.deepEqual(groups.map(group => group.severity), ['critical', 'medium', 'low']);
});

test('scope-bound evidence gaps group repeated failures but keep different reasons separate', () => {
  const firstScope = `/subscriptions/${subscription}`;
  const secondScope = '/subscriptions/33333333-3333-4333-8333-333333333333';
  const value = snapshot([
    collection('azure.roleAssignments', [], { provider: 'azure', scope: firstScope, status: 'unavailable', reason: 'permission-denied' }),
    collection('azure.roleAssignments', [], { provider: 'azure', scope: secondScope, status: 'unavailable', reason: 'permission-denied' }),
    collection('azure.roleAssignments', [], { provider: 'azure', scope: 'assessment', status: 'partial', reason: 'limit-reached' }),
    collection('entra.users', [], { status: 'unavailable', reason: 'not-found' }),
    collection('entra.groups'),
  ]);
  const groups = evidenceGaps(value);
  assert.equal(groups.length, 3);
  assert.equal(groups.find(gap => gap.reason === 'permission-denied')?.scopes.length, 2);
  assert.match(groups.find(gap => gap.reason === 'permission-denied')?.nextStep ?? '', /does not establish licensing/);
  assert.match(groups.find(gap => gap.reason === 'not-found')?.nextStep ?? '', /does not prove/);
  assert.match(groups.find(gap => gap.reason === 'limit-reached')?.nextStep ?? '', /bounded collection budgets/);
  assert.deepEqual(evidenceGaps({ ...value, collections: [...value.collections].reverse() }), groups);
  for (const report of [renderMarkdown(value), renderHtml(value)]) {
    assert.ok(report.includes('Evidence gaps and next steps'));
    assert.ok(report.includes(firstScope));
    assert.ok(report.includes(secondScope));
    assert.ok(report.includes('RoleManagement') || report.includes('Reader at each configured subscription'));
  }
});

test('manual and unconfigured gaps never recommend elevated access as a workaround', () => {
  const value = snapshot([
    collection('m365.exchangeSettings', [], { status: 'unavailable', reason: 'unsupported' }),
    collection('entra.users', [], { status: 'not-configured', reason: 'not-configured' }),
    collection('entra.groups', [], { status: 'unavailable', reason: 'scope-mismatch' }),
  ]);
  const gaps = evidenceGaps(value);
  const manual = gaps.find(gap => gap.collectionId === 'm365.exchangeSettings');
  assert.equal(manual?.manual, true);
  assert.match(manual?.nextStep ?? '', /Extra API privileges will not automate/);
  assert.match(gaps.find(gap => gap.reason === 'not-configured')?.nextStep ?? '', /Confirm approval/);
  assert.match(gaps.find(gap => gap.reason === 'scope-mismatch')?.nextStep ?? '', /Do not broaden permissions/);
  assert.ok(renderHtml(value).includes('Manual review; no API grant requested'));
});

test('recommendation and gap summaries remain escaped and link only to local finding anchors', () => {
  const label = '<img src=x onerror=alert(1)> | [click](javascript:alert(1))';
  const value = snapshot([
    collection('entra.users', [], { status: 'partial', reason: 'invalid-response', message: label }),
  ], [finding({ id: 'a" onclick="alert(1)', title: label, scope: tenant, recommendation: label, resourceId: label })]);
  const html = renderHtml(value);
  const md = renderMarkdown(value);
  assert.ok(html.includes('href="#finding-a%22%20onclick%3D%22alert(1)"'));
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('href="javascript:'));
  assert.ok(!html.includes('id="finding-a" onclick='));
  assert.ok(md.includes('&lt;img'));
  assert.ok(md.includes('\\|'));
});

test('quick-win nomination is explicit rather than guessing from an owner-related check name', () => {
  const value = snapshot([collection()], [
    finding({ id: 'owner', checkId: 'WORKLOAD.OWNERSHIP.COMBINATION', title: 'Ownership concentration' }),
    finding({ id: 'expired', checkId: 'WORKLOAD.CREDENTIAL.EXPIRED', title: 'Expired metadata' }),
  ]);
  const md = renderMarkdown(value);
  const quick = md.split('## Candidate quick wins')[1]?.split('## Strategic improvements')[0] ?? '';
  assert.ok(quick.includes('Expired metadata'));
  assert.ok(!quick.includes('Ownership concentration'));
  assert.ok(quick.includes('effort and safety are not measured'));
});

test('policy recommendation targets show resource and assignment context without discarding evidence identity', () => {
  const scope = `/subscriptions/${subscription}`;
  const resource = `${scope}/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/example`;
  const value = snapshot([
    collection('azure.policyCompliance', [{
      id: 'opaque-evaluation-id',
      properties: { resourceId: resource, policyAssignmentName: 'Require TLS' },
    }], { provider: 'azure', scope }),
  ], [finding({
    id: 'policy-finding', checkId: 'AZURE.POLICY.COMPLIANCE', domain: 'azure',
    scope, resourceId: 'opaque-evaluation-id',
    evidence: [{ collectionId: 'azure.policyCompliance', scope, recordId: 'opaque-evaluation-id' }],
  })]);
  const target = groupedRecommendations(value)[0]?.targets[0];
  assert.equal(target?.resourceId, 'opaque-evaluation-id');
  assert.equal(target?.label, `${resource} (Require TLS)`);
  for (const report of [renderMarkdown(value), renderHtml(value)]) {
    assert.ok(report.includes('Require TLS'));
    assert.ok(report.includes(resource));
    assert.ok(report.includes('opaque-evaluation-id'));
    assert.ok(report.includes('physical assets'));
  }
});

test('report headers bind the observed tenant name to the selected tenant and always show its identifier', () => {
  const name = 'Fictional <tenant> & example';
  const value = snapshot([
    collection('entra.organization', [
      { id: tenant, displayName: name },
      { id: 'different-tenant', displayName: 'Do not use this name' },
    ]),
  ]);
  for (const report of [renderMarkdown(value), renderHtml(value)]) {
    assert.ok(report.includes('Fictional &lt;tenant&gt; &amp; example'));
    assert.ok(report.includes(tenant));
    assert.ok(!report.includes('Do not use this name'));
  }
  value.collections[0]!.records = [];
  assert.ok(renderHtml(value).includes(`Tenant: ${tenant}`));
});
