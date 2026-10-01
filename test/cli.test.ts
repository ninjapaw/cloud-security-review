import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test, { type TestContext } from 'node:test';
import { MAX_JSON_BYTES, readJson, writeBundle } from '../src/storage.js';
import { parseSnapshot } from '../src/validation.js';
import { emptyNotes, presetRecipe } from '../src/report-recipe.js';
import { collection, finding, input, snapshot } from './support.js';

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const sample = fileURLToPath(new URL('../../samples/assessment-input.json', import.meta.url));

async function directory(t: TestContext): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), 'cloud-security-review-test-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}

function run(...args: string[]) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
    env: { ...process.env, GITHUB_TOKEN: '' },
  });
  assert.ifError(result.error);
  return result;
}

test('help and catalog are usable without credentials', () => {
  const help = run('--help');
  assert.equal(help.status, 0);
  assert.ok(help.stdout.includes('READ-ONLY'));
  const catalog = run('catalog');
  assert.equal(catalog.status, 0);
  const parsed: unknown = JSON.parse(catalog.stdout);
  assert.ok(Array.isArray(parsed) && parsed.length > 20);
});

test('offline assessment produces valid persisted reports and explicitly signals gaps', async t => {
  const root = await directory(t);
  const path = join(root, 'input.json');
  const output = join(root, 'report');
  await writeFile(path, JSON.stringify(input([collection('entra.users', [{ id: 'u1', accountEnabled: true }])])));
  const result = run('assess', '--input', path, '--output', output);
  assert.equal(result.status, 2, result.stderr);
  assert.ok(result.stdout.includes('collection gaps'));
  assert.deepEqual((await readdir(output)).sort(), ['assessment.json', 'report.html', 'report.md']);
  const persisted = parseSnapshot(await readJson(join(output, 'assessment.json')));
  assert.ok(persisted.findings.some(finding => finding.status === 'unable-to-assess'));
  assert.ok((await readFile(join(output, 'report.html'), 'utf8')).includes('Read-only assessment'));
  assert.equal(run('assess', '--input', path, '--output', output).status, 1);
  assert.deepEqual(parseSnapshot(await readJson(join(output, 'assessment.json'))), persisted);
});

test('sample demonstrates evidence-based risks, relationships, partial coverage and severity exit', async t => {
  const root = await directory(t);
  const output = join(root, 'sample');
  const result = run('assess', '--input', sample, '--output', output, '--fail-on', 'high');
  assert.equal(result.status, 3, result.stderr);
  const persisted = parseSnapshot(await readJson(join(output, 'assessment.json')));
  assert.ok(persisted.findings.some(finding => finding.status === 'fail' && finding.domain === 'workload-identities'));
  assert.ok(persisted.findings.some(finding => finding.status === 'fail' && finding.domain === 'azure'));
  assert.ok(persisted.findings.some(finding => finding.status === 'fail' && finding.domain === 'github'));
  for (const check of [
    'M365.SHAREPOINT.LEGACY_AUTH', 'M365.SHAREPOINT.ANONYMOUS_LINKS',
    'ENTRA.ROLE.SCHEDULE.PERMANENT', 'AZURE.POLICY.COMPLIANCE',
  ]) {
    assert.ok(persisted.findings.some(finding => finding.checkId === check && finding.status === 'fail'), check);
  }
  assert.ok(persisted.findings.some(finding => finding.checkId === 'AZURE.POLICY.EXEMPTION' && finding.status === 'informational'));
  assert.ok(persisted.findings.some(finding => finding.checkId === 'AZURE.POLICY.COMPLIANCE' && finding.status === 'pass'));
  const html = await readFile(join(output, 'report.html'), 'utf8');
  assert.ok(html.includes('Grouped recommendations'));
  assert.ok(html.includes('Evidence gaps and next steps'));
  assert.ok(html.includes('Fictional assessment tenant'));
  assert.equal(persisted.findings.filter(finding => finding.checkId === 'CODETOCLOUD.POTENTIAL_CONTROL' && finding.status === 'fail').length, 1);
  assert.ok(persisted.graph.edges.length > 5);
  assert.ok(persisted.identityRisks.some(risk => risk.score > 0 && risk.incomplete));
  assert.ok(persisted.identityRisks.some(risk => risk.displayName === 'Example deployment automation'));
  const managedIdentity = persisted.identityRisks.find(risk => risk.identityId.endsWith('/managed-identity-1'));
  assert.ok(managedIdentity);
  assert.equal(managedIdentity.score, 0);
  assert.equal(managedIdentity.incomplete, true);
  assert.ok(!managedIdentity.factors.some(factor => factor.name === 'missingOwner'));
  assert.equal(run('assess', '--input', sample, '--output', join(root, 'acknowledged'), '--allow-incomplete').status, 0);
});

test('snapshot comparison persists changes without cloud access', async t => {
  const root = await directory(t);
  const previous = join(root, 'previous.json');
  const current = join(root, 'current.json');
  await writeFile(previous, JSON.stringify(snapshot([collection()])));
  await writeFile(current, JSON.stringify(snapshot([collection('entra.users', [{ id: 'new-user' }])])));
  const output = join(root, 'diff');
  const result = run('diff', '--previous', previous, '--current', current, '--output', output);
  assert.equal(result.status, 0, result.stderr);
  const changes = await readFile(join(output, 'changes.md'), 'utf8');
  assert.ok(changes.includes('new-user'));
  assert.ok(changes.includes('added'));
  assert.ok(changes.includes('not evidence of malicious intent'));
});

test('invalid input and CLI options do not log input credentials or start an assessment', async t => {
  const root = await directory(t);
  const secretFile = join(root, 'invalid.json');
  await writeFile(secretFile, JSON.stringify({ clientSecret: 'NEVER-PRINT-SENSITIVE-SENTINEL' }));
  const result = run('assess', '--input', secretFile, '--output', join(root, 'must-not-exist'));
  assert.equal(result.status, 1);
  assert.ok(!result.stderr.includes('NEVER-PRINT'));
  assert.ok(!result.stdout.includes('NEVER-PRINT'));
  assert.ok(!(await readdir(root)).includes('must-not-exist'));
  assert.equal(run('assess', '--input', secretFile, '--config', secretFile, '--output', 'unused').status, 1);
  assert.equal(run('assess', '--input', secretFile, '--output', 'unused', '--fail-on', 'not-a-severity').status, 1);
  assert.equal(run('assess', '--input', secretFile, '--output', 'unused', '--write-tenant', 'true').status, 1);
});

test('JSON reads fail closed without raw parse diagnostics and bundle cannot escape filenames', async t => {
  const root = await directory(t);
  const invalid = join(root, 'invalid.json');
  await writeFile(invalid, '{"value": SUPER-SECRET-SENTINEL }');
  await assert.rejects(readJson(invalid), error => {
    assert.ok(error instanceof Error);
    assert.ok(!error.message.includes('SUPER-SECRET'));
    return true;
  });
  await assert.rejects(writeBundle(join(root, 'new'), { '../outside.json': '{}' }), /invalid output filename/);
  assert.deepEqual(await readdir(root), ['invalid.json']);
});

test('input file byte limit is enforced before parsing', async t => {
  const root = await directory(t);
  const large = join(root, 'large.json');
  await writeFile(large, '');
  await truncate(large, 50 * 1024 * 1024 + 1);
  await assert.rejects(readJson(large), /no larger than 50 MiB/);
});

test('oversized JSON output is refused before a report directory is created', async t => {
  const root = await directory(t);
  await assert.rejects(writeBundle(join(root, 'large-output'), {
    'assessment.json': ' '.repeat(MAX_JSON_BYTES + 1),
  }), /snapshot limit/);
  assert.deepEqual(await readdir(root), []);
});

test('saved Studio recipes produce minimized CLI reports without copying or mutating the snapshot', async t => {
  const root = await directory(t);
  const source = snapshot([collection()], [
    finding({ id: 'selected', title: 'SELECTED-PRIORITY' }),
    finding({ id: 'excluded', title: 'EXCLUDED-FROM-EXPORT', severity: 'low' }),
  ]);
  const sourceFile = join(root, 'snapshot.json');
  const recipeFile = join(root, 'recipe.json');
  const notesFile = join(root, 'notes.json');
  const output = join(root, 'configured');
  const bytes = JSON.stringify(source);
  await writeFile(sourceFile, bytes);
  await writeFile(recipeFile, JSON.stringify(presetRecipe('executive')));
  await writeFile(notesFile, JSON.stringify({ ...emptyNotes(source.assessmentId), text: 'Separate analyst commentary.' }));
  const result = run('report', '--snapshot', sourceFile, '--recipe', recipeFile, '--notes', notesFile, '--output', output);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual((await readdir(output)).sort(), ['report-recipe.json', 'report.html', 'report.md']);
  assert.equal(await readFile(sourceFile, 'utf8'), bytes);
  for (const name of ['report.html', 'report.md']) {
    const report = await readFile(join(output, name), 'utf8');
    assert.ok(report.includes('SELECTED-PRIORITY'));
    assert.ok(report.includes('Separate analyst commentary.'));
    assert.ok(!report.includes('EXCLUDED-FROM-EXPORT'));
    assert.ok(report.includes('1 excluded by filters'));
  }
  assert.ok(!(await readFile(join(output, 'report-recipe.json'), 'utf8')).includes('Separate analyst commentary.'));
  assert.equal(run('report', '--snapshot', sourceFile, '--recipe', recipeFile, '--output', output).status, 1);
});

test('CLI report refuses mismatched notes or executable recipe fields before writing output', async t => {
  const root = await directory(t);
  const source = snapshot();
  const sourceFile = join(root, 'snapshot.json');
  const recipeFile = join(root, 'recipe.json');
  const notesFile = join(root, 'notes.json');
  await writeFile(sourceFile, JSON.stringify(source));
  await writeFile(recipeFile, JSON.stringify(presetRecipe('technical')));
  await writeFile(notesFile, JSON.stringify(emptyNotes('another-assessment')));
  assert.equal(run('report', '--snapshot', sourceFile, '--recipe', recipeFile, '--notes', notesFile, '--output', join(root, 'mismatch')).status, 1);
  await writeFile(recipeFile, JSON.stringify({ ...presetRecipe('technical'), script: 'UNTRUSTED-SENTINEL' }));
  const failed = run('report', '--snapshot', sourceFile, '--recipe', recipeFile, '--output', join(root, 'unsafe'));
  assert.equal(failed.status, 1);
  assert.ok(!failed.stderr.includes('UNTRUSTED-SENTINEL'));
  assert.ok(!(await readdir(root)).includes('mismatch'));
  assert.ok(!(await readdir(root)).includes('unsafe'));
});
