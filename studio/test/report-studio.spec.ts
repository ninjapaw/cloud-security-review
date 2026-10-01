import { expect, test, type Page } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdir, readFile, readdir, rm, truncate, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseSnapshot } from '../../src/validation.js';
import { MAX_SNAPSHOT_BYTES, parseNotes, parseRecipe } from '../../src/report-recipe.js';

const report = (page: Page) => page.frameLocator('iframe[title="Configured security report preview"]');

async function upload(page: Page, label: string, value: unknown, name = 'local.json'): Promise<void> {
  const contents = JSON.stringify(value);
  if (contents === undefined) throw new Error('The test upload must be JSON.');
  await page.getByLabel(label, { exact: true }).setInputFiles({
    name, mimeType: 'application/json', buffer: Buffer.from(contents),
  });
}

async function demo(page: Page): Promise<void> {
  await page.goto('/');
  await page.getByRole('button', { name: 'Try fictional demo', exact: true }).click();
  await expect(page.getByText('Fictional demo', { exact: true })).toBeVisible();
  await expect(report(page).getByRole('heading', { level: 1 })).toHaveText('Executive security brief');
}

async function downloadText(page: Page, label: string): Promise<{ filename: string; text: string }> {
  const downloading = page.waitForEvent('download');
  await page.getByRole('button', { name: label, exact: true }).click();
  const download = await downloading;
  const path = await download.path();
  if (!path) throw new Error('The generated report download has no local file.');
  try {
    return { filename: download.suggestedFilename(), text: await readFile(path, 'utf8') };
  } finally {
    await download.delete();
  }
}

test('the local launcher builds from an unrelated directory and leaves it untouched', async ({}, testInfo) => {
  test.setTimeout(120000);
  const outside = testInfo.outputPath('unrelated working directory');
  await mkdir(outside, { recursive: true });
  const launcher = fileURLToPath(new URL('../../scripts/start-studio.mjs', import.meta.url));
  const child = spawn(process.execPath, [launcher, '--no-open', '--port', '0'], {
    cwd: outside, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = new Promise<void>(resolveExit => { child.once('exit', () => resolveExit()); });
  let log = '';
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const url = await new Promise<string>((resolveReady, reject) => {
      timer = setTimeout(() => reject(new Error(`Local startup timed out.\n${log}`)), 90000);
      child.once('error', reject);
      child.once('exit', code => reject(new Error(`Local startup exited with ${code}.\n${log}`)));
      child.stdout.on('data', (chunk: Buffer) => {
        log += chunk.toString();
        const ready = /Report Studio is ready: (http:\/\/127\.0\.0\.1:\d+\/)/.exec(log);
        if (ready?.[1]) resolveReady(ready[1]);
      });
      child.stderr.on('data', (chunk: Buffer) => { log += chunk.toString(); });
    });
    expect(log).toContain('Building Report Studio from this checkout');
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('Report Studio | Cloud Security Review');
    const demo = await fetch(`${url}demo.json`, { signal: AbortSignal.timeout(10000) });
    expect((await demo.json()).assessmentId).toBe('fictional-report-studio-demo');
    const privatePath = await fetch(`${url}config.local.json`, { signal: AbortSignal.timeout(10000) });
    expect(privatePath.status).toBe(404);
    expect(await readdir(outside)).toEqual([]);
    expect(log).toContain('Browser opening is disabled');
  } finally {
    if (timer) clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    await exited;
    await rm(outside, { recursive: true, force: true });
  }
});

test('local import, filtering, notes and real report downloads preserve evidence boundaries', async ({ page }) => {
  const requests: { url: string; method: string }[] = [];
  const errors: Error[] = [];
  page.on('request', request => requests.push({ url: request.url(), method: request.method() }));
  page.on('pageerror', error => errors.push(error));
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'HTML', exact: true })).toBeDisabled();
  const response = await page.request.get('/demo.json');
  expect(response.ok()).toBe(true);
  const source = parseSnapshot(await response.json());
  const user = source.collections.find(collection => collection.id === 'entra.users')?.records[0];
  if (!user) throw new Error('The synthetic user fixture is missing.');
  user.studioMarker = 'RAW-INVENTORY-SENTINEL';
  for (const finding of source.findings.filter(finding => finding.domain !== 'github')) {
    finding.description += ' EXCLUDED-DOMAIN-SENTINEL';
  }
  await upload(page, 'Open assessment snapshot', source, 'local-test-snapshot.json');
  await expect(page.getByText('local-test-snapshot.json', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Technical Findings and evidence' }).click();
  await page.getByRole('textbox', { name: 'Report title', exact: true }).fill('Engineering <Q3> report');
  await page.getByRole('button', { name: 'Clear domains', exact: true }).click();
  await expect(report(page).locator('.notice')).toContainText('0 findings selected');
  await expect(report(page).locator('.notice')).toContainText('37 incomplete collection/scope pairs');
  await page.getByLabel('GitHub', { exact: true }).check();
  await page.getByLabel('Finding scope', { exact: true }).selectOption('example-org/infrastructure');
  await page.getByText('Add analyst context', { exact: true }).click();
  await page.getByRole('textbox', { name: 'Author (optional)', exact: true }).fill('Example reviewer');
  await page.getByRole('textbox', { name: 'Analyst notes', exact: true }).fill('Independent commentary <b>not evidence</b>.');
  await expect(report(page).locator('.notes')).toContainText('Independent commentary');
  await expect(report(page).locator('.notes b')).toHaveCount(0);
  await page.getByRole('button', { name: 'Move notes up', exact: true }).click();
  const html = await downloadText(page, 'HTML');
  const markdown = await downloadText(page, 'Markdown');
  expect(html.filename).toBe('security-report.html');
  expect(markdown.filename).toBe('security-report.md');
  for (const { text } of [html, markdown]) {
    expect(text).toContain('Independent commentary');
    expect(text).toContain('Source evidence coverage');
    expect(text).toContain('excluded by filters');
    expect(text).not.toContain('RAW-INVENTORY-SENTINEL');
    expect(text).not.toContain('EXCLUDED-DOMAIN-SENTINEL');
  }
  expect(html.text).toContain('Engineering &lt;Q3&gt; report');
  expect(html.text).not.toMatch(/<script[\s>]/i);
  expect(html.text).not.toContain('<b>not evidence</b>');
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  const origin = new URL(page.url()).origin;
  expect(requests.filter(request => request.method !== 'GET' ||
    (request.url.startsWith('http') && new URL(request.url).origin !== origin))).toEqual([]);
  expect(errors).toEqual([]);
});

test('recipes and separately bound notes round-trip without changing the source snapshot', async ({ page }) => {
  await demo(page);
  await page.getByRole('button', { name: 'Code to cloud Delivery and cloud trust' }).click();
  await page.getByRole('textbox', { name: 'Report title', exact: true }).fill('Saved delivery review');
  await page.getByText('Add analyst context', { exact: true }).click();
  await page.getByRole('textbox', { name: 'Analyst notes', exact: true }).fill('Manual business context.');
  const recipeDownload = await downloadText(page, 'Save recipe');
  const notesDownload = await downloadText(page, 'Save notes');
  const recipe = parseRecipe(JSON.parse(recipeDownload.text));
  const notes = parseNotes(JSON.parse(notesDownload.text), 'fictional-report-studio-demo');
  expect(recipeDownload.text).not.toContain(notes.text);
  expect(recipeDownload.text).not.toContain('assessmentId');
  await page.getByRole('button', { name: 'Executive Priorities and commentary' }).click();
  await upload(page, 'Load report recipe', recipe, 'saved-recipe.json');
  await expect(report(page).getByRole('heading', { level: 1 })).toHaveText('Saved delivery review');
  await expect(page.getByLabel('Entra ID', { exact: true })).not.toBeChecked();
  await expect(page.getByLabel('GitHub', { exact: true })).toBeChecked();
  await page.getByRole('textbox', { name: 'Analyst notes', exact: true }).fill('');
  await upload(page, 'Load analyst notes', notes, 'saved-notes.json');
  await expect(report(page).locator('.notes')).toHaveText(notes.text);
  await upload(page, 'Load analyst notes', { ...notes, assessmentId: 'different-assessment' });
  await expect(page.getByRole('alert')).toContainText('different assessment');
  await expect(report(page).locator('.notes')).toHaveText(notes.text);
  await upload(page, 'Load report recipe', { ...recipe, scope: 'not-in-this-assessment' });
  await expect(page.getByRole('alert')).toContainText('scope absent');
  await expect(page.getByRole('button', { name: 'HTML', exact: true })).toBeDisabled();
  await page.getByLabel('Finding scope', { exact: true }).selectOption('');
  await expect(report(page).getByRole('heading', { level: 1 })).toHaveText('Saved delivery review');
});

test('invalid inputs fail explicitly and never leave a stale report presented as current', async ({ page }) => {
  await demo(page);
  await upload(page, 'Load report recipe', {
    kind: 'cloud-security-report-recipe', script: 'UNTRUSTED-INPUT-SENTINEL',
  });
  await expect(page.getByRole('alert')).toContainText('Report recipe is invalid');
  await expect(page.getByRole('alert')).not.toContainText('UNTRUSTED-INPUT-SENTINEL');
  await page.getByLabel('Open assessment snapshot', { exact: true }).setInputFiles({
    name: 'malformed.json', mimeType: 'application/json',
    buffer: Buffer.from('{"value": DO-NOT-ECHO-THIS }'),
  });
  await expect(page.getByRole('alert')).toContainText('not valid JSON');
  await expect(page.getByRole('alert')).not.toContainText('DO-NOT-ECHO-THIS');
  await expect(page.locator('iframe')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'HTML', exact: true })).toBeDisabled();
  await page.getByText('Add analyst context', { exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Analyst notes', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Try fictional demo', exact: true }).click();
  await expect(page.getByText('Fictional demo', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.locator('iframe')).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});

test('snapshot byte limit is checked before parsing a file', async ({ page }, testInfo) => {
  const path = testInfo.outputPath('oversized.json');
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, '');
  await truncate(path, MAX_SNAPSHOT_BYTES + 1);
  try {
    await page.goto('/');
    await page.getByLabel('Open assessment snapshot', { exact: true }).setInputFiles(path);
    await expect(page.getByRole('alert')).toHaveText('Snapshots are limited to 50 MiB.');
    await expect(page.locator('iframe')).toHaveCount(0);
  } finally {
    await rm(path, { force: true });
  }
});

test('print control uses the script-free preview and the layout works on desktop and mobile', async ({ page }) => {
  await demo(page);
  await expect(page.getByRole('button', { name: 'Print / Save as PDF', exact: true })).toBeEnabled();
  await page.evaluate(() => {
    const iframe = document.querySelector<HTMLIFrameElement>('iframe');
    if (!iframe?.contentWindow) throw new Error('Preview window missing.');
    iframe.contentWindow.print = () => { document.documentElement.dataset.printRequested = 'true'; };
  });
  await page.getByRole('button', { name: 'Print / Save as PDF', exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.dataset.printRequested)).toBe('true');
  await expect(report(page).locator('script')).toHaveCount(0);
  const html = await page.locator('iframe').getAttribute('srcdoc');
  if (!html) throw new Error('Printable report HTML is missing.');
  const printable = await page.context().newPage();
  try {
    await printable.setContent(html);
    const pdf = await printable.pdf({ format: 'A4', printBackground: true });
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
    expect(pdf.length).toBeGreaterThan(1000);
  } finally {
    await printable.close();
  }
  for (const width of [1440, 375]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole('link', { name: 'Jump to preview', exact: true }).click();
    await expect(page).toHaveURL(/#preview-heading$/);
  }
  await page.getByRole('button', { name: 'Clear data', exact: true }).click();
  await expect(page.locator('iframe')).toHaveCount(0);
  await page.getByText('Add analyst context', { exact: true }).click();
  await expect(page.getByRole('button', { name: 'Save notes', exact: true })).toBeDisabled();
});
