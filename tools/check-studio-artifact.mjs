import { readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createAssessment } from '../dist/src/engine.js';
import { parseInput } from '../dist/src/validation.js';

const root = resolve(process.argv[2] ?? 'studio/dist');
const expected = new Set(['index.html', 'demo.json', '_astro']);
const entries = await readdir(root, { withFileTypes: true });

if (entries.length !== expected.size || entries.some(entry => !expected.has(entry.name))) {
  throw new Error('Studio output contains missing or unexpected top-level assets.');
}
for (const entry of entries) {
  if (entry.name === '_astro' ? !entry.isDirectory() : !entry.isFile()) {
    throw new Error(`Unexpected Studio asset type: ${entry.name}`);
  }
}

const assets = await readdir(join(root, '_astro'), { withFileTypes: true });
if (assets.length === 0 || assets.some(entry =>
  !entry.isFile() || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.(?:js|css)$/.test(entry.name))) {
  throw new Error('Studio output contains unexpected bundled assets.');
}

const sample = JSON.parse(await readFile(new URL('../samples/assessment-input.json', import.meta.url), 'utf8'));
const expectedDemo = createAssessment(parseInput(sample), undefined, 'fictional-report-studio-demo');
const actualDemo = JSON.parse(await readFile(join(root, 'demo.json'), 'utf8'));
if (JSON.stringify(actualDemo) !== JSON.stringify(expectedDemo)) {
  throw new Error('Studio demo does not match the fictional checked-in sample.');
}

const html = await readFile(join(root, 'index.html'), 'utf8');
if (!html.includes('Report Studio | Cloud Security Review')) {
  throw new Error('Studio entry point is missing.');
}

console.log(`Verified Studio output: index.html, fictional demo.json and ${assets.length} bundled assets.`);
