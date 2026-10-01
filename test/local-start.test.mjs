import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  assertBuiltStudio, assertNodeVersion, assertPortAvailable, DEFAULT_PORT,
  parseArguments, startStudio, STUDIO_ROOT, studioConfig,
} from '../scripts/start-studio.mjs';

const launcher = fileURLToPath(new URL('../scripts/start-studio.mjs', import.meta.url));
const root = resolve(dirname(launcher), '..');

async function temporaryDirectory(t) {
  const path = await mkdtemp(join(tmpdir(), 'cloud review launcher '));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}

test('the local launcher defaults to a fresh browser-opening build on a loopback port', () => {
  const options = parseArguments([]);
  assert.deepEqual(options, { help: false, open: true, build: true, port: 4321 });
  assert.equal(DEFAULT_PORT, 4321);
  const config = studioConfig(options);
  assert.equal(config.root, resolve(root, 'studio') + sep);
  assert.equal(config.server.host, '127.0.0.1');
  assert.equal(config.server.open, true);
  assert.equal(config.vite.preview.strictPort, true);
});

test('headless operation and an explicitly selected port do not expose a network host', () => {
  const options = parseArguments(['--no-open', '--no-build', '--port', '4331']);
  assert.deepEqual(options, { help: false, open: false, build: false, port: 4331 });
  assert.equal(studioConfig(options).server.host, '127.0.0.1');
  assert.equal(studioConfig(options).server.open, false);
  assert.equal(parseArguments(['--port', '0']).port, 0);
  assert.equal(parseArguments(['--port', '65535']).port, 65535);
});

test('invalid ports, extra options and host overrides fail rather than silently broadening exposure', () => {
  for (const args of [
    ['--port'], ['--port', '-1'], ['--port', '80'], ['--port', '65536'], ['--port', '1.5'],
    ['--port', '12x'], ['--port', '1e4'], ['--port', '9007199254740993'],
    ['--host', '0.0.0.0'], ['--background'], ['--open', 'https://example.com'],
    ['--port', '4321', '--port', '4322'], ['--no-open', '--no-open'],
  ]) {
    assert.throws(() => parseArguments(args), /option|--port/);
  }
});

test('runtime checks accept supported Node releases and explain the minimum', () => {
  for (const version of ['22.12.0', '22.20.0', '24.21.0', 'v24.0.0', '26.0.0']) {
    assert.doesNotThrow(() => assertNodeVersion(version));
  }
  for (const version of ['20.19.0', '22.11.0', '18.20.0', 'not-a-version']) {
    assert.throws(() => assertNodeVersion(version), /22\.12/);
  }
});

test('the POSIX shortcut has Unix line endings and Git preserves them on every platform', async () => {
  const shell = await readFile(join(root, 'report-studio.sh'), 'utf8');
  const attributes = await readFile(join(root, '.gitattributes'), 'utf8');
  assert.ok(shell.startsWith('#!/bin/sh\n'));
  assert.equal(shell.includes('\r'), false);
  assert.match(attributes, /^\*\.sh text eol=lf$/m);
});

test('build failure stops startup; stale output is never served as a fallback', async () => {
  let previews = 0;
  await assert.rejects(startStudio(parseArguments([]), {
    build: async () => { throw new Error('build failed'); },
    preview: async () => { previews++; },
  }), /build failed/);
  assert.equal(previews, 0);
});

test('build and preview reuse the same portable config and preserve the native server handle', async () => {
  const calls = [];
  const server = { port: 4321, closed: async () => {}, stop: async () => {} };
  const options = parseArguments(['--no-open']);
  const result = await startStudio(options, {
    build: async config => { calls.push(['build', config]); },
    preview: async config => { calls.push(['preview', config]); return server; },
  });
  assert.equal(result, server);
  assert.deepEqual(calls.map(([name]) => name), ['build', 'preview']);
  assert.equal(calls[0][1], calls[1][1]);
  assert.equal(calls[0][1].root, STUDIO_ROOT);
});

test('occupied ports fail explicitly without stopping the existing listener', async t => {
  const server = createServer();
  await new Promise((resolveReady, reject) => {
    server.once('error', reject);
    server.listen({ port: 0, host: '127.0.0.1' }, resolveReady);
  });
  t.after(() => new Promise((resolveClosed, reject) => server.close(error => error ? reject(error) : resolveClosed())));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  await assert.rejects(assertPortAvailable(address.port), /already in use.*No process was stopped/);
  assert.equal(server.listening, true);
  await assert.doesNotReject(assertPortAvailable(0));
});

test('no-build mode requires both public build entrypoints to be readable', async t => {
  const path = await temporaryDirectory(t);
  await assert.rejects(assertBuiltStudio(path), /npm start without --no-build/);
  await mkdir(join(path, 'dist'));
  await writeFile(join(path, 'dist', 'index.html'), '<title>Report Studio</title>');
  await assert.rejects(assertBuiltStudio(path), /No readable Studio build/);
  await writeFile(join(path, 'dist', 'demo.json'), '{}');
  await assert.doesNotReject(assertBuiltStudio(path));
});

test('help works from a different working directory without a build or dependency installation', () => {
  const result = spawnSync(process.execPath, [launcher, '--help'], { cwd: tmpdir(), encoding: 'utf8', timeout: 10000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Windows, macOS and Linux/);
  assert.match(result.stdout, /127\.0\.0\.1:4321/);
  assert.doesNotMatch(result.stdout, /Building Report Studio/);
});

test('missing dependencies produce setup instructions without installing anything', async t => {
  const path = await temporaryDirectory(t);
  await mkdir(join(path, 'scripts'));
  const copy = join(path, 'scripts', 'start-studio.mjs');
  await copyFile(launcher, copy);
  const result = spawnSync(process.execPath, [copy, '--no-open', '--port', '0'], {
    cwd: tmpdir(), encoding: 'utf8', timeout: 15000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /npm ci --include=dev --ignore-scripts/);
  assert.match(result.stderr, /not installed automatically/);
  assert.doesNotMatch(result.stdout, /ready:/);
});

test('native platform shortcut forwards help even when invoked from outside the checkout', () => {
  const command = process.platform === 'win32' ? process.env.ComSpec : '/bin/sh';
  assert.ok(command);
  const args = process.platform === 'win32'
    ? ['/d', '/s', '/c', `""${join(root, 'Report Studio.cmd')}" --help"`]
    : [join(root, 'report-studio.sh'), '--help'];
  const result = spawnSync(command, args, {
    cwd: tmpdir(), encoding: 'utf8', timeout: 10000, windowsVerbatimArguments: process.platform === 'win32',
    env: { ...process.env, PATH: `${dirname(process.execPath)}${process.platform === 'win32' ? ';' : ':'}${process.env.PATH ?? ''}` },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Cloud Security Review - local Report Studio/);
});
