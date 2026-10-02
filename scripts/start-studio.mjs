import { access, realpath } from 'node:fs/promises';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const STUDIO_ROOT = fileURLToPath(new URL('../studio/', import.meta.url));
export const DEFAULT_PORT = 4321;

const help = `Cloud Security Review - local Report Studio

Usage: npm start -- [--no-open] [--port PORT] [--no-build]
       node scripts/start-studio.mjs [options]

Starts on http://127.0.0.1:4321 and opens your default browser.
Builds the static app first; no cloud sign-in or tenant access is needed.

Options:
  --no-open    Do not open a browser (headless / remote terminal).
  --port PORT  Choose a port from 1024-65535, or 0 for an available port.
  --no-build   Serve an existing Studio build instead of rebuilding it.
  --help       Show this help without starting a server.

Requires Node.js 22.12+ and checkout dependencies installed with:
  npm ci --include=dev --ignore-scripts

Windows, macOS and Linux use the same launcher. No administrator access needed.
Keep this terminal open; Ctrl+C stops the server. Imported data stays in the browser.
`;

/** @param {string[]} args */
export function parseArguments(args) {
  const options = { help: false, open: true, build: true, port: DEFAULT_PORT };
  const seen = new Set();
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (seen.has(argument)) throw new Error('Duplicate option. Use --help for supported arguments.');
    seen.add(argument);
    switch (argument) {
      case '--help': options.help = true; break;
      case '--no-open': options.open = false; break;
      case '--no-build': options.build = false; break;
      case '--port': {
        const value = args[++index] ?? '';
        const port = Number(value);
        if (!/^\d+$/.test(value) || !Number.isSafeInteger(port)
          || (port !== 0 && (port < 1024 || port > 65535))) {
          throw new Error('--port must be 1024-65535, or 0 for an available port.');
        }
        options.port = port;
        break;
      }
      default: throw new Error('Unknown option. Use --help for supported arguments; network host overrides are not allowed.');
    }
  }
  return options;
}

/** @param {string} version */
export function assertNodeVersion(version) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(version);
  const major = Number(match?.[1]);
  const minor = Number(match?.[2]);
  if (!match || major < 22 || (major === 22 && minor < 12)) {
    throw new Error('Report Studio requires Node.js 22.12 or newer. Install a supported Node.js LTS release, reopen your terminal, and retry.');
  }
}

/** @param {number} port */
export async function assertPortAvailable(port) {
  const probe = createServer();
  await new Promise((resolveReady, reject) => {
    probe.once('error', error => {
      if ('code' in error && error.code === 'EADDRINUSE') {
        reject(new Error(`Local port ${port} is already in use. Reuse the existing Studio, or start with --port ${port < 65535 ? port + 1 : DEFAULT_PORT}. No process was stopped.`));
      } else {
        reject(error);
      }
    });
    probe.listen({ port, host: '127.0.0.1', exclusive: true }, () => {
      probe.close(error => error ? reject(error) : resolveReady(undefined));
    });
  });
}

/** @param {string} [root] */
export async function assertBuiltStudio(root = STUDIO_ROOT) {
  try {
    await access(resolve(root, 'dist', 'index.html'));
    await access(resolve(root, 'dist', 'demo.json'));
  } catch {
    throw new Error('No readable Studio build was found. Run npm start without --no-build, or run npm run studio:build first.');
  }
}

/** @param {ReturnType<typeof parseArguments>} options */
export function studioConfig(options) {
  return {
    root: STUDIO_ROOT,
    logLevel: /** @type {const} */ ('info'),
    server: { host: '127.0.0.1', port: options.port, open: options.open },
    vite: { preview: { strictPort: true } },
  };
}

/**
 * Astro owns static serving and native browser opening on all three platforms.
 * Its API avoids CLI auto-backgrounding and keeps lifecycle control in this process.
 * @param {ReturnType<typeof parseArguments>} options
 * @param {Pick<typeof import('astro'), 'build' | 'preview'>} astro
 */
export async function startStudio(options, astro) {
  const config = studioConfig(options);
  if (options.build) await astro.build(config);
  else await assertBuiltStudio();
  return astro.preview(config);
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(help);
    return;
  }
  assertNodeVersion(process.versions.node);
  // Astro's prerender cache also uses cwd, independently of the configured root.
  process.chdir(fileURLToPath(new URL('../', import.meta.url)));
  process.env.ASTRO_TELEMETRY_DISABLED = '1';
  let astro;
  try {
    await access(new URL('../node_modules/astro/package.json', import.meta.url));
    astro = await import('astro');
  } catch (error) {
    if (error instanceof Error && 'code' in error
      && ['ENOENT', 'ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND'].includes(String(error.code))) {
      throw new Error('Studio dependencies are missing or incomplete. In this checkout, run npm ci --include=dev --ignore-scripts, then npm start. Dependencies are not installed automatically.');
    }
    throw error;
  }
  await assertPortAvailable(options.port);
  process.stdout.write(options.build ? 'Building Report Studio from this checkout...\n' : 'Using the existing Report Studio build...\n');
  const server = await startStudio(options, astro);
  const closed = server.closed();
  /** @type {Promise<void> | undefined} */
  let stopping;
  const stop = () => stopping ??= server.stop();
  const onSignal = () => { void stop().catch(failure => {
    process.stderr.write(`studio-stop-failed: ${failure instanceof Error ? failure.message : 'Unable to stop the local server.'}\n`);
    process.exitCode = 1;
  }); };
  const signals = ['SIGINT', 'SIGTERM', ...(process.platform === 'win32' ? ['SIGBREAK'] : [])];
  for (const signal of signals) process.once(signal, onSignal);
  try {
    const url = `http://127.0.0.1:${server.port}/`;
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10000) });
    if (!response.ok || !(await response.text()).includes('<title>Report Studio | Cloud Security Review</title>')) {
      throw new Error('The local server did not return the expected Report Studio page.');
    }
    process.stdout.write(`\nReport Studio is ready: ${url}\nLocal only. Keep this terminal open; press Ctrl+C to stop.\n`);
    process.stdout.write(options.open
      ? 'If your browser did not open, use the local URL above, or use --no-open on headless systems.\n'
      : 'Browser opening is disabled. Open the local URL when ready.\n');
    await closed;
  } finally {
    for (const signal of signals) process.removeListener(signal, onSignal);
    await stop();
  }
}

if (process.argv[1] && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url))) {
  try {
    await main();
  } catch (error) {
    process.stderr.write(`studio-start-failed: ${error instanceof Error ? error.message : 'An unexpected startup failure occurred.'}\n`);
    process.exitCode = 1;
  }
}
