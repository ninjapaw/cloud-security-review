import { mkdir, open } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { AssessmentError, assertSafeEvidence } from './safety.js';

export const MAX_JSON_BYTES = 50 * 1024 * 1024;

export async function readJson(path: string): Promise<unknown> {
  let contents: string;
  try {
    const handle = await open(path, 'r');
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.size > MAX_JSON_BYTES) {
        throw new AssessmentError('input-limit', 'Input must be a JSON file no larger than 50 MiB.');
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of handle.createReadStream({ autoClose: false, highWaterMark: 64 * 1024 })) {
        if (!Buffer.isBuffer(chunk)) throw new AssessmentError('read-failed', 'Input could not be read as bytes.');
        size += chunk.length;
        if (size > MAX_JSON_BYTES) throw new AssessmentError('input-limit', 'Input exceeds the 50 MiB limit.');
        chunks.push(chunk);
      }
      contents = Buffer.concat(chunks, size).toString('utf8');
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error instanceof AssessmentError) throw error;
    throw new AssessmentError('read-failed', 'Unable to read the requested input file. Check its path and permissions.');
  }
  let value: unknown;
  try {
    value = JSON.parse(contents);
  } catch {
    throw new AssessmentError('invalid-json', 'The input is not valid JSON. Input contents have not been logged.');
  }
  assertSafeEvidence(value);
  return value;
}

export async function writeBundle(directory: string, files: Record<string, string>): Promise<string> {
  const target = resolve(directory);
  if (!Object.keys(files).length || Object.keys(files).some(name => !/^[a-z][a-z0-9-]*\.(json|md|html)$/.test(name))) {
    throw new AssessmentError('invalid-output', 'Report bundle contains an invalid output filename.');
  }
  if (Object.entries(files).some(([name, contents]) => name.endsWith('.json') && Buffer.byteLength(contents) > MAX_JSON_BYTES)) {
    throw new AssessmentError('output-limit', 'JSON report exceeds the 50 MiB snapshot limit. Split future assessments into smaller explicit scopes or lower collection limits; no report was written.');
  }
  try {
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await mkdir(target, { mode: 0o700 });
  } catch {
    throw new AssessmentError('output-exists', 'Cannot create the output directory. It must be new and its parent writable; existing reports are never overwritten.');
  }
  try {
    for (const [name, content] of Object.entries(files)) {
      const handle = await open(join(target, name), 'wx', 0o600);
      try {
        await handle.writeFile(content, 'utf8');
      } finally {
        await handle.close();
      }
    }
  } catch {
    throw new AssessmentError('write-failed', 'Report writing failed. The new output directory may contain partial files; do not treat it as a completed assessment.');
  }
  return target;
}
