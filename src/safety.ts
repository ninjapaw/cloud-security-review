import { createHash } from 'node:crypto';
import type { JsonObject, JsonValue } from './model.js';

export class AssessmentError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'AssessmentError';
  }
}

const forbiddenFields = new Set([
  '__proto__', 'prototype', 'constructor', 'secrettext', 'hint', 'password',
  'clientsecret', 'client_secret', 'access_token', 'accesstoken', 'refresh_token',
  'refreshtoken', 'authorization', 'privatekey', 'private_key', 'connectionstring',
  'connection_string', 'sas', 'sastoken', 'secret', 'token',
]);
const credentialPatterns = [
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /(?:[?&](?:access_token|client_secret|sig)=)/i,
];

export function assertSafeEvidence(value: unknown): asserts value is JsonValue {
  let visited = 0;
  const visit = (entry: unknown, depth: number): void => {
    if (++visited > 2_000_000 || depth > 40) {
      throw new AssessmentError('input-limit', 'Evidence exceeds the supported structural limits.');
    }
    if (entry === null || typeof entry === 'boolean') return;
    if (typeof entry === 'number' && Number.isFinite(entry)) return;
    if (typeof entry === 'string') {
      if (credentialPatterns.some(pattern => pattern.test(entry))) {
        throw new AssessmentError('unsafe-evidence', 'Credential-shaped content is not accepted as assessment evidence.');
      }
      return;
    }
    if (Array.isArray(entry)) {
      for (const child of entry) visit(child, depth + 1);
      return;
    }
    if (typeof entry === 'object' && entry !== null && Object.getPrototypeOf(entry) === Object.prototype) {
      for (const [key, child] of Object.entries(entry)) {
        if (forbiddenFields.has(key.toLowerCase()) || credentialPatterns.some(pattern => pattern.test(key))) {
          throw new AssessmentError('unsafe-evidence', 'A prohibited credential or object-control field was found in evidence.');
        }
        visit(child, depth + 1);
      }
      return;
    }
    throw new AssessmentError('invalid-evidence', 'Assessment evidence must contain only finite JSON values.');
  };
  visit(value, 0);
}

export function canonicalJson(value: unknown): string {
  if (value === undefined) return 'undefined';
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).sort().join(',')}]`;
  }
  if (typeof value === 'object' && value !== null) {
    return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function stableId(...parts: string[]): string {
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 24);
}

export function recordId(record: JsonObject): string {
  const id = record.id;
  if (typeof id !== 'string' && typeof id !== 'number') {
    throw new AssessmentError('missing-record-id', 'Every evidence record must have a stable string or numeric id.');
  }
  if (String(id).length === 0) {
    throw new AssessmentError('missing-record-id', 'Evidence record ids cannot be empty.');
  }
  return String(id);
}

export function recordKey(record: JsonObject): string {
  return JSON.stringify([recordId(record), record.parentId ?? null, record.repository ?? null]);
}

export function collectionKey(id: string, scope: string): string {
  return JSON.stringify([id, scope]);
}

export function safeHttpsUrl(value: string): boolean {
  if (/[\u0000-\u0020<>"`\\]/.test(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password
      && !credentialPatterns.some(pattern => pattern.test(value));
  } catch {
    return false;
  }
}
