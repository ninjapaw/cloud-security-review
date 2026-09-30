import { COLLECTION_CATALOG } from './catalog.js';
import { parseConfig } from './config.js';
import { assertComparableScope, compareSnapshots } from './diff.js';
import { assessLive, createAssessment } from './engine.js';
import { SEVERITIES } from './model.js';
import type { AssessmentSnapshot, Severity } from './model.js';
import { DEFAULT_POLICY } from './policy.js';
import { assessmentSummary, renderDiffMarkdown, renderHtml, renderMarkdown } from './report.js';
import { AssessmentError } from './safety.js';
import { readJson, writeBundle } from './storage.js';
import { parseInput, parsePolicy, parseSnapshot } from './validation.js';

const help = `Microsoft cloud security assessment (READ-ONLY)

Commands:
  assess --input FILE --output NEW_DIRECTORY [--policy FILE] [--previous FILE]
  assess --config FILE --output NEW_DIRECTORY [--policy FILE] [--previous FILE]
  diff --previous FILE --current FILE --output NEW_DIRECTORY
  validate --config FILE
  validate --input FILE
  catalog
  policy

Assessment options:
  --fail-on critical|high|medium|low|informational
  --allow-incomplete   Acknowledge evidence gaps for the exit status; reports retain all gaps.

--input is offline and accepts schema 1.0 assessment input. --config explicitly
requests live reads in the approved scope using existing credentials.
No tenant configuration changes, secret retrieval, remediation, or uploads.

Exit codes: 0 report/command completed; 1 invalid input or operational failure;
2 incomplete coverage; 3 a failing check meets --fail-on.
Reports are sensitive and never overwrite an existing output directory.
`;

function options(args: string[], allowed: string[]): Map<string, string> {
  const result = new Map<string, string>();
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (!name || !allowed.includes(name) || result.has(name)) {
      throw new AssessmentError('invalid-arguments', 'Unknown or duplicate command-line option. Use --help for supported arguments.');
    }
    if (name === '--allow-incomplete') {
      result.set(name, 'true');
      continue;
    }
    const value = args[++index];
    if (!value || value.startsWith('--')) {
      throw new AssessmentError('invalid-arguments', 'An option value is missing. Use --help for usage.');
    }
    result.set(name, value);
  }
  return result;
}

function required(args: Map<string, string>, name: string): string {
  const value = args.get(name);
  if (!value) throw new AssessmentError('invalid-arguments', `${name} is required.`);
  return value;
}

function oneInput(args: Map<string, string>): { type: 'config' | 'input'; path: string } {
  if (args.has('--input') === args.has('--config')) {
    throw new AssessmentError('invalid-arguments', 'Specify exactly one of --input (offline) or --config (live).');
  }
  return args.has('--input')
    ? { type: 'input', path: required(args, '--input') }
    : { type: 'config', path: required(args, '--config') };
}

function severity(value: string | undefined): Severity | undefined {
  if (value === undefined) return undefined;
  for (const level of SEVERITIES) if (level === value) return level;
  throw new AssessmentError('invalid-arguments', '--fail-on requires a documented severity name.');
}

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  if (!command || command === '--help' || command === 'help') {
    process.stdout.write(help);
    return 0;
  }
  if (command === 'catalog' || command === 'policy') {
    if (args.length) throw new AssessmentError('invalid-arguments', 'This command takes no options.');
    process.stdout.write(`${JSON.stringify(command === 'catalog' ? COLLECTION_CATALOG : DEFAULT_POLICY, null, 2)}\n`);
    return 0;
  }
  if (command === 'validate') {
    const input = oneInput(options(args, ['--config', '--input']));
    const value = await readJson(input.path);
    if (input.type === 'config') parseConfig(value);
    else parseInput(value);
    process.stdout.write('Input is valid. No cloud requests were made.\n');
    return 0;
  }
  if (command === 'diff') {
    const parsed = options(args, ['--previous', '--current', '--output']);
    const previous = parseSnapshot(await readJson(required(parsed, '--previous')));
    const current = parseSnapshot(await readJson(required(parsed, '--current')));
    const diff = compareSnapshots(previous, current);
    const output = await writeBundle(required(parsed, '--output'), {
      'changes.json': `${JSON.stringify(diff, null, 2)}\n`,
      'changes.md': renderDiffMarkdown(diff),
    });
    process.stdout.write(`Comparison saved to ${JSON.stringify(output)}. ${diff.changes.length} observed changes.\n`);
    return 0;
  }
  if (command !== 'assess') {
    throw new AssessmentError('invalid-arguments', 'Unknown command. Use --help for usage.');
  }
  const parsed = options(args, [
    '--config', '--input', '--output', '--policy', '--previous', '--fail-on', '--allow-incomplete',
  ]);
  const input = oneInput(parsed);
  const outputPath = required(parsed, '--output');
  const threshold = severity(parsed.get('--fail-on'));
  const policyPath = parsed.get('--policy');
  const policy = policyPath ? parsePolicy(await readJson(policyPath)) : undefined;
  const previousPath = parsed.get('--previous');
  const previous = previousPath ? parseSnapshot(await readJson(previousPath)) : undefined;
  const value = await readJson(input.path);
  let snapshot: AssessmentSnapshot;
  if (input.type === 'input') {
    const evidence = parseInput(value);
    if (previous) assertComparableScope(previous.scope, evidence.scope);
    snapshot = createAssessment(evidence, policy ?? DEFAULT_POLICY);
  } else {
    const config = parseConfig(value);
    if (previous) assertComparableScope(previous.scope, config.scope);
    snapshot = await assessLive({ ...config, ...(policy ? { policy } : {}) });
  }
  const files: Record<string, string> = {
    'assessment.json': `${JSON.stringify(snapshot, null, 2)}\n`,
    'report.md': renderMarkdown(snapshot),
    'report.html': renderHtml(snapshot),
  };
  if (previous) {
    const diff = compareSnapshots(previous, snapshot);
    files['changes.json'] = `${JSON.stringify(diff, null, 2)}\n`;
    files['changes.md'] = renderDiffMarkdown(diff);
  }
  const output = await writeBundle(outputPath, files);
  const summary = assessmentSummary(snapshot);
  process.stdout.write(`Assessment saved to ${JSON.stringify(output)}.\n${summary.risks} observed risks; ${summary.unableToAssess} checks unable to assess; ${summary.incompleteCollections} collection gaps. No remediation was executed.\n`);
  if (threshold && snapshot.findings.some(finding =>
    finding.status === 'fail' && SEVERITIES.indexOf(finding.severity) <= SEVERITIES.indexOf(threshold))) return 3;
  return summary.incompleteCollections && !parsed.has('--allow-incomplete') ? 2 : 0;
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(error instanceof AssessmentError
    ? `${error.code}: ${error.message}\n`
    : 'assessment-failed: An unexpected operational failure prevented completion. No successful assessment is recorded.\n');
  process.exitCode = 1;
}
