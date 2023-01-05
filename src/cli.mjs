import { readFileSync, realpathSync, statSync, lstatSync } from 'node:fs';
import { resolve, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lintManifests, validPolicy, LIMITS, RULES, TOOL_ID } from './index.mjs';
import { inspectJsonKeys } from './json-keys.mjs';

const schemaPath = fileURLToPath(new URL('../data/schemas.json', import.meta.url));
const decode = bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
const inside = (root, path) => { const rel = relative(root, path); return rel !== '..' && !rel.startsWith('../') && !isAbsolute(rel); };
const reportError = (ruleId, message, file = '@manifests') => ({ schemaVersion: '1', tool: TOOL_ID, status: 'incomplete', summary: { checked: 0, errors: 0, warnings: 1 }, findings: [{ ruleId, severity: RULES[ruleId], message, location: { file, pointer: '' } }] });

export function runCli(args, { stdout = process.stdout, stderr = process.stderr, now = Date.now } = {}) {
  const invalid = message => { stderr.write(`${message}\n`); return 2; };
  if (args.length !== 6 || args.some((v, i) => i % 2 === 0 && !['--root', '--policy', '--manifests'].includes(v))) return invalid('Usage: --root DIR --policy FILE --manifests FILE');
  const flags = new Map();
  for (let i = 0; i < args.length; i += 2) { if (flags.has(args[i])) return invalid('Duplicate option'); flags.set(args[i], args[i + 1]); }
  if (flags.size !== 3 || [...flags.values()].some(v => typeof v !== 'string' || !v)) return invalid('Missing option value');
  let root;
  try { root = realpathSync(flags.get('--root')); if (!statSync(root).isDirectory()) return invalid('Root must be a directory'); }
  catch { return invalid('Invalid root directory'); }
  const paths = [];
  for (const key of ['--policy', '--manifests']) {
    const value = flags.get(key);
    if (isAbsolute(value) || value.split('/').some(x => x === '..' || x === '.') || /[\u0000-\u001f\u007f-\u009f\\]/u.test(value)) return invalid('Input path must be relative and confined');
    const lexical = resolve(root, value);
    if (!inside(root, lexical)) return invalid('Input path escapes root');
    try { const actual = realpathSync(lexical); if (!inside(root, actual)) return invalid('Input path escapes root'); paths.push(actual); }
    catch (error) {
      if (error.code !== 'ENOENT') return invalid('Invalid input path');
      try { if (lstatSync(lexical).isSymbolicLink()) return invalid('Invalid input link'); } catch (e) { if (e.code !== 'ENOENT') return invalid('Invalid input path'); }
      paths.push(lexical);
    }
  }
  let policy;
  try {
    const bytes = readFileSync(paths[0]);
    if (bytes.length > LIMITS.policyBytes) return invalid('Policy byte limit exceeded');
    const text = decode(bytes);
    policy = JSON.parse(text);
    if (inspectJsonKeys(text, LIMITS.depth) || !validPolicy(policy)) return invalid('Invalid manifest policy');
  } catch { return invalid('Policy could not be read, decoded, or parsed'); }
  let report;
  try {
    const bytes = readFileSync(paths[1]);
    if (bytes.length > LIMITS.bundleBytes) report = reportError('limit-exceeded', 'Manifest bundle byte limit exceeded');
    else {
      const text = decode(bytes), bundle = JSON.parse(text), problem = inspectJsonKeys(text, LIMITS.depth);
      if (problem) report = reportError(problem === 'duplicate' ? 'duplicate-key' : 'limit-exceeded', problem === 'duplicate' ? 'Manifest bundle contains duplicate JSON keys' : 'JSON depth limit exceeded');
      else {
        const source = decode(readFileSync(schemaPath)), schemas = JSON.parse(source);
        report = inspectJsonKeys(source, LIMITS.depth) ? reportError('schema-invalid', 'Pinned schema table contains ambiguous JSON', '@schemas') : lintManifests(bundle, policy, schemas, { now });
      }
    }
  } catch { report = reportError('input-unreadable', 'Manifest bundle or pinned schemas could not be read, decoded, or parsed'); }
  stdout.write(`${JSON.stringify(report)}\n`);
  return report.status === 'pass' ? 0 : report.status === 'fail' ? 1 : 2;
}
