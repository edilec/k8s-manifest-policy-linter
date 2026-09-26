import test from 'node:test';
import assert from 'node:assert/strict';
import { lintManifests, TOOL_ID } from '../src/index.mjs';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const schemas = { schemaVersion: '1', snapshotId: 'k8s-json-subset-2026-09', resources: [{ apiVersion: 'apps/v1', kind: 'Deployment', shape: 'deployment' }, { apiVersion: 'v1', kind: 'Pod', shape: 'pod' }, { apiVersion: 'v1', kind: 'Service', shape: 'service' }] };
const policy = { schemaVersion: '1', ownerLabel: 'owner', allowedOwners: ['platform'], requireCpuLimit: true, requireMemoryLimit: true, allowedRolloutTypes: ['RollingUpdate'] };
const deployment = { apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: 'demo', labels: { owner: 'platform' } }, spec: { strategy: { type: 'RollingUpdate' }, template: { spec: { containers: [{ name: 'app', image: 'example.invalid/app@sha256:abc', resources: { limits: { cpu: '500m', memory: '256Mi' } } }] } } } };
const bundle = { schemaVersion: '1', complete: true, manifests: [{ manifest: deployment }] };

test('supported pinned workload with ownership, limits and rollout passes', () => {
  const report = lintManifests(bundle, policy, schemas);
  assert.equal(TOOL_ID, 'k8s-manifest-policy-linter');
  assert.equal(report.status, 'pass');
  assert.equal(report.summary.checked, 1);
  assert.equal(JSON.stringify(report).includes('example.invalid'), false);
});

test('unsupported API version and missing resource limit fail separately', () => {
  const unsupported = { ...deployment, apiVersion: 'extensions/v1beta1' };
  const version = lintManifests({ ...bundle, manifests: [{ manifest: unsupported }] }, policy, schemas);
  assert.equal(version.status, 'fail');
  assert.equal(version.findings[0].ruleId, 'unsupported-api-version');
  const missing = structuredClone(deployment);
  delete missing.spec.template.spec.containers[0].resources.limits.memory;
  const limits = lintManifests({ ...bundle, manifests: [{ manifest: missing }] }, policy, schemas);
  assert.equal(limits.status, 'fail');
  assert.equal(limits.findings[0].ruleId, 'resource-limit-missing');
  assert.equal(limits.findings[0].location.pointer, '/manifests/0/manifest/spec/template/spec/containers/0/resources/limits');
});

test('missing owner or rollout strategy fails; unknown kind stays incomplete', () => {
  const noOwner = structuredClone(deployment); delete noOwner.metadata.labels.owner;
  assert.equal(lintManifests({ ...bundle, manifests: [{ manifest: noOwner }] }, policy, schemas).status, 'fail');
  const noStrategy = structuredClone(deployment); delete noStrategy.spec.strategy;
  assert.equal(lintManifests({ ...bundle, manifests: [{ manifest: noStrategy }] }, policy, schemas).status, 'fail');
  const unknown = { ...deployment, kind: 'Widget' };
  assert.equal(lintManifests({ ...bundle, manifests: [{ manifest: unknown }] }, policy, schemas).status, 'incomplete');
});

test('valid DNS-style dotted resource and numeric-leading container names do not cause false gaps', () => {
  const valid = structuredClone(deployment);
  valid.metadata.name = 'api.v1';
  valid.spec.template.spec.containers[0].name = '1app';
  assert.equal(lintManifests({ ...bundle, manifests: [{ manifest: valid }] }, policy, schemas).status, 'pass');
});

test('supported Service cannot pass on an empty spec', () => {
  const service = { apiVersion: 'v1', kind: 'Service', metadata: { name: 'demo', labels: { owner: 'platform' } }, spec: {} };
  const result = lintManifests({ ...bundle, manifests: [{ manifest: service }] }, policy, schemas);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.findings[0].ruleId, 'manifest-invalid');
});

test('known Service types pass but invented type and malformed labels stay incomplete', () => {
  const base = { apiVersion: 'v1', kind: 'Service', metadata: { name: 'demo', labels: { owner: 'platform' } }, spec: { ports: [{ port: 80 }] } };
  const check = service => lintManifests({ ...bundle, manifests: [{ manifest: service }] }, policy, schemas);
  for (const type of [undefined, 'ClusterIP', 'NodePort', 'LoadBalancer']) {
    assert.equal(check({ ...base, spec: { ...base.spec, type } }).status, 'pass');
  }
  assert.equal(check({ ...base, spec: { type: 'ExternalName', externalName: 'example.invalid' } }).status, 'pass');
  const invented = check({ ...base, spec: { ...base.spec, type: 'Bogus' } });
  assert.equal(invented.status, 'incomplete');
  assert.ok(invented.findings.some(f => f.ruleId === 'manifest-invalid'));
  const malformed = check({ ...base, metadata: { ...base.metadata, labels: ['owner', 'platform'] } });
  assert.equal(malformed.status, 'incomplete');
  assert.ok(malformed.findings.some(f => f.ruleId === 'manifest-invalid'));
});

test('manifest and container N/N+1, depth N/N+1, injected deadline N/N+1', () => {
  const many = n => ({ ...bundle, manifests: Array.from({ length: n }, () => bundle.manifests[0]) });
  assert.equal(lintManifests(many(1000), policy, schemas).status, 'pass');
  assert.equal(lintManifests(many(1001), policy, schemas).status, 'incomplete');
  const big = n => { const d = structuredClone(deployment); d.spec.template.spec.containers = Array.from({ length: n }, (_, i) => ({ ...deployment.spec.template.spec.containers[0], name: `app-${i}` })); return { ...bundle, manifests: [{ manifest: d }] }; };
  assert.equal(lintManifests(big(5000), policy, schemas).status, 'pass');
  assert.equal(lintManifests(big(5001), policy, schemas).status, 'incomplete');
  const nested = n => { const d = structuredClone(bundle); let x = d; for (let i = 0; i < n; i++) { x.extra = {}; x = x.extra; } return d; };
  assert.equal(lintManifests(nested(16), policy, schemas).status, 'pass');
  assert.equal(lintManifests(nested(17), policy, schemas).status, 'incomplete');
  assert.equal(lintManifests(bundle, policy, schemas, { now: () => 5000, deadline: 5000 }).status, 'pass');
  assert.equal(lintManifests(bundle, policy, schemas, { now: () => 5001, deadline: 5000 }).status, 'incomplete');
});

test('CLI configuration errors have empty stdout; unreadable manifests get incomplete report', () => {
  const root = mkdtempSync(join(tmpdir(), 'k8s-lint-test-'));
  writeFileSync(join(root, 'policy.json'), JSON.stringify(policy));
  const run = (...args) => spawnSync(process.execPath, ['bin/k8s-manifest-policy-linter.mjs', '--root', root, ...args], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });
  const bad = run('--policy', 'policy.json', '--unknown', 'x');
  assert.equal(bad.status, 2); assert.equal(bad.stdout, '');
  const missing = run('--policy', 'policy.json', '--manifests', 'missing.json');
  assert.equal(missing.status, 2); assert.equal(JSON.parse(missing.stdout).status, 'incomplete');
  const outside = mkdtempSync(join(tmpdir(), 'k8s-lint-out-'));
  writeFileSync(join(outside, 'manifests.json'), JSON.stringify(bundle));
  symlinkSync(join(outside, 'manifests.json'), join(root, 'link.json'));
  const escape = run('--policy', 'policy.json', '--manifests', 'link.json');
  assert.equal(escape.status, 2); assert.equal(escape.stdout, '');
});

test('CLI bundle byte N/N+1, strict UTF-8 and escaped duplicate completeness keys', () => {
  const root = mkdtempSync(join(tmpdir(), 'k8s-lint-bytes-'));
  writeFileSync(join(root, 'policy.json'), JSON.stringify(policy));
  const plain = JSON.stringify(bundle);
  const run = () => spawnSync(process.execPath, ['bin/k8s-manifest-policy-linter.mjs', '--root', root, '--policy', 'policy.json', '--manifests', 'manifests.json'], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });
  writeFileSync(join(root, 'manifests.json'), plain + ' '.repeat(1048576 - Buffer.byteLength(plain)));
  assert.equal(run().status, 0);
  writeFileSync(join(root, 'manifests.json'), plain + ' '.repeat(1048577 - Buffer.byteLength(plain)));
  assert.equal(JSON.parse(run().stdout).findings[0].ruleId, 'limit-exceeded');
  writeFileSync(join(root, 'manifests.json'), Buffer.from([0xff]));
  assert.equal(JSON.parse(run().stdout).findings[0].ruleId, 'input-unreadable');
  writeFileSync(join(root, 'manifests.json'), plain.replace('"complete":true', '"com\\u0070lete":false,"complete":true'));
  assert.equal(JSON.parse(run().stdout).findings[0].ruleId, 'duplicate-key');
});

test('CLI policy byte N/N+1 and duplicate keys stay configuration errors', () => {
  const root = mkdtempSync(join(tmpdir(), 'k8s-policy-bytes-'));
  const plain = JSON.stringify(policy);
  writeFileSync(join(root, 'manifests.json'), JSON.stringify(bundle));
  const run = () => spawnSync(process.execPath, ['bin/k8s-manifest-policy-linter.mjs', '--root', root, '--policy', 'policy.json', '--manifests', 'manifests.json'], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });
  writeFileSync(join(root, 'policy.json'), plain + ' '.repeat(65536 - Buffer.byteLength(plain)));
  assert.equal(run().status, 0);
  writeFileSync(join(root, 'policy.json'), plain + ' '.repeat(65537 - Buffer.byteLength(plain)));
  const over = run(); assert.equal(over.status, 2); assert.equal(over.stdout, '');
  writeFileSync(join(root, 'policy.json'), plain.replace('"schemaVersion":"1"', '"schemaVersion":"0","schemaVersion":"1"'));
  const duplicate = run(); assert.equal(duplicate.status, 2); assert.equal(duplicate.stdout, '');
});
