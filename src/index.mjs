export const TOOL_ID = 'k8s-manifest-policy-linter';
export const LIMITS = Object.freeze({ bundleBytes: 1048576, policyBytes: 65536, depth: 16, manifests: 1000, containers: 5000, milliseconds: 5000 });
export const RULES = Object.freeze({ 'policy-invalid': 'warning', 'schema-invalid': 'warning', 'bundle-invalid': 'warning', 'bundle-incomplete': 'warning', 'no-evidence': 'warning', 'manifest-invalid': 'warning', 'kind-unsupported': 'warning', 'unsupported-api-version': 'error', 'owner-missing': 'error', 'owner-not-allowed': 'error', 'resource-limit-missing': 'error', 'rollout-policy-missing': 'error', 'rollout-policy-violated': 'error', 'limit-exceeded': 'warning', 'input-unreadable': 'warning', 'duplicate-key': 'warning' });
const obj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const slug = x => typeof x === 'string' && /^[a-z][a-z0-9-]{0,79}$/.test(x);
const dnsLabel = x => typeof x === 'string' && x.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x);
const dnsName = x => typeof x === 'string' && x.length <= 253 && x.split('.').every(dnsLabel);
const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
function depth(value) {
  const stack = [[value, 0, new Set()]];
  while (stack.length) {
    const [x, n, ancestors] = stack.pop();
    if (n > LIMITS.depth) return n;
    if (x && typeof x === 'object') {
      if (ancestors.has(x)) return LIMITS.depth + 1;
      const next = new Set(ancestors); next.add(x);
      for (const child of Object.values(x)) stack.push([child, n + 1, next]);
    }
  }
  return 0;
}
export function validPolicy(p) { return obj(p) && Object.keys(p).every(k => ['schemaVersion', 'ownerLabel', 'allowedOwners', 'requireCpuLimit', 'requireMemoryLimit', 'allowedRolloutTypes'].includes(k)) && p.schemaVersion === '1' && slug(p.ownerLabel) && Array.isArray(p.allowedOwners) && p.allowedOwners.length > 0 && p.allowedOwners.length <= 100 && p.allowedOwners.every(slug) && new Set(p.allowedOwners).size === p.allowedOwners.length && typeof p.requireCpuLimit === 'boolean' && typeof p.requireMemoryLimit === 'boolean' && Array.isArray(p.allowedRolloutTypes) && p.allowedRolloutTypes.length > 0 && p.allowedRolloutTypes.every(x => x === 'RollingUpdate' || x === 'Recreate') && new Set(p.allowedRolloutTypes).size === p.allowedRolloutTypes.length; }
export function validSchemas(s) { return obj(s) && s.schemaVersion === '1' && slug(s.snapshotId) && Array.isArray(s.resources) && s.resources.length > 0 && s.resources.length <= 100 && s.resources.every(r => obj(r) && typeof r.apiVersion === 'string' && /^[A-Za-z0-9./-]{1,80}$/.test(r.apiVersion) && typeof r.kind === 'string' && /^[A-Za-z][A-Za-z0-9]{0,79}$/.test(r.kind) && ['deployment', 'pod', 'service'].includes(r.shape)) && new Set(s.resources.map(r => `${r.apiVersion}\0${r.kind}`)).size === s.resources.length; }

export function lintManifests(bundle, policy, schemas, { now = Date.now, deadline = now() + LIMITS.milliseconds } = {}) {
  const findings = [];
  const add = (ruleId, pointer, message, file = '@manifests') => {
    if (!Object.hasOwn(RULES, ruleId)) throw new Error('unknown rule');
    findings.push({ ruleId, severity: RULES[ruleId], message, location: { file, pointer } });
  };
  const finish = checked => {
    findings.sort((a, b) => cmp(a.location.file, b.location.file) || cmp(a.location.pointer, b.location.pointer) || cmp(a.ruleId, b.ruleId));
    return { schemaVersion: '1', tool: TOOL_ID, status: findings.some(f => f.severity === 'warning') ? 'incomplete' : findings.length ? 'fail' : 'pass', summary: { checked, errors: findings.filter(f => f.severity === 'error').length, warnings: findings.filter(f => f.severity === 'warning').length }, findings };
  };
  if (!validPolicy(policy)) { add('policy-invalid', '', 'Manifest policy is invalid', '@policy'); return finish(0); }
  if (!validSchemas(schemas)) { add('schema-invalid', '', 'Pinned schema table is invalid', '@schemas'); return finish(0); }
  if (depth(bundle) > LIMITS.depth) { add('limit-exceeded', '', 'JSON depth limit exceeded'); return finish(0); }
  if (!obj(bundle) || bundle.schemaVersion !== '1' || typeof bundle.complete !== 'boolean' || !Array.isArray(bundle.manifests)) { add('bundle-invalid', '', 'Manifest export is invalid'); return finish(0); }
  if (bundle.manifests.length > LIMITS.manifests) { add('limit-exceeded', '/manifests', 'Manifest record limit exceeded'); return finish(0); }
  if (!bundle.manifests.length) { add('no-evidence', '/manifests', 'At least one manifest is required'); return finish(0); }
  if (!bundle.complete) add('bundle-incomplete', '/complete', 'Manifest export declares partial coverage');
  let containers = 0;
  for (let i = 0; i < bundle.manifests.length; i++) {
    if (now() > deadline) { add('limit-exceeded', '', 'Evaluation time limit exceeded'); return finish(i); }
    const record = bundle.manifests[i], pointer = `/manifests/${i}/manifest`, m = obj(record) ? record.manifest : null;
    if (!obj(m) || typeof m.apiVersion !== 'string' || typeof m.kind !== 'string' || !obj(m.metadata) || !dnsName(m.metadata.name)) { add('manifest-invalid', pointer, 'Manifest identity or metadata is invalid'); continue; }
    const kinds = schemas.resources.filter(s => s.kind === m.kind);
    if (!kinds.length) { add('kind-unsupported', pointer, 'Resource kind is outside pinned schema subset'); continue; }
    const schema = kinds.find(s => s.apiVersion === m.apiVersion);
    if (!schema) { add('unsupported-api-version', `${pointer}/apiVersion`, 'Resource API version is outside pinned schema subset'); continue; }
    const labels = m.metadata.labels;
    if (labels !== undefined && !obj(labels)) add('manifest-invalid', `${pointer}/metadata/labels`, 'Manifest labels must be an object when present');
    const owner = obj(labels) ? labels[policy.ownerLabel] : undefined;
    if (!slug(owner)) add('owner-missing', `${pointer}/metadata/labels`, 'Declared owner label is missing or unusable');
    else if (!policy.allowedOwners.includes(owner)) add('owner-not-allowed', `${pointer}/metadata/labels`, 'Declared owner is outside policy allowlist');
    if (schema.shape === 'service') {
      const spec = m.spec;
      const type = obj(spec) && spec.type === undefined ? 'ClusterIP' : spec?.type;
      if (!['ClusterIP', 'NodePort', 'LoadBalancer', 'ExternalName'].includes(type) || (type === 'ExternalName' ? !dnsName(spec.externalName) : !Array.isArray(spec.ports) || !spec.ports.length || spec.ports.some(p => !obj(p) || !Number.isSafeInteger(p.port) || p.port < 1 || p.port > 65535))) add('manifest-invalid', `${pointer}/spec`, 'Service type or required routing evidence is invalid');
      continue;
    }
    const podSpec = schema.shape === 'deployment' ? m.spec?.template?.spec : m.spec;
    const path = schema.shape === 'deployment' ? `${pointer}/spec/template/spec/containers` : `${pointer}/spec/containers`;
    if (!obj(podSpec) || !Array.isArray(podSpec.containers) || !podSpec.containers.length) { add('manifest-invalid', path, 'Workload containers are missing'); continue; }
    containers += podSpec.containers.length;
    if (containers > LIMITS.containers) { add('limit-exceeded', '/manifests', 'Container record limit exceeded'); return finish(i); }
    for (let j = 0; j < podSpec.containers.length; j++) {
      const c = podSpec.containers[j], cp = `${path}/${j}`;
      if (!obj(c) || !dnsLabel(c.name) || typeof c.image !== 'string' || !c.image.trim()) { add('manifest-invalid', cp, 'Container identity or image reference is invalid'); continue; }
      const limits = c.resources?.limits;
      const usable = x => typeof x === 'string' && x.trim().length > 0 && x.length <= 80 && !/[\u0000-\u001f\u007f-\u009f]/u.test(x);
      if ((policy.requireCpuLimit && !usable(limits?.cpu)) || (policy.requireMemoryLimit && !usable(limits?.memory))) add('resource-limit-missing', `${cp}/resources/limits`, 'Required container resource limit is missing or unusable');
    }
    if (schema.shape === 'deployment') {
      const strategy = m.spec?.strategy;
      if (!obj(strategy) || typeof strategy.type !== 'string') add('rollout-policy-missing', `${pointer}/spec/strategy`, 'Deployment rollout strategy is missing');
      else if (!policy.allowedRolloutTypes.includes(strategy.type)) add('rollout-policy-violated', `${pointer}/spec/strategy/type`, 'Deployment rollout strategy is outside policy');
    }
  }
  return finish(bundle.manifests.length);
}
