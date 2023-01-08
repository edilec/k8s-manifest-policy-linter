# Kubernetes Manifest Policy Linter

`TOOL_ID=k8s-manifest-policy-linter`. A zero-dependency Node 22+ offline policy check for a local JSON export of Kubernetes manifests. JSON is a Kubernetes-compatible YAML subset, but this tool does not parse arbitrary YAML. It consults its pinned `data/schemas.json` subset and never contacts a cluster, loads kubeconfig, pulls an image, or changes a deployment.

```sh
node bin/k8s-manifest-policy-linter.mjs --root examples/passing --policy policy.json --manifests manifests.json
node bin/k8s-manifest-policy-linter.mjs --root examples/failing --policy policy.json --manifests manifests.json
```

The first example exits 0. The second exits 1 with separate `unsupported-api-version` and `resource-limit-missing` findings. `@manifests`, `@policy`, and `@schemas` are logical source roles, not host paths. A pointer such as `/manifests/1/manifest/spec/template/spec/containers/0/resources/limits` locates evidence within the exact exported bundle named at invocation. No object name, image reference, owner value or file path is echoed.

## Export, pinned subset and policy

Bundle: `{"schemaVersion":"1","complete":true,"manifests":[{"manifest":{...}}]}`. Both a nonempty array and explicit `complete:true` are required to pass. Each manifest has `apiVersion`, `kind`, `metadata.name`, and the kind-specific paths below. Names accept DNS-style lowercase alphanumeric labels and dotted resource names. Unknown kinds are incomplete, not green. A known kind with an API version outside the pinned table fails.

| Pinned kind | API version | Paths checked |
| --- | --- | --- |
| Deployment | `apps/v1` | owner label, `spec.template.spec.containers`, explicit rollout strategy |
| Pod | `v1` | owner label, `spec.containers` |
| Service | `v1` | owner label; type omitted/`ClusterIP`, `NodePort`, or `LoadBalancer` with `spec.ports[].port`; `ExternalName` with `spec.externalName`. Other types are incomplete. |

This is a deliberately narrow pinned schema/policy subset, not complete Kubernetes OpenAPI validation. It checks container identity, a nonblank image reference and the presence of configured CPU/memory limits; it does not parse resource-quantity syntax or validate image registries. The CLI uses only its bundled schema snapshot. A direct library caller supplies a trusted schema object explicitly.

Policy: `{"schemaVersion":"1","ownerLabel":"owner","allowedOwners":["platform"],"requireCpuLimit":true,"requireMemoryLimit":true,"allowedRolloutTypes":["RollingUpdate"]}`. The owner key/value policy uses lowercase slugs. A missing/unusable owner, owner outside the allowlist, absent required container limit, absent explicit Deployment rollout strategy, or disallowed rollout type fails. This is a declared-policy check: it does not infer Kubernetes defaults.

## Rules and exits

| Rule | Severity | Meaning |
| --- | --- | --- |
| `unsupported-api-version`, `owner-missing`, `owner-not-allowed`, `resource-limit-missing`, `rollout-policy-missing`, `rollout-policy-violated` | error | Known resource violates pinned support or policy. |
| `policy-invalid`, `schema-invalid`, `bundle-invalid`, `manifest-invalid`, `kind-unsupported` | warning | Configuration, schema or exported structure unusable/unsupported. |
| `bundle-incomplete`, `no-evidence`, `limit-exceeded`, `input-unreadable`, `duplicate-key` | warning | Partial/vacuous/bounded input failure. |

Warnings make status `incomplete` and exit 2 even alongside policy errors. Otherwise errors make `fail` and exit 1; complete clean evidence makes `pass` and exit 0. Invalid CLI usage, root, escaped/symlinked input or policy produces exit 2 with empty stdout and fixed stderr. An unreadable, undecodable, unparseable, oversized or duplicate-key bundle emits an incomplete JSON report. JSON keys are compared after escape decoding, so contradictory completeness fields cannot be hidden by last-value-wins parsing. Findings sort by code-unit `(source role, JSON pointer, rule)`.

## Limits and non-goals

Bundle 1,048,576 bytes; policy 65,536 bytes; JSON depth 16; 1,000 manifests; 5,000 containers; evaluation time 5,000 ms with injected clock. Bounds are inclusive; N+1 is incomplete for bundle evidence or invalid configuration for policy. Inputs are strictly decoded UTF-8 and realpath-confined within `--root`. The tool writes nothing and makes no network calls. No arbitrary YAML reader, full API-server schema, admission controller, live cluster state, kubeconfig, deployment action or auto-fix is included. The library exports `TOOL_ID`, `LIMITS`, `RULES`, `validPolicy`, `validSchemas`, and `lintManifests(bundle,policy,schemas,{now,deadline})`.

Run `npm run check` for syntax and behavioral tests.
