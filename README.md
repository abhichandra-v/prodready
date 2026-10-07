# prodready

**A fast, zero-dependency pre-flight check for Kubernetes manifests and Dockerfiles.**

`prodready` flags the production anti-patterns that show up in most un-reviewed
setups — `:latest` images, root containers, missing limits and probes, plaintext
secrets in env, a mounted Docker socket — and gives you the one-line fix for each.
One static binary, no dependencies, drop it in a pre-commit hook or CI.

```
$ prodready deploy/
deploy/payments.yaml
  [HIGH  ] PR009  Possible plaintext secret in env: API_KEY
           ↳ Move it to a Secret and use valueFrom.secretKeyRef instead of a literal value.
  [HIGH  ] PR001  Image is not pinned: myapp
           ↳ Pin a version or digest — :latest is unreproducible and blocks clean rollbacks.
  ...
3 findings: 2 HIGH, 1 MEDIUM, 0 LOW
```

## Why it exists

Deep scanners like `kube-score`, `checkov`, and `trivy` are excellent — and
worth running. But they're heavier than you want on every commit. `prodready` is
the fast gate *before* those: it catches the handful of issues that cause most
real incidents, in milliseconds, with zero install friction (no Python, no
database, no network). Use it as the pre-commit check; use the big scanners in CI.

## Install

```bash
go install github.com/abhichandra-v/prodready@latest
# or build from source:
git clone https://github.com/abhichandra-v/prodready && cd prodready && go build .
```

## Usage

```bash
prodready                      # scan the current directory
prodready deploy/ Dockerfile   # scan specific paths
prodready --min high .         # only report (and fail CI on) HIGH findings
prodready --format json .      # machine-readable output
```

Exit code is non-zero when any HIGH finding is reported, so it gates CI out of the box.

## What it checks

**Kubernetes workloads** (Deployment, StatefulSet, DaemonSet, Pod, Job, CronJob, Rollout):

| Rule | Severity | Checks |
| --- | --- | --- |
| PR001 | HIGH | Image pinned (not `:latest` / untagged) |
| PR002 | MEDIUM | Resource limits set |
| PR003 | HIGH | Not running privileged |
| PR004 | HIGH | `runAsNonRoot: true` |
| PR005 | MEDIUM | `allowPrivilegeEscalation: false` |
| PR006 | MEDIUM | `readOnlyRootFilesystem: true` |
| PR007 | MEDIUM | Linux capabilities dropped |
| PR008 | MEDIUM | Liveness/readiness probe present |
| PR009 | HIGH | No plaintext secret in env values |
| PR010 | HIGH | No Docker socket mounted |
| PR011 | LOW | seccomp profile set |

**Dockerfiles:**

| Rule | Severity | Checks |
| --- | --- | --- |
| PR020 | MEDIUM | Base image pinned |
| PR021 | HIGH | A non-root `USER` is set |
| PR022 | LOW | `COPY` over `ADD` for local files |
| PR023 | MEDIUM | No `curl … | sh` into the image |

## Scope & honesty

`prodready` is a **heuristic** linter: it reads manifests as text rather than
building a full Kubernetes object model, which is exactly what keeps it tiny and
dependency-free. That means it's a fast first line of defence, not a complete
policy engine — for deep, structural analysis pair it with `kube-score` and
`checkov`. It's tuned to have a low false-positive rate on already-hardened
manifests (it reports **zero** findings on a properly locked-down deployment).

## License

MIT

---

Built by [Abhichandra](https://www.abhichandra.online) — SRE / Platform Engineer.
