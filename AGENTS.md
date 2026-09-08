# AGENTS.md

## Commands

Go toolchain needs redirected caches in this environment — the default
`~/go/pkg/mod` has root-owned lock files and fails with `permission denied`:

```sh
export GOMODCACHE=/tmp/opencode/gomodcache GOCACHE=/tmp/opencode/gocache \
       GOPATH=/tmp/opencode/gopath GOSUMDB=off
go build ./... && go vet ./... && go test ./...
```

Single test: `go test ./internal/jwks -run TestSetRSA`

Helm: run `helm lint` / `helm template` **without** the `rtk` wrapper —
`rtk` silently truncates their output, which makes correct templates look
empty or missing. Verify chart changes with
`helm template test deploy/jwks-discovery-service --set config.bucket=b`.

`kubectl` dry-runs fail here (no reachable cluster). Validate manifests with
`helm template` or `kustomize build` instead. Helm v4 and kustomize are
installed via linuxbrew.

## Architecture

`cmd/jwks-discovery-service/main.go` wires everything; flow:
S3 list/fetch YAML manifests (`internal/store`) → cert→JWK conversion
(`internal/jwks`) → atomic registry swap + HTTP server (`internal/server`),
driven by the periodic rescan loop (`internal/refresher`). All config is env
based (see README table); nothing else is required to run locally.

Key invariants:

- `kid` is the RFC 7638 public-key thumbprint, stable across cert renewal;
  duplicate keys in a chain are deduplicated.
- Bad/invalid manifests are logged and skipped — a single broken manifest
  must never fail the whole rescan, but a fully failed enumeration keeps the
  last-good registry.
- `/readyz` stays 503 until the first successful rescan.

## Conventions

- Chart resource names use the **release name only** (no chart name suffix) —
  deliberate choice, keep it. Helper: `jwks-discovery-service.fullname`.
- Container image: `ghcr.io/${{ github.repository }}` in
  `.github/workflows/build-push.yaml`; tags: semver, sha, `pr-<n>`, latest.
- Module path in `go.mod` is `github.com/lukaspj/jwks-discovery-service`
  and matches the git remote — new import paths must follow `go.mod`.
