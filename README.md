# JWKS Discovery Service

A Go service that exposes [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) JWKS
endpoints for services defined by certificate manifests stored in an S3 bucket.

It periodically enumerates YAML manifests from S3, extracts the public keys from
the embedded X.509 certificates, and serves a JWKS document per service at:

```
GET /<name>/.well-known/jwks.json
GET /<name>/.well-known          # alias
```

## Manifest format

One YAML file per service in the bucket (e.g. `manifests/payments.yaml`):

```yaml
name: payments          # optional – defaults to the file name
config:                 # optional, opaque service configuration
  audience: https://payments.example.com

cert: |
  -----BEGIN CERTIFICATE-----
  ...leaf certificate...
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----
  ...intermediate(s), optional...
  -----END CERTIFICATE-----
```

Behavior:

- Every `CERTIFICATE` block in the PEM blob is parsed; each unique public key
  becomes one JWK.
- `kid` is the [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint of
  the public key, so it stays stable across certificate renewals when the key
  pair is reused.
- Supported key types: RSA, ECDSA (P-256/P-384/P-521), Ed25519.
- Invalid manifests are logged and skipped; they never block other services.
- Duplicate service names are rejected.

## Configuration (environment)

| Variable          | Required | Default     | Description                              |
| ----------------- | -------- | ----------- | ---------------------------------------- |
| `MANIFEST_BUCKET` | yes      | –           | S3 bucket holding the manifests          |
| `MANIFEST_PREFIX` | no       | `""`        | Key prefix to enumerate                  |
| `AWS_REGION`      | no       | `us-east-1` | AWS region                               |
| `RESCAN_INTERVAL` | no       | `60s`       | Rescan period (Go duration)              |
| `LISTEN_ADDR`     | no       | `:8080`     | HTTP listen address                      |
| `S3_ENDPOINT`     | no       | –           | Custom endpoint (MinIO, LocalStack, …)   |
| `S3_PATH_STYLE`   | no       | `false`     | Use path-style addressing                |

AWS credentials follow the standard chain (IRSA, instance profile, env, …).

## Endpoints

| Path                              | Purpose                              |
| --------------------------------- | ------------------------------------ |
| `/<name>/.well-known/jwks.json`   | JWKS document for the service        |
| `/healthz`                        | Liveness probe                       |
| `/readyz`                         | Readiness – 503 until first rescan   |
| `/metrics`                        | Prometheus metrics                   |

Metrics: `jwks_services_loaded`, `jwks_rescans_total{outcome}`,
`jwks_last_rescan_timestamp_seconds`, `jwks_http_requests_total{route,code}`.

Rescans swap the in-memory registry atomically: a failed rescan (e.g. S3
unreachable) keeps the previously loaded keys.

## Development

```sh
go build ./...
go test ./...
```

Run locally against MinIO:

```sh
MANIFEST_BUCKET=manifests \
S3_ENDPOINT=http://localhost:9000 \
S3_PATH_STYLE=true \
AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
go run ./cmd/jwks-discovery-service
```

## Kubernetes

Helm chart lives in [`deploy/jwks-discovery-service`](deploy/jwks-discovery-service).

```sh
helm install jwks ./deploy/jwks-discovery-service \
  --set config.bucket=my-manifest-bucket \
  --set config.prefix=manifests/ \
  --set config.region=eu-west-1 \
  --set serviceMonitor.enabled=true
```

For S3 access without static credentials, annotate the ServiceAccount with an
IRSA role (see `serviceAccount.annotations` in `values.yaml`):

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/jwks-discovery-service
```

The container image is built and pushed to GHCR by
[`.github/workflows/build-push.yaml`](.github/workflows/build-push.yaml).
