# Draft Optional Remote MCP Container

This container is an opt-in adapter for operators who want authenticated remote
access or bounded scale-out. It does not replace the local CLI or local stdio
MCP server, and the project does not publish or operate a hosted endpoint.

Status: draft artifact. The image has been built and exercised through a local
authenticated MCP smoke test, but it has not yet been promoted through a real
cloud-provider ingress, identity, autoscaling, cost, logging, rotation, and
rollback gate. Local success is useful evidence about the container contract,
not a production-readiness claim.

## Runtime contract

- Streamable HTTP MCP endpoint: `/mcp`
- Unauthenticated process health endpoint: `/health`
- Stateless JSON responses
- Explicitly read-only tools only
- Default bind: `0.0.0.0:8080`
- Non-root runtime user
- One MiB request-body limit by default
- Browser requests rejected unless their exact Origin is allowed
- Uvicorn access log disabled so bearer credentials are not copied into it

The image uses a digest-pinned Python 3.11.15 base and digest-pinned uv 0.11.17
binary. Dependencies are installed from the checked-in `uv.lock`. Build a new
image for each recon revision and deploy its immutable digest.

## Local container smoke test

Build from the repository root:

```powershell
docker build --platform linux/amd64 --file deploy/container/Dockerfile --tag recon-remote:local .
```

Generate a random token in the current PowerShell process without putting it
on the command line:

```powershell
$tokenBytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
$env:RECON_REMOTE_BEARER_TOKEN = [Convert]::ToBase64String($tokenBytes)
docker run --rm --publish 8080:8080 --env RECON_REMOTE_BEARER_TOKEN recon-remote:local
```

In another terminal, verify `http://127.0.0.1:8080/health`, then connect an MCP
Inspector or client to `http://127.0.0.1:8080/mcp` with an `Authorization:
Bearer <token>` header. A request without that header must return 401.

## Configuration

| Variable | Default | Contract |
|---|---|---|
| `RECON_REMOTE_AUTH_MODE` | `static-bearer` | `static-bearer` or `trusted-platform` |
| `RECON_REMOTE_BEARER_TOKEN` | none | Required in static mode; at least 32 ASCII bytes with no whitespace |
| `RECON_REMOTE_HOST` | `0.0.0.0` | Process bind host |
| `RECON_REMOTE_PORT` | `8080` | Process port |
| `RECON_REMOTE_MAX_REQUEST_BYTES` | `1048576` | Request cap from 1 KiB through 16 MiB |
| `RECON_REMOTE_ALLOWED_HOSTS` | empty | Optional comma-separated exact Host values |
| `RECON_REMOTE_ALLOWED_ORIGINS` | empty | Optional comma-separated exact HTTP or HTTPS browser origins |

`trusted-platform` deliberately removes application-level authentication. Use
it only when the managed runtime authenticates every request and callers cannot
bypass that ingress to reach the container. The Cloud Run Terraform reference
uses it only with Cloud Run IAM. A directly reachable container must use
`static-bearer` or sit behind a separately reviewed OAuth gateway.

The initial static token is client authentication for a trusted operator or
team. It is not per-user identity, delegated authorization, or a public
multi-tenant service. Rotate it through the platform secret manager. Do not put
it in Terraform variables, image layers, shell history, logs, or client source.

## Operational limits

The process retains only bounded in-memory cache and rate-limit state. Multiple
instances do not share cache entries or rate limits. Enforce a maximum instance
count, concurrency, per-identity quotas, and cost alerts at the hosting layer.
Cloud logs can contain queried domain names in application diagnostics, so use
restricted access and a deliberately short retention period.

For per-user OAuth, identity-provider choices, AI clients, and other clouds,
read the
[cross-platform plan](../../docs/optional-cloud-deployment-plan.md).
