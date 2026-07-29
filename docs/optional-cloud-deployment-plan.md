# Draft Optional Cloud Access and Scale-Out Framework

Status: draft, low-priority optional depth and polish. The local CLI and local
stdio MCP server remain the default and complete product. A shared runtime,
container, and Google Cloud Run Terraform starting point are checked in. This
draft is intended to be directionally useful, not a validated production
deployment. It has not yet passed a real cloud-provider promotion gate. The
project does not operate a hosted endpoint.

Research review date: 2026-07-28.

## Decision

The directionally recommended way to let people use recon at greater scale
with the AI system of their choice is one portable boundary:

```text
AI or agent with an MCP client
          |
          | authenticated HTTPS, Streamable HTTP MCP
          v
operator-owned ingress and identity boundary
          |
          v
stateless recon container, bounded concurrency and scale
          |
          v
the same public DNS, identity, CT, and MTA-STS sources as local recon
```

The AI provider and the compute provider are separate choices. Anthropic and
OpenAI can consume a remote MCP endpoint, but neither is a general-purpose
host for recon's Python process. AWS, Google Cloud, Azure, Cloudflare, a
Kubernetes platform, or any ordinary OCI host can run that process. A user
should not need a different recon implementation for each model vendor.

This means:

1. Keep `recon <domain>` and `recon mcp` local-first and unchanged.
2. Package one optional, stateless, authenticated Streamable HTTP adapter.
3. Put provider-specific IaC around that adapter only where the platform path
   is mature and testable.
4. Let Claude, OpenAI, Foundry, Bedrock, Vertex-based agents, and generic MCP
   clients consume the same contract when their client surface supports remote
   MCP.
5. Use a thin MCP client inside the agent application when an AI API does not
   provide a first-party remote MCP connector.

Serverless containers are the default scale-out shape. Functions remain valid
secondary adapters, but they add protocol bridges, framework constraints, or
authentication gaps for a Python MCP server whose calls can spend up to 120
seconds waiting on bounded public-network sources.

## What Optional Means

This track must never become an installation requirement or a prerequisite for
the CLI, JSON output, local stdio MCP, development, tests, or releases.

- A local user installs only `recon-tool`; no cloud SDK, Terraform provider, or
  container runtime is required.
- The project does not run a central endpoint, collect telemetry, receive
  query logs, manage users, or pay an operator's cloud bill.
- IaC is a reviewed reference, not an automatic deployment or support promise
  for every provider feature.
- An operator chooses and owns the account, region, identity provider, secret
  rotation, log retention, quotas, budgets, upgrades, and incident response.
- Cloud-specific work stays below the three core roadmap priorities. It may
  proceed as bounded polish when it does not displace claim truthfulness, MCP
  compatibility, or the product-quality baseline.
- A project-operated public SaaS or multi-tenant recon service is not planned.

## Maturity and Evidence Labels

This plan uses four maturity levels so research, checked-in files, and real
operational evidence are not conflated:

| Label | Meaning |
|---|---|
| Research direction | Current first-party documentation supports the approach, but no maintained recon artifact exists for it |
| Draft artifact | Code or IaC exists and passes local repository checks, but has not passed a real provider deployment gate |
| Provider-validated reference | A named operator has applied it in a non-production provider account and completed the promotion checklist below |
| Production-proven | A named operator has additionally supplied bounded load, cost, rotation, retention, rollback, and operating evidence |

Current state: the shared adapter, container, and Cloud Run Terraform are draft
artifacts. AWS, Azure, Cloudflare, Kubernetes, OAuth, and AI-client sections are
research directions or integration guidance. No path in this document is yet
claimed as a provider-validated reference or production-proven deployment.

Repository CI can prove syntax, tests, a Linux image build, and a local MCP
handshake. It cannot prove cloud IAM behavior, organization policy, regional
availability, quotas, managed-secret injection, public ingress controls,
autoscaling, cold starts, billing, logs, or rollback on a real provider.

## Who Should Use Which Path

| Need | Directional starting point | Current maturity | Why |
|---|---|---|---|
| One person or one desktop agent | Local CLI or stdio MCP | Shipped local path | Zero cloud cost, lowest latency, simplest trust boundary |
| A trusted team using different AI clients | Optional container on Cloud Run or another OCI host | Draft artifact | One model-neutral endpoint, scale to zero, bounded cost |
| Google-only private agents | Cloud Run with Google IAM | Draft artifact | Platform identity can remain closed to public invocation |
| AWS-native agent platform | Bedrock AgentCore Runtime after the IaC gate below | Research direction | Purpose-built MCP hosting, JWT auth, session and gateway options |
| Microsoft Foundry with private networking | Azure Container Apps with internal ingress | Research direction | Foundry's documented private MCP path |
| Edge-native TypeScript tools | Cloudflare Workers | Research direction | Native remote MCP handler and OAuth ecosystem |
| Existing enterprise platform with sustained traffic | Kubernetes or an existing container service | Research direction | Reuse established ingress, identity, policy, and observability |
| OpenAI access to private or on-prem compute | Local container plus OpenAI Secure MCP Tunnel | Integration guidance | Keeps the runtime private while OpenAI consumes it through the tunnel |

## Shared Runtime Contract

The draft adapter is [src/recon_tool/remote_server.py](../src/recon_tool/remote_server.py).
It deliberately is not a new CLI command, so the stable local CLI surface does
not change.

### Protocol

- HTTPS at the managed ingress.
- Streamable HTTP MCP at `/mcp`.
- Stateless mode with JSON responses.
- Process health at `/health`.
- No legacy SSE-only deployment.
- Production MCP SDK remains `mcp>=1.28.1,<2` until the separate stable-v2
  adoption review changes it. The remote adapter refuses to start on an
  unadopted SDK family rather than guessing at a production transport.

Stateless mode fits recon because the meaningful result is derived from each
tool call plus bounded process cache. recon does not need sampling, elicitation,
or multi-turn server state. It also lets a serverless platform route each
request independently and scale to zero.

### Remote tool boundary

The remote process exposes only tools with an explicit `readOnlyHint=true`.
It also removes `list_ephemeral_fingerprints`, because its corresponding write
tools are absent. The following local or session-mutating tools cannot appear:

- `inject_ephemeral_fingerprint`
- `clear_ephemeral_fingerprints`
- `reevaluate_domain`
- `reload_data`
- `list_ephemeral_fingerprints`

Catalog resources, the prompt, and the remaining read-only tools stay
available. This is a remote safety boundary, not the deferred core-versus-
advanced context-optimization profile.

### HTTP boundary

- Static bearer mode fails startup without an ASCII token of at least 32
  bytes.
- Token comparison uses constant-time digest comparison.
- Trusted platform mode must be selected explicitly and is safe only when the
  container cannot be reached around the platform's authenticated ingress.
- Duplicate or malformed authentication, Host, Origin, and Content-Length
  headers fail closed.
- Browser Origin headers are rejected by default. Exact origins can be added
  when a reviewed browser client exists.
- Request bodies are buffered only up to a one MiB default and a hard 16 MiB
  configuration ceiling.
- Responses add `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and
  `X-Content-Type-Options: nosniff`.
- Uvicorn access logging is disabled. Application diagnostics can still name a
  queried domain and therefore require restricted access and short retention.

### Runtime and scale defaults

- Non-root Linux container.
- Read-only installed application, with only the user's bounded recon cache in
  its home directory.
- One vCPU and one GiB memory as the initial Cloud Run profile.
- Concurrency eight per instance, based on Google's recommendation to begin at
  a lower concurrency when Python resource behavior is not yet load-tested.
- Minimum instances zero and maximum instances three.
- Request timeout 180 seconds, leaving margin above recon's bounded 120-second
  resolution timeout.
- Immutable image digest and numeric secret version for each revision.
- No cross-instance cache or distributed rate limiter in the initial version.

The maximum instance count is both a cost control and an abuse bound. A real
multi-user deployment also needs identity-aware quotas at the ingress because
the in-process per-domain rate limiter is not shared across instances.

## Authentication Evolution

Authentication should grow in explicit stages rather than treating one shared
secret as a user system.

### Stage A: trusted client or team

Present in the draft adapter and locally checked:

- Static random bearer stored in the provider secret manager, or
- platform IAM when every intended client can mint that platform's token.

This authenticates a client or trusted team. It does not identify individual
people, express scopes, support revocation per user, or create a multi-tenant
boundary. Static bearer mode is appropriate for OpenAI's explicit
`authorization` parameter and Anthropic's beta static request-header option,
subject to the client's own product controls.

### Stage B: per-user OAuth

Required before describing the endpoint as per-user or broadly shared:

- OAuth 2.1 authorization code flow with PKCE S256.
- Protected Resource Metadata and a correct 401 `WWW-Authenticate` challenge.
- Authorization Server Metadata.
- Client ID Metadata Documents where supported, with Dynamic Client
  Registration as a compatibility fallback.
- Short-lived access tokens, refresh-token rotation, audience restriction,
  issuer verification, and explicit recon scopes.
- Subject-derived identity, per-subject quotas, revocation, and audit events.
- No token, authorization code, DNS value, or MCP request body in logs.

The authorization server should be a mature external identity system rather
than custom password or token issuance code in recon. Auth0 is notable on AWS
because AWS's AgentCore MCP guide uses it for Dynamic Client Registration.
Entra ID, Okta, WorkOS, Stytch, Cognito, and other providers remain viable only
after their client registration and MCP discovery behavior is verified for the
chosen AI client.

### Stage C: public directory or multi-organization use

Not planned without a new product decision. It would require tenant isolation,
terms and abuse handling, privacy review, support ownership, billing controls,
data retention policy, external security review, and an availability target.
Publishing to an AI vendor directory is distribution, not hosting, and does
not remove those duties.

## AI and Agent Consumer Plans

### Anthropic and Claude

Status: integration guidance only. It has not yet been exercised against a
provider-validated recon endpoint through Claude's managed connector surface.

Anthropic's current guidance says to build the remote MCP server with OAuth
first, then add a plugin for distribution. Claude custom connectors use a
remote Streamable HTTP endpoint. OAuth is the per-user route. Team and
Enterprise administrators can also configure beta static request headers for
one organization-wide credential.

Plan:

1. Initial trusted-team use can point a custom connector at the Cloud Run
   `/mcp` URL and supply the static bearer through the supported header UI.
2. Do not call that per-user authentication. Every user shares the same remote
   credential and authorization boundary.
3. Add a DCR or CIMD-capable OAuth gateway before public connector use.
4. Add human-readable tool titles and complete the Anthropic connector review
   checklist before considering directory submission.
5. Treat directory submission as optional distribution work after real demand,
   not a condition for using Claude with a private connector.

Anthropic consumes this endpoint. It does not provide a general service that
runs recon's Python package for the operator.

Primary sources:

- [What to build for Claude](https://claude.com/docs/connectors/building/what-to-build)
- [Build remote connectors](https://claude.com/docs/connectors/building)
- [Connector authentication](https://claude.com/docs/connectors/building/authentication)
- [Custom remote connectors](https://claude.com/docs/connectors/custom/remote-mcp)
- [Connector review criteria](https://claude.com/docs/connectors/building/review-criteria)
- [Anthropic API MCP connector](https://platform.claude.com/docs/en/agents-and-tools/mcp-connector)

### OpenAI and ChatGPT

Status: integration guidance only. It has not yet been exercised against a
provider-validated recon endpoint through the Responses API, ChatGPT plugin
surface, or Secure MCP Tunnel.

OpenAI's Responses API can call remote MCP servers on the public Internet and
accepts an authorization bearer. It supports tool allowlists, deferred loading,
and approval policies. ChatGPT plugin distribution uses a fixed or templated
remote MCP endpoint and expects OAuth for authenticated per-user use. OpenAI's
Secure MCP Tunnel is the relevant private or on-prem access option. It connects
to compute; it does not replace that compute.

Plan:

1. Use `authorization` for the initial trusted-client bearer.
2. Set `allowed_tools` to the smallest task-specific subset in each API call.
3. Keep approvals enabled until the operator deliberately narrows them.
4. Use the Secure MCP Tunnel when public ingress is unacceptable.
5. Add the shared OAuth stage before ChatGPT plugin publication.
6. Review the remote MCP provider's own retention and residency because the AI
   API's data controls do not govern the independently operated endpoint.

Primary sources:

- [OpenAI connectors and remote MCP](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)
- [Build an OpenAI remote MCP server](https://developers.openai.com/api/docs/mcp)
- [Deploy a plugin MCP endpoint](https://developers.openai.com/plugins/build/mcp-server#deploy-the-endpoint)
- [Plugin authentication](https://developers.openai.com/plugins/build/auth)
- [MCP plugin submission](https://developers.openai.com/plugins/deploy/submission#mcp)

### Microsoft Foundry

Status: research direction and integration guidance only. No Foundry-to-recon
managed remote MCP path has yet passed this plan's provider promotion gate.

Foundry agents can consume public remote MCP endpoints. Microsoft's current
private-MCP guidance is more specific: use Standard Agent Setup and host the
server on Azure Container Apps with internal-only ingress in a dedicated MCP
subnet. Foundry's comparison says Container Apps supports any Linux-container
language and dependencies, while Functions requires platform-specific files,
is stateless, uses key auth by default, and needs API Management for OAuth.

Plan:

1. Prefer Container Apps for recon.
2. Use public ingress plus an application bearer only for a trusted-client
   proof.
3. Use internal ingress for a private Foundry deployment.
4. Put API Management or another verified OAuth resource-server gateway in
   front for external per-user clients.
5. Create Azure IaC only after a subscription, region, resource group, quota,
   identity design, and cost approval are supplied. The Azure preparation gate
   forbids guessing those values.

Primary sources:

- [Foundry remote MCP endpoints](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/model-context-protocol)
- [Build a Foundry MCP server](https://learn.microsoft.com/en-us/azure/foundry/mcp/build-your-own-mcp-server)
- [Azure Container Apps Well-Architected guidance](https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-container-apps)
- [Container Apps authentication](https://learn.microsoft.com/en-us/azure/container-apps/authentication)

### AWS Bedrock and other AWS agents

Status: research direction and integration guidance only. No AgentCore-hosted
or Bedrock-to-recon managed path has yet passed the provider promotion gate.

AgentCore can both host an MCP server and connect agents to remote MCP. Its
runtime is model-flexible, including Bedrock, Anthropic, Google, and OpenAI
models. AgentCore Gateway adds centralized authentication, observability,
session routing, and policy when those features are justified.

The hosting and consuming choices should stay separable. A Bedrock agent can
call recon on Cloud Run, and a non-Bedrock AI client can call recon on
AgentCore, subject to authentication compatibility.

Primary sources:

- [Host MCP servers in AgentCore Runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp.html)
- [AgentCore Runtime hosting](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html)
- [AgentCore MCP server targets](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-target-MCPservers.html)
- [AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html)

### Google agents and generic MCP clients

Status: integration guidance only. The local MCP handshake is checked, but no
managed Vertex or other hosted client path has yet passed the provider
promotion gate.

Google Cloud has first-party Cloud Run guidance for hosting remote MCP servers
and for IAM or OIDC client authentication. Vertex Agent Engine is an agent
runtime, not a replacement for the recon service. Use its framework's MCP
client or a small agent-side adapter when the selected Vertex surface does not
accept an arbitrary remote MCP URL directly.

Any other MCP client can use the same endpoint if it supports Streamable HTTP
and the selected authentication method. A client that only supports stdio
should continue to launch local `recon mcp` rather than adding a fragile remote
bridge by default.

Primary sources:

- [Host MCP servers on Cloud Run](https://docs.cloud.google.com/run/docs/host-mcp-servers)
- [Vertex AI Agent Engine](https://cloud.google.com/vertex-ai/generative-ai/docs/reasoning-engine/overview)

## Compute Provider Plans

### 1. Portable OCI container

Status: draft artifact, locally built and smoke-tested but not yet
cloud-provider-validated. See [deploy/container](../deploy/container/README.md).

This is the common artifact for Cloud Run, Container Apps, ordinary container
services, and future AgentCore support. It uses digest-pinned build inputs,
locked Python dependencies, a non-root user, a process health check, and no
embedded secret.

Acceptance before publishing a prebuilt image:

- Build and smoke-test `linux/amd64` and `linux/arm64`.
- Generate an image SBOM and vulnerability scan.
- Sign the multi-architecture image and publish provenance using the same
  identity discipline as Python releases.
- Prove wheel and container versions match.
- Document base-image refresh ownership and supported tag retention.

Until that gate passes, operators build the image from a reviewed revision.

### 2. Google Cloud Run

Status: draft Terraform artifact, locally checked but not yet applied or
validated through a real Cloud Run ingress. See
[deploy/gcp-cloud-run](../deploy/gcp-cloud-run/README.md). This is the
directional first portable serverless path.

Why first:

- Google now documents remote MCP hosting on Cloud Run directly.
- It runs the current Python container without a function adapter.
- It supports response streaming, scale to zero, bounded maximum instances,
  Secret Manager, service identities, probes, and requests up to 60 minutes.
- The recommended starting concurrency of eight matches a cautious first
  profile for recon's I/O-heavy resolver.

The draft module expresses two authentication modes:

- `application-bearer`: public Cloud Run invoker, application authentication
  from a numeric Secret Manager version. Use for AI-of-choice interoperability.
- `google-iam`: private Cloud Run invoker and named IAM members. Use only when
  every client can obtain a Google ID token.

Not yet included:

- OAuth, Cloud Armor, a global load balancer, custom domain, VPC egress, shared
  cache, or per-user quotas.
- Artifact Registry creation and image build pipeline.
- A project-wide logging or monitoring stack.

Promotion gate:

- One operator validates a real client handshake and bounded load test.
- p50 and p95 cold and warm latency, error rate, instance count, and cost per
  1,000 representative calls are recorded without target identities.
- Token rotation and immutable-image rollback are rehearsed.
- Cloud logs use an approved retention period and access policy.

### 3. AWS Bedrock AgentCore Runtime

Status: research direction and preferred AWS-specific design, plan only.

AgentCore is the strongest conceptual AWS fit in July 2026. It is a secure,
serverless, purpose-built host for MCP servers. AWS recommends stateless mode
for basic MCP servers and requires an ARM64 container listening on
`0.0.0.0:8000/mcp`. Its inbound authorizer validates JWT issuer, audience,
client, scopes, and custom claims. The official MCP guide uses Auth0 because
Dynamic Client Registration works with MCP clients.

Planned artifact:

- ARM64 build of the shared container, with port 8000.
- ECR repository with immutable tags and scan-on-push.
- Least-privilege runtime role limited to that repository and required logs.
- `MCP` protocol, stateless mode, public network egress for recon's documented
  sources, and a complete JWT authorizer.
- Runtime and endpoint outputs plus an MCP Inspector smoke test.
- Optional AgentCore Gateway only when policy, aggregation, or centralized
  observability is actually required.

Current stop rule:

AWS requires MMDSv2 for AgentCore invocations starting 2026-06-30. The
official Terraform runtime resource available during this review exposes the
runtime and custom JWT authorizer but does not expose the required metadata
configuration. The current CloudFormation runtime schema reviewed on the same
date also omits it. Do not check in IaC that needs an imperative post-apply
patch or silently creates a runtime that cannot be invoked. Implement this
reference when the official provider or stable CDK path can express and retain
MMDSv2 declaratively, then validate it in an AWS account.

Sources:

- [AgentCore MCP protocol contract](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html)
- [AgentCore inbound JWT authorizer](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html)
- [AgentCore security best practices](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-security-best-practices.html)
- [Terraform AgentCore runtime resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_agent_runtime)
- [CloudFormation AgentCore runtime resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrockagentcore-runtime.html)

### 4. AWS Lambda, App Runner, and ECS

Status: research directions for secondary AWS paths, plan only.

Lambda is viable with an OCI image and AWS Lambda Web Adapter. Use a Function
URL only for a small trusted-client deployment. Function URL authentication is
limited to IAM or none. Claude and OpenAI do not generally sign SigV4 requests,
so interoperable use means a publicly invokable URL with application auth, or
API Gateway with a JWT authorizer. Configure reserved concurrency, a timeout
near 180 seconds, immutable ECR image digest, and the adapter's readiness path.

Lambda is not first because it adds an HTTP-to-invocation adapter, has more cold
start sensitivity, and complicates OAuth and streaming. It becomes worthwhile
only if the operator already standardizes on Lambda and accepts those limits.

App Runner is a simpler long-running container endpoint but does not offer the
same scale-to-zero economics. ECS Fargate is appropriate for steady or highly
controlled traffic, VPC egress, and organization-standard load balancers. Both
should use an OAuth-capable gateway for per-user external access.

Sources:

- [Lambda container images](https://docs.aws.amazon.com/lambda/latest/dg/images-create.html)
- [Lambda timeouts](https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html)
- [Function URL authentication](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [AWS Lambda Web Adapter](https://github.com/aws/aws-lambda-web-adapter)
- [AWS SAM](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)

### 5. Azure Container Apps and Functions

Status: research direction for the preferred Azure design. IaC is deferred
until an Azure context and explicit plan approval exist.

Container Apps is preferred because recon already is a Linux container, needs
ordinary Python dependencies, and can use HTTP ingress, scale to zero, managed
identity, Key Vault, probes, and Azure Monitor. A production Bicep plan should
include:

- Resource group and region chosen by the operator.
- Container Apps environment and Log Analytics or approved Azure Monitor path.
- User-assigned managed identity with only Key Vault secret read access.
- External or internal ingress to port 8080, based on the consumer.
- Minimum replicas zero, bounded maximum replicas, HTTP concurrency scaling,
  180-second end-to-end timeout validation, and `/health` probes.
- Key Vault backed static bearer for the initial public proof, or API Management
  and Entra-compatible OAuth for per-user external access.
- Internal-only ingress and a dedicated MCP subnet for private Foundry use.
- Budgets, alerts, log retention, and image-digest rollback.

Azure Functions is a secondary path. Microsoft's current Foundry guidance says
it requires Functions-specific root files, supports only stateless servers, uses
key authentication by default, and needs API Management for OAuth. It offers no
advantage over Container Apps for the current package unless an operator has a
strong Functions standard.

Stop rule: do not invent a subscription, resource group, region, quota, Entra
tenant, or monitoring workspace. Generate and validate Azure IaC only after an
operator selects those values and approves the Azure deployment plan.

### 6. Cloudflare Workers and Containers

Status: research direction only, watching platform maturity.

For a new TypeScript MCP server, Cloudflare's current best practice is the
stateless `createMcpHandler`; the older `McpAgent` path is deprecated. Workers
can integrate Cloudflare Access or a third-party OAuth provider and are a strong
edge option for lightweight tools.

recon is a Python application with resolver, XML, graph, and catalog
dependencies, so a direct Workers rewrite would create a second implementation
and threaten output parity. Cloudflare Containers can run arbitrary OCI images
and scale to zero, but the July 2026 platform still documents explicit container
instance routing and manual pool logic while built-in autoscaling remains a
future capability. That is not yet a better reference than Cloud Run.

Planned revisit:

- Keep the Python container unchanged behind a small Worker authentication and
  routing boundary.
- Require managed autoscaling, stable request routing, health probes, secret
  integration, and local emulator parity before IaC is added.
- Do not port recon logic to TypeScript without an independently valuable use
  case and cross-language golden-output proof.

Sources:

- [Cloudflare remote MCP guide](https://developers.cloudflare.com/agents/model-context-protocol/guides/remote-mcp-server/)
- [Cloudflare MCP handler API](https://developers.cloudflare.com/agents/model-context-protocol/apis/handler-api/)
- [Cloudflare Containers](https://developers.cloudflare.com/containers/)
- [Container scaling and routing](https://developers.cloudflare.com/containers/platform-details/scaling-and-routing/)

### 7. Kubernetes, Knative, and other OCI platforms

Status: research direction for generic compatibility, with no maintained IaC.

Kubernetes is appropriate only when the operator already runs a supported
cluster or when sustained scale, custom egress, regional topology, or policy
needs exceed a managed container service. A future Helm chart would require:

- Deployment by immutable digest, non-root and read-only filesystem settings.
- ClusterIP service, ingress or Gateway API, TLS, and OAuth proxy.
- Startup, readiness, and liveness probes.
- Horizontal Pod Autoscaler with explicit minimum and maximum replicas.
- Pod disruption budget, topology spread, resource requests and limits.
- NetworkPolicy allowing DNS and the documented HTTPS destinations.
- External secret integration, per-identity rate limits, logs, metrics, and
  rollback tests.

Knative, Fly.io, Render, Railway, DigitalOcean App Platform, Oracle Container
Instances, and similar services can use the same container contract. They do
not each need project-maintained IaC. Add a provider-specific reference only
after a named user supplies a maintained platform need and can help validate
it.

## Threat Model and Operational Requirements

The remote path changes accessibility, not recon's collection boundary. It
also adds risks that do not exist in a single-user stdio process.

| Risk | Initial control | Required growth control |
|---|---|---|
| Stolen shared token | Secret manager, TLS, no access log, rotation | Short-lived per-user OAuth and revocation |
| Cost amplification, including public requests rejected only after instance startup | Maximum instances, low concurrency, request cap, budgets and alerts | Per-subject quotas and an ingress or gateway rate limit |
| Cross-user state | Stateless MCP and no remote mutation tools | Separate tenant boundary before multi-organization use |
| Browser DNS rebinding or cross-origin calls | Exact Host option and Origin denied by default | Reviewed CORS policy only for a named browser client |
| Prompt injection in observed DNS or certificate text | Existing untrusted-observed-content instruction and output sanitization | Client approvals and model-side data treatment |
| Sensitive query logs | Access log disabled; documented application-log risk | Domain redaction mode, restricted sinks, short retention |
| Supply-chain drift | Locked Python graph and digest-pinned build inputs | Signed multi-architecture image, SBOM, provenance and scans |
| Provider outage or cold start | Bounded timeouts and retry-safe read-only calls | Measured SLO, warm minimum only when justified |
| Token or identity confused deputy | Exact audience and issuer in OAuth design | Scopes, subject quotas, resource indicators and audit |

Remote deployments must preserve recon's public-metadata, passive-in-scope
language. Scaling a lookup does not turn it into active scanning, a security
verdict, or proof of organization ownership.

## Validation Plan

Current provider-validation status: none. The checks below the "In repository"
heading establish draft artifact quality only. They are not evidence that a
Cloud Run, AWS, Azure, Cloudflare, Kubernetes, or OAuth deployment works in a
real account.

### In repository

- Ruff and strict Pyright cover the remote adapter.
- Unit tests cover configuration failure, static bearer authentication,
  trusted platform mode, Host and Origin policy, health, body bounds, security
  headers, and remote tool filtering.
- CI validates Terraform formatting and schema with its locked provider.
- CI builds the container, starts it, checks health, and proves unauthenticated
  MCP requests return 401.
- The full existing suite retains branch coverage above 80 percent and the
  repository's stricter 90.2 percent CI floor.

### Before a provider reference is promoted

1. Validate IaC against the exact current provider version.
2. Produce a no-change second plan after apply.
3. Prove unauthenticated, malformed, oversize, and disallowed-origin requests
   fail before tool dispatch.
4. Initialize with MCP Inspector, list tools and resources, and call a reserved
   synthetic namespace.
5. Confirm remote mutation tools are absent.
6. Run concurrent cold and warm calls through the real ingress.
7. Record aggregate latency, errors, instance count, and cost without target
   names or per-domain rows.
8. Rotate credentials and roll back the image.
9. Confirm deletion protection and a reviewed destroy plan.
10. Recheck every first-party source and platform constraint at implementation
    time because cloud services and AI connector contracts change quickly.

## Priority and Delivery Sequence

This is roadmap track 4, below the three core priorities.

| Order within optional track | Work | State |
|---|---|---|
| 4.0 | Shared authenticated stateless remote adapter and OCI container | Draft artifact, locally checked only |
| 4.1 | Cloud Run Terraform with two auth modes and CI structural checks | Draft artifact, not yet provider-validated |
| 4.2 | One operator proof, load and cost characterization, token rotation | Awaiting external operator context |
| 4.3 | Shared OAuth 2.1 gateway contract | Planned, gated by a real per-user client |
| 4.4 | AWS AgentCore IaC | Planned, blocked on declarative MMDSv2 coverage and account validation |
| 4.5 | Azure Container Apps Bicep or Terraform | Planned, blocked on subscription, region, quota, and plan approval |
| 4.6 | Cloudflare container route or Kubernetes chart | Deferred until named demand and platform gates exist |
| 4.7 | Public directory submission or project-operated service | Not planned |

The stop rule is simple: optional cloud work pauses whenever it would displace
a higher roadmap priority, weaken local use, duplicate recon's engine, expose
an unauthenticated endpoint, or claim provider support that has not passed a
real deployment validation.
