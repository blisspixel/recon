# Draft Optional Deployment Framework

These files are optional operator-owned deployment references. They are not
required to install or use recon, and the recon project does not deploy or
operate a hosted service. The default remains the local CLI and local stdio MCP
server.

Status: draft framework intended to be directionally useful. These files pass
repository syntax, build, and local protocol checks, but they are not yet
provider-validated or production-ready. They are starting points for evaluation
in an operator-owned non-production account, not a support promise or a claim
that the documented cloud behavior has been exercised end to end.

Available draft artifacts:

| Path | Purpose | Status |
|---|---|---|
| [container](container/README.md) | Authenticated, stateless remote MCP container | Draft, locally built and smoke-tested |
| [gcp-cloud-run](gcp-cloud-run/README.md) | Scale-to-zero Cloud Run service with Terraform | Draft, syntax-checked but not applied to Cloud Run |

AWS, Azure, Cloudflare, Kubernetes, Anthropic, OpenAI, and other client paths
are evaluated in the
[optional cloud deployment plan](../docs/optional-cloud-deployment-plan.md).
They are not represented here by placeholder infrastructure that has not met
its platform-specific validation gate.

Every operator owns the cloud account, identity provider, bill, logs, policy,
target allowlist if one is needed, upgrades, and incident response for their
deployment. No deployment sends telemetry or usage data to the recon project.

## How to evaluate the draft

1. Start with the cross-platform plan and choose the client, compute provider,
   identity boundary, region, and expected traffic separately.
2. Use a dedicated non-production account or project with a budget and a hard
   resource ceiling.
3. Build from a reviewed revision, pin the image digest and secret version, and
   inspect the complete IaC plan before applying it.
4. Run the provider promotion checklist, including negative authentication,
   load and cost bounds, log review, secret rotation, rollback, and deletion.
5. Call it provider-validated only after recording that evidence. Until then,
   describe it as a draft framework and keep local recon as the default.
