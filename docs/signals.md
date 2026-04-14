# Signal Intelligence

Derived automatically from fingerprint matches. Defined in `data/signals.yaml`. 44 signals organized in four layers, plus absence signals generated from `expected_counterparts` definitions.

Signals are evaluated in two passes: non-meta signals first, then meta-signals (those with `requires_signals`) against the first-pass results. A third pass (absence evaluation) checks fired signals for missing expected counterparts. This supports `contradicts` (negation), `requires_signals` (signal-to-signal references), and `expected_counterparts` (absence detection) safely without circular dependencies.

## Layer 1 — Single-category detection

| Signal | Triggers when |
|--------|--------------|
| AI Adoption | OpenAI, Anthropic, Mistral, Perplexity, CrewAI AID, LangSmith, or MCP Discovery detected |
| Enterprise Email Deliverability | SPF flattening or DMARC management service detected (AutoSPF, OnDMARC, dmarcian, EasyDMARC, Valimail) |
| DMARC Governance Investment | Paid DMARC report vendor detected via `rua=` (Agari, Proofpoint EFD, OnDMARC, dmarcian, Valimail, EasyDMARC) |
| High GTM Maturity | 2+ sales/marketing tools (includes Salesforce MC, Braze, Iterable) |
| Enterprise Security Stack | 2+ security tools (includes Okta, Auth0, Imperva, OneLogin, Beyond Identity) |
| Modern Collaboration | 3+ collaboration tools |
| Dev & Engineering Heavy | 2+ dev tools (includes LaunchDarkly, Contentful, Fly.io, Railway, Fastly) |
| Data & Analytics Investment | 2+ data tools (includes Optimizely, WalkMe) |
| Multi-Cloud | 2+ cloud/CDN providers (includes AWS ELB/S3, Azure Front Door, GCP App Engine, Fastly, Fly.io) |
| Observability & SRE | 2+ monitoring/incident tools |

## Layer 2 — Cross-category composites

| Signal | Triggers when |
|--------|--------------|
| Email Gateway Topology | Email gateway slug detected via MX + primary email provider identified |
| Agentic AI Infrastructure | 2+ agentic AI slugs (CrewAI AID, LangSmith, MCP Discovery, OpenAI, Anthropic, etc.) |
| AI Platform Diversity | 2+ distinct AI/LLM provider verifications (OpenAI, Anthropic, Mistral, Perplexity) |
| Software Supply Chain Maturity | 2+ supply chain security tools (GitHub Advanced Security, Sonatype, Snyk, Cosign) |
| Edge-Native Architecture | 2+ edge/serverless platforms (Vercel, Netlify, Fly.io, Railway, Fastly, Cloudflare) |
| Digital Transformation | 4+ tools across AI, collaboration, and cloud |
| Sales-Led Growth | 3+ CRM, sales engagement, and marketing automation tools |
| Product-Led Growth | 3+ analytics, engagement, and support tools |
| Enterprise IT Maturity | 4+ identity, endpoint, email security, and MDM tools |
| Heavy Outbound Stack | 2+ email sending services |
| AI Security Posture | 3+ AI tools + guardrails + Zero Trust |
| Zero Trust Posture | 3+ identity + SASE + endpoint tools |
| Startup Tool Mix | 4+ modern dev + collaboration + PLG tools |
| Google-Native Identity | 3+ Google services (Workspace, DNS, Trust Services) |
| Google Cloud Investment | 2+ Google Cloud services |
| High-Security Posture (CSE) | Google Workspace Client-Side Encryption detected |

## Layer 3 — Consistency checks

| Signal | Triggers when |
|--------|--------------|
| Security Gap — Gateway Without DMARC | Email gateway deployed but DMARC not enforcing |
| Shadow IT Risk | 3+ consumer-grade SaaS tools |
| File Collaboration Sprawl | 2+ enterprise file-sharing platforms |
| Dual Email Provider | Both Microsoft 365 and Google Workspace detected |
| Legacy Provider Residue | Provider detected via TXT/DKIM alongside a different MX-based primary provider (migration residue) |

## Layer 4 — Contradiction, metadata-aware, and meta-signals

| Signal | Triggers when |
|--------|--------------|
| Federated Identity with Complex Email Delegation | External IdP detected + 5+ SPF includes |
| Active Email Sending with Minimal Security | Email sending service detected + email security score ≤ 1 |
| High Certificate Issuance Activity | 20+ certificates issued in last 90 days |
| Incomplete Identity Migration | External IdP (Okta, Auth0, Ping) detected; contradicts on Microsoft 365 |
| Split-Brain Email Config | Dual email provider detected; contradicts on MTA-STS enforce |
| Security Stack Without Governance | 2+ enterprise security tools + DMARC not reject |
| AI Adoption Without Governance | AI platform detected; contradicts on enterprise identity providers (Okta, CyberArk, Beyond Identity, Ping) |
| DevSecOps Investment Without Email Governance | Supply chain security tool detected + email security score ≤ 2 |
| Complex Migration Window | Requires "Enterprise Security Stack" AND "Dual Email Provider" signals |
| Governance Sprawl | Requires "AI Adoption" AND "Shadow IT Risk" signals |

## Custom Signals

Drop a `signals.yaml` in `~/.recon/` to add your own signal rules. Custom signals are validated the same way as built-in ones — invalid entries are skipped with a warning. Custom signals are additive only.

```yaml
signals:
  - name: Healthcare Compliance Stack
    category: Vertical
    confidence: medium
    description: HIPAA-adjacent tooling detected
    requires:
      any: [okta, crowdstrike, proofpoint, knowbe4, 1password]
    min_matches: 3
```

## Expected Counterparts and Absence Signals

Signals can define `expected_counterparts` — a list of slugs that are typically co-present when the signal fires. When a signal fires but one or more expected counterparts are absent from the detected slugs, the absence engine produces an "Absence" signal.

### How it works

1. Standard two-pass signal evaluation runs (non-meta signals, then meta-signals).
2. The absence engine (third pass) checks each fired signal that has `expected_counterparts`.
3. For each fired signal, any counterpart slug not found in the detected slugs produces an absence signal.
4. Absence signals have `category="Absence"` and use hedged language ("not observed", "may indicate a gap").

### Built-in expected counterparts

| Signal | Expected counterparts |
|--------|----------------------|
| Enterprise IT Maturity | jamf, kandji, crowdstrike, sentinelone, proofpoint, mimecast |
| AI Adoption | lakera, okta, cyberark, beyond-identity |
| Agentic AI Infrastructure | cosign-attestation, snyk |
| Enterprise Security Stack | proofpoint, mimecast, barracuda |
| DMARC Governance Investment | proofpoint, mimecast, barracuda, trendmicro |

### YAML syntax

```yaml
signals:
  - name: My Custom Signal
    category: Custom
    confidence: medium
    requires:
      any: [tool-a, tool-b]
    min_matches: 1
    expected_counterparts: [companion-x, companion-y]
```

When "My Custom Signal" fires and `companion-x` is not detected, the engine produces:

> My Custom Signal — Missing Counterparts: companion-x not observed — may indicate a gap in the expected deployment

### Absence signal output

Absence signals appear alongside standard signals in all output formats (CLI, JSON, markdown, MCP). They have:

- **Name**: `{parent_signal} — Missing Counterparts`
- **Category**: `Absence`
- **Confidence**: `medium`
- **Matched**: tuple of missing slug names
- **Description**: hedged language describing what was not observed
