# Signal Intelligence

Derived automatically from fingerprint matches. Defined in `data/signals.yaml`. 29 signals organized in four layers:

## Layer 1 — Single-category detection

| Signal | Triggers when |
|--------|--------------|
| AI Adoption | OpenAI, Anthropic, Mistral, or Perplexity detected |
| High GTM Maturity | 2+ sales/marketing tools (includes Salesforce MC, Braze, Iterable) |
| Enterprise Security Stack | 2+ security tools (includes Okta, Auth0, Imperva, OneLogin) |
| Modern Collaboration | 3+ collaboration tools |
| Dev & Engineering Heavy | 2+ dev tools (includes LaunchDarkly, Contentful) |
| Data & Analytics Investment | 2+ data tools (includes Optimizely, WalkMe) |
| Multi-Cloud | 2+ cloud/CDN providers (includes AWS ELB/S3, Azure Front Door, GCP App Engine) |
| Observability & SRE | 2+ monitoring/incident tools |

## Layer 2 — Cross-category composites

| Signal | Triggers when |
|--------|--------------|
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
