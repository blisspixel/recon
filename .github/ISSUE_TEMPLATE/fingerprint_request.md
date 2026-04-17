---
name: Fingerprint request
about: Request a new SaaS fingerprint or point out a missing detection
title: "[Fingerprint] "
labels: fingerprint
---

## Service

**Name:** (e.g., Acme Email Security)
**Category:** (Email & Communication / Security & Compliance / Identity & Access / Cloud / etc.)
**Website:** (product page URL — just for reference, not queried)

## Detection

What public DNS record pattern identifies this service? Fill in what applies:

- [ ] **TXT verification token** at the apex (e.g., `acme-verification=abc123`)
- [ ] **CNAME pattern** (e.g., `*.acme.com` on a specific subdomain prefix)
- [ ] **MX hostname** (e.g., `mx.acme-mail.com`)
- [ ] **SPF include** (e.g., `include:spf.acmemail.com`)
- [ ] **Other DNS record** — describe below

**Example record:**

```
# paste a public DNS record that matches the pattern
# e.g., the output of `dig +short TXT example.com` on a known customer
```

## Known customers

One or two public domains that use this service. recon will validate against them before merging.

1. `example.com`
2. `example.org`

## False-positive concerns

Is there any chance the detection pattern fires on a different service or a dormant account? If so, `match_mode: all` with multiple detections may be the right approach.
