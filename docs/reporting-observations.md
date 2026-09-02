# Reporting a recon result

You ran recon against a domain and now you have to say something about it, in a
deck, a ticket, or out loud on a call. This page is how to do that without
overstating what recon saw. It is written for you, the person doing the
reporting, not for an agent.

The one rule underneath all of it: recon reports what a domain publishes, never
what an organization does with it. Everything below follows from that.

## What recon observed, and what it did not

recon reads public DNS, certificate-transparency logs, and unauthenticated
identity endpoints. Everything it returns is already readable by anyone with
`dig` and a browser; recon collects it, correlates it, and shows the evidence
behind each line.

What that does **not** tell you:

- **Active use.** A fingerprint match means the evidence fits a service's public
  pattern, not that the service is deployed, licensed, or in use.
- **Ownership or corporate structure.** Shared administrative tokens, a common
  tenant ID, a broad provider, or a shared certificate issuer are overlaps, not
  proof of one owner, one operator, or one company.
- **Security maturity.** A score is a count of observable public controls, not a
  grade. A sparse panel means recon saw little from the outside, not that the
  target is weak.
- **Exploitability.** recon does not test anything. A missing DMARC record is a
  missing record; what it implies is a separate conversation.
- **Anything not in public DNS.** Server-side API use, internal workloads, and
  SaaS without DNS verification do not appear, so absence is not evidence of
  absence.

## How to phrase what it did observe

Say the observation, name the evidence, and stop before the verdict.

| Say this | Not this |
|---|---|
| Microsoft 365 tenant observed; identity is federated | They use Okta (unless the IdP is named in the output) |
| DMARC policy is set to reject | Their email security is strong |
| Passive observation only; there may be controls we cannot see | This is their full security posture |
| A CNAME points at an Okta endpoint | They authenticate with Okta |

Cite the evidence type when you state a fingerprint (MX, TXT, CNAME, NS, SRV,
CAA, SPF, certificate SAN). Never call a gap a confirmed vulnerability; recon
does not test exploitability.

When you are reporting across a set of domains, phrase it as a cohort
observation, not an industry fact: "within this set, among observable signals,
we saw X," never "companies like this do X."

## Lines you can quote

For the foot of any artifact that leaves your hands:

> Everything above was observed for this namespace in public DNS,
> certificate-transparency logs, and public identity endpoints. It shows what
> was publicly visible during this bounded observation, not what is licensed,
> deployed, or in active use, and it is not a security rating.

For a call, spoken:

> Their public DNS and identity records show a Microsoft 365 tenant with DMARC
> set to reject. That is what they publish, not a judgment on their security, and
> there are likely controls we cannot see from the outside.

When someone asks "couldn't you just look this up yourself?", the honest answer
is yes: every value recon returns is available to anyone running `dig`,
`nslookup`, or visiting the same public endpoints. recon collects it in one pass
and shows the evidence trail; it does not reach anywhere a browser cannot.

## Where the caveat travels for you

`--gaps` and, as of 2.16, `--md` end with a scope caveat, so a report generated
in those formats carries the hedge out of the terminal. `--json` does not: it is
the automation surface, and a machine consumer reads the structured `confidence`,
`degraded_sources`, and evidence fields directly. If you copy a panel or a
`--plain` block into a document by hand, paste the standing caveat above with it.

More on the boundary of what recon collects:
[how-it-works.md](how-it-works.md) and
[limitations.md](limitations.md). What leaves your machine:
[legal.md](legal.md).
