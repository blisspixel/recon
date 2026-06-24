# Full-Corpus Calibration Validation Memo (2026-06-23)

## Headline reading (honest)

A maintainer-local run over the gitignored 5,241-domain corpus at concurrency 2,
2026-06-23. Aggregates only; the run directory and per-domain pairings stayed
local. Four results, read under the CAL1 consistency-vs-calibration discipline:

- **Email-policy node, full posterior (n=2,905 with a published DMARC policy):**
  strongly calibrated against the authoritative DMARC label (ECE 0.076, Brier
  0.008, empirical enforcing-rate matching the bin in every populated reliability
  bin, stable across all 22 verticals). Caveat by construction: DMARC is both a
  predictor input and the label, so this leans toward consistency, not
  independent calibration.
- **Email-policy node, held-out residual (DMARC masked, predictor and label
  disjoint):** weak and poorly calibrated (ECE 0.373, agreement 0.189). The
  honest conclusion is that the strict-SPF + MTA-STS channel alone does not
  independently predict enforcement, so the node's strong calibration is
  DMARC-anchored. This is the modest, truthful tier-4 reading, not a clean one.
- **M365 tenancy, DNS-only vs provider attestation (n=3,309, channels split so
  predictor and label are disjoint):** well calibrated and corroborated (ECE
  0.048, agreement 0.889). The strongest independent result here.
- **GWS (n=12 attested positives):** one-sided recall 0.58, Wilson80 [0.40,
  0.74]. Low power; not a two-class calibration claim.
- **Conformal coverage (n=4,290, 20 splits):** 0.999 mean coverage against a 0.90
  target, mean set size near 1. Over-covers conservatively, consistent with the
  bimodal posterior. The distribution-free guarantee holds and then some, under
  the exchangeability assumption that excludes adversarially hardened targets.

Net: the email-policy calibration and the M365 tenancy corroboration are real and
strong against authoritative external labels; the clean DMARC-disjoint residual
is weak, which disciplines rather than inflates the node-level claim. None of this
upgrades the Bayesian 80% credible intervals from evidence-responsive to
frequentist-calibrated; that remains a separate, unclaimed property.

## Disclosure Controls

- Source apex lists and per-domain outputs remain under gitignored private validation paths.
- This memo is generated from aggregate JSON only.
- No apexes, subdomains, organization names, tenant IDs, or per-domain rows are included.
- Strata below 10 domains are suppressed or rejected before rendering.

## Email Policy Reference Calibration

### Full posterior

| Block | n | Log score | Brier | ECE | Agreement | Base rate |
|---|---:|---:|---:|---:|---:|---:|
| Pooled | 2905 | 0.077 | 0.0077 | 0.0762 | 1 | 0.8337 |

| Stratum | n | ECE | Agreement | Base rate |
|---|---:|---:|---:|---:|
| aerospace-defense | 28 | 0.0714 | 1 | 0.8929 |
| agriculture-agtech | 27 | 0.0981 | 1 | 0.7778 |
| ai-ml | 56 | 0.0982 | 1 | 0.875 |
| crypto-web3 | 65 | 0.0854 | 1 | 0.9538 |
| cybersecurity | 59 | 0.0856 | 1 | 0.9661 |
| dev-tools | 178 | 0.0837 | 1 | 0.8371 |
| energy-utilities | 48 | 0.0812 | 1 | 0.8542 |
| finance-deep | 262 | 0.0706 | 1 | 0.8931 |
| gaming | 32 | 0.0906 | 1 | 0.875 |
| gov-edu-nonprofit | 179 | 0.0735 | 1 | 0.7374 |
| healthcare | 224 | 0.0683 | 1 | 0.8125 |
| insurance | 38 | 0.0684 | 1 | 0.8947 |
| legal-proservices | 66 | 0.0652 | 1 | 0.8333 |
| logistics-shipping | 41 | 0.0841 | 1 | 0.9512 |
| manufacturing-industrial | 62 | 0.0742 | 1 | 0.7581 |
| media-entertainment | 252 | 0.0782 | 1 | 0.7857 |
| niche-saas | 397 | 0.0752 | 1 | 0.8489 |
| real-estate-proptech | 48 | 0.0667 | 1 | 0.7083 |
| retail-ecom-deep | 248 | 0.0702 | 1 | 0.8831 |
| saas-b2b | 215 | 0.0793 | 1 | 0.9163 |
| telecom | 42 | 0.0667 | 1 | 0.7619 |
| travel-hospitality-energy | 338 | 0.0799 | 1 | 0.7396 |

### Held-out residual

| Block | n | Log score | Brier | ECE | Agreement | Base rate |
|---|---:|---:|---:|---:|---:|---:|
| Pooled | 2905 | 0.6824 | 0.2454 | 0.3734 | 0.1893 | 0.8337 |

| Stratum | n | ECE | Agreement | Base rate |
|---|---:|---:|---:|---:|
| aerospace-defense | 28 | 0.4286 | 0.1429 | 0.8929 |
| agriculture-agtech | 27 | 0.3278 | 0.2222 | 0.7778 |
| ai-ml | 56 | 0.4232 | 0.1429 | 0.875 |
| crypto-web3 | 65 | 0.4977 | 0.0615 | 0.9538 |
| cybersecurity | 59 | 0.4822 | 0.1186 | 0.9661 |
| dev-tools | 178 | 0.3713 | 0.2022 | 0.8371 |
| energy-utilities | 48 | 0.3958 | 0.1667 | 0.8542 |
| finance-deep | 262 | 0.4355 | 0.126 | 0.8931 |
| gaming | 32 | 0.425 | 0.125 | 0.875 |
| gov-edu-nonprofit | 179 | 0.2852 | 0.2682 | 0.7374 |
| healthcare | 224 | 0.3607 | 0.192 | 0.8125 |
| insurance | 38 | 0.4447 | 0.1053 | 0.8947 |
| legal-proservices | 66 | 0.3652 | 0.2121 | 0.8333 |
| logistics-shipping | 41 | 0.4915 | 0.0732 | 0.9512 |
| manufacturing-industrial | 62 | 0.3065 | 0.2581 | 0.7581 |
| media-entertainment | 252 | 0.331 | 0.2262 | 0.7857 |
| niche-saas | 397 | 0.3838 | 0.1889 | 0.8489 |
| real-estate-proptech | 48 | 0.2583 | 0.2917 | 0.7083 |
| retail-ecom-deep | 248 | 0.4282 | 0.129 | 0.8831 |
| saas-b2b | 215 | 0.4421 | 0.1442 | 0.9163 |
| telecom | 42 | 0.2833 | 0.3095 | 0.7619 |
| travel-hospitality-energy | 338 | 0.2891 | 0.2663 | 0.7396 |

## Tenancy Provider Corroboration

## M365 DNS-only Stratified Corroboration

### Pooled and per-stratum

| Block | n | Log score | Brier | ECE | Agreement | Base rate |
|---|---:|---:|---:|---:|---:|---:|
| Pooled | 3309 | 0.2681 | 0.0791 | 0.0476 | 0.8894 | 0.7909 |

| Stratum | n | ECE | Agreement | Base rate |
|---|---:|---:|---:|---:|
| aerospace-defense | 9 | suppressed | suppressed | suppressed |
| agriculture-agtech | 29 | 0.0776 | 0.931 | 0.931 |
| ai-ml | 56 | 0.1089 | 0.8571 | 0.875 |
| crypto-web3 | 65 | 0.1777 | 0.6769 | 0.8 |
| cybersecurity | 60 | 0.1067 | 0.9 | 0.9667 |
| dev-tools | 207 | 0.0684 | 0.8309 | 0.715 |
| energy-utilities | 49 | 0.0459 | 0.9796 | 0.9388 |
| finance-deep | 345 | 0.0488 | 0.9159 | 0.6841 |
| gaming | 33 | 0.0379 | 0.9394 | 0.8182 |
| gov-edu-nonprofit | 180 | 0.0444 | 0.9611 | 0.9167 |
| healthcare | 250 | 0.042 | 0.916 | 0.82 |
| insurance | 39 | 0.0885 | 0.9231 | 0.9487 |
| legal-proservices | 66 | 0.0985 | 0.9242 | 0.9848 |
| logistics-shipping | 43 | 0.0593 | 0.9535 | 0.9302 |
| manufacturing-industrial | 71 | 0.0387 | 0.9437 | 0.8732 |
| media-entertainment | 301 | 0.0537 | 0.8771 | 0.7641 |
| niche-saas | 477 | 0.0408 | 0.8763 | 0.7421 |
| real-estate-proptech | 51 | 0.0324 | 0.9608 | 0.9412 |
| retail-ecom-deep | 286 | 0.0486 | 0.8392 | 0.7378 |
| saas-b2b | 224 | 0.1219 | 0.8482 | 0.875 |
| telecom | 44 | 0.0409 | 0.9773 | 0.9091 |
| travel-hospitality-energy | 424 | 0.0142 | 0.9033 | 0.7406 |

| GWS one-sided check | Value |
|---|---:|
| Attested positives | 12 |
| Threshold | 0.5 |
| Recall | 0.5833 |
| Recall Wilson80 | 0.4019, 0.7447 |
| Posterior quartiles | 0.25, 0.8846, 0.8846 |

## Conformal Coverage

| Metric | Value |
|---|---:|
| Labeled records | 4290 |
| Splits | 20 |
| Target coverage | 0.9 |
| Mean coverage | 0.999 |
| Worst split coverage | 0.9981 |
| Mean set size | 0.999 |

## Interpretation Guardrails

- Full email-policy calibration overlaps the DMARC predictor and label by design.
- The held-out residual masks the DMARC evidence unit, so predictor and label are disjoint.
- M365 DNS-only tenancy corroboration splits predictor and provider-attested label by channel.
- M365 full-pipeline tenancy agreement is a consistency check, not independent calibration.
- GWS is one-sided recall on provider-attested positives, not two-class calibration.
- Conformal coverage depends on exchangeability and is not claimed for adversarially hardened targets.

