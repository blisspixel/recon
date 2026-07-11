# Full-Corpus Calibration Refresh (2026-06-28)

Interpretation corrected 2026-07-10. The recorded aggregate values are
unchanged. Repeated conformal splits reuse one selected corpus, and the legacy
run did not record set-composition rates.

The 2,906-row email-policy block is publisher-conditional: the historical
collector retained published DMARC policies and excluded successfully observed
no-record domains. The current harness labels successful no-record observations
as 0 and leaves collection failures unlabeled, so reruns use a broader label
cohort. The 4,290-row conformal block is a separately recorded legacy
extraction; surviving provenance does not establish that it shares the same
collection run or label cohort as the reference block.

## Disclosure Controls

- Source apex lists and per-domain outputs remain under gitignored private validation paths.
- This memo is generated from aggregate JSON only.
- No apexes, subdomains, organization names, tenant IDs, or per-domain rows are included.
- Strata below 10 domains are suppressed or rejected before rendering.
- ECE columns preserve legacy fixed-bin and legacy equal-mass mean-confidence
  ECE. The historical equal-mass implementation could split tied scores across
  bins; current runs use a tie-preserving estimator and require fresh values.
- Bootstrap and Wilson ranges use naive iid rows and have no coverage interpretation for this selected cohort.

## Email Policy Reference Calibration

### Full posterior

| Block | n | Log score | Brier | ECE fixed-bin | ECE legacy equal-mass | ECE naive-iid bootstrap range80 | Agreement | Base rate |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| Pooled | 2906 | 0.0769 | 0.0077 | 0.0761 | 0.0651 | 0.0639, 0.0668 | 1 | 0.8352 |

| Stratum | n | ECE fixed-bin | ECE legacy equal-mass | ECE naive-iid bootstrap range80 | Agreement | Base rate |
|---|---:|---:|---:|---|---:|---:|
| aerospace-defense | 28 | 0.0714 | 0.0621 | 0.0519, 0.0749 | 1 | 0.8929 |
| agriculture-agtech | 27 | 0.0981 | 0.0948 | 0.0817, 0.1073 | 1 | 0.7778 |
| ai-ml | 56 | 0.0946 | 0.0887 | 0.0766, 0.0972 | 1 | 0.8929 |
| crypto-web3 | 65 | 0.0854 | 0.0769 | 0.0695, 0.0872 | 1 | 0.9538 |
| cybersecurity | 59 | 0.0856 | 0.0765 | 0.0686, 0.0877 | 1 | 0.9661 |
| dev-tools | 178 | 0.0837 | 0.0732 | 0.07, 0.0816 | 1 | 0.8371 |
| energy-utilities | 48 | 0.0812 | 0.0713 | 0.0641, 0.0839 | 1 | 0.8542 |
| finance-deep | 263 | 0.0709 | 0.0657 | 0.0591, 0.068 | 1 | 0.8973 |
| gaming | 32 | 0.0906 | 0.0857 | 0.0734, 0.1018 | 1 | 0.875 |
| gov-edu-nonprofit | 179 | 0.074 | 0.0653 | 0.0621, 0.0733 | 1 | 0.743 |
| healthcare | 224 | 0.0683 | 0.0606 | 0.0558, 0.0655 | 1 | 0.817 |
| insurance | 38 | 0.0684 | 0.061 | 0.0506, 0.0695 | 1 | 0.8947 |
| legal-proservices | 66 | 0.0652 | 0.0511 | 0.0477, 0.0621 | 1 | 0.8333 |
| logistics-shipping | 41 | 0.0841 | 0.0746 | 0.0654, 0.0879 | 1 | 0.9512 |
| manufacturing-industrial | 63 | 0.0738 | 0.0584 | 0.0538, 0.0727 | 1 | 0.7619 |
| media-entertainment | 252 | 0.0782 | 0.0743 | 0.0678, 0.0775 | 1 | 0.7857 |
| niche-saas | 397 | 0.0752 | 0.0651 | 0.062, 0.0703 | 1 | 0.8489 |
| real-estate-proptech | 48 | 0.0667 | 0.0645 | 0.0525, 0.0692 | 1 | 0.7083 |
| retail-ecom-deep | 248 | 0.0702 | 0.0635 | 0.0588, 0.0671 | 1 | 0.8831 |
| saas-b2b | 215 | 0.0793 | 0.0699 | 0.0643, 0.0756 | 1 | 0.9163 |
| telecom | 41 | 0.0671 | 0.0574 | 0.0497, 0.0686 | 1 | 0.7561 |
| travel-hospitality-energy | 338 | 0.0793 | 0.0697 | 0.0674, 0.0768 | 1 | 0.7396 |

### Held-out residual

| Block | n | Log score | Brier | ECE fixed-bin | ECE legacy equal-mass | ECE naive-iid bootstrap range80 | Agreement | Base rate |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| Pooled | 2906 | 0.6809 | 0.2448 | 0.3747 | 0.3263 | 0.3177, 0.3349 | 0.1896 | 0.8352 |

| Stratum | n | ECE fixed-bin | ECE legacy equal-mass | ECE naive-iid bootstrap range80 | Agreement | Base rate |
|---|---:|---:|---:|---|---:|---:|
| aerospace-defense | 28 | 0.4286 | 0.3805 | 0.3219, 0.4519 | 0.1429 | 0.8929 |
| agriculture-agtech | 27 | 0.3278 | 0.3893 | 0.2412, 0.3932 | 0.2222 | 0.7778 |
| ai-ml | 56 | 0.4071 | 0.361 | 0.3009, 0.421 | 0.1964 | 0.8929 |
| crypto-web3 | 65 | 0.4977 | 0.4489 | 0.4123, 0.4796 | 0.0615 | 0.9538 |
| cybersecurity | 59 | 0.489 | 0.442 | 0.4066, 0.4759 | 0.1017 | 0.9661 |
| dev-tools | 178 | 0.3713 | 0.3234 | 0.2911, 0.3586 | 0.2022 | 0.8371 |
| energy-utilities | 48 | 0.3958 | 0.3472 | 0.2904, 0.4172 | 0.1667 | 0.8542 |
| finance-deep | 263 | 0.4397 | 0.391 | 0.3654, 0.4149 | 0.1217 | 0.8973 |
| gaming | 32 | 0.425 | 0.3756 | 0.3441, 0.4412 | 0.125 | 0.875 |
| gov-edu-nonprofit | 179 | 0.2908 | 0.2526 | 0.2045, 0.2844 | 0.2626 | 0.743 |
| healthcare | 224 | 0.3652 | 0.3159 | 0.2818, 0.3472 | 0.1875 | 0.817 |
| insurance | 38 | 0.4447 | 0.3953 | 0.3427, 0.448 | 0.1053 | 0.8947 |
| legal-proservices | 66 | 0.3652 | 0.3174 | 0.2706, 0.378 | 0.2121 | 0.8333 |
| logistics-shipping | 41 | 0.4915 | 0.4429 | 0.3942, 0.4829 | 0.0732 | 0.9512 |
| manufacturing-industrial | 63 | 0.3103 | 0.2452 | 0.2145, 0.3231 | 0.254 | 0.7619 |
| media-entertainment | 252 | 0.331 | 0.282 | 0.2499, 0.3127 | 0.2262 | 0.7857 |
| niche-saas | 397 | 0.3827 | 0.3348 | 0.311, 0.3554 | 0.1914 | 0.8489 |
| real-estate-proptech | 48 | 0.2583 | 0.2296 | 0.1879, 0.313 | 0.2917 | 0.7083 |
| retail-ecom-deep | 248 | 0.4282 | 0.3793 | 0.3536, 0.4031 | 0.129 | 0.8831 |
| saas-b2b | 215 | 0.4421 | 0.3949 | 0.3699, 0.4203 | 0.1442 | 0.9163 |
| telecom | 41 | 0.2768 | 0.2787 | 0.1968, 0.3365 | 0.3171 | 0.7561 |
| travel-hospitality-energy | 338 | 0.2852 | 0.2349 | 0.2053, 0.2672 | 0.2692 | 0.7396 |

## Tenancy Provider Corroboration

## M365 DNS-only Stratified Corroboration

### Pooled and per-stratum

| Block | n | Log score | Brier | ECE fixed-bin | ECE legacy equal-mass | ECE naive-iid bootstrap range80 | Agreement | Base rate |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| Pooled | 3296 | 0.2695 | 0.0796 | 0.0471 | 0.044 | 0.0402, 0.0506 | 0.889 | 0.7897 |

| Stratum | n | ECE fixed-bin | ECE legacy equal-mass | ECE naive-iid bootstrap range80 | Agreement | Base rate |
|---|---:|---:|---:|---|---:|---:|
| aerospace-defense | 9 | suppressed | suppressed | suppressed | suppressed | suppressed |
| agriculture-agtech | 29 | 0.0431 | 0.1471 | 0.0818, 0.1709 | 0.8966 | 0.8966 |
| ai-ml | 56 | 0.0964 | 0.0972 | 0.0816, 0.1525 | 0.875 | 0.875 |
| crypto-web3 | 65 | 0.19 | 0.2036 | 0.1555, 0.2672 | 0.6615 | 0.8 |
| cybersecurity | 60 | 0.1183 | 0.1244 | 0.0901, 0.1621 | 0.8833 | 0.9667 |
| dev-tools | 207 | 0.0751 | 0.1168 | 0.0576, 0.1006 | 0.8213 | 0.715 |
| energy-utilities | 49 | 0.0459 | 0.064 | 0.0611, 0.0869 | 0.9796 | 0.9388 |
| finance-deep | 332 | 0.0536 | 0.0878 | 0.0646, 0.0975 | 0.9187 | 0.6717 |
| gaming | 33 | 0.0379 | 0.0932 | 0.0697, 0.1328 | 0.9394 | 0.8182 |
| gov-edu-nonprofit | 180 | 0.0444 | 0.0577 | 0.0526, 0.0745 | 0.9611 | 0.9167 |
| healthcare | 250 | 0.042 | 0.0734 | 0.0482, 0.0741 | 0.916 | 0.82 |
| insurance | 39 | 0.0885 | 0.0968 | 0.0697, 0.1306 | 0.9231 | 0.9487 |
| legal-proservices | 66 | 0.0985 | 0.11 | 0.0855, 0.1353 | 0.9242 | 0.9848 |
| logistics-shipping | 43 | 0.0593 | 0.0788 | 0.0652, 0.1146 | 0.9535 | 0.9302 |
| manufacturing-industrial | 71 | 0.0387 | 0.0935 | 0.0655, 0.1029 | 0.9437 | 0.8732 |
| media-entertainment | 301 | 0.0537 | 0.0452 | 0.0439, 0.0736 | 0.8771 | 0.7641 |
| niche-saas | 477 | 0.0383 | 0.0635 | 0.0389, 0.0624 | 0.8805 | 0.7421 |
| real-estate-proptech | 51 | 0.0324 | 0.0719 | 0.0658, 0.0977 | 0.9608 | 0.9412 |
| retail-ecom-deep | 286 | 0.051 | 0.0569 | 0.0416, 0.0769 | 0.8357 | 0.7378 |
| saas-b2b | 224 | 0.1219 | 0.1163 | 0.0928, 0.1428 | 0.8482 | 0.875 |
| telecom | 44 | 0.0409 | 0.0881 | 0.0686, 0.105 | 0.9773 | 0.9091 |
| travel-hospitality-energy | 424 | 0.016 | 0.0426 | 0.0367, 0.0628 | 0.9057 | 0.7406 |

| GWS one-sided check | Value |
|---|---:|
| Attested positives | 11 |
| Threshold | 0.5 |
| Recall | 0.3636 |
| Recall naive-iid Wilson diagnostic range80 | 0.2071, 0.5556 |
| Posterior quartiles | 0.25, 0.25, 0.8846 |

## Conformal Re-split Diagnostics

| Metric | Value |
|---|---:|
| Labeled records | 4290 |
| Splits | 20 |
| Nominal 1-alpha reference | 0.9 |
| Mean empirical label-inclusion across dependent re-splits | 0.9992 |
| Minimum empirical label-inclusion across re-splits | 0.9981 |
| Mean singleton-set rate | not recorded |
| Mean multi-label-set rate | not recorded |
| Mean empty-set rate | not recorded |
| Mean set size, legacy shape diagnostic | 0.9992 |

## Interpretation Guardrails

- Full email-policy scoring overlaps the DMARC predictor and label by design, so its metrics are corroboration.
- The held-out residual masks the DMARC evidence unit, so predictor and label are disjoint inside recon. The selected observations are not independent.
- M365 DNS-only tenancy corroboration splits predictor and provider-attested label by channel, but both share tenant provisioning.
- M365 full-pipeline tenancy agreement is a consistency check, not independent calibration.
- GWS is one-sided recall on provider-attested positives, not two-class calibration.
- Conformal values are dependent empirical re-split diagnostics from a separately recorded legacy extraction. Scorer-development disjointness is not established, so no future-point coverage theorem is claimed. Mean set size does not establish decisiveness.
