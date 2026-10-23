# Shared-response identity characterization

Reviewed 2026-10-23; reproducible from merged assurance revision
`9d1c84ed1b8d717f07856d12ac3498a1208e9517` and the exact shipped model digest in the
[synthetic receipt](../validation/shared-response-characterization-2026-10-23.json).
This is a bounded offline characterization for issue #269, following the
active-role assurance repair in #263. It establishes no population calibration
or numerical defect and changes no engine, parameters, collector or schema.

## Inputs and ownership

The fixtures in
[test_bayesian_shared_response.py](../tests/test_bayesian_shared_response.py)
declare one synthetic Google identity response reporting federated
authentication and Okta. Its retained HTTP record and the two Google identity
fields belong to that one origin. The real adapter derives these bindings:

| Declared origin | Derived role | Directly supported node | Connected path |
| --- | --- | --- | --- |
| Google identity response | `google_workspace_tenant_observed` | `google_workspace_tenant` | federation, then Okta |
| Same response | `federated_sso_hub` | `federated_identity` | Okta; child evidence can update either tenant root |
| Same response | `okta_idp_observed` | `okta_idp` | ancestors through the committed DAG |
| Separate MX record | `google_workspace_tenant_observed` | `google_workspace_tenant` | same graph; same Boolean role |

Different records are separately withdrawable in this fixture. Their endpoint
or provider names do not establish statistical independence. Three deductions
from one response are legitimate multiple statements about that response;
they are not three independently corroborating sources. The model multiplies
three local factors at connected nodes. Within-node evidence grouping does
not model shared observation noise across those factors.

## Reproducible differences

All cases use explicit default priors (`priors_override={}`). The receipt
includes the model SHA-256 over UTF-8 text normalized to LF line endings,
fired bindings, effective display mass,
sparse flags, local rankings, intervals and unit counterfactuals. Selected
model-relative means are:

| Input or intervention | GWS | Federation | Okta |
| --- | ---: | ---: | ---: |
| No identity observations | 0.2500 | 0.2420 | 0.0764 |
| One federated Google response naming Okta | 0.9400 | 0.9921 | 0.9457 |
| Mask only the GWS-derived unit | 0.4050 | 0.9855 | 0.9407 |
| Withdraw the entire response | 0.2500 | 0.2420 | 0.0764 |
| Withdraw response, retain separate MX | 0.8846 | 0.3715 | 0.1146 |

Duplicating the HTTP record, reordering it or adding the separate MX record
leaves this response's three Boolean roles and inference unchanged. That is
the current adapter's scoped invariance, not a universal rule about repeated
observations or a claim that corroboration never matters.

Masking the GWS unit leaves federation and Okta evidence active. GWS therefore
still moves through the graph even though its local binding is absent and its
display mass is sparse. Withdrawing the response clears both owned fields
and every copy of its retained record. With no other origin, masking all
three units matches this withdrawal. With the MX record remaining, masking
the GWS role globally would also erase its legitimate support. The receipt's
withdrawal case instead keeps the GWS direct binding at mass 5. Federation
and Okta then have no direct binding, remain sparse at mass 4, and move only
through the graph. A separate Microsoft HTTP record and its identity fields
also survive withdrawal; selecting every HTTP record would be incorrect.

Contradiction metadata survives the intervention, including competing Google
authentication values. The test preserves its existing global display-mass
penalty and provenance. Unavailable MX metadata also survives. Empty direct
evidence for the hideable identity nodes remains unresolved and sparse, not
an informative negative. Neither a moved posterior nor a sparse flag alone
establishes a private service configuration.

## Result and remaining alternatives

The existing leave-one-unit-out explanation is exact for its declared model
operation. It is not a complete raw-source withdrawal. These cases justify
clarifying that distinction and protecting it with tests; they do not justify
changing likelihoods, combining connected claims into one factor, or labeling
the diagnostic calibrated confidence. The numerical differences follow from
the committed local factors and graph propagation.

A model with explicit joint observation likelihoods or shared-error latent
variables could answer a different question. These fixtures do not identify
that observation model or quantify its error. Production also has no general
response-ownership registry: the withdrawal helper is deliberately limited to
declared synthetic field and record ownership. It is not a new public API or
a heuristic that guesses ownership from vendor names.

Reproduce without network access or local prior overrides:

```bash
uv run pytest tests/test_bayesian_shared_response.py
```

The receipt test recomputes every recorded diagnostic against the model digest.
An intentional model change requires review of the recorded characterization,
not automatic acceptance of a new result.
