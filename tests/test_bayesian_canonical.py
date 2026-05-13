"""Numerical correctness against the canonical Burglary-Earthquake-Alarm
network from Pearl (1988) / Russell & Norvig (3rd ed., §14.2).

The classic textbook query is :math:`P(B \\mid J=\\text{true}, M=\\text{true})`
which all standard implementations agree converges to ≈ 0.284. If our
variable-elimination engine matches that to several decimal places on
this independent benchmark, the implementation is correct.

We model the canonical network with our YAML schema and observe John
and Mary "calling" via tight evidence bindings (likelihood [0.999,
0.001]). With near-deterministic observation we approach the textbook
limit; the small residual difference is the noise the likelihood
[0.999, 0.001] introduces vs hard-evidence [1.0, 0.0] which our schema
forbids (and which would produce degenerate factors anyway).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from recon_tool.bayesian import infer, load_network


@pytest.fixture
def burglary_net_yaml(tmp_path: Path) -> Path:
    """The canonical 5-node Burglary-Earthquake-Alarm-John-Mary network.

    Note: parent assignments in CPT keys follow our schema: the parent
    list defines the order, and the binary states are ``present`` / ``absent``.
    """
    spec = {
        "version": 1,
        "nodes": [
            {
                "name": "burglary",
                "description": "A burglary is in progress.",
                "prior": 0.001,
            },
            {
                "name": "earthquake",
                "description": "An earthquake is occurring.",
                "prior": 0.002,
            },
            {
                "name": "alarm",
                "description": "The alarm sounded.",
                "parents": ["burglary", "earthquake"],
                "cpt": {
                    "burglary=present,earthquake=present": 0.95,
                    "burglary=present,earthquake=absent": 0.94,
                    "burglary=absent,earthquake=present": 0.29,
                    "burglary=absent,earthquake=absent": 0.001,
                },
            },
            {
                "name": "john_calls",
                "description": "John called.",
                "parents": ["alarm"],
                "cpt": {
                    "alarm=present": 0.90,
                    "alarm=absent": 0.05,
                },
                # Tight evidence binding so observing this slug ≈ John
                # actually called (matching the canonical hard-evidence
                # query as closely as our (0,1)-strict schema allows).
                "evidence": [
                    {"slug": "phone_log_john", "likelihood": [0.999, 0.001]},
                ],
            },
            {
                "name": "mary_calls",
                "description": "Mary called.",
                "parents": ["alarm"],
                "cpt": {
                    "alarm=present": 0.70,
                    "alarm=absent": 0.01,
                },
                "evidence": [
                    {"slug": "phone_log_mary", "likelihood": [0.999, 0.001]},
                ],
            },
        ],
    }
    p = tmp_path / "burglary.yaml"
    p.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return p


class TestBurglaryAlarmCanonical:
    """Reference values are computed by hand under our engine's noisy-
    likelihood model (P(obs|J=T)=0.999, P(obs|J=F)=0.001) — which is what
    our schema enforces (likelihoods strictly in (0,1)). They differ
    slightly from the textbook hard-evidence values: textbook ≈ 0.284
    for burglary; noisy ≈ 0.276. This is the correct Bayesian answer for
    our model. The hard-evidence textbook value is recovered as
    likelihood → [1,0]; we sit at [0.999, 0.001] so we land within ~0.01
    of the textbook.

    The test asserts that our engine matches the *noisy-likelihood
    canonical* values to four decimal places, which is the strongest
    statement we can make about correctness.
    """

    def test_p_burglary_given_both_calls(self, burglary_net_yaml: Path) -> None:
        """Hand-computed under our noisy likelihood: P(B|obs_j, obs_m) ≈ 0.2763."""
        net = load_network(burglary_net_yaml)
        result = infer(
            net,
            observed_slugs=["phone_log_john", "phone_log_mary"],
            observed_signals=[],
            priors_override={},
        )
        burglary = next(p for p in result.posteriors if p.name == "burglary")
        assert abs(burglary.posterior - 0.2763) < 1e-3, (
            f"Expected ~0.2763 (noisy-likelihood canonical), got {burglary.posterior}"
        )
        # And within 0.01 of the textbook hard-evidence 0.284 — slightly
        # off because we use [0.999, 0.001] not [1, 0].
        assert abs(burglary.posterior - 0.284) < 0.01

    def test_p_alarm_given_both_calls(self, burglary_net_yaml: Path) -> None:
        """Hand-computed: P(A|obs_j, obs_m) ≈ 0.7396."""
        net = load_network(burglary_net_yaml)
        result = infer(
            net,
            observed_slugs=["phone_log_john", "phone_log_mary"],
            observed_signals=[],
            priors_override={},
        )
        alarm = next(p for p in result.posteriors if p.name == "alarm")
        assert abs(alarm.posterior - 0.7396) < 1e-3, f"Expected ~0.7396, got {alarm.posterior}"
        # Textbook hard-evidence answer: 0.761.
        assert abs(alarm.posterior - 0.761) < 0.025

    def test_p_earthquake_given_both_calls(self, burglary_net_yaml: Path) -> None:
        """Hand-computed: P(E|obs_j, obs_m) ≈ 0.1712."""
        net = load_network(burglary_net_yaml)
        result = infer(
            net,
            observed_slugs=["phone_log_john", "phone_log_mary"],
            observed_signals=[],
            priors_override={},
        )
        eq = next(p for p in result.posteriors if p.name == "earthquake")
        assert abs(eq.posterior - 0.1712) < 1e-3
        # Textbook hard: 0.176
        assert abs(eq.posterior - 0.176) < 0.01

    def test_explaining_away_works(self, burglary_net_yaml: Path) -> None:
        """Classical Pearl example: observing earthquake "explains away"
        the alarm signal, so P(burglary | calls + earthquake) drops
        sharply vs P(burglary | calls). Our engine doesn't observe
        earthquake directly (no evidence binding), but raising the
        earthquake prior should reproduce the same effect."""
        net = load_network(burglary_net_yaml)
        baseline = infer(
            net,
            observed_slugs=["phone_log_john", "phone_log_mary"],
            observed_signals=[],
            priors_override={},
        )
        b_baseline = next(p for p in baseline.posteriors if p.name == "burglary").posterior
        # Override earthquake prior to "very likely earthquake happening"
        explained_away = infer(
            net,
            observed_slugs=["phone_log_john", "phone_log_mary"],
            observed_signals=[],
            priors_override={"earthquake": 0.95},
        )
        b_explained = next(p for p in explained_away.posteriors if p.name == "burglary").posterior
        # When earthquake is highly probable a priori, alarm is well-
        # explained by it and the burglary posterior drops.
        assert b_explained < b_baseline, (
            f"Explaining away failed: baseline={b_baseline:.4f}, with high-eq-prior={b_explained:.4f}"
        )

    def test_no_evidence_returns_priors(self, burglary_net_yaml: Path) -> None:
        net = load_network(burglary_net_yaml)
        result = infer(net, [], [], priors_override={})
        burglary = next(p for p in result.posteriors if p.name == "burglary")
        eq = next(p for p in result.posteriors if p.name == "earthquake")
        assert abs(burglary.posterior - 0.001) < 1e-3
        assert abs(eq.posterior - 0.002) < 1e-3


# ── Two-node Bayes' rule sanity ──────────────────────────────────────


@pytest.fixture
def disease_test_yaml(tmp_path: Path) -> Path:
    """Classic medical-test example: rare disease (1%), 99% sensitive
    test, 95% specific test. Hand answer: P(D|test+) ≈ 0.167.
    """
    spec = {
        "version": 1,
        "nodes": [
            {
                "name": "disease",
                "description": "Patient has the disease.",
                "prior": 0.01,
                "evidence": [
                    # P(test+ | disease=present) = 0.99 (sensitivity)
                    # P(test+ | disease=absent)  = 0.05 (1 - specificity)
                    {"slug": "test_positive", "likelihood": [0.99, 0.05]},
                ],
            },
        ],
    }
    p = tmp_path / "disease.yaml"
    p.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return p


class TestMedicalTestExample:
    def test_p_disease_given_positive(self, disease_test_yaml: Path) -> None:
        """Bayes by hand: 0.99 * 0.01 / (0.99 * 0.01 + 0.05 * 0.99) ≈ 0.167."""
        net = load_network(disease_test_yaml)
        result = infer(
            net,
            observed_slugs=["test_positive"],
            observed_signals=[],
            priors_override={},
        )
        d = next(p for p in result.posteriors if p.name == "disease")
        assert abs(d.posterior - 0.167) < 0.005, f"Expected ~0.167, got {d.posterior}"

    def test_no_test_returns_prior(self, disease_test_yaml: Path) -> None:
        net = load_network(disease_test_yaml)
        result = infer(net, [], [], priors_override={})
        d = next(p for p in result.posteriors if p.name == "disease")
        assert abs(d.posterior - 0.01) < 1e-4
