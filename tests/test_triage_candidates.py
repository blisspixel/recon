from __future__ import annotations

from validation.triage_candidates import entry_is_already_covered, triage


def test_entry_is_already_covered_checks_sample_terminal() -> None:
    samples = [
        {
            "terminal": "tenant.elb.us-gov-east-1.amazonaws.com",
            "chain": ["app.example.com", "tenant.elb.us-gov-east-1.amazonaws.com"],
        }
    ]

    assert entry_is_already_covered(
        "us-gov-east-1.amazonaws.com",
        samples,
        {"elb.us-gov-east-1.amazonaws.com"},
    )


def test_entry_is_already_covered_checks_chain_hops() -> None:
    samples = [
        {
            "terminal": "final.example.net",
            "chain": ["docs.example.com", "customer.edge.example.net", "final.example.net"],
        }
    ]

    assert entry_is_already_covered("example.net", samples, {"customer.edge.example.net"})


def test_triage_drops_candidates_covered_only_by_specific_sample_hostname() -> None:
    gaps = [
        {
            "suffix": "us-gov-east-1.amazonaws.com",
            "count": 5,
            "samples": [
                {
                    "terminal": "tenant.elb.us-gov-east-1.amazonaws.com",
                    "chain": ["app.example.com", "tenant.elb.us-gov-east-1.amazonaws.com"],
                }
            ],
        },
        {
            "suffix": "unclassified.example.net",
            "count": 5,
            "samples": [{"terminal": "edge.unclassified.example.net", "chain": []}],
        },
    ]

    survivors = triage(
        gaps,
        existing_patterns={"elb.us-gov-east-1.amazonaws.com"},
        min_count=3,
        drop_intra_org=False,
    )

    assert survivors == [gaps[1]]
