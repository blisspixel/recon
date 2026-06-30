from __future__ import annotations

from recon_tool.discovery import find_candidates, pattern_matches_hostname
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


def test_existing_pattern_matching_uses_dns_label_boundaries() -> None:
    assert pattern_matches_hostname("tenant.queue-it.net", "queue-it.net")
    assert pattern_matches_hostname("queue-it.net", "queue-it.net")
    assert not pattern_matches_hostname("tenant.queue-it.net.example.org", "queue-it.net")
    assert not pattern_matches_hostname("sync-transcend-cdn.com", "transcend-cdn.com")


def test_dotless_existing_patterns_keep_substring_semantics() -> None:
    assert pattern_matches_hostname("mkto-ab390043.com", "mkto-")


def test_triage_keeps_candidates_not_runtime_covered_by_specific_sample_hostname() -> None:
    samples = [
        {
            "terminal": "sync-transcend-cdn.com",
            "chain": ["sync-transcend-cdn.com"],
        }
    ]

    assert not entry_is_already_covered("sync-transcend-cdn.com", samples, {"transcend-cdn.com"})


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


def test_find_candidates_keeps_suffix_when_existing_pattern_is_only_substring() -> None:
    runs = [
        (
            "contoso.com",
            [
                {
                    "subdomain": "sync.contoso.com",
                    "chain": ["sync-transcend-cdn.com"],
                }
            ],
        )
    ]

    assert find_candidates(runs, existing_patterns={"transcend-cdn.com"}, drop_intra_org=False) == [
        {
            "suffix": "sync-transcend-cdn.com",
            "count": 1,
            "samples": [
                {
                    "subdomain": "sync.contoso.com",
                    "terminal": "sync-transcend-cdn.com",
                    "chain": ["sync-transcend-cdn.com"],
                }
            ],
        }
    ]
