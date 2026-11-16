"""The OWASP LLM Top 10 mapping carried on every check outcome.

The mapping is a published-standard citation that reaches customer-facing JSON
and HTML, so these tests guard the two ways it can be wrong in a way nobody
notices: an ID that silently means a different risk across editions, and a
check mapped approximately rather than left unmapped.
"""

from __future__ import annotations

import json

import pytest

from vecshield_platform import owasp
from vecshield_platform.compliance.data import load_references, reference_ids
from vecshield_platform.compliance.report import build_report
from vecshield_platform.coverage import check_outcome

from vecshield.models import ScanJob


# -- the published entries ------------------------------------------------- #

def test_the_two_editions_are_both_carried():
    assert owasp.EDITIONS == ("2025", "2026")
    editions = {ref["edition"] for ref in load_references("owasp_llm")["references"]}
    assert editions == {"2025", "2026"}


def test_every_id_is_written_with_its_year():
    """A bare ``LLM08`` is ambiguous between editions; the suffix is the point."""
    for check in owasp.mapped_checks():
        entry = owasp.for_check(check)
        for edition, ids in entry.items():
            assert ids, f"{check} has an empty {edition} list"
            for ref_id in ids:
                assert ref_id.endswith(f":{edition}"), (
                    f"{check} cites {ref_id} under the {edition} edition")


def test_every_cited_id_resolves_to_a_published_entry_with_a_source():
    cited = {ref_id for check in owasp.mapped_checks()
             for ids in owasp.for_check(check).values() for ref_id in ids}
    assert cited == reference_ids("owasp_llm")
    for ref_id in cited:
        ref = owasp.reference(ref_id)
        assert ref["title"] and ref["source_url"].startswith("https://")


@pytest.mark.parametrize("entry, id_2025, id_2026", [
    ("Prompt Injection", "LLM01:2025", "LLM01:2026"),
    ("Sensitive Information Disclosure", "LLM02:2025", "LLM02:2026"),
    ("Data and Model Poisoning", "LLM04:2025", "LLM05:2026"),
    ("Vector and Embedding Weaknesses", "LLM08:2025", "LLM09:2026"),
])
def test_the_2026_renumbering_is_recorded_as_published(entry, id_2025, id_2026):
    """The 2026 edition renumbered eight of ten entries.

    Carrying the 2025 number forward with a :2026 suffix would cite a different
    risk: LLM08:2026 is hidden context exposure, not vector and embedding
    weaknesses. Each pair here is checked against the published titles.
    """
    assert owasp.reference(id_2025)["title"] == entry
    assert owasp.reference(id_2026)["title"] == entry


def test_an_id_kept_at_its_2025_number_would_name_a_different_risk():
    # The regression this whole mapping exists to prevent.
    assert owasp.reference("LLM08:2026") is None or (
        owasp.reference("LLM08:2026")["title"] != "Vector and Embedding Weaknesses")


# -- what the mapping covers ------------------------------------------------ #

def test_the_checks_this_product_exists_for_cite_vector_and_embedding_weaknesses():
    for check in ("tenant_isolation", "embedding_anomaly", "prompt_injection"):
        entry = owasp.for_check(check)
        assert "LLM08:2025" in entry["2025"]
        assert "LLM09:2026" in entry["2026"]


def test_sensitive_content_checks_cite_disclosure():
    for check in ("data_classification", "nlp_classification", "model_egress"):
        assert owasp.for_check(check) == {"2025": ["LLM02:2025"],
                                          "2026": ["LLM02:2026"]}


def test_poisoning_checks_cite_data_and_model_poisoning():
    for check in ("corpus_duplication", "provenance", "chunk_versions"):
        entry = owasp.for_check(check)
        assert entry["2025"][0] == "LLM04:2025"
        assert entry["2026"][0] == "LLM05:2026"


@pytest.mark.parametrize("check", ["retention_horizon", "retention_schedule",
                                   "data_residency", "asset_inventory",
                                   "erasure_verification"])
def test_checks_the_top_10_does_not_frame_are_unmapped_on_purpose(check):
    """Retention, residency, inventory and erasure answer other obligations.

    An approximate mapping in a report a customer cites is worse than none.
    """
    assert owasp.for_check(check) is None
    assert check in load_references("owasp_llm")["unmapped_checks"]["checks"]


def test_an_unknown_check_is_unmapped_rather_than_guessed():
    assert owasp.for_check("some_future_check") is None


def test_the_mapping_returns_a_fresh_dict_each_call():
    first = owasp.for_check("tenant_isolation")
    first["2025"].append("LLM99:2025")
    assert owasp.for_check("tenant_isolation")["2025"] == ["LLM08:2025"]


# -- what reaches the output ------------------------------------------------ #

def test_a_mapped_check_outcome_carries_both_editions():
    out = check_outcome("tenant_isolation", "store", "col",
                        outcome="passed", reason="r", complete=True)
    assert out["owasp"] == {"2025": ["LLM08:2025"], "2026": ["LLM09:2026"]}
    # It describes the check, not this run, so it sits beside coverage.
    assert "owasp" not in out["coverage"]


def test_an_unmapped_check_outcome_omits_the_key_rather_than_emitting_an_empty_one():
    out = check_outcome("erasure_verification", "store", outcome="passed", reason="r")
    assert "owasp" not in out


def test_the_ids_survive_json_serialization():
    out = check_outcome("prompt_injection", "store", outcome="failed", reason="r")
    assert json.loads(json.dumps(out))["owasp"]["2026"] == ["LLM01:2026", "LLM09:2026"]


def test_the_html_report_shows_both_editions_and_an_em_dash_when_unmapped():
    assessment = {
        "id": "aud-1", "started_at": "", "finished_at": "", "status": "complete",
        "scope": {},
        "check_outcomes": [
            check_outcome("tenant_isolation", "s", "c", outcome="passed",
                          reason="verified", complete=True),
            check_outcome("erasure_verification", "s", outcome="passed", reason="done"),
        ],
    }
    html = build_report([], assessment=assessment)
    assert "<th>OWASP LLM</th>" in html
    assert "LLM08:2025, LLM09:2026" in html
    assert "—" in html  # the unmapped row
    # The report must not read the mapping as a compliance claim.
    assert "does not establish that the risk is addressed" in html


def test_the_report_reads_stored_ids_rather_than_re_deriving_them():
    """A stored audit keeps the ids it was written with.

    Re-deriving would restate an old report under a newer edition, which is
    exactly the silent-renumbering failure this mapping guards against.
    """
    outcome = check_outcome("tenant_isolation", "s", "c", outcome="passed",
                            reason="verified", complete=True)
    outcome["owasp"] = {"2025": ["LLM08:2025"]}  # as an older run recorded it
    html = build_report([], assessment={"id": "a", "scope": {},
                                        "check_outcomes": [outcome]})
    assert "LLM08:2025" in html
    assert "LLM09:2026" not in html


def test_a_job_recorded_without_the_mapping_still_renders():
    job = ScanJob(id="j1", store="s")
    job.stats = {"check_outcomes": [{"check": "legacy", "outcome": "inconclusive"}]}
    assert "<th>OWASP LLM</th>" in build_report([job])
