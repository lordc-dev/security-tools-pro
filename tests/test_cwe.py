import pytest
from core.models import CWEInfo
from modules.cwe import (
    _seg_key,
    _nth_or_last,
    _parse_related,
    _parse_consequences,
    _parse_mitigations,
    _parse_detection,
    _parse_observed,
    _parse_alt_terms,
    _parse_ordinalities,
    _parse_introduction,
    _parse_notes,
    _parse_attack_patterns,
    _parse_taxonomy,
    _parse_platforms,
    _to_cwe_info,
    format_cwe,
    format_cwe_brief,
)


class TestSegKey:
    def test_single_kv(self):
        seg = "PHASE:Implementation"
        assert _seg_key(seg, "PHASE", [r":STRATEGY:", r":DESCRIPTION:"]) == "Implementation"

    def test_last_key_in_segment(self):
        seg = "DESCRIPTION:Do not use user input directly"
        assert _seg_key(seg, "DESCRIPTION", [r":EFFECTIVENESS:", r":NOTE:"]) == "Do not use user input directly"

    def test_not_found(self):
        seg = "PHASE:Implementation"
        assert _seg_key(seg, "STRATEGY", [r":DESCRIPTION:"]) is None

    def test_strips_colon_suffix(self):
        seg = "PHASE:Implementation:"
        result = _seg_key(seg, "PHASE", [r":STRATEGY:"])
        assert result == "Implementation"

    def test_strips_whitespace(self):
        seg = "PHASE:  Implementation  :"
        result = _seg_key(seg, "PHASE", [r":STRATEGY:"])
        assert result == "Implementation  "


class TestNthOrLast:
    def test_nth_exists(self):
        assert _nth_or_last(["a", "b", "c"], 1) == "b"

    def test_nth_beyond_returns_last(self):
        assert _nth_or_last(["a", "b"], 5) == "b"

    def test_empty_list(self):
        assert _nth_or_last([], 0) == "N/A"

    def test_strips_colon(self):
        assert _nth_or_last(["value:", "other"], 0) == "value"

    def test_custom_default(self):
        assert _nth_or_last([], 0, "none") == "none"


class TestParseRelated:
    def test_empty(self):
        assert _parse_related("") == []

    def test_none(self):
        assert _parse_related(None) == []

    def test_single_relation(self):
        raw = "NATURE:ChildOf:CWE ID:89:VIEW ID:1000"
        result = _parse_related(raw)
        assert len(result) == 1
        assert result[0]["cwe_id"] == "89:VIEW ID:1000"
        assert result[0]["view_id"] == "1000"

    def test_multiple_relations(self):
        raw = "NATURE:ChildOf:CWE ID:89:VIEW ID:1000::NATURE:CanAlsoBe:CWE ID:20"
        result = _parse_related(raw)
        assert len(result) == 2
        assert result[0]["cwe_id"] == "89:VIEW ID:1000"
        assert result[1]["cwe_id"] == "20"

    def test_no_cwe_id_skipped(self):
        raw = "NATURE:SomeRelation:VIEW ID:1000"
        result = _parse_related(raw)
        assert len(result) == 0


class TestParseConsequences:
    def test_empty(self):
        assert _parse_consequences("") == []

    def test_single(self):
        raw = "SCOPE:Confidentiality:IMPACT:Read Application Data"
        result = _parse_consequences(raw)
        assert len(result) == 1
        assert result[0]["scope"] == "Confidentiality:IMPACT:Read Application Data"
        assert result[0]["impact"] == "Read Application Data"

    def test_double_colon_splits(self):
        raw = "SCOPE:Confidentiality::IMPACT:Read Application Data"
        result = _parse_consequences(raw)
        assert len(result) == 2
        assert result[0]["scope"] == "Confidentiality"
        assert result[1]["impact"] == "Read Application Data"

    def test_multiple_scopes(self):
        raw = "SCOPE:Confidentiality:SCOPE:Integrity:IMPACT:Read:IMPACT:Modify"
        result = _parse_consequences(raw)
        assert len(result) == 1
        assert result[0]["scope"] == "Confidentiality:SCOPE:Integrity:IMPACT:Read:IMPACT:Modify"
        assert result[0]["impact"] == "Read:IMPACT:Modify"

    def test_more_impacts_than_scopes(self):
        raw = "SCOPE:Confidentiality:IMPACT:Read:IMPACT:Modify"
        result = _parse_consequences(raw)
        assert len(result) == 1
        assert result[0]["scope"] == "Confidentiality:IMPACT:Read:IMPACT:Modify"
        assert result[0]["impact"] == "Read:IMPACT:Modify"


class TestParseMitigations:
    def test_empty(self):
        assert _parse_mitigations("") == []

    def test_single_all_in_one_segment(self):
        raw = "PHASE:Implementation:STRATEGY:Input Validation:DESCRIPTION:Validate all input"
        result = _parse_mitigations(raw)
        assert len(result) == 1
        assert result[0]["phase"] == "Implementation:STRATEGY:Input Validation:DESCRIPTION:Validate all input"
        assert result[0]["strategy"] == "Input Validation:DESCRIPTION:Validate all input"
        assert result[0]["description"] == "Validate all input"

    def test_double_colon_splits(self):
        raw = "PHASE:Implementation::STRATEGY:Input Validation::DESCRIPTION:Validate all input"
        result = _parse_mitigations(raw)
        assert len(result) == 3
        assert result[0]["phase"] == "Implementation"
        assert result[1]["strategy"] == "Input Validation"
        assert result[2]["description"] == "Validate all input"

    def test_multiple(self):
        raw = "PHASE:Implementation:DESCRIPTION:Use param queries::PHASE:Architecture:DESCRIPTION:Separate tiers"
        result = _parse_mitigations(raw)
        assert len(result) == 2
        assert result[0]["phase"] == "Implementation:DESCRIPTION:Use param queries"
        assert result[1]["phase"] == "Architecture:DESCRIPTION:Separate tiers"

    def test_with_effectiveness(self):
        raw = "PHASE:Implementation:DESCRIPTION:Foo:EFFECTIVENESS:Highly Effective"
        result = _parse_mitigations(raw)
        assert result[0]["effectiveness"] == "Highly Effective"


class TestParseDetection:
    def test_empty(self):
        assert _parse_detection("") == []

    def test_single(self):
        raw = "METHOD:Automated Static Analysis:DESCRIPTION:Use tools"
        result = _parse_detection(raw)
        assert len(result) == 1
        assert result[0]["method"] == "Automated Static Analysis:DESCRIPTION:Use tools"
        assert result[0]["description"] == "Use tools"

    def test_double_colon_splits(self):
        raw = "METHOD:Automated Static Analysis::DESCRIPTION:Use tools"
        result = _parse_detection(raw)
        assert len(result) == 2
        assert result[0]["method"] == "Automated Static Analysis"
        assert result[1]["description"] == "Use tools"

    def test_with_effectiveness(self):
        raw = "METHOD:Manual:DESCRIPTION:Review:EFFECTIVENESS:High"
        result = _parse_detection(raw)
        assert result[0]["effectiveness"] == "High"


class TestParseObserved:
    def test_empty(self):
        assert _parse_observed("") == []

    def test_single(self):
        raw = "REFERENCE:CVE-2021-1234:DESCRIPTION:Exploit in the wild:LINK:https://example.com"
        result = _parse_observed(raw)
        assert len(result) == 1
        assert result[0]["reference"] == "CVE-2021-1234:DESCRIPTION:Exploit in the wild:LINK:https://example.com"
        assert result[0]["link"] == "https://example.com"

    def test_double_colon_splits(self):
        raw = "REFERENCE:CVE-2021-1234::DESCRIPTION:Exploit in the wild::LINK:https://example.com"
        result = _parse_observed(raw)
        assert len(result) == 3
        assert result[0]["reference"] == "CVE-2021-1234"
        assert result[1]["description"] == "Exploit in the wild"
        assert result[2]["link"] == "https://example.com"


class TestParseAltTerms:
    def test_empty(self):
        assert _parse_alt_terms("") == []

    def test_single(self):
        raw = "TERM:SQLi:DESCRIPTION:Short for SQL Injection"
        result = _parse_alt_terms(raw)
        assert len(result) == 1
        assert result[0]["term"] == "SQLi:DESCRIPTION:Short for SQL Injection"
        assert result[0]["description"] == "Short for SQL Injection"

    def test_double_colon_splits(self):
        raw = "TERM:SQLi::DESCRIPTION:Short for SQL Injection"
        result = _parse_alt_terms(raw)
        assert len(result) == 2
        assert result[0]["term"] == "SQLi"
        assert result[1]["description"] == "Short for SQL Injection"


class TestParseOrdinalities:
    def test_empty(self):
        assert _parse_ordinalities("") == []

    def test_single(self):
        raw = "ORDINALITY:Primary"
        result = _parse_ordinalities(raw)
        assert len(result) == 1
        assert result[0]["ordinality"] == "Primary"

    def test_multiple(self):
        raw = "ORDINALITY:Primary::ORDINALITY:Secondary"
        result = _parse_ordinalities(raw)
        assert len(result) == 2


class TestParseIntroduction:
    def test_empty(self):
        assert _parse_introduction("") == []

    def test_single(self):
        raw = "PHASE:Implementation:NOTE:Be careful with user input"
        result = _parse_introduction(raw)
        assert len(result) == 1
        assert result[0]["phase"] == "Implementation:NOTE:Be careful with user input"
        assert result[0]["note"] == "Be careful with user input"

    def test_double_colon_splits(self):
        raw = "PHASE:Implementation::NOTE:Be careful with user input"
        result = _parse_introduction(raw)
        assert len(result) == 2
        assert result[0]["phase"] == "Implementation"
        assert result[1]["note"] == "Be careful with user input"


class TestParseNotes:
    def test_empty(self):
        assert _parse_notes("") == []

    def test_typed_note(self):
        raw = "TYPE:Relationship:NOTE:This is related to CWE-89"
        result = _parse_notes(raw)
        assert len(result) == 1
        assert result[0]["type"] == "Relationship:NOTE:This is related to CWE-89"
        assert result[0]["note"] == "This is related to CWE-89"

    def test_double_colon_splits(self):
        raw = "TYPE:Relationship::NOTE:This is related to CWE-89"
        result = _parse_notes(raw)
        assert len(result) == 2
        assert result[0]["type"] == "Relationship"
        assert result[1]["note"] == "This is related to CWE-89"

    def test_untyped_note(self):
        raw = "Just a plain note here"
        result = _parse_notes(raw)
        assert len(result) == 1
        assert result[0]["note"] == "Just a plain note here"


class TestParseAttackPatterns:
    def test_empty(self):
        assert _parse_attack_patterns("") == []

    def test_single(self):
        raw = "CAPEC-ID:66 ORDINAL:Typical"
        result = _parse_attack_patterns(raw)
        assert len(result) == 1
        assert result[0]["capec_id"] == "66"
        assert result[0]["ordinal"] == "Typical"

    def test_multiple(self):
        raw = "CAPEC-ID:66 ORDINAL:Typical::CAPEC-ID:100 ORDINAL:Rare"
        result = _parse_attack_patterns(raw)
        assert len(result) == 2
        assert result[0]["capec_id"] == "66"
        assert result[1]["capec_id"] == "100"

    def test_no_capec_id_keeps_ordinal(self):
        raw = "ORDINAL:Typical"
        result = _parse_attack_patterns(raw)
        assert len(result) == 1
        assert result[0]["ordinal"] == "Typical"


class TestParseTaxonomy:
    def test_empty(self):
        assert _parse_taxonomy("") == []

    def test_single(self):
        raw = "TAXONOMY NAME:OWASP:ENTRY ID:OWASP-A1:ENTRY NAME:Injection"
        result = _parse_taxonomy(raw)
        assert len(result) == 1
        assert result[0]["taxonomy"] == "OWASP:ENTRY ID:OWASP-A1:ENTRY NAME:Injection"
        assert result[0]["entry_name"] == "Injection"

    def test_double_colon_splits(self):
        raw = "TAXONOMY NAME:OWASP::ENTRY ID:OWASP-A1::ENTRY NAME:Injection"
        result = _parse_taxonomy(raw)
        assert len(result) == 3
        assert result[0]["taxonomy"] == "OWASP"
        assert result[1]["entry_id"] == "OWASP-A1"
        assert result[2]["entry_name"] == "Injection"


class TestParsePlatforms:
    def test_empty(self):
        assert _parse_platforms("") == []

    def test_language(self):
        raw = "LANGUAGE NAME:Python:LANGUAGE PREVALENCE:Often"
        result = _parse_platforms(raw)
        assert len(result) == 1
        assert result[0]["language"] == "Python:LANGUAGE PREVALENCE:Often"
        assert result[0]["prevalence"] == "Often"

    def test_os(self):
        raw = "OPERATING SYSTEM NAME:Linux:OPERATING SYSTEM PREVALENCE:Sometimes"
        result = _parse_platforms(raw)
        assert len(result) == 1
        assert result[0]["os"] == "Linux:OPERATING SYSTEM PREVALENCE:Sometimes"
        assert result[0]["os_prevalence"] == "Sometimes"

    def test_double_colon_splits(self):
        raw = "LANGUAGE NAME:Python::LANGUAGE PREVALENCE:Often"
        result = _parse_platforms(raw)
        assert len(result) == 2
        assert result[0]["language"] == "Python"
        assert result[1]["prevalence"] == "Often"


class TestToCweInfo:
    def test_full_row(self):
        row = {
            "CWE-ID": "89",
            "Name": "SQL Injection",
            "Weakness Abstraction": "Base",
            "Status": "Stable",
            "Description": "The software constructs SQL statements...",
            "Extended Description": "This is extended",
            "Common Consequences": "SCOPE:Confidentiality:IMPACT:Read Application Data",
            "Potential Mitigations": "PHASE:Implementation:DESCRIPTION:Use param queries",
            "Related Weaknesses": "NATURE:ChildOf:CWE ID:20:VIEW ID:1000",
            "Modes Of Introduction": "PHASE:Implementation",
            "Likelihood of Exploit": "High",
            "Applicable Platforms": "LANGUAGE NAME:Python:LANGUAGE PREVALENCE:Often",
            "Background Details": "Some background",
            "Alternate Terms": "TERM:SQLi",
            "Notes": "TYPE:Relationship:NOTE:Related to CWE-20",
        }
        cwe = _to_cwe_info(row)
        assert cwe.id == 89
        assert cwe.name == "SQL Injection"
        assert cwe.abstraction == "Base"
        assert cwe.status == "Stable"
        assert len(cwe.consequences) == 1
        assert len(cwe.mitigations) == 1
        assert len(cwe.related_weaknesses) == 1
        assert cwe.likelihood == "High"

    def test_empty_row(self):
        cwe = _to_cwe_info({})
        assert cwe.id == 0
        assert cwe.name == ""
        assert cwe.consequences == []
        assert cwe.mitigations == []

    def test_missing_fields(self):
        cwe = _to_cwe_info({"CWE-ID": "79", "Name": "XSS"})
        assert cwe.id == 79
        assert cwe.name == "XSS"
        assert cwe.description == ""


class TestFormatCwe:
    def test_basic(self):
        cwe = CWEInfo(
            id=89,
            name="SQL Injection",
            abstraction="Base",
            status="Stable",
            description="Constructs SQL statements from untrusted input",
        )
        out = format_cwe(cwe)
        assert "## CWE-89: SQL Injection" in out
        assert "**Abstraction:** Base" in out
        assert "**Status:** Stable" in out
        assert "Constructs SQL statements" in out

    def test_with_extended_description(self):
        cwe = CWEInfo(id=79, name="XSS", abstraction="Base", status="Stable",
                      description="Short", extended_description="Long description here")
        out = format_cwe(cwe)
        assert "Extended Description" in out
        assert "Long description here" in out

    def test_with_consequences(self):
        cwe = CWEInfo(id=89, name="SQLi", abstraction="Base", status="Stable",
                      description="Test", consequences=[{"scope": "Confidentiality", "impact": "Read"}])
        out = format_cwe(cwe)
        assert "Consequences" in out
        assert "Confidentiality" in out
        assert "Read" in out

    def test_with_likelihood(self):
        cwe = CWEInfo(id=89, name="SQLi", abstraction="Base", status="Stable",
                      description="Test", likelihood="High")
        out = format_cwe(cwe)
        assert "Likelihood of Exploit" in out
        assert "High" in out

    def test_empty_cwe(self):
        cwe = CWEInfo(id=0, name="", abstraction="", status="", description="")
        out = format_cwe(cwe)
        assert "## CWE-0:" in out

    def test_with_notes(self):
        cwe = CWEInfo(id=89, name="SQLi", abstraction="Base", status="Stable",
                      description="Test", notes="TYPE:Relationship:NOTE:Related to CWE-20")
        out = format_cwe(cwe)
        assert "Notes" in out
        assert "Relationship" in out
        assert "Related to CWE-20" in out


class TestFormatCweBrief:
    def test_short_description(self):
        cwe = CWEInfo(id=89, name="SQL Injection", abstraction="Base", status="Stable",
                      description="Short description")
        out = format_cwe_brief(cwe)
        assert "**CWE-89**" in out
        assert "[Base]" in out
        assert "SQL Injection" in out
        assert "Short description" in out
        assert "..." not in out

    def test_long_description_truncated(self):
        cwe = CWEInfo(id=89, name="SQLi", abstraction="Base", status="Stable",
                      description="A" * 300)
        out = format_cwe_brief(cwe)
        assert "..." in out
        assert len(out) < 300

class TestParseTop25Rows:
    """Test _parse_top25_rows with real HTML sample from MITRE 2025."""

    _HTML_SAMPLE = """
    <table id="Detail" border="2">
    <thead><tr><th>Rank</th><th>ID</th><th>Name</th><th>Score</th><th>KEV</th><th>Change</th></tr></thead>
    <tr>
        <td style="text-align:center;"><b>1</b></td>
        <td style="text-align:center;"><a href="/data/definitions/79.html">CWE-79</a></td>
        <td>Improper Neutralization of Input During Web Page Generation</td>
        <td style="text-align:center;">60.38</td>
        <td style="text-align:center;">7</td>
        <td style="text-align:center;">0</td>
    </tr>
    <tr>
        <td style="text-align:center;"><b>2</b></td>
        <td style="text-align:center;"><a href="/data/definitions/89.html">CWE-89</a></td>
        <td>Improper Neutralization of Special Elements used in an SQL Command</td>
        <td style="text-align:center;">28.72</td>
        <td style="text-align:center;">4</td>
        <td style="text-align:center;">+1</td>
    </tr>
    <tr>
        <td style="text-align:center;"><b>5</b></td>
        <td style="text-align:center;"><a href="/data/definitions/787.html">CWE-787</a></td>
        <td>Out-of-bounds Write</td>
        <td style="text-align:center;">12.68</td>
        <td style="text-align:center;">12</td>
        <td style="text-align:center;">-3</td>
    </tr>
    </table>
    """

    def test_parses_three_rows(self):
        from modules.cwe import _parse_top25_rows
        results = _parse_top25_rows(self._HTML_SAMPLE)
        assert len(results) == 3

    def test_first_entry_fields(self):
        from modules.cwe import _parse_top25_rows
        results = _parse_top25_rows(self._HTML_SAMPLE)
        first = results[0]
        assert first["rank"] == 1
        assert first["cwe_id"] == 79
        assert "Web Page Generation" in first["name"]
        assert first["score"] == 60.38
        assert first["kev_count"] == 7
        assert first["rank_change"] == "0"

    def test_rank_change_variants(self):
        from modules.cwe import _parse_top25_rows
        results = _parse_top25_rows(self._HTML_SAMPLE)
        assert results[1]["rank_change"] == "+1"
        assert results[2]["rank_change"] == "-3"

    def test_empty_html(self):
        from modules.cwe import _parse_top25_rows
        assert _parse_top25_rows("") == []
        assert _parse_top25_rows("no tables here") == []


class TestFindByIdIndex:
    """Test that _find_by_id uses O(1) index, not linear scan."""

    def test_find_by_id_returns_none_for_missing(self):
        from modules.cwe import _find_by_id
        assert _find_by_id(999999) is None

    def test_build_index_returns_dict(self):
        from modules.cwe import _build_index
        idx = _build_index()
        assert isinstance(idx, dict)
        assert len(idx) > 0
