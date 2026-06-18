from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from core.cache import set_json, get_json, get_config, set_config
from core.models import CWEInfo
from core.validation import validate_url_https

CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
CWE_CSV_SHA256 = os.environ.get("CWE_CSV_SHA256", "")
TTL = 86400.0
_COL_ABSTRACTION = "Weakness Abstraction"


def _seg_key(seg: str, key: str, terminators: list[str]) -> str | None:
    pattern = key + r":(.+)(?=" + "|".join(terminators) + "|$)"
    m = re.search(pattern, seg)
    if m:
        return m.group(1).strip().rstrip(":")
    return None


def _parse_related(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        nature = _seg_key(seg, "NATURE", [r":CWE ID:", r":VIEW ID:"])
        if nature:
            entry["nature"] = nature
        cwe_id = _seg_key(seg, "CWE ID", [r":NATURE:", r":VIEW ID:"])
        if cwe_id:
            entry["cwe_id"] = cwe_id
        view_id = _seg_key(seg, "VIEW ID", [r":NATURE:", r":CWE ID:"])
        if view_id:
            entry["view_id"] = view_id
        if "cwe_id" in entry:
            results.append(entry)
    return results


def _nth_or_last(lst: list[str], i: int, default: str = "N/A") -> str:
    if i < len(lst):
        return lst[i].strip().rstrip(":")
    if lst:
        return lst[-1].strip().rstrip(":")
    return default


def _parse_consequences(raw: str) -> list[dict]:
    if not raw:
        return []
    consequences = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        scopes = re.findall(r"SCOPE:(.+)(?=:SCOPE:|:IMPACT:|:NOTE:|$)", seg)
        impacts = re.findall(r"IMPACT:(.+)(?=:SCOPE:|:IMPACT:|:NOTE:|$)", seg)
        if scopes or impacts:
            for i in range(max(len(scopes), len(impacts))):
                consequences.append({
                    "scope": _nth_or_last(scopes, i),
                    "impact": _nth_or_last(impacts, i),
                })
    return consequences


def _parse_mitigations(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        phase = _seg_key(seg, "PHASE", [r"STRATEGY:", r"DESCRIPTION:", r"EFFECTIVENESS:", r"NOTE:"])
        if phase is not None:
            entry["phase"] = phase
        strategy = _seg_key(seg, "STRATEGY", [r"DESCRIPTION:", r"EFFECTIVENESS:", r"NOTE:"])
        if strategy is not None:
            entry["strategy"] = strategy
        desc = _seg_key(seg, "DESCRIPTION", [r"EFFECTIVENESS:", r"NOTE:"])
        if desc is not None:
            entry["description"] = desc
        eff = _seg_key(seg, "EFFECTIVENESS", [r"DESCRIPTION:", r"NOTE:"])
        if eff is not None:
            entry["effectiveness"] = eff
        if entry:
            results.append(entry)
    return results


def _parse_detection(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        method = _seg_key(seg, "METHOD", [r":EFFECTIVENESS:", r":DESCRIPTION:", r":NOTE:"])
        if method is not None:
            entry["method"] = method
        eff = _seg_key(seg, "EFFECTIVENESS", [r":METHOD:", r":DESCRIPTION:", r":NOTE:"])
        if eff is not None:
            entry["effectiveness"] = eff
        desc = _seg_key(seg, "DESCRIPTION", [r":EFFECTIVENESS:", r":NOTE:"])
        if desc is not None:
            entry["description"] = desc
        if entry:
            results.append(entry)
    return results


def _parse_observed(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        ref = _seg_key(seg, "REFERENCE", [r":DESCRIPTION:", r":NOTE:"])
        if ref is not None:
            entry["reference"] = ref
        desc = _seg_key(seg, "DESCRIPTION", [r":REFERENCE:", r":NOTE:"])
        if desc is not None:
            entry["description"] = desc
        link = re.search(r"LINK:(.+)$", seg)
        if link:
            entry["link"] = link.group(1).strip().rstrip(":")
        if entry:
            results.append(entry)
    return results


def _parse_alt_terms(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        term = _seg_key(seg, "TERM", [r":DESCRIPTION:"])
        if term is not None:
            entry["term"] = term
        desc = _seg_key(seg, "DESCRIPTION", [r":TERM:"])
        if desc is not None:
            entry["description"] = desc
        if entry:
            results.append(entry)
    return results


def _parse_ordinalities(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        ordinality = _seg_key(seg, "ORDINALITY", [r":ORDINALITY:"])
        if ordinality is not None:
            entry["ordinality"] = ordinality
        if entry:
            results.append(entry)
    return results


def _parse_introduction(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        phase = _seg_key(seg, "PHASE", [r":NOTE:", r":REALIZATION:"])
        if phase is not None:
            entry["phase"] = phase
        note = _seg_key(seg, "NOTE", [r":PHASE:"])
        if note is not None:
            entry["note"] = note
        if entry:
            results.append(entry)
    return results


def _parse_notes(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        typ = _seg_key(seg, "TYPE", [r":NOTE:"])
        if typ is not None:
            entry["type"] = typ
        note = _seg_key(seg, "NOTE", [r":TYPE:"])
        if note is not None:
            entry["note"] = note
        if not entry and seg:
            entry["note"] = seg.rstrip(":")
        if entry:
            results.append(entry)
    return results


def _parse_attack_patterns(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        m = re.search(r"CAPEC-ID:(\d+)", seg)
        if m:
            entry["capec_id"] = m.group(1)
        m = re.search(r"ORDINAL:(\w+)", seg)
        if m:
            entry["ordinal"] = m.group(1)
        if entry:
            results.append(entry)
    return results


def _parse_taxonomy(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        taxonomy = _seg_key(seg, "TAXONOMY NAME", [r":ENTRY ID:", r":ENTRY NAME:"])
        if taxonomy is not None:
            entry["taxonomy"] = taxonomy
        entry_id = _seg_key(seg, "ENTRY ID", [r":TAXONOMY NAME:", r":ENTRY NAME:"])
        if entry_id is not None:
            entry["entry_id"] = entry_id
        m = re.search(r"ENTRY NAME:(.+)$", seg)
        if m:
            entry["entry_name"] = m.group(1).strip().rstrip(":")
        if entry:
            results.append(entry)
    return results


def _parse_platforms(raw: str) -> list[dict]:
    if not raw:
        return []
    results = []
    for seg in (s.strip() for s in raw.split("::") if s.strip()):
        entry = {}
        lang = _seg_key(seg, "LANGUAGE NAME", [r":LANGUAGE PREVALENCE:"])
        if lang is not None:
            entry["language"] = lang
        prev = _seg_key(seg, "LANGUAGE PREVALENCE", [r":LANGUAGE NAME:"])
        if prev is not None:
            entry["prevalence"] = prev
        os_name = _seg_key(seg, "OPERATING SYSTEM NAME", [r":OPERATING SYSTEM PREVALENCE:"])
        if os_name is not None:
            entry["os"] = os_name
        os_prev = _seg_key(seg, "OPERATING SYSTEM PREVALENCE", [r":OPERATING SYSTEM NAME:"])
        if os_prev is not None:
            entry["os_prevalence"] = os_prev
        if entry:
            results.append(entry)
    return results


def _load_data() -> list[dict]:
    cached = get_json("cwe:catalog")
    if cached is not None:
        return cached

    try:
        validate_url_https(CWE_CSV_URL)
    except ValueError:
        return []
    resp = urllib.request.urlopen(CWE_CSV_URL, timeout=60)
    raw = resp.read()
    content_hash = hashlib.sha256(raw).hexdigest()
    if CWE_CSV_SHA256 and content_hash != CWE_CSV_SHA256:
        raise ValueError(f"CWE CSV integrity check failed. Expected {CWE_CSV_SHA256[:16]}... got {content_hash[:16]}...")
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        csv_name = [n for n in zf.namelist() if n.endswith(".csv")][0]
        with zf.open(csv_name) as f:
            reader = csv.DictReader(io.TextIOWrapper(f, "utf-8"))
            rows = list(reader)

    set_json("cwe:catalog", rows, TTL)
    set_config("cwe:catalog:sha256", content_hash)
    set_config("cwe:catalog:fetched_at", datetime.now(timezone.utc).isoformat())
    set_config("cwe:catalog:url", CWE_CSV_URL)
    return rows


def get_cwe_version() -> dict:
    return {
        "sha256": get_config("cwe:catalog:sha256", "unknown"),
        "fetched_at": get_config("cwe:catalog:fetched_at", "unknown"),
        "source_url": get_config("cwe:catalog:url", CWE_CSV_URL),
        "cache_ttl_seconds": TTL,
    }


def _find_by_id(cwe_id: int) -> dict | None:
    for row in _load_data():
        try:
            if int(row.get("CWE-ID", 0)) == cwe_id:
                return row
        except (ValueError, TypeError):
            continue
    return None


def _to_cwe_info(row: dict) -> CWEInfo:
    return CWEInfo(
        id=int(row.get("CWE-ID", 0)),
        name=row.get("Name", ""),
        abstraction=row.get(_COL_ABSTRACTION, ""),
        status=row.get("Status", ""),
        description=row.get("Description", ""),
        extended_description=row.get("Extended Description", ""),
        consequences=_parse_consequences(row.get("Common Consequences", "")),
        mitigations=_parse_mitigations(row.get("Potential Mitigations", "")),
        related_weaknesses=_parse_related(row.get("Related Weaknesses", "")),
        introduction_phases=row.get("Modes Of Introduction", ""),
        likelihood=row.get("Likelihood of Exploit", ""),
        applicable_platforms=row.get("Applicable Platforms", ""),
        background_details=row.get("Background Details", ""),
        alternate_terms=row.get("Alternate Terms", ""),
        exploitation_factors=row.get("Exploitation Factors", ""),
        detection_methods=row.get("Detection Methods", ""),
        observed_examples=row.get("Observed Examples", ""),
        functional_areas=row.get("Functional Areas", ""),
        affected_resources=row.get("Affected Resources", ""),
        taxonomy_mappings=row.get("Taxonomy Mappings", ""),
        related_attack_patterns=row.get("Related Attack Patterns", ""),
        notes=row.get("Notes", ""),
        weakness_ordinalities=row.get("Weakness Ordinalities", ""),
    )


def get_cwe(cwe_id: int) -> CWEInfo | None:
    row = _find_by_id(cwe_id)
    if row is None:
        return None
    return _to_cwe_info(row)


def search_cwes(term: str, limit: int = 20) -> list[CWEInfo]:
    data = _load_data()
    term_lower = term.lower()
    results = []
    for row in data:
        if term_lower in row.get("Name", "").lower() or term_lower in row.get("Description", "").lower():
            results.append(_to_cwe_info(row))
            if len(results) >= limit:
                break
    return results


def list_cwes_by_abstraction(abstraction: str, limit: int = 50) -> list[CWEInfo]:
    data = _load_data()
    results = []
    for row in data:
        if row.get(_COL_ABSTRACTION, "") == abstraction:
            results.append(_to_cwe_info(row))
            if len(results) >= limit:
                break
    return results


def _format_alt_terms(cwe: CWEInfo) -> str:
    if not cwe.alternate_terms:
        return ""
    terms = _parse_alt_terms(cwe.alternate_terms)
    if terms:
        lines = ["\n**Alternate Terms:**\n"]
        for t in terms:
            line = f"- **{t.get('term', '?')}**"
            if t.get('description'):
                line += f": {t['description']}"
            lines.append(line + "\n")
        return "".join(lines)
    return f"\n**Alternate Terms:** {cwe.alternate_terms}\n"


def _format_platforms(cwe: CWEInfo) -> str:
    platforms = _parse_platforms(cwe.applicable_platforms) if cwe.applicable_platforms else []
    if platforms:
        lines = ["\n**Applicable Platforms:**\n"]
        for p in platforms:
            parts = []
            if p.get("language"):
                parts.append(f"{p['language']} ({p.get('prevalence', 'N/A')})")
            if p.get("os"):
                parts.append(f"{p['os']} ({p.get('os_prevalence', 'N/A')})")
            lines.append(f"- {', '.join(parts) if parts else str(p)}\n")
        return "".join(lines)
    if cwe.applicable_platforms:
        return f"\n**Applicable Platforms:** {cwe.applicable_platforms}\n"
    return ""


def _format_background(cwe: CWEInfo) -> str:
    if not cwe.background_details:
        return ""
    bg = cwe.background_details.strip(':')
    bg_entries = [s.strip() for s in bg.split('::') if s.strip()]
    if len(bg_entries) > 1:
        lines = ["\n**Background Details:**\n"]
        for entry in bg_entries:
            lines.append(f"- {entry}\n")
        return "".join(lines)
    return f"\n**Background Details:** {bg}\n"


def _format_ordinalities(cwe: CWEInfo) -> str:
    if not cwe.weakness_ordinalities:
        return ""
    ordinalities = _parse_ordinalities(cwe.weakness_ordinalities)
    if ordinalities:
        lines = ["\n**Weakness Ordinalities:**\n"]
        for o in ordinalities:
            lines.append(f"- {o.get('ordinality', 'N/A')}\n")
        return "".join(lines)
    return f"\n**Weakness Ordinalities:** {cwe.weakness_ordinalities}\n"


def _format_introduction(cwe: CWEInfo) -> str:
    if not cwe.introduction_phases:
        return ""
    intro = _parse_introduction(cwe.introduction_phases)
    if intro:
        lines = ["\n**Modes of Introduction:**\n"]
        for ip in intro:
            line = f"- {ip.get('phase', 'N/A')}"
            if ip.get('note'):
                line += f": {ip['note']}"
            lines.append(line + "\n")
        return "".join(lines)
    return f"\n**Modes of Introduction:** {cwe.introduction_phases}\n"


def _format_detection(cwe: CWEInfo) -> str:
    detection = _parse_detection(cwe.detection_methods) if cwe.detection_methods else []
    if detection:
        lines = ["\n**Detection Methods:**\n"]
        for i, d in enumerate(detection, 1):
            line = f"{i}. {d.get('method', 'N/A')}"
            if d.get('effectiveness'):
                line += f" (Effectiveness: {d['effectiveness']})"
            if d.get('description'):
                line += f" — {d['description']}"
            lines.append(line + "\n")
        return "".join(lines)
    if cwe.detection_methods:
        return f"\n**Detection Methods:** {cwe.detection_methods}\n"
    return ""


def _format_mitigations_section(cwe: CWEInfo) -> str:
    if not cwe.mitigations:
        return ""
    lines = ["\n**Mitigations:**\n"]
    for i, m in enumerate(cwe.mitigations, 1):
        line = f"{i}. [{m.get('phase', 'N/A')}]"
        if m.get("strategy"):
            line += f" Strategy: {m['strategy']}."
        if m.get("description"):
            line += f" {m['description']}"
        if m.get("effectiveness"):
            line += f" (Effectiveness: {m['effectiveness']})"
        lines.append(line + "\n")
    return "".join(lines)


def _format_observed(cwe: CWEInfo) -> str:
    observed = _parse_observed(cwe.observed_examples) if cwe.observed_examples else []
    if observed:
        lines = ["\n**Observed Examples:**\n"]
        for o in observed:
            line = "-"
            if o.get("reference"):
                line += f" {o['reference']}"
            if o.get("description"):
                line += f": {o['description']}"
            if o.get("link"):
                line += f" [{o['link']}]"
            lines.append(line + "\n")
        return "".join(lines)
    if cwe.observed_examples:
        return f"\n**Observed Examples:** {cwe.observed_examples}\n"
    return ""


def _format_related_cwes(cwe: CWEInfo) -> str:
    if not cwe.related_weaknesses:
        return ""
    lines = ["\n**Related CWEs:**\n"]
    for r in cwe.related_weaknesses:
        line = f"- CWE-{r['cwe_id']} ({r.get('nature', 'N/A')})"
        rel_cwe = get_cwe(int(r['cwe_id'])) if r['cwe_id'].isdigit() else None
        if rel_cwe:
            line += f" — {rel_cwe.name}"
        lines.append(line + "\n")
    return "".join(lines)


def _format_attack_patterns(cwe: CWEInfo) -> str:
    patterns = _parse_attack_patterns(cwe.related_attack_patterns) if cwe.related_attack_patterns else []
    if patterns:
        lines = ["\n**Related Attack Patterns:**\n"]
        for ap in patterns:
            lines.append(f"- CAPEC-{ap.get('capec_id', '?')} ({ap.get('ordinal', 'N/A')})\n")
        return "".join(lines)
    if cwe.related_attack_patterns:
        return f"\n**Related Attack Patterns:** {cwe.related_attack_patterns}\n"
    return ""


def _format_taxonomy(cwe: CWEInfo) -> str:
    taxonomy = _parse_taxonomy(cwe.taxonomy_mappings) if cwe.taxonomy_mappings else []
    if taxonomy:
        lines = ["\n**Taxonomy Mappings:**\n"]
        for t in taxonomy:
            line = f"- {t.get('taxonomy', 'N/A')}"
            if t.get('entry_id'):
                line += f" [{t['entry_id']}]"
            if t.get('entry_name'):
                line += f": {t['entry_name']}"
            lines.append(line + "\n")
        return "".join(lines)
    if cwe.taxonomy_mappings:
        return f"\n**Taxonomy Mappings:** {cwe.taxonomy_mappings}\n"
    return ""


def _format_notes(cwe: CWEInfo) -> str:
    if not cwe.notes:
        return ""
    notes = _parse_notes(cwe.notes)
    if notes:
        lines = ["\n**Notes:**\n"]
        for n in notes:
            line = "-"
            if n.get('type'):
                line += f" [{n['type']}]"
            if n.get('note'):
                line += f" {n['note']}"
            lines.append(line + "\n")
        return "".join(lines)
    return f"\n**Notes:** {cwe.notes}\n"


def format_cwe(cwe: CWEInfo) -> str:
    out = f"## CWE-{cwe.id}: {cwe.name}\n"
    out += f"**Abstraction:** {cwe.abstraction} | **Status:** {cwe.status}\n\n"
    out += f"**Description:** {cwe.description}\n"
    if cwe.extended_description:
        out += f"\n**Extended Description:** {cwe.extended_description}\n"
    out += _format_alt_terms(cwe)
    out += _format_platforms(cwe)
    out += _format_background(cwe)
    out += _format_ordinalities(cwe)
    out += _format_introduction(cwe)
    if cwe.exploitation_factors:
        out += f"\n**Exploitation Factors:** {cwe.exploitation_factors}\n"
    if cwe.likelihood:
        out += f"\n**Likelihood of Exploit:** {cwe.likelihood}\n"
    if cwe.consequences:
        out += "\n**Consequences:**\n"
        for c in cwe.consequences:
            out += f"- Scope: **{c.get('scope', 'N/A')}** → Impact: **{c.get('impact', 'N/A')}**\n"
    out += _format_detection(cwe)
    out += _format_mitigations_section(cwe)
    out += _format_observed(cwe)
    if cwe.functional_areas:
        out += f"\n**Functional Areas:** {cwe.functional_areas}\n"
    if cwe.affected_resources:
        out += f"\n**Affected Resources:** {cwe.affected_resources}\n"
    out += _format_related_cwes(cwe)
    out += _format_attack_patterns(cwe)
    out += _format_taxonomy(cwe)
    out += _format_notes(cwe)
    return out


def format_cwe_brief(cwe: CWEInfo) -> str:
    desc = cwe.description[:200] + ('...' if len(cwe.description) > 200 else '')
    return f"- **CWE-{cwe.id}** [{cwe.abstraction}]: {cwe.name} — {desc}"


def dump_all_cwes(abstraction: str | None = None, limit: int = 0) -> list[dict]:
    rows = _load_data()
    if abstraction:
        rows = [r for r in rows if r.get(_COL_ABSTRACTION, "") == abstraction]
    if limit > 0:
        rows = rows[:limit]
    results = []
    for row in rows:
        cwe = _to_cwe_info(row)
        results.append({
            "id": cwe.id,
            "name": cwe.name,
            "abstraction": cwe.abstraction,
            "status": cwe.status,
            "description": cwe.description,
            "extended_description": cwe.extended_description,
            "consequences": cwe.consequences,
            "mitigations": cwe.mitigations,
            "related_weaknesses": cwe.related_weaknesses,
            "likelihood": cwe.likelihood,
            "applicable_platforms": cwe.applicable_platforms,
            "background_details": cwe.background_details,
            "alternate_terms": cwe.alternate_terms,
            "exploitation_factors": cwe.exploitation_factors,
            "detection_methods": cwe.detection_methods,
            "observed_examples": cwe.observed_examples,
            "functional_areas": cwe.functional_areas,
            "affected_resources": cwe.affected_resources,
            "taxonomy_mappings": cwe.taxonomy_mappings,
            "related_attack_patterns": cwe.related_attack_patterns,
            "notes": cwe.notes,
            "weakness_ordinalities": cwe.weakness_ordinalities,
            "introduction_phases": cwe.introduction_phases,
        })
    return results