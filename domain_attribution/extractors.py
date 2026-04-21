from __future__ import annotations

import json
import re
from html import unescape

from domain_attribution.models import CrawlRecord, Evidence, OwnershipRecord
from domain_attribution.parsing import normalize_text

LEGAL_SUFFIX_GROUP = (
    r"Inc\.?|L\.?L\.?C\.?|Ltd\.?|Limited|Corp\.?|Corporation|Company|"
    r"Holdings|Group|Holding|Co\.?|PLC|Plc|GmbH|AG|SE|S\.?A\.?|S\.?L\.?|"
    r"S\.?R\.?L\.?|S\.?p\.?A\.?|B\.?V\.?|N\.?V\.?|Oy|AB|ApS|K\.?K\.?|"
    r"Pty\.?\s*Ltd\.?|Pvt\.?\s*Ltd\.?|Sdn\.?\s*Bhd\.?"
)
LEGAL_ENTITY_PATTERN = re.compile(
    r"\b([A-Z][A-Za-z0-9&'.\-]*(?:\s+(?:&|and|of|the|de|la|le)?\s*[A-Z][A-Za-z0-9&'.\-]*){0,5})\s*,?\s+(" + LEGAL_SUFFIX_GROUP + r")\b",
    re.UNICODE,
)
COPYRIGHT_PATTERN = re.compile(
    r"(?:©|\(c\)|copyright)\s*(?:\d{4}(?:\s*[-–]\s*\d{4})?)?\s*(?:by\s+)?([A-Za-z0-9][^.|·©\n\r]{1,120}?)"
    r"(?=\s*(?:[.|·]|all rights reserved|$))",
    re.IGNORECASE,
)
JSONLD_SCRIPT_PATTERN = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)

PAGE_EVIDENCE_CAP = 50

EVIDENCE_WEIGHTS = {
    "rdap_org": 55,
    "rdap_entity": 45,
    "whois_registrant": 50,
    "whois_contact": 35,
    "cert_org": 45,
    "cert_cn": 25,
    "jsonld_org": 50,
    "copyright_entity": 55,
    "legal_entity_legal": 50,
    "legal_entity_about": 40,
    "legal_entity_other": 30,
    "page_text_legal": 25,
    "page_text_about": 18,
    "page_text_other": 10,
}


def _clean_html(raw_text: str) -> str:
    without_scripts = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw_text)
    without_tags = re.sub(r"(?is)<[^>]+>", " ", without_scripts)
    collapsed = re.sub(r"\s+", " ", unescape(without_tags))
    return collapsed.strip()


def _page_weight(label: str, tier: str) -> int:
    if label in {"privacy", "terms", "legal", "imprint", "impressum"}:
        return EVIDENCE_WEIGHTS[f"{tier}_legal"]
    if label in {"about", "contact"}:
        return EVIDENCE_WEIGHTS[f"{tier}_about"]
    return EVIDENCE_WEIGHTS[f"{tier}_other"]


def _word_boundary_match(needle: str, haystack: str) -> bool:
    if not needle or not haystack:
        return False
    pattern = re.compile(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])")
    return bool(pattern.search(haystack))


def _matches_candidate(value: str, candidate: str) -> bool:
    normalized_value = normalize_text(value)
    normalized_candidate = normalize_text(candidate)
    return _word_boundary_match(normalized_candidate, normalized_value)


def _extract_jsonld_orgs(raw_html: str) -> list[str]:
    orgs: list[str] = []
    for match in JSONLD_SCRIPT_PATTERN.finditer(raw_html):
        block = match.group(1).strip()
        if not block:
            continue
        try:
            data = json.loads(block)
        except (ValueError, TypeError):
            continue
        _walk_jsonld(data, orgs)
    seen: set[str] = set()
    deduped: list[str] = []
    for name in orgs:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(name)
    return deduped


def _walk_jsonld(node: object, accumulator: list[str]) -> None:
    if isinstance(node, list):
        for child in node:
            _walk_jsonld(child, accumulator)
        return
    if not isinstance(node, dict):
        return
    node_type = node.get("@type")
    types: set[str] = set()
    if isinstance(node_type, str):
        types.add(node_type.lower())
    elif isinstance(node_type, list):
        types = {item.lower() for item in node_type if isinstance(item, str)}
    if types & {"organization", "corporation", "localbusiness", "onlinebusiness", "onlinestore", "newsmediaorganization", "educationalorganization", "ngo"}:
        for key in ("legalName", "name", "parentOrganization", "alternateName"):
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                accumulator.append(value.strip())
            elif isinstance(value, dict):
                inner = value.get("name")
                if isinstance(inner, str) and inner.strip():
                    accumulator.append(inner.strip())
    for value in node.values():
        _walk_jsonld(value, accumulator)


def _extract_legal_entities(cleaned_text: str) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for match in LEGAL_ENTITY_PATTERN.finditer(cleaned_text):
        phrase = f"{match.group(1).strip()} {match.group(2).strip()}"
        key = normalize_text(phrase)
        if not key or key in seen:
            continue
        seen.add(key)
        hits.append(phrase)
    return hits


def _extract_copyright_entities(cleaned_text: str) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for match in COPYRIGHT_PATTERN.finditer(cleaned_text):
        phrase = match.group(1).strip().rstrip(",;:-")
        key = normalize_text(phrase)
        if len(key) < 3 or key in seen:
            continue
        seen.add(key)
        hits.append(phrase)
    return hits


def _snippet(text: str, needle: str, radius: int = 120) -> str:
    pattern = re.compile(re.escape(needle), re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        return text[: radius * 2].strip()
    start = max(0, match.start() - radius)
    end = min(len(text), match.end() + radius)
    return text[start:end].strip()


def _append(items: list[Evidence], candidate_company: str, source_type: str, source_url: str, snippet: str, matched_text: str, score: int) -> None:
    items.append(
        Evidence(
            source_type=source_type,
            source_url=source_url,
            snippet=snippet,
            matched_text=matched_text,
            score=score,
            candidate_company=candidate_company,
        )
    )


def build_evidence(
    company_name: str,
    aliases: list[str],
    ownership: OwnershipRecord,
    crawl: CrawlRecord,
) -> list[Evidence]:
    evidence_items: list[Evidence] = []
    candidates = [company_name, *aliases]

    for candidate in candidates:
        if ownership.rdap_role == "registrant" and _matches_candidate(ownership.rdap_org, candidate):
            _append(evidence_items, company_name, "rdap_org", ownership.rdap_source_url, ownership.rdap_org, candidate, EVIDENCE_WEIGHTS["rdap_org"])
            break
    for candidate in candidates:
        if ownership.rdap_role == "registrant" and _matches_candidate(ownership.rdap_entity_name, candidate):
            _append(evidence_items, company_name, "rdap_entity", ownership.rdap_source_url, ownership.rdap_entity_name, candidate, EVIDENCE_WEIGHTS["rdap_entity"])
            break

    whois_is_contact = ownership.whois_field_label.startswith("registrant_contact") or "contact" in ownership.whois_field_label
    whois_weight = EVIDENCE_WEIGHTS["whois_contact"] if whois_is_contact else EVIDENCE_WEIGHTS["whois_registrant"]
    whois_source_type = f"whois_{ownership.whois_field_label}" if ownership.whois_field_label else "whois_registrant"
    for candidate in candidates:
        if _matches_candidate(ownership.whois_registrant, candidate):
            _append(evidence_items, company_name, whois_source_type, ownership.whois_source, ownership.whois_registrant, candidate, whois_weight)
            break

    if crawl.cert_subject_org:
        for candidate in candidates:
            if _matches_candidate(crawl.cert_subject_org, candidate):
                _append(evidence_items, company_name, "cert_subject_org", crawl.final_url, crawl.cert_subject_org, candidate, EVIDENCE_WEIGHTS["cert_org"])
                break
    if crawl.cert_subject_cn:
        for candidate in candidates:
            if _matches_candidate(crawl.cert_subject_cn, candidate):
                _append(evidence_items, company_name, "cert_subject_cn", crawl.final_url, crawl.cert_subject_cn, candidate, EVIDENCE_WEIGHTS["cert_cn"])
                break

    page_evidence: list[Evidence] = []
    for label, page_text in crawl.pages.items():
        cleaned_text = _clean_html(page_text)
        if not cleaned_text:
            continue
        source_url = crawl.page_urls.get(label, "")
        display_label = label.removesuffix("_browser")

        jsonld_orgs = _extract_jsonld_orgs(page_text)
        for org in jsonld_orgs:
            for candidate in candidates:
                if _matches_candidate(org, candidate):
                    _append(page_evidence, company_name, f"jsonld_org_{display_label}", source_url, org, candidate, EVIDENCE_WEIGHTS["jsonld_org"])
                    break

        copyright_entities = _extract_copyright_entities(cleaned_text)
        for phrase in copyright_entities:
            for candidate in candidates:
                if _matches_candidate(phrase, candidate):
                    _append(page_evidence, company_name, f"copyright_{display_label}", source_url, phrase, candidate, EVIDENCE_WEIGHTS["copyright_entity"])
                    break

        legal_entities = _extract_legal_entities(cleaned_text)
        for phrase in legal_entities:
            for candidate in candidates:
                if _matches_candidate(phrase, candidate):
                    _append(page_evidence, company_name, f"legal_entity_{display_label}", source_url, phrase, candidate, _page_weight(display_label, "legal_entity"))
                    break

        normalized_page = normalize_text(cleaned_text)
        for candidate in candidates:
            normalized_candidate = normalize_text(candidate)
            if len(normalized_candidate) < 3:
                continue
            if not _word_boundary_match(normalized_candidate, normalized_page):
                continue
            _append(page_evidence, company_name, f"{display_label}_page", source_url, _snippet(cleaned_text, candidate), candidate, _page_weight(display_label, "page_text"))
            break

    deduped: dict[str, Evidence] = {}
    for item in page_evidence:
        key = item.source_type
        current = deduped.get(key)
        if current is None or item.score > current.score:
            deduped[key] = item
    capped_page = sorted(deduped.values(), key=lambda e: e.score, reverse=True)

    total_from_pages = 0
    for item in capped_page:
        if total_from_pages >= PAGE_EVIDENCE_CAP:
            break
        remaining = PAGE_EVIDENCE_CAP - total_from_pages
        if item.score > remaining:
            trimmed = Evidence(
                source_type=item.source_type,
                source_url=item.source_url,
                snippet=item.snippet,
                matched_text=item.matched_text,
                score=remaining,
                candidate_company=item.candidate_company,
            )
            evidence_items.append(trimmed)
            total_from_pages = PAGE_EVIDENCE_CAP
            break
        evidence_items.append(item)
        total_from_pages += item.score

    evidence_items.sort(key=lambda e: e.score, reverse=True)
    return evidence_items
