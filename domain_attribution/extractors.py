from __future__ import annotations

import re
from html import unescape

from domain_attribution.models import CrawlRecord, Evidence, OwnershipRecord
from domain_attribution.parsing import normalize_text


def _clean_html(raw_text: str) -> str:
    without_scripts = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw_text)
    without_tags = re.sub(r"(?is)<[^>]+>", " ", without_scripts)
    collapsed = re.sub(r"\s+", " ", unescape(without_tags))
    return collapsed.strip()


def build_evidence(
    company_name: str,
    aliases: list[str],
    ownership: OwnershipRecord,
    crawl: CrawlRecord,
) -> list[Evidence]:
    evidence_items: list[Evidence] = []
    candidates = [company_name, *aliases]

    whois_score = 40
    whois_source_type = "whois_registrant"
    if "registrant_contact" in ownership.whois_field_label:
        whois_score = 30
        whois_source_type = f"whois_{ownership.whois_field_label}"

    rdap_signals = []
    if ownership.rdap_role == "registrant":
        rdap_signals.extend(
            [
                (ownership.rdap_org, "rdap_org", ownership.rdap_source_url, 45),
                (ownership.rdap_entity_name, "rdap_entity", ownership.rdap_source_url, 35),
            ]
        )

    for value, source_type, source_url, score in (
        *rdap_signals,
        (ownership.whois_registrant, whois_source_type, ownership.whois_source, whois_score),
    ):
        normalized_value = normalize_text(value)
        for candidate in candidates:
            normalized_candidate = normalize_text(candidate)
            if normalized_value and normalized_candidate and normalized_candidate in normalized_value:
                evidence_items.append(
                    Evidence(
                        source_type=source_type,
                        source_url=source_url,
                        snippet=value,
                        matched_text=candidate,
                        score=score,
                        candidate_company=company_name,
                    )
                )
                break

    for label, page_text in crawl.pages.items():
        cleaned_text = _clean_html(page_text)
        normalized_page = normalize_text(cleaned_text)
        source_url = crawl.page_urls.get(label, "")
        for candidate in candidates:
            normalized_candidate = normalize_text(candidate)
            if not normalized_candidate or normalized_candidate not in normalized_page:
                continue
            snippet = _snippet(cleaned_text, candidate)
            source_type = f"{label}_page"
            page_score = 35 if label in {"privacy", "terms"} else 25 if label in {"about", "contact"} else 15
            evidence_items.append(
                Evidence(
                    source_type=source_type,
                    source_url=source_url,
                    snippet=snippet,
                    matched_text=candidate,
                    score=page_score,
                    candidate_company=company_name,
                )
            )
            break
    return evidence_items


def _snippet(text: str, candidate: str, radius: int = 120) -> str:
    pattern = re.compile(re.escape(candidate), re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        return text[: radius * 2].strip()
    start = max(0, match.start() - radius)
    end = min(len(text), match.end() + radius)
    return text[start:end].strip()
