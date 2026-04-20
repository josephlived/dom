from __future__ import annotations

from domain_attribution.extractors import build_evidence
from domain_attribution.models import CandidateMatch, Company, CrawlRecord, OwnershipRecord


def score_company(company: Company, ownership: OwnershipRecord, crawl: CrawlRecord) -> CandidateMatch | None:
    evidence = build_evidence(company.name, company.aliases, ownership, crawl)
    if not evidence:
        return None
    total_score = sum(item.score for item in evidence)
    confidence_label = confidence_band(total_score)
    return CandidateMatch(
        company_name=company.name,
        score=total_score,
        confidence_label=confidence_label,
        evidence=evidence,
    )


def confidence_band(score: int) -> str:
    if score >= 85:
        return "High"
    if score >= 70:
        return "Medium"
    if score >= 50:
        return "Low"
    return "Very Low"


def derive_match_status(
    candidates: list[CandidateMatch],
    crawl: CrawlRecord,
    ownership: OwnershipRecord,
    threshold: int,
) -> str:
    if crawl.parked_detected:
        return "Parked"
    if crawl.site_status in {"timeout", "ssl_error", "connection_failed", "blocked_or_unreachable"} and not candidates:
        if ownership.is_privacy_protected:
            return "Privacy Protected"
        return "Insufficient Evidence"
    if not candidates:
        if ownership.is_privacy_protected:
            return "Privacy Protected"
        if ownership.rdap_org or ownership.rdap_entity_name or ownership.whois_registrant:
            return "Insufficient Evidence"
        return "Not Matched"

    top_score = candidates[0].score
    if top_score < threshold:
        if ownership.is_privacy_protected and top_score < 50:
            return "Privacy Protected"
        return "Candidate Matches"
    if len(candidates) > 1 and top_score - candidates[1].score < 15:
        return "Ambiguous"
    return "Matched"
