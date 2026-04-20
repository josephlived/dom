from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Company:
    name: str
    aliases: list[str]
    normalized_names: list[str]


@dataclass(slots=True)
class Evidence:
    source_type: str
    source_url: str
    snippet: str
    matched_text: str
    score: int
    candidate_company: str


@dataclass(slots=True)
class CandidateMatch:
    company_name: str
    score: int
    confidence_label: str
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class OwnershipRecord:
    rdap_org: str = ""
    rdap_source_url: str = ""
    rdap_entity_name: str = ""
    rdap_role: str = ""
    whois_registrant: str = ""
    whois_field_label: str = ""
    whois_source: str = ""
    whois_raw_excerpt: str = ""
    is_privacy_protected: bool = False
    status_notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CrawlRecord:
    requested_domain: str
    redirect_detected: bool
    redirect_target: str
    redirect_signal: str
    browser_fallback_used: bool
    parked_detected: bool
    parked_reason: str
    final_url: str
    site_status: str
    pages: dict[str, str] = field(default_factory=dict)
    page_urls: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class DomainResult:
    input_domain: str
    redirect_detected: bool
    redirect_target: str
    redirect_signal: str
    site_status: str
    match_status: str
    top_candidate: str
    confidence: int
    top_evidence: str
    candidates: list[CandidateMatch] = field(default_factory=list)
    ownership: OwnershipRecord = field(default_factory=OwnershipRecord)
    crawl: CrawlRecord | None = None
