from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from domain_attribution.crawler import DEFAULT_PATHS, crawl_domain
from domain_attribution.models import DomainResult
from domain_attribution.ownership import lookup_ownership
from domain_attribution.parsing import parse_companies, parse_domains
from domain_attribution.scoring import derive_match_status, score_company

ProgressCallback = Callable[[int, int, str], None]


def _paths_for_mode(analysis_mode: str) -> tuple[str, ...]:
    if analysis_mode == "quick":
        return ("",)
    return DEFAULT_PATHS


def _analyze_one_domain(domain: str, companies, confidence_threshold: int, analysis_mode: str) -> DomainResult:
    crawl = crawl_domain(domain, _paths_for_mode(analysis_mode))
    ownership = lookup_ownership(domain)
    candidates = []
    for company in companies:
        candidate = score_company(company, ownership, crawl)
        if candidate:
            candidates.append(candidate)
    candidates.sort(key=lambda item: item.score, reverse=True)
    match_status = derive_match_status(candidates, crawl, ownership, confidence_threshold)
    top_candidate = candidates[0].company_name if candidates else ""
    confidence = candidates[0].score if candidates else 0
    top_evidence = ""
    if candidates and candidates[0].evidence:
        lead = candidates[0].evidence[0]
        source_suffix = f" ({lead.source_url})" if lead.source_url else ""
        whois_hint = ""
        if lead.source_type.startswith("whois") and ownership.whois_source:
            whois_hint = f" via {ownership.whois_source}"
        top_evidence = f"{lead.source_type}{whois_hint}: {lead.snippet[:140]}{source_suffix}"

    return DomainResult(
        input_domain=domain,
        redirect_detected=crawl.redirect_detected,
        redirect_target=crawl.redirect_target,
        redirect_signal=crawl.redirect_signal,
        site_status=crawl.site_status,
        match_status=match_status,
        top_candidate=top_candidate,
        confidence=confidence,
        top_evidence=top_evidence,
        candidates=candidates,
        ownership=ownership,
        crawl=crawl,
    )


def analyze_domains(
    company_text: str,
    domain_text: str,
    confidence_threshold: int,
    analysis_mode: str = "deep",
    max_workers: int = 6,
    progress_callback: ProgressCallback | None = None,
) -> list[DomainResult]:
    companies = parse_companies(company_text)
    domains = parse_domains(domain_text)
    if not companies or not domains:
        return []

    worker_count = max(1, min(max_workers, len(domains)))
    indexed_results: dict[int, DomainResult] = {}

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(_analyze_one_domain, domain, companies, confidence_threshold, analysis_mode): (index, domain)
            for index, domain in enumerate(domains)
        }
        completed = 0
        for future in as_completed(futures):
            index, domain = futures[future]
            indexed_results[index] = future.result()
            completed += 1
            if progress_callback:
                progress_callback(completed, len(domains), domain)

    return [indexed_results[index] for index in sorted(indexed_results)]
