from __future__ import annotations

import csv
from io import StringIO

from domain_attribution.models import DomainResult


def results_to_rows(results: list[DomainResult]) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    for item in results:
        rows.append(
            {
                "Input Domain": item.input_domain,
                "Redirected?": "Yes" if item.redirect_detected else "No",
                "Redirect Target": item.redirect_target,
                "Redirect Signal": item.redirect_signal,
                "Browser Fallback": "Yes" if item.crawl and item.crawl.browser_fallback_used else "No",
                "Site Status": item.site_status,
                "Match Status": item.match_status,
                "Top Candidate": item.top_candidate,
                "Confidence": item.confidence,
                "Top Evidence": item.top_evidence,
            }
        )
    return rows


def _cross_domain_links_summary(item: DomainResult) -> str:
    parts = []
    for candidate in item.candidates:
        for evidence in candidate.evidence:
            if evidence.source_type.startswith("cross_domain_"):
                kind = evidence.source_type.removeprefix("cross_domain_")
                parts.append(f"{kind}→{evidence.matched_text}")
    seen: set[str] = set()
    deduped: list[str] = []
    for part in parts:
        if part not in seen:
            seen.add(part)
            deduped.append(part)
    return " | ".join(deduped)


def results_to_csv(results: list[DomainResult]) -> str:
    output = StringIO()
    fieldnames = [
        "Input Domain",
        "Redirected?",
        "Redirect Target",
        "Redirect Signal",
        "Browser Fallback",
        "Site Status",
        "Match Status",
        "Top Candidate",
        "Confidence",
        "Top Evidence",
        "Candidate Count",
        "Final URL",
        "Parked Detected",
        "Parked Reason",
        "RDAP Org",
        "RDAP Entity",
        "WHOIS Registrant",
        "WHOIS Field Label",
        "WHOIS Source",
        "WHOIS Raw Excerpt",
        "Nameservers",
        "Cross-Domain Legal Links",
        "Cert Subject Org",
        "Cert Subject CN",
        "Cert Issuer Org",
        "Ownership Notes",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for item in results:
        writer.writerow(
            {
                "Input Domain": item.input_domain,
                "Redirected?": "Yes" if item.redirect_detected else "No",
                "Redirect Target": item.redirect_target,
                "Redirect Signal": item.redirect_signal,
                "Browser Fallback": "Yes" if item.crawl and item.crawl.browser_fallback_used else "No",
                "Site Status": item.site_status,
                "Match Status": item.match_status,
                "Top Candidate": item.top_candidate,
                "Confidence": item.confidence,
                "Top Evidence": item.top_evidence,
                "Candidate Count": len(item.candidates),
                "Final URL": item.crawl.final_url if item.crawl else "",
                "Parked Detected": "Yes" if item.crawl and item.crawl.parked_detected else "No",
                "Parked Reason": item.crawl.parked_reason if item.crawl else "",
                "RDAP Org": item.ownership.rdap_org,
                "RDAP Entity": item.ownership.rdap_entity_name,
                "WHOIS Registrant": item.ownership.whois_registrant,
                "WHOIS Field Label": item.ownership.whois_field_label,
                "WHOIS Source": item.ownership.whois_source,
                "WHOIS Raw Excerpt": item.ownership.whois_raw_excerpt,
                "Nameservers": ", ".join(item.ownership.nameservers),
                "Cross-Domain Legal Links": _cross_domain_links_summary(item),
                "Cert Subject Org": item.crawl.cert_subject_org if item.crawl else "",
                "Cert Subject CN": item.crawl.cert_subject_cn if item.crawl else "",
                "Cert Issuer Org": item.crawl.cert_issuer_org if item.crawl else "",
                "Ownership Notes": " | ".join(item.ownership.status_notes),
            }
        )
    return output.getvalue()
