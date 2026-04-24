from __future__ import annotations

import json
import re
from html import unescape
from urllib.parse import urljoin, urlparse

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
    "nameserver_root_match": 65,
    "cross_domain_imprint": 70,
    "cross_domain_privacy": 60,
    "cross_domain_terms": 55,
    "cross_domain_legal_other": 45,
}

SHARED_DNS_PROVIDERS = frozenset({
    "cloudflare.com",
    "cloudflare.net",
    "awsdns-01.com",
    "awsdns-02.com",
    "awsdns-03.com",
    "awsdns-04.com",
    "awsdns-01.net",
    "awsdns-02.net",
    "awsdns-03.net",
    "awsdns-04.net",
    "awsdns-01.org",
    "awsdns-02.org",
    "awsdns-03.org",
    "awsdns-04.org",
    "awsdns-01.co.uk",
    "awsdns-02.co.uk",
    "awsdns-03.co.uk",
    "awsdns-04.co.uk",
    "domaincontrol.com",
    "googledomains.com",
    "google.com",
    "azure-dns.com",
    "azure-dns.net",
    "azure-dns.org",
    "azure-dns.info",
    "dnsimple.com",
    "gandi.net",
    "registrar-servers.com",
    "dynect.net",
    "ultradns.com",
    "ultradns.net",
    "ultradns.org",
    "ultradns.biz",
    "ultradns.info",
    "nsone.net",
    "hover.com",
    "name.com",
    "nic.ru",
    "yandex.net",
    "he.net",
    "afraid.org",
    "digitalocean.com",
    "linode.com",
    "akam.net",
    "akamai.net",
    "akamaiedge.net",
    "akamaistream.net",
    "edgekey.net",
    "edgesuite.net",
    "dns.com",
    "dnsmadeeasy.com",
    "easydns.com",
    "worldnic.com",
    "networksolutions.com",
    "markmonitor.com",
    "cscdns.net",
    "cscglobal.com",
    "verisign-grs.com",
    "wixdns.net",
    "squarespacedns.com",
    "shopifydns.com",
    "webflowdns.com",
    "bluehost.com",
    "hostgator.com",
    "dreamhost.com",
})

TWO_PART_TLDS = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "net.za",
    "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn",
    "com.mx", "com.ar", "com.sg", "com.hk",
    "com.tw", "com.tr",
    "co.in", "net.in", "org.in",
    "com.pk", "com.my",
})

LEGAL_LINK_PHRASES = (
    ("impressum", "imprint"),
    ("imprint", "imprint"),
    ("mentions legales", "imprint"),
    ("mentions légales", "imprint"),
    ("modern slavery", "imprint"),
    ("privacy policy", "privacy"),
    ("privacy notice", "privacy"),
    ("privacy statement", "privacy"),
    ("privacy", "privacy"),
    ("terms of service", "terms"),
    ("terms of use", "terms"),
    ("terms and conditions", "terms"),
    ("terms", "terms"),
    ("legal notices", "legal_other"),
    ("legal notice", "legal_other"),
    ("legal", "legal_other"),
    ("cookie policy", "legal_other"),
    ("cookie notice", "legal_other"),
    ("accessibility statement", "legal_other"),
    ("do not sell", "legal_other"),
)

ANCHOR_PATTERN = re.compile(
    r"<a\b[^>]*?\bhref\s*=\s*['\"]([^'\"]+)['\"][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
ANCHOR_TEXT_CLEAN = re.compile(r"<[^>]+>")


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


def _registrable_root(host: str) -> str:
    if not host:
        return ""
    value = host.strip().lower()
    if "://" in value:
        value = urlparse(value).netloc
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split(":")[0].rstrip(".")
    if value.startswith("www."):
        value = value[4:]
    if not value or "." not in value:
        return ""
    parts = value.split(".")
    if len(parts) < 2:
        return ""
    last_two = ".".join(parts[-2:])
    if len(parts) >= 3:
        last_three = ".".join(parts[-3:])
        if last_two in TWO_PART_TLDS:
            return last_three
    return last_two


def _is_shared_dns_provider(root: str) -> bool:
    return root in SHARED_DNS_PROVIDERS


def _nameserver_evidence(
    company_name: str,
    candidates: list[str],
    ownership: OwnershipRecord,
    input_domain: str,
) -> Evidence | None:
    if not ownership.nameservers:
        return None
    input_root = _registrable_root(input_domain)
    candidate_roots: list[str] = []
    for ns in ownership.nameservers:
        root = _registrable_root(ns)
        if not root:
            continue
        if root == input_root:
            continue
        if _is_shared_dns_provider(root):
            continue
        candidate_roots.append(root)
    candidate_roots = list(dict.fromkeys(candidate_roots))
    if not candidate_roots:
        return None
    for root in candidate_roots:
        for candidate in candidates:
            if _matches_candidate(root, candidate):
                ns_list = ", ".join(ownership.nameservers[:4])
                snippet = f"{input_domain} nameservers [{ns_list}] → {root}"
                return Evidence(
                    source_type="nameserver_root_match",
                    source_url="",
                    snippet=snippet,
                    matched_text=root,
                    score=EVIDENCE_WEIGHTS["nameserver_root_match"],
                    candidate_company=company_name,
                )
    return None


def _clean_anchor_text(raw: str) -> str:
    stripped = ANCHOR_TEXT_CLEAN.sub(" ", raw)
    collapsed = re.sub(r"\s+", " ", unescape(stripped)).strip().lower()
    return collapsed


def _classify_anchor(text: str) -> str:
    if not text or len(text) > 80:
        return ""
    for phrase, kind in LEGAL_LINK_PHRASES:
        if phrase in text:
            return kind
    return ""


def _iter_cross_domain_legal_links(
    html: str,
    base_url: str,
    input_root: str,
) -> list[tuple[str, str, str, str]]:
    """Yields (kind, anchor_text, destination_root, absolute_url) for cross-domain legal links."""
    if not html or not input_root:
        return []
    results: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in ANCHOR_PATTERN.finditer(html):
        href = match.group(1).strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        text = _clean_anchor_text(match.group(2))
        kind = _classify_anchor(text)
        if not kind:
            continue
        absolute = urljoin(base_url or "", href)
        destination_root = _registrable_root(absolute)
        if not destination_root or destination_root == input_root:
            continue
        key = (kind, destination_root)
        if key in seen:
            continue
        seen.add(key)
        results.append((kind, text, destination_root, absolute))
    return results


def _cross_domain_legal_evidence(
    company_name: str,
    candidates: list[str],
    crawl: CrawlRecord,
) -> list[Evidence]:
    if not crawl.pages:
        return []
    input_root = _registrable_root(crawl.requested_domain)
    if not input_root:
        return []
    evidence: list[Evidence] = []
    seen_kinds: set[str] = set()
    for label, html in crawl.pages.items():
        base_url = crawl.page_urls.get(label, "") or crawl.final_url
        for kind, anchor_text, destination_root, absolute in _iter_cross_domain_legal_links(html, base_url, input_root):
            if kind in seen_kinds:
                continue
            for candidate in candidates:
                if _matches_candidate(destination_root, candidate):
                    weight_key = f"cross_domain_{kind}"
                    score = EVIDENCE_WEIGHTS.get(weight_key, EVIDENCE_WEIGHTS["cross_domain_legal_other"])
                    snippet = f"{crawl.requested_domain} '{anchor_text}' → {destination_root}"
                    evidence.append(
                        Evidence(
                            source_type=weight_key,
                            source_url=absolute,
                            snippet=snippet,
                            matched_text=destination_root,
                            score=score,
                            candidate_company=company_name,
                        )
                    )
                    seen_kinds.add(kind)
                    break
    return evidence


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

    ns_hit = _nameserver_evidence(company_name, candidates, ownership, crawl.requested_domain)
    if ns_hit is not None:
        evidence_items.append(ns_hit)

    for cross_hit in _cross_domain_legal_evidence(company_name, candidates, crawl):
        evidence_items.append(cross_hit)

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
