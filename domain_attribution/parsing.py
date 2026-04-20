from __future__ import annotations

import re
from urllib.parse import urlparse

from domain_attribution.models import Company

COMPANY_SUFFIXES = {
    "inc",
    "inc.",
    "llc",
    "l.l.c",
    "ltd",
    "ltd.",
    "limited",
    "corp",
    "corp.",
    "corporation",
    "company",
    "co",
    "co.",
    "holdings",
    "group",
}


def normalize_text(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9\s]", " ", value.lower())
    tokens = [token for token in cleaned.split() if token and token not in COMPANY_SUFFIXES]
    return " ".join(tokens)


def parse_companies(raw_text: str) -> list[Company]:
    companies: list[Company] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = [part.strip() for part in stripped.split("|") if part.strip()]
        if not parts:
            continue
        name = parts[0]
        aliases = parts[1:]
        normalized_names = []
        for part in parts:
            normalized = normalize_text(part)
            if normalized and normalized not in normalized_names:
                normalized_names.append(normalized)
        companies.append(Company(name=name, aliases=aliases, normalized_names=normalized_names))
    return companies


def normalize_domain(raw_value: str) -> str:
    stripped = raw_value.strip()
    if not stripped:
        return ""
    if "://" not in stripped:
        stripped = f"https://{stripped}"
    parsed = urlparse(stripped)
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host.split(":")[0]


def parse_domains(raw_text: str) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for line in raw_text.splitlines():
        domain = normalize_domain(line)
        if domain and domain not in seen:
            domains.append(domain)
            seen.add(domain)
    return domains
