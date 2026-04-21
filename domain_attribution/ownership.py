from __future__ import annotations

import re
import socket
from functools import lru_cache
from urllib.parse import urlparse

import requests

from domain_attribution.models import OwnershipRecord

IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK_URL = "https://rdap.org/domain/{domain}"
REQUEST_TIMEOUT_SECONDS = 12
WHOIS_TIMEOUT_SECONDS = 10
WHOIS_PORT = 43
WHOIS_IANA_SERVER = "whois.iana.org"
WHOIS_WEB_URL = "https://www.whois.com/whois/{domain}"
WHOIS_DIRECT_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "ai": "whois.nic.ai",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "nl": "whois.domain-registry.nl",
    "eu": "whois.eu",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "es": "whois.nic.es",
    "it": "whois.nic.it",
    "in": "whois.registry.in",
    "br": "whois.registro.br",
    "ru": "whois.tcinet.ru",
    "us": "whois.nic.us",
    "me": "whois.nic.me",
    "tv": "whois.nic.tv",
    "cc": "whois.nic.cc",
    "biz": "whois.biz",
    "info": "whois.afilias.net",
    "xyz": "whois.nic.xyz",
    "gg": "whois.gg",
    "je": "whois.je",
}
WHOIS_FIELD_PATTERNS = (
    ("registrant_organization", re.compile(r"^\s*Registrant Organization:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_name", re.compile(r"^\s*Registrant Name:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_contact_organization", re.compile(r"^\s*Registrant Contact Organization:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_contact_name", re.compile(r"^\s*Registrant Contact Name:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_contact", re.compile(r"^\s*Registrant Contact:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_block_nominet", re.compile(r"^\s*Registrant:\s*\n\s+(\S.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_jprs", re.compile(r"^\s*\[?(?:Registrant|登録者名|組織名)\]?\s*[:.]?\s*(?:\[Organization\])?\s+(.+)$", re.MULTILINE)),
    ("registrant_jprs_g", re.compile(r"^g\.\s*\[Organization\]\s+(.+)$", re.MULTILINE)),
    ("registrant_br", re.compile(r"^\s*(?:responsible|owner):\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_fr_holder", re.compile(r"^\s*holder-c:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("org_name", re.compile(r"^\s*OrgName:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("org_name_alt", re.compile(r"^\s*org-name:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("organisation", re.compile(r"^\s*organisation:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("organization_ripe", re.compile(r"^\s*org:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("descr", re.compile(r"^\s*descr:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("owner", re.compile(r"^\s*owner:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
)
WHOIS_REFER_PATTERN = re.compile(r"^\s*(Registrar WHOIS Server|refer):\s*(.+)$", re.IGNORECASE | re.MULTILINE)
WHOIS_WEB_CONTACT_ORG_PATTERN = re.compile(
    r"Registrant Contact</div><div class=\"df-row\"><div class=\"df-label\">Organization:</div><div class=\"df-value\">([^<]+)</div>",
    re.IGNORECASE,
)
WHOIS_WEB_CONTACT_NAME_PATTERN = re.compile(
    r"Registrant Contact</div><div class=\"df-row\"><div class=\"df-label\">Name:</div><div class=\"df-value\">([^<]+)</div>",
    re.IGNORECASE,
)
PRIVACY_TOKENS = ("privacy", "redacted", "proxy", "whoisguard", "contact privacy", "domains by proxy")
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"})
    return session


@lru_cache(maxsize=1)
def _load_bootstrap() -> dict:
    response = _session().get(IANA_RDAP_BOOTSTRAP_URL, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def _bootstrap_rdap_url(domain: str) -> str:
    bootstrap = _load_bootstrap()
    labels = domain.lower().split(".")
    if len(labels) < 2:
        return RDAP_FALLBACK_URL.format(domain=domain)
    tld = labels[-1]
    for suffixes, urls in bootstrap.get("services", []):
        if tld in suffixes and urls:
            base_url = urls[0].rstrip("/")
            return f"{base_url}/domain/{domain}"
    return RDAP_FALLBACK_URL.format(domain=domain)


def _extract_entity_name(entity: dict) -> str:
    vcard_array = entity.get("vcardArray", [])
    if len(vcard_array) < 2:
        return ""
    for item in vcard_array[1]:
        if item and item[0] == "fn" and len(item) >= 4 and isinstance(item[3], str):
            return item[3].strip()
    return ""


def _extract_org_name(payload: dict) -> tuple[str, str, str]:
    entities = payload.get("entities", [])
    registrant_name = ""
    registrar_name = ""
    fallback_name = ""
    privacy_hit = False
    for entity in entities:
        name = _extract_entity_name(entity)
        roles = {role.lower() for role in entity.get("roles", [])}
        if not name:
            continue
        lowered = name.lower()
        if any(token in lowered for token in PRIVACY_TOKENS):
            privacy_hit = True
        if "registrant" in roles and not registrant_name:
            registrant_name = name
        elif "registrar" in roles and not registrar_name:
            registrar_name = name
        if not fallback_name:
            fallback_name = name
    if registrant_name:
        return registrant_name, "privacy" if privacy_hit else "", "registrant"
    if registrar_name:
        return registrar_name, "privacy" if privacy_hit else "", "registrar"
    return fallback_name, "privacy" if privacy_hit else "", "unknown"


def _extract_rdap_response_url(response: requests.Response) -> str:
    parsed = urlparse(response.url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _whois_query_for(server: str, domain: str) -> str:
    if server == "whois.jprs.jp":
        return f"{domain}/e"
    if server == "whois.verisign-grs.com":
        return f"domain {domain}"
    return domain


def _query_whois(server: str, query: str) -> str:
    with socket.create_connection((server, WHOIS_PORT), timeout=WHOIS_TIMEOUT_SECONDS) as sock:
        sock.sendall(f"{query}\r\n".encode("utf-8"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _detect_whois_server(domain: str) -> str:
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in WHOIS_DIRECT_SERVERS:
        return WHOIS_DIRECT_SERVERS[tld]
    response = _query_whois(WHOIS_IANA_SERVER, tld)
    for line in response.splitlines():
        if line.lower().startswith("whois:"):
            return line.split(":", 1)[1].strip()
    return ""


def _extract_whois_value(raw_text: str) -> tuple[str, str]:
    for label, pattern in WHOIS_FIELD_PATTERNS:
        match = pattern.search(raw_text)
        if match:
            value = match.group(1).strip()
            if value:
                return value, label
    return "", ""


def _extract_whois_refer(raw_text: str) -> str:
    match = WHOIS_REFER_PATTERN.search(raw_text)
    if not match:
        return ""
    return match.group(2).strip().removeprefix("whois://")


def _is_privacy_name(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in PRIVACY_TOKENS)


def _excerpt(text: str, limit: int = 280) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    return collapsed[:limit]


def _should_run_whois(rdap_org: str, entity_name: str, rdap_role: str, privacy_protected: bool) -> bool:
    if privacy_protected:
        return True
    if rdap_role != "registrant":
        return True
    if not rdap_org and not entity_name:
        return True
    if _is_privacy_name(rdap_org) or _is_privacy_name(entity_name):
        return True
    return False


def _lookup_whois(domain: str) -> tuple[str, str, str, str, list[str], bool]:
    notes: list[str] = []
    try:
        server = _detect_whois_server(domain)
    except OSError as exc:
        return "", "", "", "", [f"WHOIS server discovery failed: {exc.__class__.__name__}"], False

    if not server:
        return "", "", "", "", ["WHOIS server discovery returned no server"], False

    try:
        raw_text = _query_whois(server, _whois_query_for(server, domain))
    except OSError as exc:
        return "", "", server, "", [f"WHOIS lookup failed: {exc.__class__.__name__}"], False

    refer_server = _extract_whois_refer(raw_text)
    if refer_server and refer_server.lower() != server.lower():
        try:
            referred_text = _query_whois(refer_server, _whois_query_for(refer_server, domain))
            if len(referred_text) > len(raw_text):
                raw_text = referred_text
                server = refer_server
                notes.append(f"WHOIS referral followed to {refer_server}")
        except OSError:
            notes.append(f"WHOIS referral to {refer_server} failed")

    registrant, field_label = _extract_whois_value(raw_text)
    privacy_protected = _is_privacy_name(registrant) if registrant else False
    if not registrant:
        notes.append("WHOIS returned no registrant organization, name, or contact field")
    elif field_label.startswith("registrant_contact"):
        notes.append(f"WHOIS matched contact field: {field_label}")
    if privacy_protected:
        notes.append("WHOIS suggests privacy-protected registration")
    return registrant, field_label, server, _excerpt(raw_text), notes, privacy_protected


def _lookup_whois_web(domain: str) -> tuple[str, str, str, list[str], bool]:
    notes: list[str] = []
    try:
        response = _session().get(WHOIS_WEB_URL.format(domain=domain), timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as exc:
        return "", "", "", [f"WHOIS web fallback failed: {exc.__class__.__name__}"], False

    html = response.text
    match = WHOIS_WEB_CONTACT_ORG_PATTERN.search(html)
    field_label = "whois_web_registrant_contact_organization"
    if not match:
        match = WHOIS_WEB_CONTACT_NAME_PATTERN.search(html)
        field_label = "whois_web_registrant_contact_name"
    if not match:
        return "", "", _excerpt(html), ["WHOIS web fallback returned no registrant contact field"], False

    registrant = match.group(1).strip()
    privacy_protected = _is_privacy_name(registrant)
    if privacy_protected:
        notes.append("WHOIS web fallback suggests privacy-protected registration")
    return registrant, field_label, _excerpt(html), notes, privacy_protected


@lru_cache(maxsize=512)
def lookup_ownership(domain: str) -> OwnershipRecord:
    notes: list[str] = []
    rdap_org = ""
    rdap_entity_name = ""
    rdap_source_url = ""
    rdap_role = ""
    is_privacy_protected = False

    try:
        rdap_url = _bootstrap_rdap_url(domain)
    except requests.RequestException as exc:
        notes.append(f"RDAP bootstrap lookup failed: {exc.__class__.__name__}")
        rdap_url = RDAP_FALLBACK_URL.format(domain=domain)

    try:
        response = _session().get(rdap_url, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
        rdap_entity_name, privacy_note, rdap_role = _extract_org_name(payload)
        rdap_org = payload.get("name", "").strip() or rdap_entity_name
        rdap_source_url = _extract_rdap_response_url(response)
        if not rdap_org:
            notes.append("RDAP returned no clear registrant or entity name")
        elif rdap_role == "registrar":
            notes.append("RDAP returned registrar data, not registrant data")
        if privacy_note:
            is_privacy_protected = True
            notes.append("RDAP suggests privacy-protected registration")
    except requests.exceptions.Timeout:
        notes.append("RDAP lookup timed out")
    except requests.RequestException as exc:
        notes.append(f"RDAP lookup failed: {exc.__class__.__name__}")
    except ValueError:
        notes.append("RDAP returned unreadable JSON")

    whois_registrant = ""
    whois_field_label = ""
    whois_source = ""
    whois_raw_excerpt = ""
    if _should_run_whois(rdap_org, rdap_entity_name, rdap_role, is_privacy_protected):
        registrant, field_label, source, excerpt, whois_notes, whois_privacy = _lookup_whois(domain)
        whois_registrant = registrant
        whois_field_label = field_label
        whois_source = source
        whois_raw_excerpt = excerpt
        notes.extend(whois_notes)
        is_privacy_protected = is_privacy_protected or whois_privacy
        if not whois_registrant:
            web_registrant, web_field_label, web_excerpt, web_notes, web_privacy = _lookup_whois_web(domain)
            if web_registrant:
                whois_registrant = web_registrant
                whois_field_label = web_field_label
                whois_source = "www.whois.com"
                whois_raw_excerpt = web_excerpt
            notes.extend(web_notes)
            is_privacy_protected = is_privacy_protected or web_privacy
    else:
        notes.append("WHOIS fallback skipped because RDAP returned usable ownership data")

    return OwnershipRecord(
        rdap_org=rdap_org,
        rdap_source_url=rdap_source_url,
        rdap_entity_name=rdap_entity_name,
        rdap_role=rdap_role,
        whois_registrant=whois_registrant,
        whois_field_label=whois_field_label,
        whois_source=whois_source,
        whois_raw_excerpt=whois_raw_excerpt,
        is_privacy_protected=is_privacy_protected,
        status_notes=notes or ["Ownership lookup completed"],
    )
