from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import urlparse

import requests

from domain_attribution.models import OwnershipRecord

IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK_URL = "https://rdap.org/domain/{domain}"
REQUEST_TIMEOUT_SECONDS = 12
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


def _extract_rdap_nameservers(payload: dict) -> list[str]:
    servers: list[str] = []
    for entry in payload.get("nameservers", []) or []:
        name = ""
        if isinstance(entry, dict):
            name = (entry.get("ldhName") or entry.get("unicodeName") or "").strip()
        if name:
            servers.append(name.lower().rstrip("."))
    return _dedupe_preserve_order(servers)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _extract_rdap_response_url(response: requests.Response) -> str:
    parsed = urlparse(response.url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _is_privacy_name(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in PRIVACY_TOKENS)


def _excerpt(text: str, limit: int = 280) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    return collapsed[:limit]


def _should_run_whois(rdap_org: str, entity_name: str, rdap_role: str, privacy_protected: bool, have_nameservers: bool) -> bool:
    if not have_nameservers:
        return True
    if privacy_protected:
        return True
    if rdap_role != "registrant":
        return True
    if not rdap_org and not entity_name:
        return True
    if _is_privacy_name(rdap_org) or _is_privacy_name(entity_name):
        return True
    return False


def _coerce_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    try:
        return [str(item).strip() for item in value if str(item).strip()]
    except TypeError:
        return []


def _first_nonempty(*values) -> str:
    for value in values:
        if not value:
            continue
        if isinstance(value, list):
            for item in value:
                text = str(item).strip()
                if text:
                    return text
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _lookup_whois(domain: str) -> tuple[str, str, str, str, list[str], list[str], bool]:
    """Query WHOIS via python-whois. Returns registrant, field_label, source, excerpt, nameservers, notes, privacy."""
    notes: list[str] = []
    try:
        import whois as pywhois
    except ImportError:
        notes.append("python-whois not installed; skipping WHOIS fallback")
        return "", "", "", "", [], notes, False

    try:
        record = pywhois.whois(domain)
    except Exception as exc:
        notes.append(f"WHOIS lookup failed: {exc.__class__.__name__}")
        return "", "", "", "", [], notes, False

    registrant = _first_nonempty(
        getattr(record, "org", None),
        getattr(record, "registrant_org", None),
        getattr(record, "registrant_organization", None),
        getattr(record, "registrant_name", None),
        getattr(record, "name", None),
    )

    if registrant:
        raw = registrant
        if getattr(record, "org", None):
            field_label = "registrant_organization"
        elif getattr(record, "registrant_name", None) or getattr(record, "name", None):
            field_label = "registrant_name"
        else:
            field_label = "registrant_organization"
    else:
        raw = ""
        field_label = ""

    source = "python-whois"
    whois_server = _first_nonempty(getattr(record, "whois_server", None), getattr(record, "registrar_whois", None))
    if whois_server:
        source = f"python-whois ({whois_server})"

    raw_text = ""
    text_attr = getattr(record, "text", None)
    if isinstance(text_attr, str):
        raw_text = text_attr
    elif text_attr is not None:
        raw_text = str(text_attr)

    nameservers = _dedupe_preserve_order(
        [ns.lower().rstrip(".") for ns in _coerce_list(getattr(record, "name_servers", None))]
    )

    privacy_protected = _is_privacy_name(raw) if raw else False
    if not raw:
        notes.append("WHOIS returned no registrant organization or name")
    if privacy_protected:
        notes.append("WHOIS suggests privacy-protected registration")

    return raw, field_label, source, _excerpt(raw_text), nameservers, notes, privacy_protected


@lru_cache(maxsize=512)
def lookup_ownership(domain: str) -> OwnershipRecord:
    notes: list[str] = []
    rdap_org = ""
    rdap_entity_name = ""
    rdap_source_url = ""
    rdap_role = ""
    is_privacy_protected = False
    nameservers: list[str] = []

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
        nameservers = _extract_rdap_nameservers(payload)
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
    if _should_run_whois(rdap_org, rdap_entity_name, rdap_role, is_privacy_protected, bool(nameservers)):
        registrant, field_label, source, excerpt, whois_nameservers, whois_notes, whois_privacy = _lookup_whois(domain)
        whois_registrant = registrant
        whois_field_label = field_label
        whois_source = source
        whois_raw_excerpt = excerpt
        notes.extend(whois_notes)
        is_privacy_protected = is_privacy_protected or whois_privacy
        if whois_nameservers:
            nameservers = _dedupe_preserve_order(nameservers + whois_nameservers)
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
        nameservers=nameservers,
        status_notes=notes or ["Ownership lookup completed"],
    )
