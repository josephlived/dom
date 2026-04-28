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

WHOIS_TEXT_FALLBACK_PATTERNS = (
    ("registrant_organization", re.compile(r"^\s*Registrant Organization:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_name", re.compile(r"^\s*Registrant Name:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_contact_organization", re.compile(r"^\s*Registrant Contact Organization:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_contact_name", re.compile(r"^\s*Registrant Contact Name:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_block_nominet", re.compile(r"^\s*Registrant:\s*\n\s+(\S.+)$", re.IGNORECASE | re.MULTILINE)),
    ("registrant_jprs_g", re.compile(r"^g\.\s*\[Organization\]\s+(.+)$", re.MULTILINE)),
    ("registrant_jprs", re.compile(r"^\s*\[?(?:Registrant|登録者名|組織名)\]?\s*[:.]?\s*(?:\[Organization\])?\s+(.+)$", re.MULTILINE)),
    ("registrant_br_owner", re.compile(r"^\s*(?:responsible|owner):\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("org_name", re.compile(r"^\s*OrgName:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("org_name_alt", re.compile(r"^\s*org-name:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("organisation", re.compile(r"^\s*organisation:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("organization_ripe", re.compile(r"^\s*org:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
    ("descr", re.compile(r"^\s*descr:\s*(.+)$", re.IGNORECASE | re.MULTILINE)),
)

# Used only for source-column labeling when python-whois doesn't expose the answering
# server. Limited to thick TLDs where the registry itself holds the data, so the
# inference is reliable. Thin TLDs (.com/.net/.org) are intentionally excluded since
# the actual source there depends on the registrar's WHOIS server, not the registry.
TLD_REGISTRY_HINTS = {
    "de": "whois.denic.de",
    "uk": "whois.nic.uk",
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
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "ai": "whois.nic.ai",
    "ch": "whois.nic.ch",
    "at": "whois.nic.at",
    "be": "whois.dns.be",
    "pl": "whois.dns.pl",
    "se": "whois.iis.se",
    "no": "whois.norid.no",
    "dk": "whois.dk-hostmaster.dk",
    "fi": "whois.fi",
    "nz": "whois.srs.net.nz",
    "za": "whois.registry.net.za",
    "tv": "whois.nic.tv",
    "cc": "whois.nic.cc",
    "biz": "whois.biz",
    "info": "whois.afilias.net",
    "xyz": "whois.nic.xyz",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "gg": "whois.gg",
    "je": "whois.je",
}


def _infer_whois_server(domain: str) -> str:
    tld = domain.rsplit(".", 1)[-1].lower()
    return TLD_REGISTRY_HINTS.get(tld, "")


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


def _extract_registrar_rdap_referral(payload: dict) -> str:
    """Find an RDAP referral URL inside a registrar entity's links list."""
    for entity in payload.get("entities", []) or []:
        roles = {str(role).lower() for role in entity.get("roles", []) or []}
        if "registrar" not in roles:
            continue
        for link in entity.get("links", []) or []:
            if not isinstance(link, dict):
                continue
            href = (link.get("href") or "").strip()
            if not href.lower().startswith("https://"):
                continue
            rel = (link.get("rel") or "").lower()
            if rel in ("self", "related", "about", ""):
                return href
    return ""


def _follow_rdap_registrar_referral(
    referral_url: str,
    session: requests.Session,
) -> tuple[dict | None, str]:
    """Query the registrar's RDAP server. Returns (payload_or_none, error_message)."""
    try:
        response = session.get(referral_url, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json(), ""
    except requests.exceptions.Timeout:
        return None, "timeout"
    except requests.RequestException as exc:
        return None, exc.__class__.__name__
    except ValueError:
        return None, "unreadable JSON"


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


def _extract_from_raw_text(raw_text: str) -> tuple[str, str]:
    for label, pattern in WHOIS_TEXT_FALLBACK_PATTERNS:
        match = pattern.search(raw_text)
        if not match:
            continue
        value = match.group(1).strip()
        if not value:
            continue
        if _is_privacy_name(value):
            continue
        if value.lower() in {"redacted", "redacted for privacy", "not disclosed", "n/a", "-"}:
            continue
        return value, label
    return "", ""


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
    else:
        inferred = _infer_whois_server(domain)
        if inferred:
            source = f"python-whois ({inferred}, inferred from .{domain.rsplit('.', 1)[-1].lower()})"

    raw_text = ""
    text_attr = getattr(record, "text", None)
    if isinstance(text_attr, str):
        raw_text = text_attr
    elif isinstance(text_attr, list):
        raw_text = "\n".join(str(item) for item in text_attr if item)
    elif text_attr is not None:
        raw_text = str(text_attr)

    if not raw and raw_text:
        text_value, text_label = _extract_from_raw_text(raw_text)
        if text_value:
            raw = text_value
            field_label = f"raw_text_{text_label}"
            notes.append(f"python-whois did not expose registrant; recovered via raw text ({text_label})")

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

    registry_payload: dict | None = None
    try:
        response = _session().get(rdap_url, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        registry_payload = response.json()
        rdap_entity_name, privacy_note, rdap_role = _extract_org_name(registry_payload)
        rdap_org = registry_payload.get("name", "").strip() or rdap_entity_name
        rdap_source_url = _extract_rdap_response_url(response)
        nameservers = _extract_rdap_nameservers(registry_payload)
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

    if registry_payload is not None and rdap_role == "registrar":
        referral_url = _extract_registrar_rdap_referral(registry_payload)
        if not referral_url:
            notes.append("No registrar RDAP referral link found in registry response")
        else:
            registrar_payload, error = _follow_rdap_registrar_referral(referral_url, _session())
            if registrar_payload is None:
                notes.append(f"Followed registrar RDAP referral to {referral_url} but request failed ({error})")
            else:
                followed_entity_name, followed_privacy, followed_role = _extract_org_name(registrar_payload)
                followed_org = registrar_payload.get("name", "").strip() or followed_entity_name
                if followed_role == "registrant" and followed_org and not _is_privacy_name(followed_org):
                    rdap_org = followed_org
                    rdap_entity_name = followed_entity_name
                    rdap_role = followed_role
                    rdap_source_url = referral_url
                    if followed_privacy:
                        is_privacy_protected = True
                    registrar_nameservers = _extract_rdap_nameservers(registrar_payload)
                    if registrar_nameservers:
                        nameservers = _dedupe_preserve_order(nameservers + registrar_nameservers)
                    notes.append(f"Followed registrar RDAP referral to {referral_url} and recovered registrant data")
                else:
                    notes.append(f"Followed registrar RDAP referral to {referral_url} but registrant was redacted or absent")

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

    notes.append(f"Cross-check at https://www.whois.com/whois/{domain}")

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
