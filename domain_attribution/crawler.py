from __future__ import annotations

import atexit
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
from functools import lru_cache
from html import unescape
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests

from domain_attribution.models import CrawlRecord
from domain_attribution.parsing import normalize_domain

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_PATHS = ("", "/about", "/privacy", "/terms", "/legal", "/imprint", "/impressum", "/contact")
BROWSER_NAV_TIMEOUT_MS = 15000
BROWSER_INSTALL_TIMEOUT_SECONDS = 240
CERT_TIMEOUT_SECONDS = 6
_BROWSER_LOCK = threading.Lock()
_BROWSER_READY: bool | None = None
_BROWSER_THREAD: threading.Thread | None = None
_BROWSER_REQUESTS: "queue.Queue[tuple[str, queue.Queue[str]] | None]" = queue.Queue()
_BROWSER_WORKER_OK = True
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
META_REFRESH_PATTERN = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\']+)["\']',
    re.IGNORECASE,
)
CANONICAL_PATTERN = re.compile(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
OG_URL_PATTERN = re.compile(r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
JS_REDIRECT_PATTERNS = (
    re.compile(r"window\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"location\.replace\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE),
)
PARKED_PATTERNS = (
    (re.compile(r"\bbuy this domain\b", re.IGNORECASE), "buy this domain"),
    (re.compile(r"\bdomain (?:is|may be) for sale\b", re.IGNORECASE), "domain for sale"),
    (re.compile(r"\bthis domain is for sale\b", re.IGNORECASE), "domain for sale"),
    (re.compile(r"\bparked free\b", re.IGNORECASE), "parked free"),
    (re.compile(r"\bsedo\b", re.IGNORECASE), "sedo"),
    (re.compile(r"\bafternic\b", re.IGNORECASE), "afternic"),
    (re.compile(r"\bdan\.com\b", re.IGNORECASE), "dan.com"),
    (re.compile(r"\bundeveloped\b", re.IGNORECASE), "undeveloped"),
    (re.compile(r"\bparkingcrew\b", re.IGNORECASE), "parkingcrew"),
    (re.compile(r"\babove\.com\b", re.IGNORECASE), "above.com"),
    (re.compile(r"\bhugedomains\b", re.IGNORECASE), "hugedomains"),
    (re.compile(r"\bbodis\b", re.IGNORECASE), "bodis"),
    (re.compile(r"\bnamebright\b", re.IGNORECASE), "namebright"),
    (re.compile(r"\bdomain[^a-z]{0,3}parking\b", re.IGNORECASE), "generic parking"),
    (re.compile(r"\bmake an offer\b.*\b(?:this domain|domain name)\b", re.IGNORECASE), "make an offer"),
    (re.compile(r"\binterested in this domain\??\b", re.IGNORECASE), "interested in this domain"),
)


def _fetch(session: requests.Session, url: str) -> tuple[str, str]:
    response = session.get(url, timeout=DEFAULT_TIMEOUT_SECONDS, allow_redirects=True)
    response.raise_for_status()
    return response.url, response.text


def _install_chromium() -> bool:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True,
            text=True,
            timeout=BROWSER_INSTALL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _shutdown_browser_worker() -> None:
    _BROWSER_REQUESTS.put(None)


def _browser_worker_loop() -> None:
    global _BROWSER_WORKER_OK
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        _BROWSER_WORKER_OK = False
        _drain_browser_queue()
        return
    for attempt in range(2):
        try:
            pw = sync_playwright().start()
        except Exception:
            if attempt == 0 and _install_chromium():
                continue
            _BROWSER_WORKER_OK = False
            _drain_browser_queue()
            return
        break
    try:
        try:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
        except Exception as exc:
            message = str(exc).lower()
            if ("executable doesn't exist" in message or "playwright install" in message) and _install_chromium():
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
            else:
                _BROWSER_WORKER_OK = False
                _drain_browser_queue()
                return
        try:
            while True:
                item = _BROWSER_REQUESTS.get()
                if item is None:
                    break
                url, response_queue = item
                html = ""
                try:
                    context = browser.new_context(user_agent=USER_AGENT)
                    try:
                        page = context.new_page()
                        try:
                            page.goto(url, wait_until="domcontentloaded", timeout=BROWSER_NAV_TIMEOUT_MS)
                            html = page.content()
                        except (PlaywrightTimeoutError, PlaywrightError):
                            html = ""
                        finally:
                            page.close()
                    finally:
                        context.close()
                except Exception:
                    html = ""
                response_queue.put(html)
        finally:
            try:
                browser.close()
            except Exception:
                pass
    finally:
        try:
            pw.stop()
        except Exception:
            pass


def _drain_browser_queue() -> None:
    while True:
        try:
            item = _BROWSER_REQUESTS.get_nowait()
        except queue.Empty:
            return
        if item is None:
            return
        _, response_queue = item
        response_queue.put("")


def _ensure_browser_thread() -> bool:
    global _BROWSER_THREAD, _BROWSER_READY
    if _BROWSER_READY is False:
        return False
    with _BROWSER_LOCK:
        if _BROWSER_THREAD and _BROWSER_THREAD.is_alive():
            return _BROWSER_WORKER_OK
        try:
            import playwright.sync_api  # noqa: F401
        except ImportError:
            _BROWSER_READY = False
            return False
        _BROWSER_THREAD = threading.Thread(target=_browser_worker_loop, daemon=True, name="playwright-worker")
        _BROWSER_THREAD.start()
        atexit.register(_shutdown_browser_worker)
        _BROWSER_READY = True
        return True


def _browser_dump(url: str) -> str:
    if not _ensure_browser_thread():
        return ""
    response_queue: queue.Queue[str] = queue.Queue(maxsize=1)
    _BROWSER_REQUESTS.put((url, response_queue))
    try:
        return response_queue.get(timeout=(BROWSER_NAV_TIMEOUT_MS / 1000) + 10)
    except queue.Empty:
        return ""


def _probe_redirect(session: requests.Session, domain: str) -> tuple[str, str, str]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = session.get(url, timeout=DEFAULT_TIMEOUT_SECONDS, allow_redirects=True, stream=True)
            response.close()
            final_url = response.url
            final_domain = normalize_domain(final_url)
            if final_domain and final_domain != domain:
                return final_url, final_domain, "confirmed"
            if response.ok:
                return final_url, final_domain, "none"
            if response.history:
                return final_url, final_domain, "partial"
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.RequestException:
            continue
    return "", "", "none"


def _extract_redirect_hint(html: str, base_url: str, domain: str) -> tuple[str, str]:
    patterns = (
        ("meta_refresh", META_REFRESH_PATTERN),
        ("canonical", CANONICAL_PATTERN),
        ("og_url", OG_URL_PATTERN),
    )
    for label, pattern in patterns:
        match = pattern.search(html)
        if not match:
            continue
        candidate_url = urljoin(base_url, match.group(1).strip())
        candidate_domain = normalize_domain(candidate_url)
        if candidate_domain and candidate_domain != domain:
            return candidate_domain, label
    for pattern in JS_REDIRECT_PATTERNS:
        match = pattern.search(html)
        if not match:
            continue
        candidate_url = urljoin(base_url, match.group(1).strip())
        candidate_domain = normalize_domain(candidate_url)
        if candidate_domain and candidate_domain != domain:
            return candidate_domain, "js"
    return "", ""


def _clean_html(raw_text: str) -> str:
    without_scripts = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw_text)
    without_tags = re.sub(r"(?is)<[^>]+>", " ", without_scripts)
    collapsed = re.sub(r"\s+", " ", unescape(without_tags))
    return collapsed.strip()


def _detect_parked(html: str, final_url: str) -> tuple[bool, str]:
    corpus = f"{final_url} {_clean_html(html)}"
    for pattern, reason in PARKED_PATTERNS:
        if pattern.search(corpus):
            return True, reason
    return False, ""


def _rdn_value(seq: tuple, key: str) -> str:
    for rdn in seq:
        for attr_key, attr_value in rdn:
            if attr_key == key and attr_value:
                return str(attr_value).strip()
    return ""


def _fetch_tls_certificate(host: str) -> tuple[str, str, str, list[str]]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=CERT_TIMEOUT_SECONDS) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return "", "", "", []
    if not cert:
        return "", "", "", []
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    subject_org = _rdn_value(subject, "organizationName")
    subject_cn = _rdn_value(subject, "commonName")
    issuer_org = _rdn_value(issuer, "organizationName")
    sans: list[str] = []
    for entry in cert.get("subjectAltName", ()):
        if len(entry) >= 2 and entry[0] == "DNS":
            sans.append(entry[1])
    return subject_org, subject_cn, issuer_org, sans


def _browser_fallback(domain: str, final_url: str, redirect_target: str, redirect_signal: str) -> tuple[str, str, str, bool]:
    url = final_url or f"https://{domain}"
    html = _browser_dump(url)
    if not html:
        return "", redirect_target, redirect_signal, False
    hinted_domain, hinted_signal = _extract_redirect_hint(html, url, domain)
    if hinted_domain:
        redirect_target = hinted_domain
        redirect_signal = f"browser:{hinted_signal}"
    elif not redirect_signal:
        redirect_signal = "browser:none"
    return html, redirect_target, redirect_signal, True


@lru_cache(maxsize=512)
def crawl_domain(domain: str, extra_paths: tuple[str, ...] | None = None) -> CrawlRecord:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT})
    paths = extra_paths if extra_paths else DEFAULT_PATHS
    pages: dict[str, str] = {}
    page_urls: dict[str, str] = {}
    cert_subject_org, cert_subject_cn, cert_issuer_org, cert_sans = _fetch_tls_certificate(domain)
    probed_final_url, probed_final_domain, redirect_signal = _probe_redirect(session, domain)
    redirect_detected = bool(probed_final_domain and probed_final_domain != domain)
    redirect_target = probed_final_domain if redirect_detected else ""
    final_url = probed_final_url or f"https://{domain}"
    site_status = "not_requested"
    browser_fallback_used = False
    parked_detected = False
    parked_reason = ""

    try:
        fetch_url = probed_final_url or final_url
        final_url, homepage_text = _fetch(session, fetch_url)
        final_domain = normalize_domain(final_url)
        if final_domain and final_domain != domain:
            redirect_detected = True
            redirect_target = final_domain
            redirect_signal = "confirmed"
        elif not redirect_detected:
            hinted_domain, hinted_signal = _extract_redirect_hint(homepage_text, final_url, domain)
            if hinted_domain:
                redirect_detected = True
                redirect_target = hinted_domain
                redirect_signal = f"hinted:{hinted_signal}"
        parked_detected, parked_reason = _detect_parked(homepage_text, final_url)
        pages["homepage"] = homepage_text
        page_urls["homepage"] = final_url
        site_status = "parked" if parked_detected else "reachable"
    except requests.exceptions.Timeout:
        site_status = "timeout"
    except requests.exceptions.SSLError:
        site_status = "ssl_error"
    except requests.exceptions.ConnectionError:
        site_status = "connection_failed"
    except requests.RequestException:
        site_status = "blocked_or_unreachable"

    should_browser_fallback = site_status in {"timeout", "ssl_error", "connection_failed", "blocked_or_unreachable"} or (
        redirect_signal in {"partial", "none"} and not pages
    )
    if should_browser_fallback:
        browser_html, redirect_target, redirect_signal, browser_fallback_used = _browser_fallback(
            domain,
            final_url,
            redirect_target,
            redirect_signal,
        )
        if browser_html:
            pages["homepage_browser"] = browser_html
            page_urls["homepage_browser"] = final_url or f"https://{domain}"
            redirect_detected = bool(redirect_target)
            parked_detected, parked_reason = _detect_parked(browser_html, final_url)
            if parked_detected:
                site_status = "parked"
            elif site_status in {"timeout", "ssl_error", "connection_failed", "blocked_or_unreachable"}:
                site_status = "browser_rendered"

    if site_status in {"timeout", "ssl_error", "connection_failed", "blocked_or_unreachable"} and not pages:
        return CrawlRecord(
            requested_domain=domain,
            redirect_detected=redirect_detected,
            redirect_target=redirect_target,
            redirect_signal=redirect_signal,
            browser_fallback_used=browser_fallback_used,
            parked_detected=parked_detected,
            parked_reason=parked_reason,
            final_url=final_url,
            site_status=site_status,
            cert_subject_org=cert_subject_org,
            cert_subject_cn=cert_subject_cn,
            cert_issuer_org=cert_issuer_org,
            cert_sans=cert_sans,
        )

    crawl_base = final_url.rstrip("/")
    parsed_base = urlparse(crawl_base)
    base_root = f"{parsed_base.scheme}://{parsed_base.netloc}"
    for path in paths:
        if not path:
            continue
        label = path.strip("/").replace("-", "_") or "homepage"
        url = f"{base_root}{path}"
        try:
            fetched_url, page_text = _fetch(session, url)
        except requests.RequestException:
            continue
        pages[label] = page_text
        page_urls[label] = fetched_url

    return CrawlRecord(
        requested_domain=domain,
        redirect_detected=redirect_detected,
        redirect_target=redirect_target,
        redirect_signal=redirect_signal,
        browser_fallback_used=browser_fallback_used,
        parked_detected=parked_detected,
        parked_reason=parked_reason,
        final_url=final_url,
        site_status=site_status,
        pages=pages,
        page_urls=page_urls,
        cert_subject_org=cert_subject_org,
        cert_subject_cn=cert_subject_cn,
        cert_issuer_org=cert_issuer_org,
        cert_sans=cert_sans,
    )
