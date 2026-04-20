from __future__ import annotations

import re
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
DEFAULT_PATHS = ("", "/about", "/privacy", "/terms", "/contact")
BROWSER_NAV_TIMEOUT_MS = 15000
BROWSER_INSTALL_TIMEOUT_SECONDS = 240
_BROWSER_LOCK = threading.Lock()
_BROWSER_READY: bool | None = None
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
    (re.compile(r"\bthis domain is for sale\b", re.IGNORECASE), "domain for sale"),
    (re.compile(r"\bparked free\b", re.IGNORECASE), "parked free"),
    (re.compile(r"\bsedo\b", re.IGNORECASE), "sedo"),
    (re.compile(r"\bafternic\b", re.IGNORECASE), "afternic"),
    (re.compile(r"\bdan\.com\b", re.IGNORECASE), "dan.com"),
    (re.compile(r"\bundeveloped\b", re.IGNORECASE), "undeveloped"),
    (re.compile(r"\bparkingcrew\b", re.IGNORECASE), "parkingcrew"),
    (re.compile(r"\babove\.com\b", re.IGNORECASE), "above.com"),
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


def _ensure_playwright_browser() -> bool:
    global _BROWSER_READY
    if _BROWSER_READY is not None:
        return _BROWSER_READY
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _BROWSER_READY = False
        return False
    for attempt in range(2):
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
                browser.close()
            _BROWSER_READY = True
            return True
        except Exception as exc:
            message = str(exc).lower()
            missing_browser = "executable doesn't exist" in message or "playwright install" in message
            if attempt == 0 and missing_browser and _install_chromium():
                continue
            _BROWSER_READY = False
            return False
    _BROWSER_READY = False
    return False


def _browser_dump(url: str) -> str:
    with _BROWSER_LOCK:
        if not _ensure_playwright_browser():
            return ""
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ImportError:
            return ""
        html = ""
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
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
                finally:
                    browser.close()
        except Exception:
            return ""
        return html


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
    )
