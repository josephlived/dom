# Domain Attribution Workbench

Internal Streamlit app for matching input domains to a pasted company list using multiple ownership signals.

## V1 goals

- Paste companies with optional aliases
- Paste root domains
- Detect redirects
- Score candidate company matches using ownership and website evidence
- Return ranked candidates with confidence and evidence URLs

## Input format

### Companies

One company per line. Optional aliases can be separated with `|`.

```text
Meta Platforms, Inc. | Meta | Facebook
Alphabet Inc. | Google
```

### Domains

One root domain per line.

```text
fb.com
instagram.com
example.com
```

## Current state

Includes:

- Streamlit UI
- normalized company/domain parsing
- concurrent per-domain processing
- redirect checks using HTTP behavior plus HTML redirect hints
- Playwright/Chromium headless fallback run from a dedicated worker thread that reuses one long-lived browser
- live RDAP lookups for registrant/entity signals
- WHOIS fallback with expanded ccTLD coverage (`.uk`, `.de`, `.fr`, `.nl`, `.eu`, `.jp`, `.cn`, `.au`, `.ca`, `.es`, `.it`, `.in`, `.br`, `.ru`, `.us`, `.me`, …) and RIPE/APNIC/JPRS field patterns
- TLS certificate subject `O` / `CN` / SAN as an extra ownership signal
- parked-domain detection with broader pattern set (sedo, afternic, dan.com, hugedomains, bodis, namebright, etc.)
- website evidence extraction from homepage + `/about`, `/privacy`, `/terms`, `/legal`, `/imprint`, `/impressum`, `/contact`
- word-boundary candidate matching (no more `apple` matching `pineapple`)
- high-precision extractors: JSON-LD `Organization`/`Corporation` nodes, `© YYYY <entity>` copyright lines, legal-entity phrases (`Inc.`, `LLC`, `Ltd.`, `GmbH`, `S.A.`, `Pty Ltd`, `K.K.`, …)
- evidence deduplication per (candidate, source_type) and a cap on stacked page-text signals so weak brand mentions can't outweigh strong ownership evidence
- candidate scoring, ranked output, and CSV export (now including cert subject/issuer columns)

Known limitations:

- WHOIS fallback is still field-based, not registry-perfect; DENIC (`.de`) returns almost nothing post-GDPR
- the `whois.com` HTML fallback depends on brittle class-name regexes
- browser fallback is best-effort and will not reliably beat strong anti-bot systems

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m playwright install chromium
python -m streamlit run app.py
```

The first time the browser fallback runs, Playwright will auto-install Chromium
if it's missing. Pre-running `python -m playwright install chromium` avoids the
~30s cold-start delay on the first hard domain.

## Deploy to Streamlit Cloud

`packages.txt` installs the Chromium system libraries at build time.
`requirements.txt` installs Playwright. On the first domain that needs the
browser fallback, the app runs `python -m playwright install chromium` to fetch
the Chromium binary (~170 MB, ~30s); subsequent requests in the same container
reuse it. The browser is serialized behind a module-level lock, so only one
Chromium runs at a time regardless of the `max_workers` slider — important on
the free tier's ~1 GB RAM.

## Recommended next steps

1. Improve extraction rules for legal entity phrases from crawled pages.
2. Detect stronger anti-bot failures explicitly.
3. Build a validation set before trusting scores at scale.
