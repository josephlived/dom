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

This scaffold includes:

- Streamlit UI
- normalized company/domain parsing
- concurrent per-domain processing
- redirect checks using HTTP behavior plus HTML redirect hints
- Playwright/Chromium headless fallback for hard domains (works on Windows dev + Streamlit Cloud)
- live RDAP lookups for registrant/entity signals
- WHOIS fallback when RDAP is weak, empty, or privacy-masked
- parked-domain detection
- basic website evidence extraction from homepage and common legal/about/contact paths
- candidate scoring, ranked output, and CSV export

Current ownership logic is still incomplete:

- RDAP is live
- WHOIS fallback is basic and field-based, not registry-perfect
- crawled-page evidence can still overstate weak brand mentions if you trust the score blindly
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
