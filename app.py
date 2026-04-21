from __future__ import annotations

from collections import Counter

import streamlit as st

from domain_attribution.crawler import crawl_domain
from domain_attribution.ownership import lookup_ownership
from domain_attribution.pipeline import analyze_domains
from domain_attribution.reporting import results_to_csv, results_to_rows

st.set_page_config(page_title="Domain Attribution Workbench", layout="wide")

st.title("Domain Attribution Workbench")
st.caption(
    "Match pasted root domains against pasted companies using redirect behavior, site evidence, and ownership signals."
)

with st.sidebar:
    st.header("Run Settings")
    analysis_mode = st.radio("Analysis mode", options=["quick", "deep"], index=1, help="Quick checks homepage only. Deep checks homepage plus legal/about/contact pages.")
    max_workers = st.slider("Parallel workers", min_value=1, max_value=12, value=6, step=1)
    confidence_threshold = st.slider("Confidence threshold", min_value=50, max_value=95, value=85, step=5)
    st.markdown(
        "Use conservative thresholds. Weak evidence should produce candidate or ambiguous results, not fake certainty."
    )

    st.divider()
    st.subheader("Cache")
    force_fresh = st.checkbox(
        "Force fresh data on each run",
        value=False,
        help="Clears cached crawl and ownership results before running. Useful if you suspect stale data or switched between quick/deep mode on the same domains.",
    )
    if st.button("Clear Cache Now", use_container_width=True):
        crawl_domain.cache_clear()
        lookup_ownership.cache_clear()
        st.success("Cache cleared.")

company_text = st.text_area(
    "Companies",
    height=220,
    placeholder="Meta Platforms, Inc. | Meta | Facebook\nAlphabet Inc. | Google",
)
domain_text = st.text_area(
    "Domains",
    height=220,
    placeholder="fb.com\ninstagram.com\nexample.com",
)

run = st.button("Analyze", type="primary", use_container_width=True)

if run:
    if not company_text.strip() or not domain_text.strip():
        st.error("Provide both companies and domains before running the analysis.")
    else:
        progress = st.progress(0, text="Preparing analysis...")
        status = st.empty()

        def update_progress(completed: int, total: int, domain: str) -> None:
            percent = int((completed / total) * 100)
            progress.progress(percent, text=f"Processed {completed}/{total}: {domain}")
            status.caption(f"Latest completed domain: `{domain}`")

        if force_fresh:
            crawl_domain.cache_clear()
            lookup_ownership.cache_clear()

        with st.spinner("Running attribution analysis..."):
            results = analyze_domains(
                company_text,
                domain_text,
                confidence_threshold,
                analysis_mode=analysis_mode,
                max_workers=max_workers,
                progress_callback=update_progress,
            )
        progress.empty()
        status.empty()

        st.subheader("Results")
        table_rows = results_to_rows(results)
        status_counts = Counter(item.match_status for item in results)
        redirected_count = sum(1 for item in results if item.redirect_detected)
        browser_count = sum(1 for item in results if item.crawl and item.crawl.browser_fallback_used)
        matched_count = status_counts.get("Matched", 0)
        candidate_count = status_counts.get("Candidate Matches", 0)

        metric1, metric2, metric3, metric4, metric5 = st.columns(5)
        metric1.metric("Domains", len(results))
        metric2.metric("Matched", matched_count)
        metric3.metric("Candidates", candidate_count)
        metric4.metric("Redirects", redirected_count)
        metric5.metric("Browser Fallback", browser_count)

        with st.expander("Status Breakdown", expanded=False):
            st.write(dict(status_counts))

        st.download_button(
            "Download CSV",
            data=results_to_csv(results),
            file_name="domain-attribution-results.csv",
            mime="text/csv",
            use_container_width=False,
        )

        st.dataframe(table_rows, use_container_width=True, hide_index=True)

        st.subheader("Details")
        for item in results:
            label = f"{item.input_domain} | {item.match_status}"
            with st.expander(label):
                st.write(
                    {
                        "input_domain": item.input_domain,
                        "redirect_detected": item.redirect_detected,
                        "redirect_target": item.redirect_target,
                        "redirect_signal": item.redirect_signal,
                        "browser_fallback_used": item.crawl.browser_fallback_used if item.crawl else False,
                        "site_status": item.site_status,
                        "parked_detected": item.crawl.parked_detected if item.crawl else False,
                        "parked_reason": item.crawl.parked_reason if item.crawl else "",
                        "rdap_org": item.ownership.rdap_org,
                        "rdap_entity_name": item.ownership.rdap_entity_name,
                        "rdap_role": item.ownership.rdap_role,
                        "rdap_source_url": item.ownership.rdap_source_url,
                        "whois_registrant": item.ownership.whois_registrant,
                        "whois_field_label": item.ownership.whois_field_label,
                        "whois_source": item.ownership.whois_source,
                        "whois_raw_excerpt": item.ownership.whois_raw_excerpt,
                        "is_privacy_protected": item.ownership.is_privacy_protected,
                        "ownership_notes": item.ownership.status_notes,
                        "final_url": item.crawl.final_url if item.crawl else "",
                    }
                )

                if item.candidates:
                    for candidate in item.candidates:
                        st.markdown(
                            f"**{candidate.company_name}** | score `{candidate.score}` | confidence `{candidate.confidence_label}`"
                        )
                        evidence_rows = []
                        for evidence in candidate.evidence:
                            evidence_rows.append(
                                {
                                    "Source Type": evidence.source_type,
                                    "Matched Text": evidence.matched_text,
                                    "Score": evidence.score,
                                    "Source URL": evidence.source_url,
                                    "Snippet": evidence.snippet,
                                }
                            )
                        st.dataframe(evidence_rows, use_container_width=True, hide_index=True)
                else:
                    st.info("No candidate companies cleared the current evidence rules.")
