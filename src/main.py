from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.asyncresolver
import httpx
from apify import Actor
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Fingerprints & Detection Signatures
# ---------------------------------------------------------------------------

TRUST_PLATFORM_SIGNATURES: dict[str, list[str]] = {
    "Vanta": ["vanta.com", "vantatrust.com", "trust.vanta.com", "vanta-trust", "__vanta"],
    "Drata": ["drata.com", "trust.drata.com", "drata-trust"],
    "SafeBase": ["safebase.io", "app.safebase.io", "safebase"],
    "Conveyor": ["conveyor.com", "aptible.com/conveyor", "conveyor-trust"],
    "Secureframe": ["secureframe.com", "trust.secureframe.com"],
    "Whistic": ["whistic.com", "trust.whistic.com"],
    "OneTrust": ["onetrust.com", "optanon"],
    "Hyperproof": ["hyperproof.io"],
}

CERTIFICATION_PATTERNS: dict[str, str] = {
    "SOC 2 Type II": r"soc[\s_\-]*2[\s_\-]*(?:type[\s_\-]*(?:ii|2))",
    "SOC 2": r"soc[\s_\-]*2\b",
    "SOC 3": r"soc[\s_\-]*3\b",
    "ISO 27001": r"iso(?:[/_\-\s]*iec)?[/_\-\s]*27001",
    "ISO 27701": r"iso(?:[/_\-\s]*iec)?[/_\-\s]*27701",
    "ISO 42001 (AI)": r"iso(?:[/_\-\s]*iec)?[/_\-\s]*42001",
    "HIPAA": r"\bhipaa\b",
    "GDPR": r"\bgdpr\b",
    "CCPA / CPRA": r"\b(?:ccpa|cpra)\b",
    "PCI-DSS": r"\bpci[\s_\-]*dss\b",
    "FedRAMP": r"\bfedramp\b",
    "CSA STAR": r"\bcsa[\s_\-]*star\b",
    "NIST CSF / 800-53": r"\bnist\b",
    "TX-RAMP": r"\btx[\s_\-]*ramp\b",
}

SUBPROCESSOR_VENDORS: dict[str, str] = {
    "Amazon Web Services (AWS)": r"\b(?:amazon\s+web\s+services|aws|amazonaws\.com)\b",
    "Google Cloud Platform (GCP)": r"\b(?:google\s+cloud|gcp|cloud\.google\.com)\b",
    "Microsoft Azure": r"\b(?:microsoft\s+azure|azure)\b",
    "Cloudflare": r"\bcloudflare\b",
    "Snowflake": r"\bsnowflake\b",
    "Databricks": r"\bdatabricks\b",
    "OpenAI": r"\bopenai\b",
    "Anthropic": r"\banthropic\b",
    "Stripe": r"\bstripe\b",
    "Datadog": r"\bdatadog\b",
    "Sentry": r"\bsentry\b",
    "MongoDB Atlas": r"\bmongodb\b",
    "Supabase": r"\bsupabase\b",
    "Auth0": r"\bauth0\b",
    "Okta": r"\bokta\b",
    "SendGrid / Twilio": r"\b(?:sendgrid|twilio)\b",
    "HubSpot": r"\bhubspot\b",
    "Salesforce": r"\bsalesforce\b",
    "Intercom": r"\bintercom\b",
    "Zendesk": r"\bzendesk\b",
    "Linear": r"\blinear\b",
    "Vercel": r"\bvercel\b",
    "Fastly": r"\bfastly\b",
}

DNS_IDP_AND_TECH_SIGNATURES: dict[str, list[str]] = {
    "Okta": ["okta-verification", "okta.com", "_okta"],
    "Microsoft Entra ID / M365": ["ms=", "spf.protection.outlook.com", "mail.protection.outlook.com", "onmicrosoft.com"],
    "Google Workspace": ["google-site-verification", "_spf.google.com", "aspmx.l.google.com", "googlehosted.com"],
    "Ping Identity": ["pingidentity", "pingone"],
    "OneLogin": ["onelogin"],
    "Duo Security": ["duosecurity"],
    "JumpCloud": ["jumpcloud"],
    "Cisco Umbrella / Duo": ["cisco-ci-domain-verification"],
    "Proofpoint": ["pphosted.com", "proofpoint"],
    "Mimecast": ["mimecast.com"],
    "Cloudflare Security": ["cloudflare", "include:_spf.mx.cloudflare.net"],
    "KnowBe4": ["knowbe4"],
    "Atlassian Cloud": ["atlassian-domain-verification"],
    "Slack Enterprise": ["slack-domain-verification"],
    "1Password": ["1password-site-verification"],
    "Wiz": ["wiz-domain-verification"],
    "Drata DNS Verified": ["drata-domain-verification"],
    "Vanta DNS Verified": ["vanta-verification"],
}


class AIEnrichmentOutput(BaseModel):
    grc_summary: str = Field(
        description="Concise 2-sentence Third-Party Risk Management (TPRM) assessment for GRC/Security teams."
    )
    b2b_sales_signal: str = Field(
        description="Actionable 1-2 sentence B2B sales & technographic signal for RevOps/Clay workflows."
    )


def normalize_domain(raw: str) -> str:
    raw = raw.strip().lower()
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.netloc or parsed.path
    else:
        host = raw.split("/")[0]
    host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


async def inspect_dns_footprint(domain: str) -> dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.5
    resolver.lifetime = 4.5

    txt_records: list[str] = []
    mx_records: list[str] = []
    dmarc_present = False
    spf_present = False
    cname_targets: dict[str, str] = {}

    async def query_txt(target: str) -> list[str]:
        try:
            answers = await resolver.resolve(target, "TXT")
            return [b"".join(rdata.strings).decode("utf-8", errors="ignore") for rdata in answers]
        except Exception:
            return []

    async def query_mx(target: str) -> list[str]:
        try:
            answers = await resolver.resolve(target, "MX")
            return [str(rdata.exchange).rstrip(".").lower() for rdata in answers]
        except Exception:
            return []

    async def query_cname(sub: str) -> str | None:
        try:
            answers = await resolver.resolve(f"{sub}.{domain}", "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".").lower()
        except Exception:
            return None

    root_txt, dmarc_txt, mx_list, trust_cname, sec_cname, status_cname = await asyncio.gather(
        query_txt(domain),
        query_txt(f"_dmarc.{domain}"),
        query_mx(domain),
        query_cname("trust"),
        query_cname("security"),
        query_cname("status"),
    )

    txt_records.extend(root_txt)
    mx_records.extend(mx_list)

    if any("v=spf1" in r.lower() for r in root_txt):
        spf_present = True
    if any("v=dmarc1" in r.lower() for r in dmarc_txt):
        dmarc_present = True

    if trust_cname:
        cname_targets["trust"] = trust_cname
    if sec_cname:
        cname_targets["security"] = sec_cname
    if status_cname:
        cname_targets["status"] = status_cname

    combined_blob = " ".join(txt_records + mx_records + list(cname_targets.values())).lower()

    detected_stack: list[str] = []
    for label, patterns in DNS_IDP_AND_TECH_SIGNATURES.items():
        if any(pat.lower() in combined_blob for pat in patterns):
            detected_stack.append(label)

    return {
        "spf_enabled": spf_present,
        "dmarc_enabled": dmarc_present,
        "mx_hosts": mx_records[:5],
        "subdomain_cnames": cname_targets,
        "identity_and_security_stack": sorted(set(detected_stack)),
        "raw_txt_count": len(txt_records),
    }


async def probe_trust_center(client: httpx.AsyncClient, domain: str, cnames: dict[str, str]) -> dict[str, Any]:
    candidate_urls = [
        f"https://trust.{domain}",
        f"https://security.{domain}",
        f"https://{domain}/security",
        f"https://www.{domain}/security",
        f"https://{domain}/trust",
        f"https://www.{domain}/trust",
        f"https://{domain}",
    ]

    trust_url: str | None = None
    trust_platform = "None Detected"
    combined_text = ""
    combined_html = ""

    # Check CNAME hints first
    cname_blob = " ".join(cnames.values()).lower()
    for platform, sigs in TRUST_PLATFORM_SIGNATURES.items():
        if any(sig in cname_blob for sig in sigs):
            trust_platform = platform
            if "trust" in cnames:
                trust_url = f"https://trust.{domain}"
            elif "security" in cnames:
                trust_url = f"https://security.{domain}"
            break

    async def fetch_candidate(url: str) -> tuple[str, str, str] | None:
        try:
            resp = await client.get(url, follow_redirects=True, timeout=15.0)
            if resp.status_code == 403:
                resp = await client.get(
                    url,
                    headers={"User-Agent": "python-httpx/0.28.1", "Accept": "*/*"},
                    follow_redirects=True,
                    timeout=15.0,
                )
            if resp.status_code >= 400:
                return None
            return url, str(resp.url), resp.text
        except Exception:
            return None

    fetched_pages = await asyncio.gather(*(fetch_candidate(u) for u in candidate_urls))

    for item in fetched_pages:
        if not item:
            continue
        orig_url, final_url, html = item
        soup = BeautifulSoup(html, "html.parser")
        page_text = soup.get_text(separator=" ", strip=True)
        lower_html = (html + " " + final_url).lower()

        if trust_platform == "None Detected":
            for platform, sigs in TRUST_PLATFORM_SIGNATURES.items():
                if any(sig in lower_html for sig in sigs):
                    trust_platform = platform
                    if not trust_url:
                        trust_url = final_url
                    break

        is_trust_page = any(
            k in final_url.lower() or k in (soup.title.string.lower() if soup.title and soup.title.string else "")
            for k in ["trust", "security", "compliance", "soc 2", "iso 27001"]
        )
        if is_trust_page and not trust_url:
            trust_url = final_url
            if trust_platform == "None Detected":
                trust_platform = "Custom / Self-Hosted Trust Center"

        combined_text += " " + page_text
        combined_html += " " + lower_html

    # Extract Certifications from both visible text and embedded SPA JSON
    found_certs: list[str] = []
    search_corpus = combined_text + " " + combined_html
    for cert_name, pattern in CERTIFICATION_PATTERNS.items():
        if re.search(pattern, search_corpus, re.IGNORECASE):
            found_certs.append(cert_name)

    if "SOC 2 Type II" in found_certs and "SOC 2" in found_certs:
        found_certs.remove("SOC 2")

    # Extract Sub-processors (excluding the company's own brand name)
    domain_root = domain.split(".")[0].lower()
    found_subprocessors: list[str] = []
    for vendor_name, pattern in SUBPROCESSOR_VENDORS.items():
        if domain_root in vendor_name.lower():
            continue
        if re.search(pattern, search_corpus, re.IGNORECASE):
            found_subprocessors.append(vendor_name)

    return {
        "trust_center_url": trust_url or f"https://{domain}",
        "trust_center_platform": trust_platform,
        "certifications": sorted(set(found_certs)),
        "subprocessors": sorted(set(found_subprocessors)),
    }


async def probe_status_page(client: httpx.AsyncClient, domain: str) -> dict[str, str]:
    status_api_url = f"https://status.{domain}/api/v2/status.json"
    status_web_url = f"https://status.{domain}"

    try:
        resp = await client.get(status_api_url, follow_redirects=True, timeout=5.0)
        if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
            data = resp.json()
            indicator = data.get("status", {}).get("indicator", "unknown")
            description = data.get("status", {}).get("description", "Status Page Active")
            return {
                "status_page_url": status_web_url,
                "status_page_indicator": f"{indicator.upper()} ({description})",
            }
    except Exception:
        pass

    try:
        resp = await client.get(status_web_url, follow_redirects=True, timeout=5.0)
        if resp.status_code < 400:
            text_lower = resp.text.lower()
            if "all systems operational" in text_lower or "operational" in text_lower:
                return {
                    "status_page_url": str(resp.url),
                    "status_page_indicator": "NONE (All Systems Operational)",
                }
            return {
                "status_page_url": str(resp.url),
                "status_page_indicator": "ACTIVE (Public Status Portal Verified)",
            }
    except Exception:
        pass

    return {
        "status_page_url": "",
        "status_page_indicator": "Not Published on status.<domain>",
    }


def compute_score_and_fallbacks(
    domain: str,
    dns_info: dict[str, Any],
    trust_info: dict[str, Any],
    status_info: dict[str, str],
) -> tuple[int, str, str, str]:
    score = 20
    certs = trust_info["certifications"]
    platform = trust_info["trust_center_platform"]
    idps = dns_info["identity_and_security_stack"]
    subprocs = trust_info["subprocessors"]

    if platform != "None Detected":
        score += 25
    if any("SOC 2" in c for c in certs):
        score += 20
    if "ISO 27001" in certs:
        score += 15
    if len(certs) >= 3:
        score += 5
    if dns_info["spf_enabled"] and dns_info["dmarc_enabled"]:
        score += 10
    if status_info["status_page_url"]:
        score += 5

    score = min(100, score)
    if score >= 80:
        risk_tier = "LOW RISK (Enterprise Ready)"
    elif score >= 55:
        risk_tier = "MODERATE RISK (Standard Posture)"
    else:
        risk_tier = "ELEVATED RISK (Manual TPRM Review Needed)"

    cert_str = ", ".join(certs) if certs else "no publicly indexed SOC/ISO badges"
    idp_str = ", ".join(idps) if idps else "standard DNS configuration"
    grc_summary = (
        f"{domain} operates a {platform} trust posture (Score: {score}/100) with {cert_str}. "
        f"Email/DNS authentication is {'enforced (SPF+DMARC)' if (dns_info['spf_enabled'] and dns_info['dmarc_enabled']) else 'partially configured'}."
    )
    sales_signal = (
        f"Technographic footprint for {domain}: Trust Platform={platform}; Identity/Security DNS={idp_str}; "
        f"Detected Cloud/Sub-processors={', '.join(subprocs[:5]) if subprocs else 'Unlisted'}."
    )
    return score, risk_tier, grc_summary, sales_signal


async def maybe_enrich_with_gemini(
    api_key: str | None,
    domain: str,
    score: int,
    dns_info: dict[str, Any],
    trust_info: dict[str, Any],
    status_info: dict[str, str],
    default_grc: str,
    default_sales: str,
) -> tuple[str, str]:
    key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return default_grc, default_sales

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=key)
        prompt = (
            f"Analyze this vendor security & technographic audit for {domain}:\n"
            f"- Trust Score: {score}/100\n"
            f"- Trust Center Platform: {trust_info['trust_center_platform']} ({trust_info['trust_center_url']})\n"
            f"- Certifications: {trust_info['certifications']}\n"
            f"- DNS Identity/Security Stack: {dns_info['identity_and_security_stack']}\n"
            f"- Detected Sub-processors: {trust_info['subprocessors']}\n"
            f"- Status Page: {status_info['status_page_indicator']}\n"
        )
        response = await asyncio.to_thread(
            client.models.generate_content,
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AIEnrichmentOutput,
                temperature=0.2,
            ),
        )
        parsed = AIEnrichmentOutput.model_validate_json(response.text)
        return parsed.grc_summary, parsed.b2b_sales_signal
    except Exception as exc:
        Actor.log.warning(f"Gemini enrichment fallback for {domain}: {exc}")
        return default_grc, default_sales


async def audit_single_domain(
    client: httpx.AsyncClient,
    raw_domain: str,
    check_status: bool,
    gemini_api_key: str | None,
) -> dict[str, Any]:
    domain = normalize_domain(raw_domain)
    Actor.log.info(f"Auditing domain: {domain}")

    dns_info = await inspect_dns_footprint(domain)
    trust_task = probe_trust_center(client, domain, dns_info["subdomain_cnames"])
    status_task = (
        probe_status_page(client, domain)
        if check_status
        else asyncio.sleep(0, result={"status_page_url": "", "status_page_indicator": "Skipped"})
    )

    trust_info, status_info = await asyncio.gather(trust_task, status_task)

    score, risk_tier, default_grc, default_sales = compute_score_and_fallbacks(
        domain, dns_info, trust_info, status_info
    )
    grc_summary, sales_signal = await maybe_enrich_with_gemini(
        gemini_api_key,
        domain,
        score,
        dns_info,
        trust_info,
        status_info,
        default_grc,
        default_sales,
    )

    record = {
        "domain": domain,
        "audited_at": datetime.now(timezone.utc).isoformat(),
        "risk_tier": risk_tier,
        "trust_score": score,
        "trust_center_platform": trust_info["trust_center_platform"],
        "trust_center_url": trust_info["trust_center_url"],
        "certifications": trust_info["certifications"],
        "certifications_csv": ", ".join(trust_info["certifications"]),
        "identity_providers": dns_info["identity_and_security_stack"],
        "identity_providers_csv": ", ".join(dns_info["identity_and_security_stack"]),
        "subprocessors": trust_info["subprocessors"],
        "subprocessors_csv": ", ".join(trust_info["subprocessors"]),
        "spf_enabled": dns_info["spf_enabled"],
        "dmarc_enabled": dns_info["dmarc_enabled"],
        "mx_hosts": dns_info["mx_hosts"],
        "subdomain_cnames": dns_info["subdomain_cnames"],
        "status_page_url": status_info["status_page_url"],
        "status_page_indicator": status_info["status_page_indicator"],
        "grc_summary": grc_summary,
        "b2b_sales_signal": sales_signal,
    }

    await Actor.push_data(record)

    # Pay-Per-Event (PPE) charging hook (safe in local/non-PPE environments)
    if hasattr(Actor, "charge"):
        try:
            await Actor.charge(event_name="vendor-audited", count=1)
        except Exception as exc:
            Actor.log.debug(f"PPE charge skipped/unsupported in current environment: {exc}")

    return record


async def main() -> None:
    async with Actor:
        actor_input = await Actor.get_input() or {}
        domains: list[str] = actor_input.get("domains") or ["vanta.com", "drata.com", "linear.app"]
        gemini_api_key: str | None = actor_input.get("gemini_api_key")
        check_status: bool = bool(actor_input.get("check_status_page", True))
        max_concurrency: int = int(actor_input.get("max_concurrency", 5))

        Actor.log.info(f"Starting Trust Center & IAM Auditor for {len(domains)} domain(s)...")

        semaphore = asyncio.Semaphore(max(1, min(max_concurrency, 20)))
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }

        async with httpx.AsyncClient(headers=headers, http2=False) as client:
            async def sem_task(d: str) -> dict[str, Any]:
                async with semaphore:
                    return await audit_single_domain(client, d, check_status, gemini_api_key)

            results = await asyncio.gather(*(sem_task(d) for d in domains), return_exceptions=True)

        succeeded = sum(1 for r in results if isinstance(r, dict))
        Actor.log.info(f"Audit complete! Successfully audited {succeeded}/{len(domains)} domains.")
