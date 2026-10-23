# 🛡️ Trust Center, SOC 2 Compliance & IAM Technographic Auditor

Turn a **30-minute manual vendor security review** into a **2-second automated API call**.

Give this Actor a list of company domains (e.g., `vanta.com`, `drata.com`, `linear.app`), and it inspects each company's live **Trust Center**, **DNS/TXT security records**, **CNAME routing**, and **Status Page** to generate a complete compliance and technographic dossier.

Built specifically for **GRC / Third-Party Risk Management (TPRM) teams**, **Cybersecurity Sales / RevOps**, and **Clay.com / n8n workflows**.

> 🌐 **Live Benchmark Demo:** Explore our live audit of leading SaaS & AI companies at **[The 2026 B2B SaaS Trust Center, AI Sub-Processor & SSO-Tax Index](https://tobiaslofton.github.io/saas-trust-ai-index/)** (Open-source dataset & n8n templates: [Index Repo](https://github.com/tobiaslofton/saas-trust-ai-index) | [n8n & Clay Workflows Repo](https://github.com/tobiaslofton/n8n-clay-b2b-trust-center-workflows)).
>
> 💸 **Companion Actor:** Also check out our **[B2B SaaS Pricing Model, PLG & Enterprise SSO-Tax Auditor](https://apify.com/algernontechnologies/saas-pricing-sso-tax-auditor)** to enrich target domains with pricing models, starting price, free tier flags, and SAML/SSO gating.

---

## 🚀 What Data Does It Extract?

| Category | Extracted Signals & Fields |
| :--- | :--- |
| **Trust Center Platform** | Detects **Vanta**, **Drata**, **SafeBase**, **Conveyor**, **Secureframe**, **Whistic**, **OneTrust**, **Hyperproof**, or custom Trust Centers + direct URL. |
| **Compliance Frameworks** | **SOC 2 Type II**, **SOC 3**, **ISO 27001**, **ISO 27701**, **ISO 42001 (AI)**, **HIPAA**, **GDPR**, **PCI-DSS**, **FedRAMP**, **CSA STAR**, **NIST**, **CCPA**. |
| **DNS Identity & Security Stack** | Detects **Okta**, **Microsoft Entra ID / M365**, **Google Workspace**, **Ping Identity**, **OneLogin**, **Duo**, **1Password**, **Wiz**, **Proofpoint**, **Mimecast**, **KnowBe4**, **Atlassian Cloud**, and **Slack Enterprise**. |
| **Cloud & AI Sub-processors** | Identifies **AWS**, **Google Cloud (GCP)**, **Azure**, **Snowflake**, **Databricks**, **OpenAI**, **Anthropic**, **Stripe**, **Datadog**, **Cloudflare**, **MongoDB**, **Auth0**, **Vercel**, and more. |
| **Email & DNS Hardening** | Verifies **SPF**, **DMARC**, MX routing hosts, and Trust/Status subdomain CNAME targets. |
| **Live Status Page Health** | Queries `status.<domain>` (including Atlassian Statuspage APIs) for real-time operational health. |
| **Risk Score & Executive Summary** | Calculates a **0–100 Trust Score**, Risk Tier (`LOW`, `MODERATE`, `ELEVATED`), **GRC TPRM Summary**, and **B2B Sales Technographic Signal** (with optional **Gemini 2.5 Flash** AI synthesis). |

---

## 💼 Top Use Cases

### 1. Automated Vendor Pre-Screening (GRC & Security Teams)
Before onboarding a new SaaS vendor, run their domain through this Actor to automatically verify whether they publish a live Trust Center, hold active **SOC 2 Type II** or **ISO 27001** certifications, enforce **SPF + DMARC**, and disclose AI sub-processors like **OpenAI** or **Anthropic**.

### 2. High-Intent Technographic Enrichment (Clay.com & B2B Sales)
Stop sending generic cold emails. Enrich thousands of prospect domains in **Clay.com**, **Make**, or **n8n** to know the exact compliance platform (`Vanta` vs. `Drata` vs. `SafeBase` vs. `None Detected`), Identity Provider (`Okta` vs. `Entra ID`), and cloud stack a prospect uses before reaching out.

---

## 📊 Sample Output (Clay & Webhook Ready)

Every output item includes both clean JSON arrays and flat `_csv` strings so you can map columns in **Clay.com**, **Zapier**, or **Google Sheets** with zero formulas:

```json
{
  "domain": "vanta.com",
  "risk_tier": "LOW RISK (Enterprise Ready)",
  "trust_score": 100,
  "trust_center_platform": "Vanta",
  "trust_center_url": "https://trust.vanta.com",
  "certifications": [
    "CCPA / CPRA",
    "FedRAMP",
    "GDPR",
    "HIPAA",
    "ISO 27001",
    "ISO 42001 (AI)",
    "NIST CSF / 800-53",
    "PCI-DSS",
    "SOC 2 Type II"
  ],
  "certifications_csv": "CCPA / CPRA, FedRAMP, GDPR, HIPAA, ISO 27001, ISO 42001 (AI), NIST CSF / 800-53, PCI-DSS, SOC 2 Type II",
  "identity_providers": [
    "Atlassian Cloud",
    "Google Workspace",
    "Microsoft Entra ID / M365",
    "Slack Enterprise"
  ],
  "identity_providers_csv": "Atlassian Cloud, Google Workspace, Microsoft Entra ID / M365, Slack Enterprise",
  "subprocessors": [
    "Amazon Web Services (AWS)",
    "Datadog",
    "HubSpot",
    "Intercom",
    "Okta",
    "OpenAI",
    "Snowflake"
  ],
  "subprocessors_csv": "Amazon Web Services (AWS), Datadog, HubSpot, Intercom, Okta, OpenAI, Snowflake",
  "spf_enabled": true,
  "dmarc_enabled": true,
  "status_page_url": "https://status.vanta.com",
  "status_page_indicator": "NONE (All Systems Operational)",
  "grc_summary": "vanta.com operates a Vanta trust posture (Score: 100/100) with CCPA / CPRA, FedRAMP, GDPR, HIPAA, ISO 27001, ISO 42001 (AI), NIST CSF / 800-53, PCI-DSS, SOC 2 Type II. Email/DNS authentication is enforced (SPF+DMARC).",
  "b2b_sales_signal": "Technographic footprint for vanta.com: Trust Platform=Vanta; Identity/Security DNS=Atlassian Cloud, Google Workspace, Microsoft Entra ID / M365, Slack Enterprise; Detected Cloud/Sub-processors=Amazon Web Services (AWS), Datadog, HubSpot, Intercom, Okta."
}
```

---

## 🤖 Connect as an MCP Server (Claude, Cursor, Antigravity)

Give your AI assistant real-time vendor compliance lookup capabilities using the Apify MCP Server:

```json
{
  "mcpServers": {
    "apify-trust-auditor": {
      "url": "https://mcp.apify.com?actors=AlgernonTechnologies/trust-center-iam-auditor",
      "headers": {
        "Authorization": "Bearer YOUR_APIFY_API_TOKEN"
      }
    }
  }
}
```
