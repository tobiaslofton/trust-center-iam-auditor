# 🛡️ Trust Center, SOC 2 Compliance & IAM Security Auditor — MCP Server

[![tobiaslofton/trust-center-iam-auditor MCP server](https://glama.ai/mcp/servers/tobiaslofton/trust-center-iam-auditor/badges/score.svg)](https://glama.ai/mcp/servers/tobiaslofton/trust-center-iam-auditor)

A standalone, self-contained **Model Context Protocol (MCP) Server** written in Python (`mcp_server.py`) that enables AI assistants (Claude Desktop, Cursor, Windsurf, Cline, and custom MCP clients) to audit any company domain's live **Trust Center**, **SOC 2 / ISO 27001 / HIPAA certifications**, **AI & cloud sub-processors**, **DNS/TXT Identity & Security stack**, **SPF/DMARC email hardening**, and **Status Page health** directly over local `stdio`.

Zero third-party API keys or external cloud subscriptions are required. All DNS resolution (`dnspython`) and HTTP Trust Center inspection (`httpx` + `BeautifulSoup4`) execute locally inside the server process.

---

## 🔧 MCP Tools Provided

This MCP server exposes two tools over JSON-RPC 2.0 `stdio`:

### 1. `audit_vendor_domain`
Audits a single company domain and returns a structured compliance, sub-processor, and DNS security posture report.
- **Input Schema:**
  - `domain` (`string`, required): Company domain to inspect (e.g., `"vanta.com"`, `"drata.com"`, `"linear.app"`).

### 2. `batch_audit_vendor_domains`
Concurrently audits up to 15 company domains in parallel using asynchronous DNS and HTTP probing.
- **Input Schema:**
  - `domains` (`array[string]`, required): List of company domains to inspect concurrently.

---

## 📦 Installation & Local MCP Configuration

### Prerequisites
- Python 3.11+ (or Docker)
- Dependencies: `httpx`, `dnspython`, `beautifulsoup4`, `pydantic`

```bash
git clone https://github.com/tobiaslofton/trust-center-iam-auditor.git
cd trust-center-iam-auditor
pip install -r requirements.txt
```

### Option 1: Claude Desktop / Cursor / Windsurf (`uv` or `python` over `stdio`)

Add the following entry to your `claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "trust-center-iam-auditor": {
      "command": "python",
      "args": [
        "/absolute/path/to/trust-center-iam-auditor/mcp_server.py"
      ]
    }
  }
}
```

Or using `uv`:

```json
{
  "mcpServers": {
    "trust-center-iam-auditor": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/trust-center-iam-auditor",
        "run",
        "python",
        "mcp_server.py"
      ]
    }
  }
}
```

### Option 2: Run via Docker (`stdio`)

Build the local image and connect via `docker run -i`:

```bash
docker build -t trust-center-iam-auditor .
```

```json
{
  "mcpServers": {
    "trust-center-iam-auditor": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "trust-center-iam-auditor"
      ]
    }
  }
}
```

---

## 🔍 What Signals Does the MCP Server Extract?

| Category | Extracted Signals & Fields |
| :--- | :--- |
| **Trust Center Platform** | Fingerprints **Vanta**, **Drata**, **SafeBase**, **Conveyor**, **Secureframe**, **Whistic**, **OneTrust**, **Hyperproof**, or custom Trust Centers + direct URL via HTML signatures and `trust.<domain>` / `security.<domain>` CNAME inspection. |
| **Compliance Frameworks** | Detects **SOC 2 Type II**, **SOC 3**, **ISO 27001**, **ISO 27701**, **ISO 42001 (AI)**, **HIPAA**, **GDPR**, **PCI-DSS**, **FedRAMP**, **CSA STAR**, **NIST CSF / 800-53**, **CCPA / CPRA**. |
| **DNS Identity & Security Stack** | Inspects root TXT, MX, and CNAME records for **Okta**, **Microsoft Entra ID / M365**, **Google Workspace**, **Ping Identity**, **OneLogin**, **Duo**, **1Password**, **Wiz**, **Proofpoint**, **Mimecast**, **KnowBe4**, **Atlassian Cloud**, and **Slack Enterprise**. |
| **Cloud & AI Sub-processors** | Identifies disclosed sub-processors including **AWS**, **Google Cloud (GCP)**, **Azure**, **Snowflake**, **Databricks**, **OpenAI**, **Anthropic**, **Stripe**, **Datadog**, **Cloudflare**, **MongoDB**, **Auth0**, and **Vercel**. |
| **Email & DNS Hardening** | Verifies **SPF** (`v=spf1`), **DMARC** (`_dmarc.<domain>` `v=DMARC1`), MX routing hosts, and subdomain CNAME targets. |
| **Live Status Page Health** | Probes `status.<domain>` (including Atlassian Statuspage `/api/v2/status.json`) for real-time operational health. |
| **Risk Score & GRC Summary** | Computes a deterministic **0–100 Trust Score**, Risk Tier (`LOW`, `MODERATE`, `ELEVATED`), **GRC TPRM Summary**, and **Technographic Footprint**. |

---

## 📊 Example Tool Output (`audit_vendor_domain`)

```json
{
  "domain": "vanta.com",
  "trust_score": 100,
  "risk_tier": "LOW RISK (Enterprise Ready)",
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
  "subprocessors": [
    "Amazon Web Services (AWS)",
    "Datadog",
    "HubSpot",
    "Intercom",
    "Okta",
    "OpenAI",
    "Snowflake"
  ],
  "identity_providers": [
    "Atlassian Cloud",
    "Google Workspace",
    "Microsoft Entra ID / M365",
    "Slack Enterprise"
  ],
  "spf_enabled": true,
  "dmarc_enabled": true,
  "status_page_url": "https://status.vanta.com",
  "status_page_indicator": "NONE (All Systems Operational)",
  "grc_summary": "vanta.com operates a Vanta trust posture (Score: 100/100) with CCPA / CPRA, FedRAMP, GDPR, HIPAA, ISO 27001, ISO 42001 (AI), NIST CSF / 800-53, PCI-DSS, SOC 2 Type II. Email/DNS authentication is enforced (SPF+DMARC).",
  "b2b_sales_signal": "Technographic footprint for vanta.com: Trust Platform=Vanta; Identity/Security DNS=Atlassian Cloud, Google Workspace, Microsoft Entra ID / M365, Slack Enterprise; Detected Cloud/Sub-processors=Amazon Web Services (AWS), Datadog, HubSpot, Intercom, Okta."
}
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE).
