# 🔗 Clay.com, n8n & Make.com Integration Templates
**Powered by [Trust Center, SOC 2 Compliance & IAM Technographic Auditor](https://apify.com/algernontechnologies/trust-center-iam-auditor)**

This folder contains ready-to-import automation templates that enrich B2B domains or automate GRC vendor security reviews.

---

## 1. Included n8n Workflow Templates (1-Click Import)
1. **[`n8n-b2b-lead-technographic-enricher.json`](./n8n-b2b-lead-technographic-enricher.json)**
   - **Use Case:** Enriches target company domains with their Trust Center platform (`Vanta`, `Drata`, `SafeBase`), compliance certifications (`SOC 2 Type II`, `ISO 27001`, `HIPAA`), AI sub-processors (`OpenAI`, `Anthropic`, `Snowflake`, `AWS`), and DNS Identity stack (`Okta`, `Entra ID`, `Google Workspace`, `Wiz`).
2. **[`n8n-automated-vendor-tprm-triage.json`](./n8n-automated-vendor-tprm-triage.json)**
   - **Use Case:** Provides an internal "Request New SaaS Vendor" web form that automatically audits the vendor domain in ~2 seconds and routes Low-Risk (`trust_score >= 80`) vs. Manual-Review vendors.

---

## 2. Clay.com HTTP API Setup (30-Second Copy & Paste)
In any **Clay.com** table containing a `/domain` column:
1. Click **Add Enrichment** -> **HTTP API**.
2. Set **Method**: `POST`
3. Set **Endpoint URL**:
   ```text
   https://api.apify.com/v2/acts/AlgernonTechnologies~trust-center-iam-auditor/run-sync-get-dataset-items?token=YOUR_APIFY_API_TOKEN
   ```
4. Set **Headers**:
   - `Content-Type`: `application/json`
5. Set **Body**:
   ```json
   {
     "domains": ["{{domain}}"],
     "check_status_page": true
   }
   ```
6. Click **Save & Run** -> Map the returned flat fields (`trust_center_platform`, `certifications_csv`, `identity_providers_csv`, `subprocessors_csv`, `trust_score`, `b2b_sales_signal`) directly as columns!
