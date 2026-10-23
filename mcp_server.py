"""
MCP Server interface for Trust Center, SOC 2 Compliance & IAM Technographic Auditor.

Can be run locally via stdio (`python mcp_server.py`) or remotely in the cloud via the
hosted Apify MCP Server (`https://mcp.apify.com?actors=AlgernonTechnologies/trust-center-iam-auditor`).
"""
from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import httpx
from src.main import (
    compute_score_and_fallbacks,
    inspect_dns_footprint,
    normalize_domain,
    probe_status_page,
    probe_trust_center,
)


async def audit_vendor_domain(domain: str) -> dict[str, Any]:
    """Audit a vendor domain's Trust Center, SOC 2 / ISO 27001 certifications, AI sub-processors, DNS Identity stack, and status page."""
    clean = normalize_domain(domain)
    dns_info = await inspect_dns_footprint(clean)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }
    async with httpx.AsyncClient(headers=headers, http2=False) as client:
        trust_info, status_info = await asyncio.gather(
            probe_trust_center(client, clean, dns_info["subdomain_cnames"]),
            probe_status_page(client, clean),
        )
    score, risk_tier, grc_summary, sales_signal = compute_score_and_fallbacks(
        clean, dns_info, trust_info, status_info
    )
    return {
        "domain": clean,
        "trust_score": score,
        "risk_tier": risk_tier,
        "trust_center_platform": trust_info["trust_center_platform"],
        "trust_center_url": trust_info["trust_center_url"],
        "certifications": trust_info["certifications"],
        "subprocessors": trust_info["subprocessors"],
        "identity_providers": dns_info["identity_and_security_stack"],
        "spf_enabled": dns_info["spf_enabled"],
        "dmarc_enabled": dns_info["dmarc_enabled"],
        "status_page_indicator": status_info["status_page_indicator"],
        "grc_summary": grc_summary,
        "b2b_sales_signal": sales_signal,
    }


async def handle_jsonrpc() -> None:
    """Lightweight JSON-RPC 2.0 MCP Stdio handler."""
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        try:
            req = json.loads(line)
        except Exception:
            continue
        method = req.get("method")
        req_id = req.get("id")
        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "trust-center-iam-auditor", "version": "0.1.4"},
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "audit_vendor_domain",
                            "description": "Audit a company domain's Trust Center (Vanta/Drata/SafeBase), SOC 2 / ISO 27001 / HIPAA certifications, AI sub-processors (OpenAI/Anthropic), DNS Identity stack (Okta/Entra/Wiz), and status page.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "domain": {
                                        "type": "string",
                                        "description": "Company domain to audit (e.g. 'linear.app' or 'vanta.com')",
                                    }
                                },
                                "required": ["domain"],
                            },
                        }
                    ]
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif method == "tools/call":
            params = req.get("params", {})
            args = params.get("arguments", {})
            domain = args.get("domain", "vanta.com")
            result_data = await audit_vendor_domain(domain)
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result_data, indent=2)}]
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(handle_jsonrpc())
