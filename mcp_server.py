#!/usr/bin/env python3
"""
Standalone Model Context Protocol (MCP) Server for B2B Trust Center, SOC 2 Compliance & IAM Security Auditing.
Executes locally over stdio for Claude Desktop, Cursor, Windsurf, and MCP-compatible clients.
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

TOOLS = [
    {
        "name": "audit_vendor_domain",
        "description": (
            "Audit a company domain's Trust Center (Vanta, Drata, SafeBase, Conveyor, Secureframe, Whistic, OneTrust), "
            "SOC 2 Type II / ISO 27001 / HIPAA / GDPR / ISO 42001 certifications, AI & cloud sub-processors "
            "(OpenAI, Anthropic, AWS, GCP, Snowflake), DNS Identity stack (Okta, Microsoft Entra ID, Google Workspace, Wiz), "
            "SPF/DMARC email security, and live status page health."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Company domain to audit (e.g., 'linear.app', 'vanta.com', 'drata.com').",
                }
            },
            "required": ["domain"],
        },
    },
    {
        "name": "batch_audit_vendor_domains",
        "description": "Concurrently audit multiple vendor domains for Trust Center platforms, SOC 2 / ISO 27001 compliance, AI sub-processors, and DNS Identity stacks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of company domains to audit concurrently (up to 15 domains).",
                }
            },
            "required": ["domains"],
        },
    },
]


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
        "status_page_url": status_info.get("status_page_url"),
        "status_page_indicator": status_info["status_page_indicator"],
        "grc_summary": grc_summary,
        "b2b_sales_signal": sales_signal,
    }


async def handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {
                    "name": "trust-center-iam-auditor",
                    "version": "0.1.5",
                },
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}}
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            if name == "audit_vendor_domain":
                domain = args.get("domain", "vanta.com")
                res = await audit_vendor_domain(domain)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]},
                }
            if name == "batch_audit_vendor_domains":
                domains = args.get("domains") or []
                results = await asyncio.gather(*(audit_vendor_domain(d) for d in domains[:15]))
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(results, indent=2)}]},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {name}"},
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error auditing domain: {exc}"}],
                    "isError": True,
                },
            }
    if req_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


async def stdio_loop() -> None:
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        raw = line.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            continue
        resp = await handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(stdio_loop())
