from __future__ import annotations

import ipaddress
import json
import os
import socket
from typing import Any
from urllib.parse import urlparse

import requests
from fastapi import HTTPException

from .schemas import ToolImportResponse


MAX_IMPORT_BYTES = 300_000


def import_tool_from_url(url: str) -> ToolImportResponse:
    parsed = urlparse(url)
    allow_insecure = os.getenv("ALLOW_INSECURE_IMPORTS", "").lower() in {
        "1",
        "true",
        "yes",
    }

    if parsed.scheme not in {"https"} and not (
        allow_insecure and parsed.scheme == "http"
    ):
        raise HTTPException(
            status_code=400,
            detail="Only HTTPS import URLs are allowed. Set ALLOW_INSECURE_IMPORTS=true for local development.",
        )

    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Import URL must include a host.")

    if _is_private_host(parsed.hostname) and not os.getenv("ALLOW_PRIVATE_IMPORTS"):
        raise HTTPException(
            status_code=400,
            detail="Private, loopback, and link-local import hosts are blocked by default.",
        )

    try:
        response = requests.get(url, timeout=8, stream=True)
        response.raise_for_status()
        content = response.raw.read(MAX_IMPORT_BYTES + 1, decode_content=True)
    except requests.RequestException as exc:
        raise HTTPException(status_code=400, detail=f"Could not fetch import URL: {exc}") from exc

    if len(content) > MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Import payload exceeds {MAX_IMPORT_BYTES} bytes.",
        )

    try:
        payload = json.loads(content.decode(response.encoding or "utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Import URL must return JSON. Use a raw GitHub JSON URL or hosted tool manifest.",
        ) from exc

    imported = normalize_tool_payload(payload)
    imported.source_url = url
    return imported


def normalize_tool_payload(payload: Any) -> ToolImportResponse:
    warnings: list[str] = []

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Import payload must be a JSON object.")

    if "tool" in payload and isinstance(payload["tool"], dict):
        tool = payload["tool"]
        sample_input = payload.get("sample_input", payload.get("sampleInput"))
        sample_output = payload.get("sample_output", payload.get("sampleOutput"))
    elif "toolDefinition" in payload and isinstance(payload["toolDefinition"], dict):
        tool = payload["toolDefinition"]
        sample_input = payload.get("sample_input", payload.get("sampleInput"))
        sample_output = payload.get("sample_output", payload.get("sampleOutput"))
    elif "tools" in payload and isinstance(payload["tools"], list) and payload["tools"]:
        first = payload["tools"][0]
        if not isinstance(first, dict):
            raise HTTPException(status_code=400, detail="tools[0] must be an object.")
        tool = first.get("tool", first)
        sample_input = first.get("sample_input", first.get("sampleInput"))
        sample_output = first.get("sample_output", first.get("sampleOutput"))
        warnings.append("Imported the first tool from the tools array.")
    else:
        tool = payload
        sample_input = payload.get("sample_input", payload.get("sampleInput"))
        sample_output = payload.get("sample_output", payload.get("sampleOutput"))

    if not _looks_like_tool(tool):
        raise HTTPException(
            status_code=400,
            detail="Could not find a WebMCP-like tool. Expected name, description, and inputSchema.",
        )

    clean_tool = dict(tool)
    clean_tool.pop("sample_input", None)
    clean_tool.pop("sampleInput", None)
    clean_tool.pop("sample_output", None)
    clean_tool.pop("sampleOutput", None)

    return ToolImportResponse(
        tool=clean_tool,
        sample_input=sample_input,
        sample_output=sample_output,
        source_url="",
        warnings=warnings,
    )


def _looks_like_tool(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("name"), str)
        and isinstance(value.get("description"), str)
        and isinstance(value.get("inputSchema"), dict)
    )


def _is_private_host(hostname: str) -> bool:
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for address in addresses:
        ip_text = address[4][0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        ):
            return True

    return False
