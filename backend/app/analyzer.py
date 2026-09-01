from __future__ import annotations

import json
import re
from typing import Any

from .scanners import get_scanner
from .schemas import Finding, GuardPolicy, PromptScanResult, ToolAnalysis


WRITE_TERMS = {
    "add",
    "book",
    "buy",
    "cancel",
    "checkout",
    "create",
    "delete",
    "email",
    "execute",
    "modify",
    "order",
    "post",
    "purchase",
    "refund",
    "remove",
    "send",
    "submit",
    "transfer",
    "update",
    "upload",
    "write",
}

SENSITIVE_TERMS = {
    "api key",
    "bank",
    "card",
    "checkout",
    "credential",
    "delete",
    "email",
    "payment",
    "password",
    "secret",
    "submit",
    "token",
    "transfer",
}

UNTRUSTED_TERMS = {
    "comment",
    "external",
    "fetch",
    "html",
    "inbox",
    "review",
    "rss",
    "scrape",
    "search",
    "third-party",
    "url",
    "web",
}

SENSITIVE_DATA_KEYS = {
    "address",
    "apiKey",
    "authorization",
    "creditCard",
    "email",
    "password",
    "phone",
    "secret",
    "ssn",
    "token",
}


def analyze_tool(
    tool: dict[str, Any],
    sample_input: Any | None = None,
    sample_output: Any | None = None,
) -> ToolAnalysis:
    findings: list[Finding] = []
    recommendations: list[str] = []

    name = str(tool.get("name") or "unnamed_tool")
    title = str(tool.get("title") or name)
    description = str(tool.get("description") or "")
    annotations = tool.get("annotations") or {}
    input_schema = tool.get("inputSchema") or {}
    registration_options = tool.get("registrationOptions") or {}
    runtime_input = sample_input if sample_input is not None else tool.get("sampleInput")
    runtime_output = sample_output if sample_output is not None else tool.get("sampleOutput")

    searchable = " ".join(
        [
            name,
            title,
            description,
            json.dumps(input_schema, default=str),
            json.dumps(runtime_input, default=str),
            json.dumps(runtime_output, default=str),
        ]
    ).lower()

    has_write_terms = any(term in searchable for term in WRITE_TERMS)
    has_sensitive_terms = any(term in searchable for term in SENSITIVE_TERMS)
    has_untrusted_terms = any(term in searchable for term in UNTRUSTED_TERMS)

    if has_sensitive_terms:
        tool_type = "sensitive"
    elif has_write_terms:
        tool_type = "write"
    else:
        tool_type = "read_only"

    if "readOnlyHint" not in annotations:
        findings.append(
            Finding(
                id="missing-read-only-hint",
                title="Missing readOnlyHint annotation",
                severity="medium" if tool_type == "read_only" else "low",
                detail="Agents need a clear signal for whether the tool is safe to call without changing state.",
                recommendation="Add annotations.readOnlyHint with true for read-only tools and false for write tools.",
                path="annotations.readOnlyHint",
            )
        )
    elif bool(annotations.get("readOnlyHint")) and tool_type != "read_only":
        findings.append(
            Finding(
                id="misleading-read-only-hint",
                title="readOnlyHint conflicts with tool behavior",
                severity="high",
                detail="The tool appears to perform a write or sensitive action while claiming to be read-only.",
                recommendation="Set annotations.readOnlyHint to false and add an approval gate.",
                evidence=str(annotations.get("readOnlyHint")),
                path="annotations.readOnlyHint",
            )
        )

    if has_untrusted_terms and "untrustedContentHint" not in annotations:
        findings.append(
            Finding(
                id="missing-untrusted-content-hint",
                title="Missing untrustedContentHint for external content",
                severity="high",
                detail="The tool appears to retrieve or summarize user-generated or third-party content.",
                recommendation="Add annotations.untrustedContentHint and treat returned text as untrusted.",
                path="annotations.untrustedContentHint",
            )
        )

    if not description or len(description.strip()) < 24:
        findings.append(
            Finding(
                id="weak-description",
                title="Tool description is too vague",
                severity="medium",
                detail="Short descriptions make it harder for an agent to understand when the tool is appropriate.",
                recommendation="Describe the exact capability, boundaries, side effects, and approval expectations.",
                path="description",
            )
        )

    if len(description) > 700:
        findings.append(
            Finding(
                id="oversized-description",
                title="Tool description is too large",
                severity="low",
                detail="Long tool descriptions increase prompt surface area and can bury operational constraints.",
                recommendation="Move detailed instructions into app-side policy and keep the tool description concise.",
                path="description",
            )
        )

    if input_schema.get("type") != "object":
        findings.append(
            Finding(
                id="schema-not-object",
                title="Input schema should be an object",
                severity="medium",
                detail="Structured object schemas are easier to validate and safer to execute.",
                recommendation='Set inputSchema.type to "object" and define explicit properties.',
                path="inputSchema.type",
            )
        )

    if input_schema.get("additionalProperties") is not False:
        findings.append(
            Finding(
                id="additional-properties-open",
                title="Input schema allows unknown fields",
                severity="medium",
                detail="Unexpected fields can carry instructions, irrelevant data, or oversized payloads.",
                recommendation="Set inputSchema.additionalProperties to false.",
                path="inputSchema.additionalProperties",
            )
        )

    _check_properties(input_schema.get("properties") or {}, findings)
    _check_exposed_to(registration_options.get("exposedTo"), findings)
    _check_sample_input(runtime_input, input_schema, findings)
    _check_sample_output(runtime_output, findings)

    prompt_scan_text = "\n".join(
        [
            f"name: {name}",
            f"title: {title}",
            f"description: {description}",
            f"inputSchema: {json.dumps(input_schema, default=str)}",
            f"sampleInput: {json.dumps(runtime_input, default=str)}",
            f"sampleOutput: {json.dumps(runtime_output, default=str)}",
        ]
    )
    prompt_scan = get_scanner().scan(prompt_scan_text, "tool_definition")

    if prompt_scan.decision == "block":
        findings.append(
            Finding(
                id="prompt-injection-detected",
                title="Prompt-injection pattern detected",
                severity="critical",
                detail="The tool definition or sample output contains text that resembles an attempt to override agent instructions.",
                recommendation="Remove hostile instruction text from trusted fields and mark external outputs as untrusted.",
                evidence=", ".join(prompt_scan.matches or prompt_scan.labels),
            )
        )
    elif prompt_scan.decision == "review":
        findings.append(
            Finding(
                id="prompt-injection-review",
                title="Prompt-injection scanner requested review",
                severity="high",
                detail="The scanner found content that should be reviewed before exposing this tool.",
                recommendation="Inspect flagged labels and limit the amount of untrusted content returned to agents.",
                evidence=", ".join(prompt_scan.matches or prompt_scan.labels),
            )
        )

    recommendations.extend(_build_recommendations(tool_type, has_untrusted_terms, findings))

    score = _score_findings(findings, tool_type, prompt_scan)
    risk_level = _risk_level(score)
    policy = _build_policy(tool_type, has_untrusted_terms, findings)

    return ToolAnalysis(
        tool_name=name,
        risk_level=risk_level,
        score=score,
        tool_type=tool_type,
        summary=f"{name} is classified as {tool_type.replace('_', '-')} with {len(findings)} guardrail finding(s).",
        findings=findings,
        recommendations=recommendations,
        prompt_scan=prompt_scan,
        guard_policy=policy,
    )


def _check_properties(properties: dict[str, Any], findings: list[Finding]) -> None:
    for key, schema in properties.items():
        schema = schema or {}
        path = f"inputSchema.properties.{key}"
        lower_key = str(key).lower()

        if (
            schema.get("type") == "string"
            and "maxLength" not in schema
            and "enum" not in schema
        ):
            severity = "high" if lower_key in {"prompt", "content", "message", "body"} else "medium"
            findings.append(
                Finding(
                    id=f"string-without-max-length-{key}",
                    title=f"{key} has no maxLength",
                    severity=severity,
                    detail="Unbounded strings can carry large prompt-injection payloads or sensitive data.",
                    recommendation="Add a maxLength that matches the smallest practical input size.",
                    path=path,
                )
            )

        if lower_key in {"prompt", "instruction", "system", "developer_message"}:
            findings.append(
                Finding(
                    id=f"dangerous-param-name-{key}",
                    title=f"{key} is a risky parameter name",
                    severity="high",
                    detail="Parameters that invite free-form instructions increase agent confusion and injection risk.",
                    recommendation="Rename the field around the business object it controls and validate accepted values.",
                    path=path,
                )
            )

        enum_values = schema.get("enum")
        if schema.get("type") == "string" and lower_key in {"action", "operation", "mode"} and not enum_values:
            findings.append(
                Finding(
                    id=f"open-action-param-{key}",
                    title=f"{key} should use an enum",
                    severity="high",
                    detail="Open-ended action parameters can turn one tool into many undeclared capabilities.",
                    recommendation="Constrain the field with enum values and implement each operation explicitly.",
                    path=path,
                )
            )


def _check_exposed_to(exposed_to: Any, findings: list[Finding]) -> None:
    if not exposed_to:
        return

    values = exposed_to if isinstance(exposed_to, list) else [exposed_to]
    broad = [value for value in values if value in {"*", "https://*"}]
    insecure = [value for value in values if isinstance(value, str) and value.startswith("http://")]

    if broad:
        findings.append(
            Finding(
                id="broad-exposed-to",
                title="Tool has broad cross-origin exposure",
                severity="critical",
                detail="Broad exposure lets other origins request access to this tool.",
                recommendation="Expose tools only to explicit trusted origins, or keep them same-origin.",
                evidence=", ".join(map(str, broad)),
                path="registrationOptions.exposedTo",
            )
        )

    if insecure:
        findings.append(
            Finding(
                id="insecure-exposed-to",
                title="Tool exposes HTTP origins",
                severity="high",
                detail="HTTP origins are not secure enough for agent tool access.",
                recommendation="Use HTTPS-only trusted origins.",
                evidence=", ".join(map(str, insecure)),
                path="registrationOptions.exposedTo",
            )
        )


def _check_sample_input(
    sample_input: Any, input_schema: dict[str, Any], findings: list[Finding]
) -> None:
    if sample_input is None:
        return

    if not isinstance(sample_input, dict):
        findings.append(
            Finding(
                id="sample-input-not-object",
                title="Sample input is not an object",
                severity="medium",
                detail="WebMCP tool input should be sent as a JSON object matching the input schema.",
                recommendation="Provide representative sample input as an object keyed by inputSchema properties.",
                path="sampleInput",
            )
        )
        return

    properties = input_schema.get("properties") or {}
    required = set(input_schema.get("required") or [])
    unknown_keys = sorted(set(sample_input.keys()) - set(properties.keys()))
    missing_keys = sorted(key for key in required if key not in sample_input)

    if unknown_keys and input_schema.get("additionalProperties") is False:
        findings.append(
            Finding(
                id="sample-input-unknown-fields",
                title="Sample input contains fields outside the schema",
                severity="medium",
                detail="Runtime input includes keys that the declared WebMCP schema does not allow.",
                recommendation="Remove unknown fields or explicitly add them to inputSchema with tight validation.",
                evidence=", ".join(unknown_keys),
                path="sampleInput",
            )
        )

    if missing_keys:
        findings.append(
            Finding(
                id="sample-input-missing-required",
                title="Sample input is missing required fields",
                severity="medium",
                detail="The sample runtime input does not satisfy the tool's required schema fields.",
                recommendation="Update the sample input or revise the required fields to match real tool calls.",
                evidence=", ".join(missing_keys),
                path="sampleInput",
            )
        )

    for key, value in sample_input.items():
        schema = properties.get(key) or {}
        path = f"sampleInput.{key}"

        if schema.get("type") == "string" and isinstance(value, str):
            max_length = schema.get("maxLength")
            if isinstance(max_length, int) and len(value) > max_length:
                findings.append(
                    Finding(
                        id=f"sample-input-too-long-{key}",
                        title=f"{key} exceeds maxLength",
                        severity="high",
                        detail="Runtime input is longer than the declared schema allows.",
                        recommendation="Reject this input at the UI/API boundary before the tool executes.",
                        evidence=f"{len(value)} > {max_length}",
                        path=path,
                    )
                )

        enum_values = schema.get("enum")
        if enum_values and value not in enum_values:
            findings.append(
                Finding(
                    id=f"sample-input-invalid-enum-{key}",
                    title=f"{key} is outside allowed enum values",
                    severity="medium",
                    detail="Runtime input does not match the allowed operation set.",
                    recommendation="Reject invalid enum values and avoid routing arbitrary actions through one tool.",
                    evidence=str(value),
                    path=path,
                )
            )

    _check_sensitive_payload(sample_input, "input", "sampleInput", findings)


def _check_sample_output(sample_output: Any, findings: list[Finding]) -> None:
    if sample_output is None:
        return

    _check_sensitive_payload(sample_output, "output", "sampleOutput", findings)


def _check_sensitive_payload(
    payload: Any, payload_kind: str, path: str, findings: list[Finding]
) -> None:
    payload_text = json.dumps(payload, default=str)
    for key in SENSITIVE_DATA_KEYS:
        if re.search(rf"\b{re.escape(key)}\b", payload_text, re.IGNORECASE):
            findings.append(
                Finding(
                    id=f"sensitive-{payload_kind}-{key.lower()}",
                    title=f"Sample {payload_kind} includes {key}",
                    severity="high",
                    detail=f"Runtime {payload_kind} includes data that may need redaction, minimization, or explicit user consent.",
                    recommendation="Return or accept only the fields the agent needs, and redact sensitive values where possible.",
                    evidence=key,
                    path=path,
                )
            )
            break


def _build_recommendations(
    tool_type: str, has_untrusted_terms: bool, findings: list[Finding]
) -> list[str]:
    recommendations = []

    if tool_type in {"write", "sensitive"}:
        recommendations.append("Require human approval before executing consequential actions.")
        recommendations.append("Add dry-run output so the agent can prepare the action without committing it.")

    if has_untrusted_terms:
        recommendations.append("Mark returned third-party content as untrusted and limit output size.")

    if any(finding.id.startswith("string-without-max-length") for finding in findings):
        recommendations.append("Constrain string inputs with maxLength and server-side validation.")

    if any(finding.severity in {"high", "critical"} for finding in findings):
        recommendations.append("Record an audit event for every agent call, approval decision, and blocked call.")

    if not recommendations:
        recommendations.append("Keep the tool narrow, typed, and covered by explicit execution policy.")

    return recommendations


def _build_policy(
    tool_type: str, has_untrusted_terms: bool, findings: list[Finding]
) -> GuardPolicy:
    requires_approval = tool_type in {"write", "sensitive"} or any(
        finding.severity == "critical" for finding in findings
    )

    return GuardPolicy(
        tool_type=tool_type,  # type: ignore[arg-type]
        requires_approval=requires_approval,
        dry_run_default=tool_type in {"write", "sensitive"},
        read_only_hint=tool_type == "read_only",
        untrusted_content_hint=has_untrusted_terms,
        max_output_chars=1200 if has_untrusted_terms else 1500,
        reason=(
            "Sensitive tools require explicit user approval."
            if tool_type == "sensitive"
            else "Write tools should be prepared in dry-run mode first."
            if tool_type == "write"
            else "Read-only tools can execute without approval when inputs are bounded."
        ),
    )


def _score_findings(
    findings: list[Finding], tool_type: str, prompt_scan: PromptScanResult
) -> int:
    severity_points = {
        "info": 1,
        "low": 4,
        "medium": 10,
        "high": 18,
        "critical": 30,
    }
    base = 8 if tool_type == "read_only" else 22 if tool_type == "write" else 34
    total = base + sum(severity_points[finding.severity] for finding in findings)

    if prompt_scan.decision == "review":
        total += 10
    elif prompt_scan.decision == "block":
        total += 20

    return max(0, min(total, 100))


def _risk_level(score: int) -> str:
    if score >= 78:
        return "critical"
    if score >= 56:
        return "high"
    if score >= 30:
        return "medium"
    return "low"
