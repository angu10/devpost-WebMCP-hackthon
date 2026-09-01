from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from .analyzer import analyze_tool
from .schemas import CodegenResponse, GuardPolicy


def generate_guarded_code(tool: dict[str, Any], policy: GuardPolicy | None = None) -> CodegenResponse:
    if policy is None:
        policy = analyze_tool(tool).guard_policy

    normalized = deepcopy(tool)
    name = str(normalized.get("name") or "unnamed_tool")
    title = str(normalized.get("title") or name.replace("_", " ").title())
    description = str(normalized.get("description") or f"Execute {name}.")
    input_schema = deepcopy(normalized.get("inputSchema") or {"type": "object", "properties": {}})
    input_schema.setdefault("type", "object")
    input_schema.setdefault("properties", {})
    input_schema["additionalProperties"] = False

    annotations = deepcopy(normalized.get("annotations") or {})
    annotations["readOnlyHint"] = policy.read_only_hint
    annotations["untrustedContentHint"] = policy.untrusted_content_hint

    safe_function_name = _safe_function_name(name)
    schema_json = json.dumps(input_schema, indent=2)
    annotations_json = json.dumps(annotations, indent=2)
    policy_json = json.dumps(policy.model_dump(), indent=2)

    code = f"""const {safe_function_name}Schema = {schema_json};
const {safe_function_name}Policy = {policy_json};

function truncateToolOutput(value, maxChars = {policy.max_output_chars}) {{
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  return serialized.length > maxChars ? serialized.slice(0, maxChars) + "...[truncated]" : serialized;
}}

async function requestHumanApproval(toolName, input, policy) {{
  // Replace this with your app's confirmation modal or approval queue.
  const message = `${{toolName}} wants to perform a ${{policy.tool_type}} action. Approve?`;
  return window.confirm(message);
}}

function auditToolCall(event) {{
  // Keep this stateless in the demo. Production apps should send it to an audit sink.
  console.info("[WebMCP audit]", {{
    timestamp: new Date().toISOString(),
    ...event
  }});
}}

async function executeOriginalHandler(input, context) {{
  // Replace with the original app action. Keep consequential actions server-side.
  return {{
    status: "prepared",
    dryRun: {str(policy.dry_run_default).lower()},
    tool: "{name}",
    input
  }};
}}

await document.modelContext.registerTool({{
  name: "{name}",
  title: "{_escape_js(title)}",
  description: "{_escape_js(description)}",
  inputSchema: {safe_function_name}Schema,
  annotations: {annotations_json},
  execute: async (input, context = {{}}) => {{
    auditToolCall({{ tool: "{name}", phase: "requested", input }});

    if ({str(policy.requires_approval).lower()}) {{
      const approved = await requestHumanApproval("{name}", input, {safe_function_name}Policy);
      auditToolCall({{ tool: "{name}", phase: approved ? "approved" : "rejected" }});
      if (!approved) {{
        return JSON.stringify({{ status: "blocked", reason: "human_approval_required" }});
      }}
    }}

    const result = await executeOriginalHandler(input, context);
    const output = truncateToolOutput(result, {safe_function_name}Policy.max_output_chars);
    auditToolCall({{ tool: "{name}", phase: "completed", outputChars: output.length }});
    return output;
  }}
}});
"""

    notes = [
        "Generated code adds WebMCP annotations, output truncation, audit events, and a human approval gate when required.",
        "Replace executeOriginalHandler with the app's real implementation.",
        "Keep sensitive execution on the server and return only minimal fields to the agent.",
    ]

    return CodegenResponse(code=code, notes=notes, policy=policy)


def _safe_function_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"tool_{cleaned}"
    return cleaned


def _escape_js(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
