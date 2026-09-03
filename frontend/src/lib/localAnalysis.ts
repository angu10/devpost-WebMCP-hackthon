import type {
  Finding,
  GuardPolicy,
  PromptScanResult,
  RuntimeData,
  ToolAnalysis,
  WebMcpToolDefinition
} from "../types";

const writeTerms = [
  "add",
  "book",
  "buy",
  "cancel",
  "checkout",
  "create",
  "delete",
  "email",
  "execute",
  "order",
  "post",
  "purchase",
  "send",
  "submit",
  "transfer",
  "update"
];

const sensitiveTerms = [
  "api key",
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
  "transfer"
];

const untrustedTerms = [
  "comment",
  "external",
  "fetch",
  "html",
  "review",
  "scrape",
  "search",
  "third-party",
  "url",
  "web"
];

const injectionPatterns: Array<[string, RegExp]> = [
  ["ignore_previous", /\bignore (all )?(previous|prior|above) (instructions|messages|rules)\b/i],
  ["system_prompt", /\b(system|developer) (prompt|message|note|instructions?|directive)\b/i],
  ["secret_exfiltration", /\b(reveal|print|dump|exfiltrate|send|post|upload|forward|email|transmit).{0,40}\b(secret|token|api key|password|credential)s?\b/i],
  ["policy_override", /\b(disable|bypass|override|turn off).{0,40}\b(safety|guard|policy|filter|approval)\b/i],
  ["role_play_jailbreak", /\b(jailbreak|dan mode|developer mode|act as an unrestricted)\b/i],
  ["external_leak", /\b(send|post|upload|forward|transmit).{0,60}\b(to|at)\b.{0,80}(https?:\/\/|www\.|webhook|email|slack|discord)/i],
  ["hidden_instruction", /\b(do not|don't|never) (tell|mention|reveal|disclose|inform).{0,80}\b(user|developer|owner|admin)\b/i],
  ["concealment", /\b(do not|don't|never|without) (tell(ing)?|mention(ing)?|disclos(e|ing)|reveal(ing)?|inform(ing)?)\b/i],
  ["silent_action", /\bsilently (post|send|call|execute|run|forward|upload)\b/i]
];

export function scanTextLocally(text: string, surface = "tool_description"): PromptScanResult {
  const matches = injectionPatterns
    .filter(([, pattern]) => pattern.test(text))
    .map(([label]) => label);

  let score = matches.length ? Math.min(0.18 + matches.length * 0.22, 0.96) : 0.04;
  if (surface.includes("output") && matches.length) {
    score = Math.min(score + 0.12, 0.99);
  }

  return {
    decision: score >= 0.72 ? "block" : score >= 0.34 ? "review" : "allow",
    score: Number(score.toFixed(3)),
    labels: matches,
    matches,
    backend: "frontend_heuristic",
    model_name: null,
    truncated: text.length > 6000
  };
}

export function analyzeToolLocally(
  tool: WebMcpToolDefinition,
  runtimeData: RuntimeData = {}
): ToolAnalysis {
  const findings: Finding[] = [];
  const serialized = JSON.stringify({ tool, runtimeData }).toLowerCase();
  const toolType = sensitiveTerms.some((term) => serialized.includes(term))
    ? "sensitive"
    : writeTerms.some((term) => serialized.includes(term))
      ? "write"
      : "read_only";
  const hasUntrusted = untrustedTerms.some((term) => serialized.includes(term));

  if (tool.annotations?.readOnlyHint === undefined) {
    findings.push({
      id: "missing-read-only-hint",
      title: "Missing readOnlyHint annotation",
      severity: toolType === "read_only" ? "medium" : "low",
      detail: "Agents need a clear signal for whether the tool changes state.",
      recommendation: "Add annotations.readOnlyHint with the correct boolean value.",
      path: "annotations.readOnlyHint"
    });
  }

  if (tool.annotations?.readOnlyHint === true && toolType !== "read_only") {
    findings.push({
      id: "misleading-read-only-hint",
      title: "readOnlyHint conflicts with tool behavior",
      severity: "high",
      detail: "The tool appears to perform a write or sensitive action.",
      recommendation: "Set readOnlyHint to false and add an approval gate.",
      path: "annotations.readOnlyHint"
    });
  }

  if (hasUntrusted && tool.annotations?.untrustedContentHint === undefined) {
    findings.push({
      id: "missing-untrusted-content-hint",
      title: "Missing untrustedContentHint",
      severity: "high",
      detail: "The tool appears to retrieve external or user-generated content.",
      recommendation: "Add untrustedContentHint and bound returned text.",
      path: "annotations.untrustedContentHint"
    });
  }

  if (tool.inputSchema?.additionalProperties !== false) {
    findings.push({
      id: "additional-properties-open",
      title: "Input schema allows unknown fields",
      severity: "medium",
      detail: "Unexpected fields can carry irrelevant instructions or oversized payloads.",
      recommendation: "Set inputSchema.additionalProperties to false.",
      path: "inputSchema.additionalProperties"
    });
  }

  Object.entries(tool.inputSchema?.properties ?? {}).forEach(([key, property]) => {
    if (property.type === "string" && property.maxLength === undefined && !property.enum?.length) {
      findings.push({
        id: `string-without-max-length-${key}`,
        title: `${key} has no maxLength`,
        severity: key === "body" || key === "prompt" ? "high" : "medium",
        detail: "Unbounded strings can carry large prompt-injection payloads.",
        recommendation: "Add maxLength and validate on the server.",
        path: `inputSchema.properties.${key}`
      });
    }
  });

  checkRuntimeInput(tool, runtimeData.sampleInput, findings);
  checkSensitivePayload(runtimeData.sampleInput, "input", "sampleInput", findings);
  checkSensitivePayload(runtimeData.sampleOutput, "output", "sampleOutput", findings);

  const promptScan = scanTextLocally(JSON.stringify({ tool, runtimeData }), "tool_definition");
  if (promptScan.decision !== "allow") {
    findings.push({
      id: "prompt-injection-detected",
      title: "Prompt-injection pattern detected",
      severity: promptScan.decision === "block" ? "critical" : "high",
      detail: "The tool definition or sample output contains instruction-like hostile content.",
      recommendation: "Move third-party text into untrusted output and limit what the agent sees.",
      evidence: promptScan.matches.join(", ")
    });
  }

  const score = Math.min(
    (toolType === "read_only" ? 8 : toolType === "write" ? 22 : 34) +
      findings.reduce((sum, finding) => {
        const weights = { info: 1, low: 4, medium: 10, high: 18, critical: 30 };
        return sum + weights[finding.severity];
      }, 0),
    100
  );

  const policy: GuardPolicy = {
    tool_type: toolType,
    requires_approval: toolType !== "read_only" || findings.some((f) => f.severity === "critical"),
    dry_run_default: toolType !== "read_only",
    read_only_hint: toolType === "read_only",
    untrusted_content_hint: hasUntrusted,
    max_output_chars: hasUntrusted ? 1200 : 1500,
    reason:
      toolType === "sensitive"
        ? "Sensitive tools require explicit user approval."
        : toolType === "write"
          ? "Write tools should be prepared in dry-run mode first."
          : "Read-only tools can execute without approval when inputs are bounded."
  };

  return {
    tool_name: tool.name,
    risk_level: score >= 78 ? "critical" : score >= 56 ? "high" : score >= 30 ? "medium" : "low",
    score,
    tool_type: toolType,
    summary: `${tool.name} is classified as ${toolType.replace("_", "-")} with ${findings.length} guardrail finding(s).`,
    findings,
    recommendations: [
      ...(policy.requires_approval ? ["Require human approval before consequential actions."] : []),
      "Record audit events for agent calls, approval decisions, and blocked calls.",
      "Constrain input schemas and minimize returned fields."
    ],
    prompt_scan: promptScan,
    guard_policy: policy
  };
}

function checkRuntimeInput(
  tool: WebMcpToolDefinition,
  sampleInput: unknown,
  findings: Finding[]
) {
  if (sampleInput === undefined || sampleInput === null) {
    return;
  }

  if (!isRecord(sampleInput)) {
    findings.push({
      id: "sample-input-not-object",
      title: "Sample input is not an object",
      severity: "medium",
      detail: "WebMCP tool input should be a JSON object matching the input schema.",
      recommendation: "Provide representative input as an object keyed by inputSchema properties.",
      path: "sampleInput"
    });
    return;
  }

  const properties = tool.inputSchema?.properties ?? {};
  const required = new Set(tool.inputSchema?.required ?? []);
  const unknownKeys = Object.keys(sampleInput).filter((key) => !(key in properties));
  const missingKeys = Array.from(required).filter((key) => !(key in sampleInput));

  if (unknownKeys.length && tool.inputSchema?.additionalProperties === false) {
    findings.push({
      id: "sample-input-unknown-fields",
      title: "Sample input contains fields outside the schema",
      severity: "medium",
      detail: "Runtime input includes keys that the declared WebMCP schema does not allow.",
      recommendation: "Remove unknown fields or explicitly add them to inputSchema with tight validation.",
      evidence: unknownKeys.join(", "),
      path: "sampleInput"
    });
  }

  if (missingKeys.length) {
    findings.push({
      id: "sample-input-missing-required",
      title: "Sample input is missing required fields",
      severity: "medium",
      detail: "The sample runtime input does not satisfy required schema fields.",
      recommendation: "Update the sample input or revise required fields to match real calls.",
      evidence: missingKeys.join(", "),
      path: "sampleInput"
    });
  }

  Object.entries(sampleInput).forEach(([key, value]) => {
    const schema = properties[key];
    if (!schema) {
      return;
    }

    if (schema.type === "string" && typeof value === "string" && schema.maxLength !== undefined) {
      if (value.length > schema.maxLength) {
        findings.push({
          id: `sample-input-too-long-${key}`,
          title: `${key} exceeds maxLength`,
          severity: "high",
          detail: "Runtime input is longer than the declared schema allows.",
          recommendation: "Reject this input before the WebMCP tool executes.",
          evidence: `${value.length} > ${schema.maxLength}`,
          path: `sampleInput.${key}`
        });
      }
    }

    if (schema.enum?.length && !schema.enum.includes(String(value))) {
      findings.push({
        id: `sample-input-invalid-enum-${key}`,
        title: `${key} is outside allowed enum values`,
        severity: "medium",
        detail: "Runtime input does not match the allowed operation set.",
        recommendation: "Reject invalid enum values and keep tool operations explicit.",
        evidence: String(value),
        path: `sampleInput.${key}`
      });
    }
  });
}

function checkSensitivePayload(
  payload: unknown,
  kind: "input" | "output",
  path: string,
  findings: Finding[]
) {
  if (payload === undefined || payload === null) {
    return;
  }

  const text = JSON.stringify(payload);
  const sensitiveKeys = ["address", "apiKey", "authorization", "creditCard", "email", "password", "phone", "secret", "ssn", "token"];
  const match = sensitiveKeys.find((key) => new RegExp(`\\b${key}\\b`, "i").test(text));
  if (!match) {
    return;
  }

  findings.push({
    id: `sensitive-${kind}-${match.toLowerCase()}`,
    title: `Sample ${kind} includes ${match}`,
    severity: "high",
    detail: `Runtime ${kind} includes data that may need redaction, minimization, or explicit user consent.`,
    recommendation: "Accept or return only the fields the agent needs, and redact sensitive values where possible.",
    evidence: match,
    path
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
