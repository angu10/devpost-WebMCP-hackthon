import type {
  CodegenResponse,
  HealthResponse,
  PromptScanResult,
  RuntimeData,
  ToolImportResponse,
  ToolAnalysis,
  WebMcpToolDefinition
} from "../types";
import { analyzeToolLocally, scanTextLocally } from "./localAnalysis";

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function postJson<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body),
    signal
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const response = await fetch(`${apiBaseUrl}/health`, { signal });
  if (!response.ok) {
    throw new Error(`Health check failed with ${response.status}`);
  }
  return response.json() as Promise<HealthResponse>;
}

export async function analyzeTool(
  tool: WebMcpToolDefinition,
  runtimeData: RuntimeData = {},
  signal?: AbortSignal
): Promise<ToolAnalysis> {
  try {
    return await postJson<ToolAnalysis>(
      "/scan/tool",
      {
        tool,
        sample_input: runtimeData.sampleInput,
        sample_output: runtimeData.sampleOutput
      },
      signal
    );
  } catch (error) {
    console.warn("Backend analysis unavailable, using frontend fallback.", error);
    return analyzeToolLocally(tool, runtimeData);
  }
}

export async function scanPromptText(
  text: string,
  surface: string,
  signal?: AbortSignal
): Promise<PromptScanResult> {
  try {
    return await postJson<PromptScanResult>("/scan/prompt", { text, surface }, signal);
  } catch (error) {
    console.warn("Backend prompt scan unavailable, using frontend fallback.", error);
    return scanTextLocally(text, surface);
  }
}

export async function generateGuardedCode(
  tool: WebMcpToolDefinition,
  policy?: ToolAnalysis["guard_policy"],
  signal?: AbortSignal
): Promise<CodegenResponse> {
  try {
    return await postJson<CodegenResponse>(
      "/generate/guarded-code",
      { tool, policy },
      signal
    );
  } catch (error) {
    console.warn("Backend codegen unavailable, using frontend fallback.", error);
    return generateLocalCode(tool, policy ?? analyzeToolLocally(tool).guard_policy);
  }
}

export async function importToolFromUrl(
  url: string,
  signal?: AbortSignal
): Promise<ToolImportResponse> {
  return postJson<ToolImportResponse>("/import/tool-url", { url }, signal);
}

export function getApiBaseUrl(): string {
  return apiBaseUrl;
}

function generateLocalCode(
  tool: WebMcpToolDefinition,
  policy: ToolAnalysis["guard_policy"]
): CodegenResponse {
  const inputSchema = {
    ...tool.inputSchema,
    additionalProperties: false
  };
  const annotations = {
    ...(tool.annotations ?? {}),
    readOnlyHint: policy.read_only_hint,
    untrustedContentHint: policy.untrusted_content_hint
  };

  const code = `await document.modelContext.registerTool({
  name: ${JSON.stringify(tool.name)},
  title: ${JSON.stringify(tool.title ?? tool.name)},
  description: ${JSON.stringify(tool.description)},
  inputSchema: ${JSON.stringify(inputSchema, null, 2)},
  annotations: ${JSON.stringify(annotations, null, 2)},
  execute: async (input, context = {}) => {
    console.info("[WebMCP audit]", { tool: ${JSON.stringify(tool.name)}, phase: "requested", input });
    if (${JSON.stringify(policy.requires_approval)}) {
      const approved = window.confirm("${tool.name} requires human approval. Approve?");
      if (!approved) return JSON.stringify({ status: "blocked", reason: "human_approval_required" });
    }
    return JSON.stringify({ status: "prepared", dryRun: ${JSON.stringify(policy.dry_run_default)}, input }).slice(0, ${policy.max_output_chars});
  }
});`;

  return {
    code,
    notes: ["Generated locally because the backend code generator was unavailable."],
    policy
  };
}
