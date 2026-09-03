import type {
  AuditEvent,
  CodegenResponse,
  PromptScanResult,
  RuntimeData,
  ToolImportResponse,
  ToolAnalysis,
  WebMcpToolDefinition
} from "../types";
import { analyzeTool, generateGuardedCode, importToolFromUrl, scanPromptText } from "./api";

interface WebMcpExecutionContext {
  signal?: AbortSignal;
}

interface WebMcpRegistration {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  execute: (input: Record<string, unknown>, context?: WebMcpExecutionContext) => Promise<string>;
}

declare global {
  interface Document {
    modelContext?: {
      registerTool: (
        tool: WebMcpRegistration,
        options?: Record<string, unknown>
      ) => Promise<void> | void;
    };
  }
}

interface RegisterOptions {
  getSelectedTool: () => WebMcpToolDefinition;
  getRuntimeData: () => RuntimeData;
  getToolByName: (name: string) => WebMcpToolDefinition | undefined;
  loadImportedPayload: (payload: ToolImportResponse | unknown, source: string) => void;
  requestApproval: (request: { toolName: string; reason: string }) => Promise<boolean>;
  setAnalysis: (analysis: ToolAnalysis) => void;
  setPromptScan: (scan: PromptScanResult) => void;
  setGeneratedCode: (code: CodegenResponse) => void;
  addAudit: (event: Omit<AuditEvent, "id" | "timestamp">) => void;
}

export async function registerGuardStudioTools(options: RegisterOptions): Promise<boolean> {
  if (!document.modelContext?.registerTool) {
    return false;
  }

  const register = document.modelContext.registerTool.bind(document.modelContext);

  await register({
    name: "guardstudio_import_tool_url",
    title: "Import WebMCP Tool URL",
    description:
      "Import a hosted JSON WebMCP tool manifest, including optional representative sample input and output payloads.",
    annotations: {
      readOnlyHint: false,
      untrustedContentHint: true
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["url"],
      properties: {
        url: {
          type: "string",
          description: "HTTPS URL for a JSON tool manifest or raw GitHub JSON file.",
          maxLength: 2048
        }
      }
    },
    execute: async (input, context = {}) => {
      const url = typeof input.url === "string" ? input.url : "";
      const imported = await importToolFromUrl(url, context.signal);
      options.loadImportedPayload(imported, imported.source_url || url);

      options.addAudit({
        actor: "agent",
        action: "guardstudio_import_tool_url",
        status: "ok",
        detail: `${imported.tool.name} imported from URL`
      });

      return compact({
        tool: imported.tool.name,
        sourceUrl: imported.source_url,
        warnings: imported.warnings
      });
    }
  });

  await register({
    name: "guardstudio_analyze_tool",
    title: "Analyze WebMCP Tool",
    description:
      "Analyze a WebMCP tool definition for risky actions, prompt-injection exposure, schema gaps, and missing guard annotations.",
    annotations: {
      readOnlyHint: false,
      untrustedContentHint: false
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        toolName: {
          type: "string",
          description: "Optional sample tool name to analyze.",
          maxLength: 80
        },
        toolDefinition: {
          type: "object",
          description: "Optional complete WebMCP tool definition JSON."
        },
        sampleInput: {
          type: "object",
          description: "Optional representative input payload for the tool."
        },
        sampleOutput: {
          type: "object",
          description: "Optional representative output payload returned by the tool."
        }
      }
    },
    execute: async (input, context = {}) => {
      const namedTool =
        typeof input.toolName === "string" ? options.getToolByName(input.toolName) : undefined;
      const target =
        (input.toolDefinition as WebMcpToolDefinition | undefined) ??
        namedTool ??
        options.getSelectedTool();
      const runtimeData = getRuntimeInput(input, options.getRuntimeData());
      const analysis = await analyzeTool(target, runtimeData, context.signal);

      options.setAnalysis(analysis);
      options.addAudit({
        actor: "agent",
        action: "guardstudio_analyze_tool",
        status: analysis.risk_level === "critical" ? "blocked" : analysis.risk_level === "high" ? "review" : "ok",
        detail: `${analysis.tool_name}: ${analysis.risk_level} risk, ${analysis.findings.length} findings`
      });

      return compact({
        tool: analysis.tool_name,
        riskLevel: analysis.risk_level,
        score: analysis.score,
        topFindings: analysis.findings.slice(0, 4).map((finding) => finding.title),
        policy: analysis.guard_policy
      });
    }
  });

  await register({
    name: "guardstudio_scan_text",
    title: "Scan Text",
    description:
      "Scan tool descriptions, tool outputs, or sample agent prompts for jailbreak and prompt-injection indicators.",
    annotations: {
      readOnlyHint: true,
      untrustedContentHint: true
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["text"],
      properties: {
        text: {
          type: "string",
          description: "Text to scan.",
          maxLength: 6000
        },
        surface: {
          type: "string",
          enum: ["tool_description", "tool_output", "external_content", "user_prompt"],
          description: "Where the text came from."
        }
      }
    },
    execute: async (input, context = {}) => {
      const text = typeof input.text === "string" ? input.text : "";
      const surface = typeof input.surface === "string" ? input.surface : "tool_output";
      const scan = await scanPromptText(text, surface, context.signal);

      options.setPromptScan(scan);
      options.addAudit({
        actor: "agent",
        action: "guardstudio_scan_text",
        status: scan.decision === "block" ? "blocked" : scan.decision === "review" ? "review" : "ok",
        detail: `${scan.backend}: ${scan.decision} at ${Math.round(scan.score * 100)}%`
      });

      return compact(scan);
    }
  });

  await register({
    name: "guardstudio_generate_guarded_code",
    title: "Generate Guarded Code",
    description:
      "Generate guarded document.modelContext.registerTool code with annotations, output limits, audit events, and approval gates.",
    annotations: {
      readOnlyHint: false,
      untrustedContentHint: false
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        toolName: {
          type: "string",
          description: "Optional sample tool name to generate code for.",
          maxLength: 80
        }
      }
    },
    execute: async (input, context = {}) => {
      const namedTool =
        typeof input.toolName === "string" ? options.getToolByName(input.toolName) : undefined;
      const target = namedTool ?? options.getSelectedTool();
      const analysis = await analyzeTool(target, options.getRuntimeData(), context.signal);
      const code = await generateGuardedCode(target, analysis.guard_policy, context.signal);

      options.setAnalysis(analysis);
      options.setGeneratedCode(code);
      options.addAudit({
        actor: "agent",
        action: "guardstudio_generate_guarded_code",
        status: code.policy.requires_approval ? "review" : "ok",
        detail: `${target.name}: approval=${String(code.policy.requires_approval)}`
      });

      return compact({
        tool: target.name,
        requiresApproval: code.policy.requires_approval,
        notes: code.notes
      });
    }
  });

  await register({
    name: "guardstudio_simulate_call",
    title: "Simulate Guarded Call",
    description:
      "Simulate a WebMCP tool call under the generated guard policy. If the policy requires approval, this call pauses until a human approves or denies it in the Guard Studio approval queue.",
    annotations: {
      readOnlyHint: false,
      untrustedContentHint: false
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["toolName"],
      properties: {
        toolName: {
          type: "string",
          description: "Sample tool name to simulate.",
          maxLength: 80
        }
      }
    },
    execute: async (input, context = {}) => {
      const namedTool =
        typeof input.toolName === "string" ? options.getToolByName(input.toolName) : undefined;
      const target = namedTool ?? options.getSelectedTool();
      const runtimeData = getRuntimeInput(input, options.getRuntimeData());
      const analysis = await analyzeTool(target, runtimeData, context.signal);
      options.setAnalysis(analysis);

      let approved = true;
      if (analysis.guard_policy.requires_approval) {
        options.addAudit({
          actor: "agent",
          action: "guardstudio_simulate_call",
          status: "review",
          detail: `${target.name} paused: waiting for human approval`
        });
        approved = await options.requestApproval({
          toolName: target.name,
          reason: analysis.guard_policy.reason
        });
      }
      const blocked = analysis.guard_policy.requires_approval && !approved;

      options.addAudit({
        actor: "agent",
        action: "guardstudio_simulate_call",
        status: blocked ? "blocked" : analysis.guard_policy.requires_approval ? "review" : "ok",
        detail: blocked
          ? `${target.name} blocked: human denied the call`
          : analysis.guard_policy.requires_approval
            ? `${target.name} executed after human approval`
            : `${target.name} prepared under ${analysis.guard_policy.tool_type} policy`
      });

      return compact({
        tool: target.name,
        blocked,
        approvedByHuman: analysis.guard_policy.requires_approval ? approved : null,
        requiresApproval: analysis.guard_policy.requires_approval,
        dryRun: analysis.guard_policy.dry_run_default
      });
    }
  });

  options.addAudit({
    actor: "system",
    action: "register_webmcp_tools",
    status: "ok",
    detail: "Registered Guard Studio WebMCP tools in document.modelContext"
  });

  return true;
}

function compact(value: unknown): string {
  const serialized = JSON.stringify(value, null, 2);
  return serialized.length > 1500 ? `${serialized.slice(0, 1500)}...[truncated]` : serialized;
}

function getRuntimeInput(input: Record<string, unknown>, fallback: RuntimeData): RuntimeData {
  return {
    sampleInput: input.sampleInput ?? fallback.sampleInput,
    sampleOutput: input.sampleOutput ?? fallback.sampleOutput
  };
}
