export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type ToolType = "read_only" | "write" | "sensitive";

export interface JsonSchemaProperty {
  type?: string;
  description?: string;
  enum?: string[];
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  [key: string]: unknown;
}

export interface WebMcpToolDefinition {
  name: string;
  title?: string;
  description: string;
  inputSchema: {
    type?: string;
    properties?: Record<string, JsonSchemaProperty>;
    required?: string[];
    additionalProperties?: boolean;
    [key: string]: unknown;
  };
  annotations?: {
    readOnlyHint?: boolean;
    untrustedContentHint?: boolean;
    [key: string]: unknown;
  };
  registrationOptions?: {
    exposedTo?: string | string[];
    [key: string]: unknown;
  };
}

export interface RuntimeData {
  sampleInput?: unknown;
  sampleOutput?: unknown;
}

export interface ToolFixture {
  id: string;
  label: string;
  domain: string;
  tool: WebMcpToolDefinition;
  sampleInput: unknown;
  sampleOutput: unknown;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  detail: string;
  recommendation: string;
  evidence?: string | null;
  path?: string | null;
}

export interface PromptScanResult {
  decision: "allow" | "review" | "block";
  score: number;
  labels: string[];
  matches: string[];
  backend: string;
  model_name?: string | null;
  truncated: boolean;
}

export interface GuardPolicy {
  tool_type: ToolType;
  requires_approval: boolean;
  dry_run_default: boolean;
  read_only_hint: boolean;
  untrusted_content_hint: boolean;
  max_output_chars: number;
  reason: string;
}

export interface ToolAnalysis {
  tool_name: string;
  risk_level: RiskLevel;
  score: number;
  tool_type: ToolType;
  summary: string;
  findings: Finding[];
  recommendations: string[];
  prompt_scan: PromptScanResult;
  guard_policy: GuardPolicy;
}

export interface CodegenResponse {
  code: string;
  notes: string[];
  policy: GuardPolicy;
}

export interface ToolImportResponse {
  tool: WebMcpToolDefinition;
  sample_input?: unknown;
  sample_output?: unknown;
  source_url: string;
  warnings: string[];
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: "user" | "agent" | "system";
  action: string;
  status: "ok" | "review" | "blocked";
  detail: string;
}

export interface HealthResponse {
  service: string;
  status: string;
  stateless: boolean;
  scanner: {
    mode: string;
    backend: string;
    model_name: string;
    detail: string;
  };
}
