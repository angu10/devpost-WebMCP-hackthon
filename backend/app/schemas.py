from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["info", "low", "medium", "high", "critical"]
RiskLevel = Literal["low", "medium", "high", "critical"]
ToolType = Literal["read_only", "write", "sensitive"]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    detail: str
    recommendation: str
    evidence: str | None = None
    path: str | None = None


class PromptScanRequest(BaseModel):
    text: str = Field(default="", max_length=12000)
    surface: str = Field(default="tool_description", max_length=80)


class PromptScanResult(BaseModel):
    decision: Literal["allow", "review", "block"]
    score: float = Field(ge=0, le=1)
    labels: list[str] = Field(default_factory=list)
    matches: list[str] = Field(default_factory=list)
    backend: str
    model_name: str | None = None
    truncated: bool = False


class ToolScanRequest(BaseModel):
    tool: dict[str, Any]
    sample_input: dict[str, Any] | list[Any] | str | int | float | bool | None = None
    sample_output: dict[str, Any] | list[Any] | str | int | float | bool | None = None


class ToolImportRequest(BaseModel):
    url: str = Field(max_length=2048)


class ToolImportResponse(BaseModel):
    tool: dict[str, Any]
    sample_input: dict[str, Any] | list[Any] | str | int | float | bool | None = None
    sample_output: dict[str, Any] | list[Any] | str | int | float | bool | None = None
    source_url: str
    warnings: list[str] = Field(default_factory=list)


class GuardPolicy(BaseModel):
    tool_type: ToolType
    requires_approval: bool
    dry_run_default: bool
    read_only_hint: bool
    untrusted_content_hint: bool
    max_output_chars: int = 1500
    reason: str


class ToolAnalysis(BaseModel):
    tool_name: str
    risk_level: RiskLevel
    score: int = Field(ge=0, le=100)
    tool_type: ToolType
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    prompt_scan: PromptScanResult
    guard_policy: GuardPolicy


class CodegenRequest(BaseModel):
    tool: dict[str, Any]
    policy: GuardPolicy | None = None


class CodegenResponse(BaseModel):
    code: str
    notes: list[str] = Field(default_factory=list)
    policy: GuardPolicy
