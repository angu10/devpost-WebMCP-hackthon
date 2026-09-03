# WebMCP Guard Studio API

Stateless FastAPI service for static WebMCP risk analysis and optional Prompt Guard model scanning.

The scanner is domain-neutral. Send any WebMCP tool definition plus optional representative `sample_input` and `sample_output` payloads to validate schema fit, sensitive data exposure, prompt-injection content, and approval policy.

## Endpoints

```text
GET  /health
POST /scan/prompt
POST /scan/tool
POST /import/tool-url
POST /generate/guarded-code
```

## Scanner Modes

```text
SCANNER_MODE=heuristic  Use deterministic pattern checks only.
SCANNER_MODE=auto       Try Meta LlamaFirewall, then Prompt Guard only when HF_TOKEN or MODEL_AUTO_WITHOUT_TOKEN=true is set.
SCANNER_MODE=model      Try Transformers Prompt Guard, then heuristic fallback.
```

Use `PROMPT_GUARD_MODEL=meta-llama/Llama-Prompt-Guard-2-22M` for the smallest Prompt Guard 2 model path.

The base `requirements.txt` installs only the lightweight API dependencies (heuristic scanner). For `SCANNER_MODE=model` or `auto`, install the optional ML stack with `pip install -r requirements-ml.txt` — not suitable for the Render free tier (512 MB RAM).
