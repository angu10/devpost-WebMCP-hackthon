from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Any

from .schemas import PromptScanResult


MAX_SCAN_CHARS = 6000
PROMPT_GUARD_MODEL = os.getenv(
    "PROMPT_GUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-22M"
)

INJECTION_PATTERNS: list[tuple[str, str]] = [
    ("ignore_previous", r"\bignore (all )?(previous|prior|above) (instructions|messages|rules)\b"),
    ("system_prompt", r"\b(system|developer) (prompt|message|instructions?)\b"),
    ("secret_exfiltration", r"\b(reveal|print|dump|exfiltrate|send).{0,40}\b(secret|token|api key|password|credential)s?\b"),
    ("policy_override", r"\b(disable|bypass|override|turn off).{0,40}\b(safety|guard|policy|filter|approval)\b"),
    ("role_play_jailbreak", r"\b(jailbreak|dan mode|developer mode|act as an unrestricted)\b"),
    ("external_leak", r"\b(send|post|upload|forward).{0,60}\b(to|at)\b.{0,80}\b(http|webhook|email|slack|discord)\b"),
    ("hidden_instruction", r"\bdo not (tell|mention|reveal).{0,80}\b(user|developer|owner|admin)\b"),
]


def _truncate(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_SCAN_CHARS:
        return text, False
    return text[:MAX_SCAN_CHARS], True


def _heuristic_scan(text: str, surface: str, backend: str = "heuristic") -> PromptScanResult:
    scan_text, truncated = _truncate(text or "")
    matches: list[str] = []

    for label, pattern in INJECTION_PATTERNS:
        if re.search(pattern, scan_text, flags=re.IGNORECASE | re.DOTALL):
            matches.append(label)

    score = min(0.18 + 0.22 * len(matches), 0.96) if matches else 0.04
    if surface in {"tool_output", "external_content", "sample_output"} and matches:
        score = min(score + 0.12, 0.99)

    if score >= 0.72:
        decision = "block"
    elif score >= 0.34:
        decision = "review"
    else:
        decision = "allow"

    return PromptScanResult(
        decision=decision,
        score=round(score, 3),
        labels=matches,
        matches=matches,
        backend=backend,
        model_name=None,
        truncated=truncated,
    )


class ScannerEngine:
    def __init__(self) -> None:
        self.mode = os.getenv("SCANNER_MODE", "heuristic").lower()
        self.model_name = PROMPT_GUARD_MODEL
        self._tokenizer: Any | None = None
        self._model: Any | None = None
        self._model_error: str | None = None
        self._firewall: Any | None = None
        self._firewall_error: str | None = None

    def scan(self, text: str, surface: str = "tool_description") -> PromptScanResult:
        if self.mode in {"auto", "llamafirewall"}:
            result = self._scan_with_llamafirewall(text, surface)
            if result:
                return result

        should_try_model = self.mode in {"model", "transformers"} or (
            self.mode == "auto" and self._auto_model_enabled()
        )
        if should_try_model:
            result = self._scan_with_transformers(text, surface)
            if result:
                return result

        return _heuristic_scan(text, surface)

    def status(self) -> dict[str, Any]:
        backend = "heuristic"
        detail = "No model loaded yet."

        if self._firewall is not None:
            backend = "llamafirewall"
            detail = "Meta LlamaFirewall scanner is available."
        elif self._model is not None:
            backend = "transformers"
            detail = f"Prompt Guard model loaded: {self.model_name}"
        elif self._model_error:
            detail = f"Model fallback active: {self._model_error}"
        elif self._firewall_error:
            detail = f"LlamaFirewall fallback active: {self._firewall_error}"

        return {
            "mode": self.mode,
            "backend": backend,
            "model_name": self.model_name,
            "detail": detail,
        }

    def _auto_model_enabled(self) -> bool:
        return bool(os.getenv("HF_TOKEN")) or os.getenv(
            "MODEL_AUTO_WITHOUT_TOKEN", ""
        ).lower() in {"1", "true", "yes"}

    def _scan_with_llamafirewall(
        self, text: str, surface: str
    ) -> PromptScanResult | None:
        if self._firewall_error:
            return None

        try:
            if self._firewall is None:
                from llamafirewall import LlamaFirewall, Role, ScannerType

                self._firewall = LlamaFirewall(
                    {
                        Role.USER: [ScannerType.PROMPT_GUARD],
                        Role.TOOL: [ScannerType.PROMPT_GUARD],
                    }
                )

            scan_text, truncated = _truncate(text)
            result = self._firewall.scan(scan_text)
            decision_value = getattr(result, "decision", None)
            decision_text = str(
                getattr(decision_value, "name", decision_value or "")
            ).lower()
            raw_score = getattr(result, "score", None) or getattr(
                result, "risk_score", None
            )
            score = float(raw_score) if raw_score is not None else 0.5
            labels = [str(item) for item in getattr(result, "labels", [])]

            if any(word in decision_text for word in ["block", "unsafe", "malicious"]):
                decision = "block"
            elif any(word in decision_text for word in ["review", "warn"]):
                decision = "review"
            else:
                decision = "allow" if score < 0.34 else "review"

            return PromptScanResult(
                decision=decision,
                score=max(0, min(round(score, 3), 1)),
                labels=labels,
                matches=labels,
                backend="llamafirewall",
                model_name=self.model_name,
                truncated=truncated,
            )
        except Exception as exc:  # pragma: no cover - optional dependency path
            self._firewall_error = str(exc)
            return None

    def _scan_with_transformers(
        self, text: str, surface: str
    ) -> PromptScanResult | None:
        if self._model_error:
            return None

        try:
            if self._tokenizer is None or self._model is None:
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                token = os.getenv("HF_TOKEN") or None
                self._tokenizer = AutoTokenizer.from_pretrained(
                    self.model_name, token=token
                )
                self._model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name, token=token
                )
                self._model.eval()

            import torch

            scan_text, truncated = _truncate(text)
            inputs = self._tokenizer(
                scan_text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            )

            with torch.no_grad():
                logits = self._model(**inputs).logits
                probabilities = torch.softmax(logits, dim=-1)[0].tolist()

            id_to_label = getattr(self._model.config, "id2label", {}) or {}
            labels_by_score: list[tuple[str, float]] = []
            unsafe_score = 0.0

            for index, probability in enumerate(probabilities):
                label = str(id_to_label.get(index, f"label_{index}")).lower()
                labels_by_score.append((label, float(probability)))
                safe_label = any(
                    marker in label
                    for marker in ["benign", "safe", "no injection", "not"]
                )
                if not safe_label:
                    unsafe_score += float(probability)

            labels_by_score.sort(key=lambda item: item[1], reverse=True)
            top_labels = [
                f"{label}:{probability:.3f}"
                for label, probability in labels_by_score[:3]
            ]

            if unsafe_score >= 0.72:
                decision = "block"
            elif unsafe_score >= 0.34:
                decision = "review"
            else:
                decision = "allow"

            heuristic = _heuristic_scan(scan_text, surface, backend="heuristic_shadow")
            if heuristic.decision == "block" and decision == "allow":
                decision = "review"
                unsafe_score = max(unsafe_score, heuristic.score)
                top_labels.extend(heuristic.matches)

            return PromptScanResult(
                decision=decision,
                score=max(0, min(round(float(unsafe_score), 3), 1)),
                labels=top_labels,
                matches=heuristic.matches,
                backend="transformers",
                model_name=self.model_name,
                truncated=truncated,
            )
        except Exception as exc:  # pragma: no cover - model path needs network/weights
            self._model_error = str(exc)
            return None


@lru_cache(maxsize=1)
def get_scanner() -> ScannerEngine:
    return ScannerEngine()
