"""
ONYX CTI Platform — LLM Security Guardrails Engine
Declarative YAML-driven input/output validation inspired by NeMo Guardrails.
Blocks prompt injection, jailbreaks, off-topic queries, and output leakage.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("onyx.guardrails")

# ── Result Types ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class GuardrailResult:
    """Immutable result of a guardrail check."""

    allowed: bool
    violation_type: str | None = None
    detail: str = ""


# ── Engine ───────────────────────────────────────────────────────────────────


class GuardrailsEngine:
    """
    YAML-driven guardrail engine for LLM input/output validation.

    Loads ``guardrails_config.yml`` once at first use, compiles all
    regex patterns for performance, and exposes ``validate_input``
    and ``validate_output`` methods.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        self._config: dict[str, Any] = {}
        self._compiled_input: dict[str, list[re.Pattern[str]]] = {}
        self._compiled_output: dict[str, list[re.Pattern[str]]] = {}
        self._cti_keywords: list[str] = []
        self._scope_min_words: int = 8
        self._max_input_length: int = 4000
        self._max_output_length: int = 16000
        self._loaded: bool = False
        self._config_path = config_path

    # ── Lazy loader ──────────────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        """Load and compile YAML config exactly once."""
        if self._loaded:
            return

        if self._config_path:
            path = Path(self._config_path)
        else:
            # Default: look for guardrails_config.yml relative to the API package
            path = Path(__file__).resolve().parent.parent.parent / "guardrails_config.yml"

        if not path.exists():
            logger.warning(
                "guardrails.config_missing",
                extra={"path": str(path)},
            )
            self._loaded = True
            return

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        self._config = raw.get("guardrails", {})
        inp = self._config.get("input", {})
        out = self._config.get("output", {})

        # Compile input patterns
        self._compiled_input = {
            "prompt_injection": self._compile_patterns(
                inp.get("prompt_injection_patterns", [])
            ),
            "jailbreak": self._compile_patterns(
                inp.get("jailbreak_patterns", [])
            ),
            "blocked_topics": self._compile_patterns(
                inp.get("blocked_topics", [])
            ),
        }

        # Compile output patterns
        self._compiled_output = {
            "pii": self._compile_patterns(out.get("pii_patterns", [])),
            "credentials": self._compile_patterns(
                out.get("credential_patterns", [])
            ),
            "toxic": self._compile_patterns(out.get("toxic_patterns", [])),
        }

        self._cti_keywords = [kw.lower() for kw in inp.get("cti_scope_keywords", [])]
        self._scope_min_words = inp.get("scope_check_min_words", 8)
        self._max_input_length = inp.get("max_length", 4000)
        self._max_output_length = out.get("max_length", 16000)

        logger.info(
            "guardrails.loaded",
            extra={
                "input_rules": sum(len(v) for v in self._compiled_input.values()),
                "output_rules": sum(len(v) for v in self._compiled_output.values()),
                "cti_keywords": len(self._cti_keywords),
            },
        )
        self._loaded = True

    @staticmethod
    def _compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
        """Compile a list of regex strings into ``re.Pattern`` objects."""
        compiled: list[re.Pattern[str]] = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, re.IGNORECASE))
            except re.error as exc:
                logger.warning(
                    "guardrails.bad_pattern",
                    extra={"pattern": p, "error": str(exc)},
                )
        return compiled

    # ── Input Validation ─────────────────────────────────────────────────

    def validate_input(self, text: str) -> GuardrailResult:
        """
        Validate a user prompt against all input guardrails.

        Returns ``GuardrailResult(allowed=True)`` if the prompt is clean,
        or a detailed violation result otherwise.
        """
        self._ensure_loaded()

        # --- Length check ---
        if len(text) > self._max_input_length:
            return GuardrailResult(
                allowed=False,
                violation_type="input_length",
                detail=f"Input exceeds maximum length ({self._max_input_length} chars).",
            )

        lower = text.lower()

        # --- Prompt injection ---
        for pattern in self._compiled_input.get("prompt_injection", []):
            if pattern.search(lower):
                return GuardrailResult(
                    allowed=False,
                    violation_type="prompt_injection",
                    detail="Prompt injection attempt detected.",
                )

        # --- Jailbreak ---
        for pattern in self._compiled_input.get("jailbreak", []):
            if pattern.search(lower):
                return GuardrailResult(
                    allowed=False,
                    violation_type="jailbreak",
                    detail="Jailbreak attempt detected.",
                )

        # --- Blocked topics (offensive intent) ---
        for pattern in self._compiled_input.get("blocked_topics", []):
            if pattern.search(lower):
                return GuardrailResult(
                    allowed=False,
                    violation_type="blocked_topic",
                    detail="Offensive or weapon-building content blocked.",
                )

        # --- CTI scope enforcement (long queries only) ---
        word_count = len(text.split())
        if word_count >= self._scope_min_words and self._cti_keywords:
            has_cti_keyword = any(kw in lower for kw in self._cti_keywords)

            # Allow raw IOC patterns (IP / hash) regardless
            ioc_pattern = (
                r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
                r"|[a-fA-F0-9]{32,64}"  # hash
            )
            has_ioc = bool(re.search(ioc_pattern, text))

            if not has_cti_keyword and not has_ioc:
                return GuardrailResult(
                    allowed=False,
                    violation_type="out_of_scope",
                    detail="Query does not contain relevant CTI/OSINT context.",
                )

        return GuardrailResult(allowed=True)

    # ── Output Validation ────────────────────────────────────────────────

    def validate_output(self, text: str) -> GuardrailResult:
        """
        Validate LLM output for PII leakage, credential exposure,
        or toxic content before returning to the user.
        """
        self._ensure_loaded()

        # --- Length check ---
        if len(text) > self._max_output_length:
            return GuardrailResult(
                allowed=False,
                violation_type="output_length",
                detail=f"Output exceeds maximum length ({self._max_output_length} chars).",
            )

        # --- PII ---
        for pattern in self._compiled_output.get("pii", []):
            if pattern.search(text):
                return GuardrailResult(
                    allowed=False,
                    violation_type="pii_leakage",
                    detail="Potential PII detected in LLM output.",
                )

        # --- Credential leakage ---
        for pattern in self._compiled_output.get("credentials", []):
            if pattern.search(text):
                return GuardrailResult(
                    allowed=False,
                    violation_type="credential_leakage",
                    detail="Potential credential/API key leakage detected in output.",
                )

        # --- Toxic content ---
        for pattern in self._compiled_output.get("toxic", []):
            if pattern.search(text):
                return GuardrailResult(
                    allowed=False,
                    violation_type="toxic_content",
                    detail="Harmful content detected in LLM output.",
                )

        return GuardrailResult(allowed=True)


# ── Singleton ────────────────────────────────────────────────────────────────

guardrails_engine = GuardrailsEngine()
