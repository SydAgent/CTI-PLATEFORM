"""
ONYX CTI Platform — LLM Security Guardrails
NeMo-Guardrails-inspired dual-layer validation engine.

Input Layer:  Prompt injection, jailbreak, offensive intent, scope enforcement.
Output Layer: PII/credential leakage, toxic content, length sanity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger("onyx.guardrails")


@dataclass(frozen=True)
class GuardrailResult:
    """Immutable result of a guardrail check."""
    allowed: bool
    reason: str
    violation_type: str = ""  # e.g., "prompt_injection", "jailbreak", "scope"


class OnyxGuardrails:
    """
    Production-grade LLM security guardrails.
    Loads policy from a YAML configuration file and enforces input/output
    validation with compiled regex patterns for sub-millisecond checks.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        if config_path is None:
            # Resolve relative to the onyx-api package root
            config_path = Path(__file__).resolve().parent.parent.parent / "guardrails_config.yml"
        self._config_path = Path(config_path)
        self._input_cfg: dict[str, Any] = {}
        self._output_cfg: dict[str, Any] = {}

        # Compiled regex caches
        self._injection_patterns: list[re.Pattern[str]] = []
        self._jailbreak_patterns: list[re.Pattern[str]] = []
        self._blocked_patterns: list[re.Pattern[str]] = []
        self._scope_keywords: list[re.Pattern[str]] = []
        self._pii_patterns: list[re.Pattern[str]] = []
        self._credential_patterns: list[re.Pattern[str]] = []
        self._toxic_patterns: list[re.Pattern[str]] = []

        self._load_config()
        logger.info("onyx.guardrails.initialized", config=str(self._config_path))

    # ── Config Loading ─────────────────────────────────────────────────────

    def _load_config(self) -> None:
        """Load and compile all guardrail patterns from YAML."""
        try:
            with open(self._config_path, encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning("onyx.guardrails.config_missing", path=str(self._config_path))
            raw = {"guardrails": {"input": {}, "output": {}}}

        cfg = raw.get("guardrails", {})
        self._input_cfg = cfg.get("input", {})
        self._output_cfg = cfg.get("output", {})

        # Compile input patterns
        self._injection_patterns = self._compile_list(
            self._input_cfg.get("prompt_injection_patterns", [])
        )
        self._jailbreak_patterns = self._compile_list(
            self._input_cfg.get("jailbreak_patterns", [])
        )
        self._blocked_patterns = self._compile_list(
            self._input_cfg.get("blocked_topics", [])
        )
        self._scope_keywords = self._compile_list(
            self._input_cfg.get("cti_scope_keywords", [])
        )

        # Compile output patterns
        self._pii_patterns = self._compile_list(
            self._output_cfg.get("pii_patterns", [])
        )
        self._credential_patterns = self._compile_list(
            self._output_cfg.get("credential_patterns", [])
        )
        self._toxic_patterns = self._compile_list(
            self._output_cfg.get("toxic_patterns", [])
        )

    @staticmethod
    def _compile_list(patterns: list[str]) -> list[re.Pattern[str]]:
        """Compile a list of regex strings into Pattern objects."""
        compiled: list[re.Pattern[str]] = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, re.IGNORECASE))
            except re.error:
                logger.warning("onyx.guardrails.bad_pattern", pattern=p)
        return compiled

    # ── Input Validation ───────────────────────────────────────────────────

    def validate_input(self, text: str) -> GuardrailResult:
        """
        Validate user input against all input guardrail policies.
        Returns GuardrailResult(allowed=False, ...) on first violation.
        """
        if not text or not text.strip():
            return GuardrailResult(allowed=False, reason="Empty input.", violation_type="empty")

        # Length check
        max_len = self._input_cfg.get("max_length", 4000)
        if len(text) > max_len:
            return GuardrailResult(
                allowed=False,
                reason=f"Input exceeds maximum length ({max_len} characters).",
                violation_type="length",
            )

        text_lower = text.lower()

        # 1. Prompt injection detection
        for pattern in self._injection_patterns:
            if pattern.search(text_lower):
                logger.warning(
                    "onyx.guardrails.injection_blocked",
                    pattern=pattern.pattern,
                    input_preview=text[:80],
                )
                return GuardrailResult(
                    allowed=False,
                    reason="Security policy violation detected.",
                    violation_type="prompt_injection",
                )

        # 2. Jailbreak detection
        for pattern in self._jailbreak_patterns:
            if pattern.search(text_lower):
                logger.warning(
                    "onyx.guardrails.jailbreak_blocked",
                    pattern=pattern.pattern,
                    input_preview=text[:80],
                )
                return GuardrailResult(
                    allowed=False,
                    reason="Security policy violation detected.",
                    violation_type="jailbreak",
                )

        # 3. Offensive topic blocking
        for pattern in self._blocked_patterns:
            if pattern.search(text_lower):
                logger.warning(
                    "onyx.guardrails.offensive_blocked",
                    pattern=pattern.pattern,
                )
                return GuardrailResult(
                    allowed=False,
                    reason="Request contains prohibited content.",
                    violation_type="offensive",
                )

        # 4. CTI scope enforcement (only for longer queries)
        min_words = self._input_cfg.get("scope_check_min_words", 8)
        word_count = len(text.split())
        if word_count > min_words and self._scope_keywords:
            scope_match = any(kw.search(text_lower) for kw in self._scope_keywords)
            # Also allow bare IOC formats
            is_bare_ioc = bool(
                re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", text.strip())
                or re.match(r"^[a-fA-F0-9]{32,64}$", text.strip())
            )
            if not scope_match and not is_bare_ioc:
                return GuardrailResult(
                    allowed=False,
                    reason="Query is outside the scope of Cyber Threat Intelligence.",
                    violation_type="scope",
                )

        return GuardrailResult(allowed=True, reason="Input validated.")

    # ── Output Validation ──────────────────────────────────────────────────

    def validate_output(self, text: str) -> GuardrailResult:
        """
        Validate LLM output for PII leakage, credential exposure,
        toxic content, and length sanity.
        """
        if not text:
            return GuardrailResult(allowed=True, reason="Empty output — pass.")

        # Length check
        max_len = self._output_cfg.get("max_length", 16000)
        if len(text) > max_len:
            return GuardrailResult(
                allowed=False,
                reason="Response exceeds maximum allowed length.",
                violation_type="output_length",
            )

        # Credential leakage (highest priority)
        for pattern in self._credential_patterns:
            if pattern.search(text):
                logger.warning("onyx.guardrails.credential_leak_blocked")
                return GuardrailResult(
                    allowed=False,
                    reason="Response redacted — potential credential exposure.",
                    violation_type="credential_leak",
                )

        # Toxic content
        for pattern in self._toxic_patterns:
            if pattern.search(text):
                logger.warning("onyx.guardrails.toxic_output_blocked")
                return GuardrailResult(
                    allowed=False,
                    reason="Response redacted — safety policy violation.",
                    violation_type="toxic_output",
                )

        return GuardrailResult(allowed=True, reason="Output validated.")
