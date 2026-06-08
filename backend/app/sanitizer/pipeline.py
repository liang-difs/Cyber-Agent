"""
Sanitizer pipeline — strips PII and credentials before LLM exposure.

Mandatory: all pcap-derived data MUST pass through this pipeline before
being sent to the LLM as an Observation.

Rules:
- Replace internal IPs with placeholders (10.x, 172.16-31.x, 192.168.x)
- Strip passwords, API keys, tokens from payloads
- Replace email addresses with [REDACTED_EMAIL]
- Replace credit card numbers with [REDACTED_CC]
- Replace SSN patterns with [REDACTED_SSN]
- Keep external IPs intact (for threat intel)
- Log all redactions to audit trail
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PASSWORD_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+"
)
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})\b"
)


@dataclass
class SanitizeResult:
    sanitized_text: str
    redaction_count: int = 0
    redaction_types: dict[str, int] = field(default_factory=dict)
    original_length: int = 0
    sanitized_length: int = 0


class SanitizerPipeline:
    def sanitize(self, text: str) -> SanitizeResult:
        result = SanitizeResult(
            sanitized_text=text,
            original_length=len(text),
        )

        for name, pattern, replacement in self._rules():
            result.sanitized_text, n = self._apply_rule(
                result.sanitized_text, pattern, replacement
            )
            if n > 0:
                result.redaction_count += n
                result.redaction_types[name] = result.redaction_types.get(name, 0) + n

        result.sanitized_length = len(result.sanitized_text)

        if result.redaction_count > 0:
            logger.info(
                "Sanitizer: %d redactions (types: %s)",
                result.redaction_count,
                result.redaction_types,
            )

        return result

    @staticmethod
    def _rules() -> list[tuple[str, re.Pattern, str | callable]]:
        return [
            ("email", _EMAIL_RE, "[REDACTED_EMAIL]"),
            ("credit_card", _CC_RE, "[REDACTED_CC]"),
            ("ssn", _SSN_RE, "[REDACTED_SSN]"),
            ("credential", _PASSWORD_RE, lambda m: f"{m.group(1)}: [REDACTED]"),
            ("private_ip", _PRIVATE_IP_RE, "[REDACTED_IP]"),
        ]

    @staticmethod
    def _apply_rule(text: str, pattern: re.Pattern, replacement) -> tuple[str, int]:
        matches = pattern.findall(text)
        if not matches:
            return text, 0
        if callable(replacement):
            text = pattern.sub(replacement, text)
        else:
            text = pattern.sub(replacement, text)
        return text, len(matches)


sanitizer = SanitizerPipeline()
