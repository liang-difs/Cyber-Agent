"""Encoding/Decoding Tool — CTF and reverse engineering helper.

Supports base64, hex, URL encoding, ROT13, Morse code, binary, and more.
Follows tool_protocol.md. No external dependencies.
"""

from __future__ import annotations

import base64
import binascii
import html
import codecs
import time
import urllib.parse
from typing import Any

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult

# ── Morse code table ──────────────────────────────────────────────
_MORSE_ENCODE = {
    "A": ".-",    "B": "-...",  "C": "-.-.",  "D": "-..",
    "E": ".",     "F": "..-.",  "G": "--.",   "H": "....",
    "I": "..",    "J": ".---",  "K": "-.-",   "L": ".-..",
    "M": "--",    "N": "-.",    "O": "---",   "P": ".--.",
    "Q": "--.-",  "R": ".-.",   "S": "...",   "T": "-",
    "U": "..-",   "V": "...-",  "W": ".--",   "X": "-..-",
    "Y": "-.--",  "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--",
    "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "!": "-.-.--",
    "/": "-..-.",  "(": "-.--.", ")": "-.--.-", "&": ".-...",
    ":": "---...", ";": "-.-.-.", "=": "-...-",  "+": ".-.-.",
    "-": "-....-", "_": "..--.-", '"': ".-..-.", "'": ".----.",
    "@": ".--.-.",
}
_MORSE_DECODE = {v: k for k, v in _MORSE_ENCODE.items()}


class EncodingInput(ToolInput):
    """Encoding Tool input."""

    text: str = Field(..., description="待编解码的文本")
    operation: str = Field(
        ...,
        description=(
            "操作类型。encode 系列: base64_encode, hex_encode, url_encode, "
            "html_escape, rot13, morse_encode, binary_encode。"
            "decode 系列: base64_decode, hex_decode, url_decode, "
            "html_unescape, rot13, morse_decode, binary_decode, auto_detect。"
        ),
    )


def _auto_detect(text: str) -> dict[str, Any]:
    """Try all decode operations and return those that succeed."""
    results: dict[str, Any] = {"original": text}

    # Base64
    try:
        decoded = base64.b64decode(text, validate=True)
        results["base64_decode"] = decoded.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Hex
    try:
        decoded = bytes.fromhex(text.replace(" ", ""))
        results["hex_decode"] = decoded.decode("utf-8", errors="replace")
    except Exception:
        pass

    # URL
    decoded_url = urllib.parse.unquote(text)
    if decoded_url != text:
        results["url_decode"] = decoded_url

    # HTML
    decoded_html = html.unescape(text)
    if decoded_html != text:
        results["html_unescape"] = decoded_html

    # ROT13
    rot = codecs.decode(text, "rot_13")
    if rot != text:
        results["rot13"] = rot

    # Binary (space-separated 8-bit groups)
    parts = text.strip().split()
    if all(len(p) == 8 and all(c in "01" for c in p) for p in parts) and len(parts) >= 2:
        try:
            results["binary_decode"] = "".join(chr(int(p, 2)) for p in parts)
        except Exception:
            pass

    # Morse (dots and dashes separated by spaces/slashes)
    if all(c in ".- /" for c in text) and len(text) >= 4:
        decoded_morse: list[str] = []
        for word in text.strip().split(" / "):
            chars = []
            for code in word.split():
                if code in _MORSE_DECODE:
                    chars.append(_MORSE_DECODE[code])
            decoded_morse.append("".join(chars))
        morse_result = " ".join(decoded_morse)
        if morse_result and all(c.isalpha() or c.isspace() for c in morse_result):
            results["morse_decode"] = morse_result

    results["detected_formats"] = [k for k in results if k not in ("original", "detected_formats")]
    return results


def _run_operation(text: str, operation: str) -> dict[str, Any]:
    """Execute the requested encoding/decoding operation."""

    if operation == "base64_encode":
        return {"result": base64.b64encode(text.encode()).decode(), "format": "base64"}

    if operation == "base64_decode":
        try:
            return {"result": base64.b64decode(text, validate=True).decode("utf-8", errors="replace"), "format": "plaintext"}
        except Exception as e:
            return {"error": f"Base64 decode failed: {e}"}

    if operation == "hex_encode":
        return {"result": text.encode().hex(), "format": "hex"}

    if operation == "hex_decode":
        try:
            return {"result": bytes.fromhex(text.replace(" ", "")).decode("utf-8", errors="replace"), "format": "plaintext"}
        except Exception as e:
            return {"error": f"Hex decode failed: {e}"}

    if operation == "url_encode":
        return {"result": urllib.parse.quote(text, safe=""), "format": "url_encoded"}

    if operation == "url_decode":
        return {"result": urllib.parse.unquote(text), "format": "plaintext"}

    if operation == "html_escape":
        return {"result": html.escape(text), "format": "html"}

    if operation == "html_unescape":
        return {"result": html.unescape(text), "format": "plaintext"}

    if operation == "rot13":
        return {"result": codecs.decode(text, "rot_13"), "format": "plaintext"}

    if operation == "binary_encode":
        return {"result": " ".join(format(ord(c), "08b") for c in text), "format": "binary"}

    if operation == "binary_decode":
        try:
            parts = text.strip().split()
            return {"result": "".join(chr(int(p, 2)) for p in parts), "format": "plaintext"}
        except Exception as e:
            return {"error": f"Binary decode failed: {e}"}

    if operation == "morse_encode":
        encoded: list[str] = []
        for ch in text.upper():
            if ch == " ":
                encoded.append("/")
            elif ch in _MORSE_ENCODE:
                encoded.append(_MORSE_ENCODE[ch])
        return {"result": " ".join(encoded), "format": "morse"}

    if operation == "morse_decode":
        decoded: list[str] = []
        for word in text.strip().split(" / "):
            chars = []
            for code in word.split():
                if code in _MORSE_DECODE:
                    chars.append(_MORSE_DECODE[code])
            decoded.append("".join(chars))
        return {"result": " ".join(decoded), "format": "plaintext"}

    if operation == "auto_detect":
        return _auto_detect(text)

    return {"error": f"Unknown operation: {operation}"}


class EncodingTool:
    """编解码工具 — 支持 base64/hex/url/html/rot13/morse/binary/auto_detect。"""

    name = "encoding_tool"
    version = "v1"
    input_class = EncodingInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": (
                    "文本编解码工具，支持 base64、hex、URL encoding、HTML entity、"
                    "ROT13、Morse code、二进制编解码，以及自动检测编码格式。"
                    "CTF/逆向分析常用。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "待编解码的文本"},
                        "operation": {
                            "type": "string",
                            "enum": [
                                "base64_encode", "base64_decode",
                                "hex_encode", "hex_decode",
                                "url_encode", "url_decode",
                                "html_escape", "html_unescape",
                                "rot13",
                                "binary_encode", "binary_decode",
                                "morse_encode", "morse_decode",
                                "auto_detect",
                            ],
                            "description": "编解码操作类型",
                        },
                    },
                    "required": ["text", "operation"],
                },
            },
        }

    async def execute(self, input_data: EncodingInput) -> ToolResult:
        start = time.monotonic()
        try:
            result = _run_operation(input_data.text, input_data.operation)
            has_error = "error" in result
            return ToolResult(
                success=not has_error,
                tool_name=self.name,
                tool_version=self.version,
                data=result,
                error=result.get("error"),
                confidence=0.95 if not has_error else 0.0,
                evidence_source=["local_computation"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=str(e),
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )
