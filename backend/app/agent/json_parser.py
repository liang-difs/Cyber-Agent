"""5-level fallback JSON parser for LLM output.

Parse priority chain (try each until success):
1. Direct JSON: json.loads(output)
2. Code block: regex match ```json ... ``` then parse
3. Loose extract: regex match outermost { ... } braces
4. Fix attempts: remove Chinese comments, trailing commas, single quotes
5. Structured fallback: {"error": "parse_failed", "raw": output}
"""

from __future__ import annotations

import json
import re
from typing import Any


def parse_llm_json(raw: str) -> dict[str, Any]:
    """Parse LLM output into JSON with 6-level fallback."""
    raw = raw.strip()
    if not raw:
        return {"error": "parse_failed", "raw": raw}

    # Level 1: Direct JSON
    result = _try_direct_json(raw)
    if result is not None:
        return result

    # Level 2: Extract from code block
    result = _try_code_block(raw)
    if result is not None:
        return result

    # Level 3: Loose brace extraction
    result = _try_loose_braces(raw)
    if result is not None:
        return result

    # Level 4: Fix common issues and retry
    result = _try_fix_and_parse(raw)
    if result is not None:
        return result

    # Level 5: Extract final_answer from malformed JSON
    result = _try_extract_final_answer(raw)
    if result is not None:
        return result

    # Level 6: Structured fallback
    return {"error": "parse_failed", "raw": raw}


def _try_direct_json(raw: str) -> dict[str, Any] | None:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _try_code_block(raw: str) -> dict[str, Any] | None:
    pattern = r"```(?:json)?\s*\n?(.*?)\n?\s*```"
    match = re.search(pattern, raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def _try_loose_braces(raw: str) -> dict[str, Any] | None:
    # Find the outermost balanced braces
    start = raw.find("{")
    if start == -1:
        return None

    depth = 0
    for i in range(start, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                candidate = raw[start : i + 1]
                try:
                    return json.loads(candidate)
                except (json.JSONDecodeError, TypeError):
                    return None
    return None


def _try_fix_and_parse(raw: str) -> dict[str, Any] | None:
    fixed = raw

    # Remove Chinese comments: /* ... */
    fixed = re.sub(r"/\*[\s\S]*?\*/", "", fixed)

    # Remove // comments (not inside strings)
    fixed = re.sub(r"//[^\n]*", "", fixed)

    # Remove trailing commas before } or ]
    fixed = re.sub(r",\s*([}\]])", r"\1", fixed)

    # Replace single quotes with double quotes (crude but effective for LLM output)
    # Only do this if there are no existing double quotes (avoid breaking valid JSON)
    if '"' not in fixed:
        fixed = fixed.replace("'", '"')

    # Try parsing the fixed version
    # First try direct
    result = _try_direct_json(fixed)
    if result is not None:
        return result

    # Try brace extraction on fixed version
    result = _try_loose_braces(fixed)
    if result is not None:
        return result

    return None


def _try_extract_final_answer(raw: str) -> dict[str, Any] | None:
    """Level 5: Extract final_answer from malformed JSON.

    When the LLM produces output like:
    {"final_answer": "long text with unescaped quotes...", "confidence": 0.8}
    where the inner text breaks JSON parsing, try to extract the answer directly.
    """
    if '"final_answer"' not in raw and "final_answer" not in raw:
        return None

    # Extract confidence
    confidence = 0.5
    conf_match = re.search(r'"confidence"\s*:\s*([\d.]+)', raw)
    if conf_match:
        try:
            confidence = float(conf_match.group(1))
        except ValueError:
            pass

    # Extract evidence
    evidence: list[str] = []
    ev_match = re.search(r'"evidence"\s*:\s*\[(.*?)\]', raw, re.DOTALL)
    if ev_match:
        for m in re.finditer(r'"([^"]+)"', ev_match.group(1)):
            evidence.append(m.group(1))

    # Extract answer text
    answer = None
    m = re.search(r'"final_answer"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
    if m:
        answer = m.group(1)
    if not answer:
        m = re.search(r'"final_answer"\s*:\s*"(.+)', raw)
        if m:
            answer = re.sub(r'",?\s*"(confidence|evidence)".*$', '', m.group(1), flags=re.DOTALL).rstrip('"').rstrip()

    if answer and len(answer) > 10:
        return {"final_answer": answer, "confidence": confidence, "evidence": evidence}

    return None
