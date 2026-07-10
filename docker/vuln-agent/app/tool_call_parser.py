"""LLM 응답에서 첫 번째 유효한 tool-call JSON 객체를 추출한다."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional


def extract_tool_call(text: str) -> Optional[Dict[str, Any]]:
    """Return the first JSON object with a tool name and object-shaped args.

    설명 문장이나 Markdown code fence가 함께 와도 모든 여는 중괄호를 JSON
    시작 후보로 검사한다. 이 방식은 중첩된 ``args`` 객체를 정규식 없이 읽고,
    객체가 아닌 ``args``는 실행 경계 전에 거부한다.
    """
    decoder = json.JSONDecoder()

    for index, char in enumerate(text):
        if char != "{":
            continue

        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue

        if not isinstance(value, dict):
            continue
        if not isinstance(value.get("tool"), str) or not value["tool"]:
            continue

        args = value.get("args", {})
        if not isinstance(args, dict):
            continue

        value["args"] = args
        return value

    return None
