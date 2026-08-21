#!/usr/bin/env python3
"""Learner-editable raw/redacted output boundary for the Day 6 workshop."""
from __future__ import annotations

from collections.abc import Callable


ScanInput = Callable[[str], dict]


def expose_raw_personal_data(text: str, scan_input: ScanInput) -> dict:
    # 취약 구현: 전달받은 Presidio 함수를 호출하지 않고 원문을 그대로 반환한다.
    # scanner_called=False와 modified=False가 검사 우회 사실을 증거로 남긴다.
    del scan_input
    return {
        "event": "day6_secure_coding_policy",
        "lab": "day6-presidio",
        "policy": "raw-personal-data-passthrough",
        "application_decision": "allow",
        "blocking_reason": None,
        "original_text": text,
        "sanitized_text": text,
        "entity_types": [],
        "scanner_called": False,
        "modified": False,
        "upstream_called": False,
    }


def redact_personal_data_with_presidio(text: str, scan_input: ScanInput) -> dict:
    # 안전 구현: 같은 입력을 Presidio에 전달하고 비식별화된 결과를 사용한다.
    # 최종 정책은 원문이 아니라 scan 결과의 decision·entity·sanitized_text를 따른다.
    scan = scan_input(text)
    return {
        "event": "day6_secure_coding_policy",
        "lab": "day6-presidio",
        "policy": "presidio-input-redaction",
        "application_decision": scan["application_decision"],
        "blocking_reason": "pii-detected" if not scan["valid"] else None,
        "original_text": scan["original_text"],
        "sanitized_text": scan["sanitized_text"],
        "entity_types": scan["entity_types"],
        "scanner_called": True,
        "modified": scan["modified"],
        "upstream_called": False,
    }


def select_personal_data_policy(text: str, scan_input: ScanInput) -> dict:
    # NODEGOAT-LAB: DAY6 — 이 안정적인 anchor를 교재와 checker가 함께 참조한다.
    # NodeGoat 방식의 유일한 전환 지점이다. 두 return을 동시에 활성화하지 않는다.
    # 기본 image는 취약 호출이 활성화되어 있으며 수강생은 아래 두 줄의 주석만 바꾼다.
    return expose_raw_personal_data(text, scan_input)  # VULNERABLE-ACTIVE
    # return redact_personal_data_with_presidio(text, scan_input)  # SAFE-ENABLE
