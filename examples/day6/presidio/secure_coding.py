#!/usr/bin/env python3
"""Learner-editable raw/redacted output boundary for the Day 6 workshop."""
from __future__ import annotations

from collections.abc import Callable


ScanInput = Callable[[str], dict]


def expose_raw_personal_data(text: str, scan_input: ScanInput) -> dict:
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
