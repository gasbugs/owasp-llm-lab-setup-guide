#!/usr/bin/env python3
"""Shared Microsoft Presidio policy core for the Day 6 CLI and HTTP API."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


FRAMEWORK = "microsoft-presidio"
FRAMEWORK_VERSION = "2.2.362"
NLP_MODEL = "en_core_web_sm"
DEFAULT_ENTITIES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IP_ADDRESS",
    "US_SSN",
    "KR_RRN",
    "DEMO_API_KEY",
)


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class PolicySettings:
    score_threshold: float = 0.5
    language: str = "en"
    input_enabled: bool = True
    output_enabled: bool = True
    entities: tuple[str, ...] = DEFAULT_ENTITIES

    @classmethod
    def from_env(cls) -> "PolicySettings":
        threshold = float(os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.5"))
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("PRESIDIO_SCORE_THRESHOLD must be between 0 and 1")
        entities = tuple(
            item.strip().upper()
            for item in os.getenv("PRESIDIO_ENTITIES", ",".join(DEFAULT_ENTITIES)).split(",")
            if item.strip()
        )
        if not entities:
            raise ValueError("PRESIDIO_ENTITIES must contain at least one entity")
        return cls(
            score_threshold=threshold,
            language=os.getenv("PRESIDIO_LANGUAGE", "en").strip().lower(),
            input_enabled=env_bool("PRESIDIO_INPUT_ENABLED", True),
            output_enabled=env_bool("PRESIDIO_OUTPUT_ENABLED", True),
            entities=entities,
        )

    def as_public_dict(self) -> dict:
        return {
            "analyzer": {
                "enabled_for_input": self.input_enabled,
                "enabled_for_output": self.output_enabled,
                "language": self.language,
                "score_threshold": self.score_threshold,
                "nlp_model": NLP_MODEL,
                "entities": list(self.entities),
            },
            "anonymizer": {
                "operator": "replace",
                "replacement_format": "<ENTITY_TYPE>",
            },
            "custom_recognizers": {
                "KR_RRN": r"\b\d{6}-[1-4]\d{6}\b",
                "DEMO_API_KEY": r"\bDEMO_API_KEY=[A-Za-z0-9-]+\b",
            },
        }


CASES = {
    "input-clean": {
        "direction": "input",
        "scanner": "PresidioAnalyzer",
        "text": "Summarize the public incident response checklist.",
        "purpose": "input without PII",
    },
    "input-email": {
        "direction": "input",
        "scanner": "PresidioAnalyzer",
        "text": "Send the report to alice@example.com after review.",
        "purpose": "email address detection and replacement",
    },
    "input-phone": {
        "direction": "input",
        "scanner": "PresidioAnalyzer",
        "text": "My phone number is +1 202-555-0123.",
        "purpose": "phone number detection and replacement",
    },
    "input-credit-card": {
        "direction": "input",
        "scanner": "PresidioAnalyzer",
        "text": "Use test card 4111 1111 1111 1111 for the sandbox purchase.",
        "purpose": "credit-card checksum recognizer",
    },
    "input-kr-rrn": {
        "direction": "input",
        "scanner": "PresidioAnalyzer+custom-recognizer",
        "text": "교육용 합성 주민번호는 900101-1234567 입니다.",
        "purpose": "project custom Korean resident-number recognizer",
    },
    "output-clean": {
        "direction": "output",
        "scanner": "PresidioAnalyzer+Anonymizer",
        "prompt": "Return a generic status message.",
        "text": "The service is operating normally.",
        "purpose": "output without PII",
    },
    "output-email": {
        "direction": "output",
        "scanner": "PresidioAnalyzer+Anonymizer",
        "prompt": "Return the support contact.",
        "text": "Contact security-team@example.com for assistance.",
        "purpose": "model-output email replacement",
    },
    "output-api-key": {
        "direction": "output",
        "scanner": "PresidioAnalyzer+custom-recognizer+Anonymizer",
        "prompt": "Return the diagnostic status.",
        "text": "Status is green. DEMO_API_KEY=sk-demo-12345",
        "purpose": "project custom credential recognizer",
    },
}


class PresidioCore:
    def __init__(self, settings: PolicySettings | None = None) -> None:
        self.settings = settings or PolicySettings.from_env()
        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": self.settings.language, "model_name": NLP_MODEL},
            ],
        }
        nlp_engine = NlpEngineProvider(
            nlp_configuration=nlp_configuration,
        ).create_engine()
        self.analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=[self.settings.language],
        )
        self.anonymizer = AnonymizerEngine()
        self._register_custom_recognizers()

    def _register_custom_recognizers(self) -> None:
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="KR_RRN",
                supported_language=self.settings.language,
                patterns=[
                    Pattern(
                        name="kr_rrn_synthetic_training_pattern",
                        regex=r"\b\d{6}-[1-4]\d{6}\b",
                        score=0.85,
                    )
                ],
            )
        )
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="DEMO_API_KEY",
                supported_language=self.settings.language,
                patterns=[
                    Pattern(
                        name="day6_demo_api_key",
                        regex=r"\bDEMO_API_KEY=[A-Za-z0-9-]+\b",
                        score=0.95,
                    )
                ],
            )
        )

    def scan_text(
        self,
        *,
        direction: str,
        text: str,
        prompt: str | None = None,
        entities: list[str] | None = None,
    ) -> dict:
        if direction not in {"input", "output"}:
            raise ValueError("direction must be input or output")
        enabled = self.settings.input_enabled if direction == "input" else self.settings.output_enabled
        if not enabled:
            raise ValueError(f"Presidio {direction} analysis disabled by policy")
        selected_entities = [item.upper() for item in entities] if entities else list(self.settings.entities)
        unknown = sorted(set(selected_entities) - set(self.settings.entities))
        if unknown:
            raise ValueError(f"entities not allowed by policy: {', '.join(unknown)}")

        started = time.perf_counter()
        findings = self.analyzer.analyze(
            text=text,
            language=self.settings.language,
            entities=selected_entities,
            score_threshold=self.settings.score_threshold,
        )
        operators = {
            entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
            for entity in {finding.entity_type for finding in findings}
        }
        sanitized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=findings,
            operators=operators,
        ).text if findings else text
        detections = [
            {
                "entity_type": finding.entity_type,
                "start": finding.start,
                "end": finding.end,
                "score": round(float(finding.score), 4),
            }
            for finding in sorted(findings, key=lambda item: (item.start, item.end))
        ]
        result = {
            "event": "presidio_scan",
            "framework": FRAMEWORK,
            "framework_version": FRAMEWORK_VERSION,
            "direction": direction,
            "original_text": text,
            "sanitized_text": sanitized,
            "modified": sanitized != text,
            "valid": not findings,
            "risk_score": max((item["score"] for item in detections), default=0.0),
            "detections": detections,
            "entity_types": sorted({item["entity_type"] for item in detections}),
            "application_decision": "redact" if findings else "allow",
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        if prompt is not None:
            result["input_prompt"] = prompt
        return result

    def scan_input(self, text: str, entities: list[str] | None = None) -> dict:
        return self.scan_text(direction="input", text=text, entities=entities)

    def scan_output(
        self,
        prompt: str,
        model_output: str,
        entities: list[str] | None = None,
    ) -> dict:
        return self.scan_text(
            direction="output",
            text=model_output,
            prompt=prompt,
            entities=entities,
        )

    def run_case(self, case_name: str, *, text_override: str | None = None) -> dict:
        case = CASES[case_name]
        text = text_override if text_override is not None else case["text"]
        if case["direction"] == "input":
            result = self.scan_input(text)
        else:
            result = self.scan_output(case["prompt"], text)
        result.update(
            {
                "case": case_name,
                "scanner": case["scanner"],
                "policy": case["scanner"],
                "purpose": case["purpose"],
            }
        )
        return result

    def run_suite(
        self,
        *,
        text_overrides: dict[str, str] | None = None,
    ) -> tuple[list[dict], dict]:
        overrides = text_overrides or {}
        results = [
            self.run_case(case_name, text_override=overrides.get(case_name))
            for case_name in CASES
        ]
        decisions = {"allow": 0, "redact": 0}
        for result in results:
            decisions[result["application_decision"]] += 1
        summary = {
            "event": "presidio_suite_summary",
            "framework": FRAMEWORK,
            "total_cases": len(results),
            "decisions": decisions,
            "total_duration_ms": round(
                sum(float(result["duration_ms"]) for result in results), 2,
            ),
        }
        return results, summary
