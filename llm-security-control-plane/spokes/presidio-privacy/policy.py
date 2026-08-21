"""Presidio 개인정보 탐지 Spoke의 정책 정본.

처음에는 ``DEFAULT_ENTITIES``와 ``PrivacyPolicy``에서 탐지 대상과 임계값을
확인한다. 다음으로 ``_register_project_recognizers``에서 프로젝트 전용 형식을,
마지막으로 ``analyze``에서 input·retrieval·output을 검사하는 흐름을 읽는다.

이 모듈은 탐지 결과와 비식별화 후보만 NeMo Hub에 반환한다. allow·block·redact
중 무엇을 적용할지는 이곳이 아니라 NeMo와 Application이 최종 결정한다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# 프로젝트 전용 합성 주민등록번호 형식이다. 실제 주민번호를 fixture로 쓰지 않는다.
KR_RRN_PATTERN = r"(?<!\d)\d{6}-[1-4]\d{6}(?!\d)"
DEFAULT_ENTITIES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IP_ADDRESS",
    "US_SSN",
    "KR_RRN",
    "DEMO_API_KEY",
)


@dataclass(frozen=True)
class PrivacyPolicy:
    # 임계값과 Entity 목록은 탐지 범위를 정하지만 최종 차단 여부는 결정하지 않는다.
    language: str = "en"
    score_threshold: float = 0.5
    entities: tuple[str, ...] = DEFAULT_ENTITIES


class PrivacyAnalyzer:
    def __init__(self, settings: PrivacyPolicy | None = None) -> None:
        self.settings = settings or PrivacyPolicy()
        nlp_engine = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [
                    {"lang_code": self.settings.language, "model_name": "en_core_web_sm"}
                ],
            }
        ).create_engine()
        self.analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=[self.settings.language],
        )
        self.anonymizer = AnonymizerEngine()
        self._register_project_recognizers()

    def _register_project_recognizers(self) -> None:
        # Presidio 기본 Recognizer에 없는 교육용 Entity를 명시적으로 등록한다.
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="KR_RRN",
                supported_language=self.settings.language,
                patterns=[Pattern("synthetic_kr_rrn", KR_RRN_PATTERN, 0.85)],
            )
        )
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="DEMO_API_KEY",
                supported_language=self.settings.language,
                patterns=[
                    Pattern(
                        "synthetic_demo_api_key",
                        r"\bDEMO_API_KEY=[A-Za-z0-9-]+\b",
                        0.95,
                    )
                ],
            )
        )

    def analyze(self, *, stage: str, text: str, request_id: str) -> dict:
        # 같은 Analyzer를 input·retrieval·output 경계에서 재사용하되 stage를 기록한다.
        if stage not in {"input", "retrieval", "output"}:
            raise ValueError("stage must be input, retrieval, or output")
        started = time.perf_counter()
        findings = self.analyzer.analyze(
            text=text,
            language=self.settings.language,
            entities=list(self.settings.entities),
            score_threshold=self.settings.score_threshold,
        )
        detections = [
            {
                "entity_type": finding.entity_type,
                "start": finding.start,
                "end": finding.end,
                "score": round(float(finding.score), 4),
            }
            for finding in sorted(findings, key=lambda item: (item.start, item.end))
        ]
        operators = {
            entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
            for entity in {item["entity_type"] for item in detections}
        }
        sanitized = (
            self.anonymizer.anonymize(
                text=text,
                analyzer_results=findings,
                operators=operators,
            ).text
            if findings
            else text
        )
        # Spoke는 원문 허용·차단을 결정하지 않는다. 탐지 근거와 비식별화 후보만
        # Hub에 반환하고 최종 application decision은 상위 계층이 집행한다.
        return {
            "request_id": request_id,
            "spoke": "presidio-privacy",
            "stage": stage,
            "valid": not detections,
            "risk_score": max((item["score"] for item in detections), default=0.0),
            "detections": detections,
            "entity_types": sorted({item["entity_type"] for item in detections}),
            "sanitized_candidate": sanitized,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }

    def public_policy(self) -> dict:
        return {
            "policy_id": "presidio-privacy-spoke-v1",
            "role": "detection-and-sanitized-candidate-only",
            "decision_owner": "nemo-policy-hub-and-application",
            "language": self.settings.language,
            "score_threshold": self.settings.score_threshold,
            "entities": list(self.settings.entities),
            "custom_recognizers": {
                "KR_RRN": KR_RRN_PATTERN,
                "DEMO_API_KEY": r"\bDEMO_API_KEY=[A-Za-z0-9-]+\b",
            },
        }
