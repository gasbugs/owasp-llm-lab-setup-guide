"""Learner-owned H09 Presidio policy with an intentionally unsafe release step."""

from __future__ import annotations

from importlib.metadata import version

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import KrRrnRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


FRAMEWORK_VERSION = version("presidio-analyzer")
LANGUAGE = "en"
# KrRrnRecognizer가 반환하는 엔티티 타입인 KR_RRN을 포함합니다.
ENTITIES = ("EMAIL_ADDRESS", "KR_RRN")


def build_engines() -> tuple[AnalyzerEngine, AnonymizerEngine]:
    """Build the fixed English pipeline used by the learner policy."""
    nlp = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": LANGUAGE, "model_name": "en_core_web_sm"}],
        }
    ).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=[LANGUAGE])
    # 영어 Analyzer에서도 공식 한국 주민번호 인식기가 실제 선택되게 언어를 맞춥니다.
    analyzer.registry.add_recognizer(KrRrnRecognizer(supported_language=LANGUAGE))
    return analyzer, AnonymizerEngine()


ANALYZER, ANONYMIZER = build_engines()


def apply_privacy_policy(*, stage: str, text: str) -> dict:
    """Analyze PII and choose the text released to the delivery boundary."""
    findings = ANALYZER.analyze(
        text=text,
        language=LANGUAGE,
        entities=list(ENTITIES),
        score_threshold=0.5,
    )
    operators = {
        finding.entity_type: OperatorConfig(
            "replace", {"new_value": f"<{finding.entity_type}>"}
        )
        for finding in findings
    }
    sanitized = (
        ANONYMIZER.anonymize(
            text=text,
            analyzer_results=findings,
            operators=operators,
        ).text
        if findings
        else text
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
    return {
        "framework": "microsoft-presidio",
        "framework_version": FRAMEWORK_VERSION,
        "stage": stage,
        "entities": list(ENTITIES),
        "recognizer_classes": sorted(
            {type(item).__name__ for item in ANALYZER.registry.recognizers}
        ),
        "recognizers": sorted(
            {
                (type(item).__module__, type(item).__name__)
                for item in ANALYZER.registry.recognizers
            }
        ),
        "operator": "replace",
        "detections": detections,
        "sanitized_candidate": sanitized,
        # 원문 대신 비식별화된 sanitized 문자열 전달
        "released_text": sanitized,
    }
