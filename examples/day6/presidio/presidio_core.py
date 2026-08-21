#!/usr/bin/env python3
"""Day 6 CLI와 HTTP API가 함께 사용하는 Microsoft Presidio 정책 모듈.

처리 흐름은 다음과 같다.

1. ``AnalyzerEngine``이 원문에서 개인정보(PII)의 종류와 위치를 찾는다.
2. ``AnonymizerEngine``이 탐지된 구간을 ``<EMAIL_ADDRESS>`` 같은 값으로 바꾼다.
3. 애플리케이션은 원문이 아니라 반환된 ``sanitized_text``를 다음 계층으로 보낸다.

Presidio는 탐지·비식별화를 제공하는 라이브러리다. 실제 차단 또는 전달 결정은
이 모듈을 호출하는 애플리케이션이 수행해야 한다.
"""

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
# ``\b``는 한글도 단어 문자로 취급하므로 ``...1234567는``처럼 조사가
# 바로 붙으면 경계를 찾지 못한다. 숫자열의 앞뒤만 검사하면 한글 문장에서도
# 주민번호 부분을 안정적으로 분리할 수 있다.
KR_RRN_PATTERN = r"(?<!\d)\d{6}-[1-4]\d{6}(?!\d)"
# 이 목록은 호출자가 임의의 Entity를 검사하도록 허용하는 목록이 아니라,
# 애플리케이션 정책이 검사 대상으로 승인한 Entity allowlist다.
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
    """환경변수의 대표적인 참 값을 Python bool로 변환한다."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class PolicySettings:
    """Presidio 검사에 적용할 변경 불가능한(immutable) 애플리케이션 정책."""

    # Presidio recognizer는 탐지 결과에 0~1 신뢰도 점수를 부여한다.
    # 이 값보다 낮은 결과는 개인정보로 취급하지 않는다.
    score_threshold: float = 0.5
    language: str = "en"
    input_enabled: bool = True
    output_enabled: bool = True
    entities: tuple[str, ...] = DEFAULT_ENTITIES

    @classmethod
    def from_env(cls) -> "PolicySettings":
        """컨테이너 환경변수를 읽고 잘못된 정책은 시작 단계에서 거부한다."""
        # 임계값 범위를 벗어나거나 Entity 목록이 비어 있으면 약한 기본 정책으로
        # 자동 전환하지 않고 컨테이너 시작을 실패시킨다.
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
        """비밀값 없이 현재 정책을 API 응답이나 실습 화면에 공개한다."""
        # 원문 입력이나 탐지된 값은 공개하지 않고 활성 정책과 Pattern만 반환한다.
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
                "KR_RRN": KR_RRN_PATTERN,
                "DEMO_API_KEY": r"\bDEMO_API_KEY=[A-Za-z0-9-]+\b",
            },
        }


# 같은 정책을 반복 가능하게 확인하기 위한 교육용 정상·PII 테스트 데이터다.
# 실제 서비스 요청은 아래 CASES가 아니라 scan_input/scan_output으로 전달된다.
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
    """Analyzer, Anonymizer와 프로젝트 사용자 정의 recognizer를 묶은 정책 객체."""

    def __init__(self, settings: PolicySettings | None = None) -> None:
        self.settings = settings or PolicySettings.from_env()

        # Presidio의 이메일·전화번호 같은 기본 recognizer 중 일부는 주변 문맥을
        # 이해하기 위해 NLP 엔진을 사용한다. 여기서는 영어 spaCy 모델을 연결한다.
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
        # Analyzer와 Anonymizer는 역할이 다르다. Analyzer는 위치를 찾고,
        # Anonymizer는 그 위치에 실제 치환 연산을 적용한다.
        self.anonymizer = AnonymizerEngine()
        self._register_custom_recognizers()

    def _register_custom_recognizers(self) -> None:
        """Presidio 기본 목록에 없는 교육용 엔터티 패턴을 등록한다."""

        # PatternRecognizer는 정규식 기반 확장 지점이다. score는 정규식이
        # 일치했을 때 부여할 신뢰도이며 전체 정책 threshold와 비교된다.
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="KR_RRN",
                supported_language=self.settings.language,
                patterns=[
                    Pattern(
                        name="kr_rrn_synthetic_training_pattern",
                        regex=KR_RRN_PATTERN,
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
        """한 문자열을 분석·비식별화하고 애플리케이션용 판정 정보를 반환한다.

        ``direction``은 입력과 출력 중 어떤 정책 스위치를 적용할지 결정한다.
        ``entities``를 생략하면 PolicySettings에 허용된 전체 엔터티를 검사한다.
        """
        if direction not in {"input", "output"}:
            raise ValueError("direction must be input or output")
        enabled = self.settings.input_enabled if direction == "input" else self.settings.output_enabled
        if not enabled:
            raise ValueError(f"Presidio {direction} analysis disabled by policy")
        selected_entities = [item.upper() for item in entities] if entities else list(self.settings.entities)

        # 호출자가 정책에 없는 엔터티를 임의로 요청하지 못하게 allowlist로 제한한다.
        unknown = sorted(set(selected_entities) - set(self.settings.entities))
        if unknown:
            raise ValueError(f"entities not allowed by policy: {', '.join(unknown)}")

        started = time.perf_counter()
        # analyze()는 문자열을 변경하지 않는다. 각 결과에는 entity_type,
        # start/end 문자 인덱스와 score가 들어 있다.
        findings = self.analyzer.analyze(
            text=text,
            language=self.settings.language,
            entities=selected_entities,
            score_threshold=self.settings.score_threshold,
        )
        # 탐지된 엔터티별 치환 규칙을 만든다. 예를 들어 이메일은 원문 대신
        # <EMAIL_ADDRESS>로 바뀐다. 원래 값을 복원할 수 없는 비식별화 방식이다.
        operators = {
            entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
            for entity in {finding.entity_type for finding in findings}
        }
        sanitized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=findings,
            operators=operators,
        ).text if findings else text
        # Presidio 객체를 JSON 직렬화 가능한 최소 메타데이터로 변환한다.
        # start/end는 원문의 위치이므로 원문 자체를 로그에 남기지 않아도 된다.
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
            # 이것은 Presidio 자체 결정이 아니라 이 실습 애플리케이션의 정책이다.
            # PII가 있으면 요청을 버리지 않고 sanitized_text로 계속 처리한다.
            "application_decision": "redact" if findings else "allow",
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        if prompt is not None:
            result["input_prompt"] = prompt
        return result

    def scan_input(self, text: str, entities: list[str] | None = None) -> dict:
        """사용자 입력을 검사한다. 호출자는 반환값의 sanitized_text를 전달한다."""
        return self.scan_text(direction="input", text=text, entities=entities)

    def scan_output(
        self,
        prompt: str,
        model_output: str,
        entities: list[str] | None = None,
    ) -> dict:
        """모델 출력을 검사해 사용자에게 반환하기 전에 개인정보를 치환한다."""
        return self.scan_text(
            direction="output",
            text=model_output,
            prompt=prompt,
            entities=entities,
        )

    def run_case(self, case_name: str, *, text_override: str | None = None) -> dict:
        """CASES의 단일 교육용 시나리오를 실행한다."""
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
        """모든 교육용 시나리오와 allow/redact 집계를 한 번에 반환한다."""
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
