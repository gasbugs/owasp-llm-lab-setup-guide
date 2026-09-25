"""Actual P12 Presidio boundary; no case IDs, verdicts, or simulated stage responses."""
from collections import Counter
from hashlib import sha256
from importlib.metadata import version

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import EmailRecognizer, KrRrnRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from tldextract import TLDExtract

ENTITIES = ("EMAIL_ADDRESS", "KR_RRN")
STAGES = frozenset({"input_privacy", "output_privacy"})


class OfflineEmailRecognizer(EmailRecognizer):
    """Keep Presidio's email patterns and validate against the packaged suffix snapshot."""
    def __init__(self):
        super().__init__(supported_language="en")
        self.extract = TLDExtract(suffix_list_urls=(), cache_dir=None)

    def validate_result(self, pattern_text):
        return self.extract(pattern_text).fqdn != ""


class PrivacyBoundary:
    def __init__(self):
        nlp = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }).create_engine()
        registry = RecognizerRegistry(supported_languages=["en"], recognizers=[
            OfflineEmailRecognizer(), KrRrnRecognizer(supported_language="en"),
        ])
        self.analyzer = AnalyzerEngine(nlp_engine=nlp, registry=registry, supported_languages=["en"])
        self.anonymizer = AnonymizerEngine()
        self.versions = {name: version(name) for name in ("presidio-analyzer", "presidio-anonymizer")}

    def process(self, stage: str, text: str) -> dict:
        if not isinstance(stage, str) or stage not in STAGES:
            raise ValueError("unsupported privacy stage")
        if not isinstance(text, str) or not text.strip() or len(text) > 16000:
            raise ValueError("text must contain 1..16000 characters")
        findings = self.analyzer.analyze(text=text, language="en", entities=list(ENTITIES),
                                         score_threshold=0.5)
        sanitized = self.anonymizer.anonymize(
            text=text, analyzer_results=findings,
            operators={entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
                       for entity in ENTITIES},
        ).text if findings else text
        counts = dict(sorted(Counter(finding.entity_type for finding in findings).items()))
        return {
            "text": sanitized,
            "evidence": {
                "stage": stage,
                "framework": "microsoft-presidio",
                "versions": dict(self.versions),
                "input_digest": sha256(text.encode("utf-8")).hexdigest(),
                "output_digest": sha256(sanitized.encode("utf-8")).hexdigest(),
                "input_bytes": len(text.encode("utf-8")),
                "output_bytes": len(sanitized.encode("utf-8")),
                "entity_counts": counts,
                "operator": "replace",
            },
        }
