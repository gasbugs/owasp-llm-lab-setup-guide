import sys

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

text = sys.argv[1]
provider = NlpEngineProvider(
    nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
)
analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
entities = analyzer.analyze(text=text, language="en", entities=["EMAIL_ADDRESS"])
masked = AnonymizerEngine().anonymize(text=text, analyzer_results=entities)
print([entity.entity_type for entity in entities])
print(masked.text)
