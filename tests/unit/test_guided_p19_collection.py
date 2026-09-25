"""Raw-format fixtures for defensive product parsing; no external requests."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

import httpx

PATH = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-labs/h19-incident-investigation/collection.py'
spec = importlib.util.spec_from_file_location('p19_collection', PATH)
collection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collection)


class P19CollectionTests(unittest.TestCase):
    def setUp(self):
        self.case = {'request_id': str(uuid.uuid4()), 'trace_id': 'a' * 32, 'decision': 'block',
                     'stop_stage': 'authenticate', 'started_ns': 1, 'finished_ns': 10,
                     'closed': True, 'downstream_count': 0}
        def attrs(**values):
            return [{'key': key, 'value': {'intValue' if type(value) is int else 'stringValue': value}}
                    for key, value in values.items()]
        span = {'traceId': self.case['trace_id'], 'startTimeUnixNano': '2', 'endTimeUnixNano': '9'}
        self.raw = {
            'loki': {'status': 'success', 'data': {'resultType': 'streams', 'result': [{
                'stream': {'service_name': 'guided-h19-investigation'},
                'values': [['5', json.dumps(self.case)]]}]}},
            'tempo': {'batches': [{'resource': {'attributes': attrs(**{'service.name': 'guided-h19-investigation'})},
                'scopeSpans': [{'spans': [
                    {**span, 'name': 'authenticate', 'spanId': '2' * 16, 'parentSpanId': '1' * 16,
                     'attributes': attrs(request_id=self.case['request_id'], sequence=1)},
                    {**span, 'name': 'security.request', 'spanId': '1' * 16,
                     'attributes': attrs(request_id=self.case['request_id'], decision='block',
                                         stop_stage='authenticate', stage_count=1)},
                ]}]}]},
        }

    def test_raw_product_records_are_normalized_without_editing_originals(self):
        before = copy.deepcopy(self.raw)
        logs, spans = collection.normalize(self.raw, self.case)
        self.assertEqual(logs[0]['stop_stage'], 'authenticate')
        self.assertEqual(spans[0]['stage'], 'authenticate')
        self.assertEqual(spans[0]['sequence'], 1)
        self.assertEqual(self.raw, before)

    def test_wrong_parent_identity_window_and_duplicate_spans_are_rejected(self):
        for field, value in [('parentSpanId', '3' * 16), ('traceId', 'b' * 32),
                             ('startTimeUnixNano', '0'), ('endTimeUnixNano', '11')]:
            raw = copy.deepcopy(self.raw)
            raw['tempo']['batches'][0]['scopeSpans'][0]['spans'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                collection.normalize(raw, self.case)
        raw = copy.deepcopy(self.raw)
        spans = raw['tempo']['batches'][0]['scopeSpans'][0]['spans']
        spans.append(copy.deepcopy(spans[0]))
        with self.assertRaises(ValueError):
            collection.normalize(raw, self.case)

    def test_partial_export_is_pending_not_complete(self):
        for missing_root in (False, True):
            raw = copy.deepcopy(self.raw)
            spans = raw['tempo']['batches'][0]['scopeSpans'][0]['spans']
            spans.pop(1 if missing_root else 0)
            with self.assertRaises(collection.NotReady):
                collection.normalize(raw, self.case)

    def test_conflicting_log_identity_is_rejected(self):
        self.raw['loki']['data']['result'][0]['values'][0].append({'request_id': 'foreign'})
        with self.assertRaises(ValueError):
            collection.normalize(self.raw, self.case)

    def test_pending_trace_retries_only_product_reads(self):
        seen = []
        def reply(request):
            seen.append(request)
            if 'loki' in request.url.host:
                return httpx.Response(200, json=self.raw['loki'])
            return httpx.Response(404) if len(seen) == 2 else httpx.Response(200, json=self.raw['tempo'])
        with httpx.Client(transport=httpx.MockTransport(reply)) as client, patch.object(collection.time, 'sleep'):
            result = collection.collect([self.case], [], client=client)
        self.assertEqual(len(seen), 4)
        self.assertTrue(all(request.method == 'GET' for request in seen))
        self.assertEqual(result['products'][0]['tempo'], self.raw['tempo'])
        self.assertEqual(result['bundle']['closures'], [self.case])
        self.assertIsNot(result['bundle']['closures'][0], self.case)

    def test_storage_error_is_not_success_or_automatic_retry(self):
        seen = []
        def reply(request):
            seen.append(request)
            return httpx.Response(500)
        with httpx.Client(transport=httpx.MockTransport(reply)) as client, self.assertRaises(httpx.HTTPStatusError):
            collection.collect([self.case], [], client=client)
        self.assertEqual(len(seen), 1)

    def test_collection_deadline_rejects_empty_logs(self):
        self.raw['loki']['data']['result'] = []
        def reply(request):
            return httpx.Response(200, json=self.raw['loki' if request.url.host == 'loki' else 'tempo'])
        with httpx.Client(transport=httpx.MockTransport(reply)) as client, self.assertRaises(TimeoutError):
            collection.collect([self.case], [], client=client, timeout=0)


if __name__ == '__main__':
    unittest.main()
