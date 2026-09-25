"""P17 semantic checks accept real SDK output and reject false telemetry."""
import copy
import importlib.util
import json
import unittest

import test_guided_p17_runner as fixtures

spec = importlib.util.spec_from_file_location('p17_results', fixtures.ROOT /
    'llm-security-control-plane/guided-evidence-verifier/p17_results.py')
results = importlib.util.module_from_spec(spec)
spec.loader.exec_module(results)


def attrs(values):
    return [{'key': key, 'value': ({'intValue': str(value)} if type(value) is int else {'stringValue': value})}
            for key, value in values.items()]


class P17ResultTests(unittest.TestCase):
    def setUp(self):
        signals = fixtures.TestSignals()
        self.addCleanup(signals.close)
        source = fixtures.ROOT / 'tests/e2e/fixtures/p17_instrumentation.py'
        self.execution = fixtures.runner.run_suite(source, {'allow': 0, 'block': 0}, signals)
        self.products = []
        for case in self.execution['cases']:
            request = case['request_id']
            spans = [s for s in signals.spans.get_finished_spans() if s.attributes['request_id'] == request]
            records = [r.log_record for r in signals.logs.get_finished_logs()
                       if json.loads(r.log_record.body)['request_id'] == request]
            raw = {'loki': {'status': 'success', 'data': {'resultType': 'streams', 'result': [{
                'stream': {'service_name': 'guided-h17-telemetry'},
                'values': [[str(r.timestamp), r.body] for r in records]}]}},
                'tempo': {'resourceSpans': [{'resource': {'attributes': attrs({'service.name': 'guided-h17-telemetry'})},
                    'scopeSpans': [{'spans': [{'name': s.name, 'spanId': f'{s.context.span_id:016x}',
                        'traceId': f'{s.context.trace_id:032x}',
                        'parentSpanId': f'{s.parent.span_id:016x}' if s.parent else '',
                        'startTimeUnixNano': str(s.start_time), 'endTimeUnixNano': str(s.end_time),
                        'attributes': attrs(s.attributes)} for s in spans]}]}]}}
            self.products.append(raw)

    def test_actual_sdk_records_pass(self):
        analyses = [results.verify_case(c, p) for c, p in zip(self.execution['cases'], self.products)]
        self.assertEqual([a['downstream_count'] for a in analyses], [1, 0, 0])

    def test_signal_and_business_tampering_is_rejected(self):
        for mutation in ('duplicate_log', 'foreign_metadata', 'missing_span', 'foreign_span', 'wrong_parent',
                         'wrong_sequence', 'outside_time', 'return_changed', 'duplicate_business', 'open_business'):
            with self.subTest(mutation=mutation):
                case, product = copy.deepcopy(self.execution['cases'][0]), copy.deepcopy(self.products[0])
                spans = product['tempo']['resourceSpans'][0]['scopeSpans'][0]['spans']
                if mutation == 'duplicate_log':
                    product['loki']['data']['result'][0]['values'] *= 2
                elif mutation == 'foreign_metadata':
                    product['loki']['data']['result'][0]['values'][0].append({'trace_id': '0' * 32})
                elif mutation == 'missing_span':
                    spans.pop(0)
                elif mutation == 'foreign_span':
                    spans[0]['traceId'] = 'f' * 32
                elif mutation == 'wrong_parent':
                    spans[0]['parentSpanId'] = 'f' * 16
                elif mutation == 'wrong_sequence':
                    spans[0]['attributes'] = attrs({'request_id': case['request_id'], 'sequence': 3})
                elif mutation == 'outside_time':
                    spans[0]['startTimeUnixNano'] = '0'
                elif mutation == 'return_changed':
                    case['returned']['downstream_count'] = True
                elif mutation == 'duplicate_business':
                    case['ledger']['invocations'] = 2
                else:
                    case['ledger']['closures'][0]['closed'] = False
                with self.assertRaises(results.EvidenceMismatch):
                    results.verify_case(case, product)

    def test_extra_nonsecret_log_field_and_hex_id_case_are_accepted(self):
        case, product = self.execution['cases'][0], self.products[0]
        row = product['loki']['data']['result'][0]['values'][0]
        row[1] = json.dumps({**json.loads(row[1]), 'fixture': 'notice-authorization'})
        for span in product['tempo']['resourceSpans'][0]['scopeSpans'][0]['spans']:
            span['traceId'] = span['traceId'].upper()
        results.verify_case(case, product)

    def test_counter_shape_and_cardinality(self):
        value = {'status': 'success', 'data': {'resultType': 'vector', 'result': [
            {'metric': {'__name__': 'guided_p17_decisions_total', 'decision': d, 'job': 'p17', 'instance': 'p17:8000'},
             'value': [1, str(n)]} for d, n in [('allow', 1), ('block', 2)]]}}
        self.assertEqual(results.counter_values(value), {'allow': 1, 'block': 2})
        for mutation in ('id_label', 'nonfinite', 'duplicate', 'extra_series'):
            bad = copy.deepcopy(value)
            rows = bad['data']['result']
            if mutation == 'id_label':
                rows[0]['metric']['request_id'] = 'unbounded'
            elif mutation == 'nonfinite':
                rows[0]['value'][1] = 'NaN'
            elif mutation == 'duplicate':
                rows[1]['metric']['decision'] = 'allow'
            else:
                rows.append(copy.deepcopy(rows[0]))
            with self.subTest(mutation=mutation), self.assertRaises(results.EvidenceMismatch):
                results.counter_values(bad)


if __name__ == '__main__':
    unittest.main()
