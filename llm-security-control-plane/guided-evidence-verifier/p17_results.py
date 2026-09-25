"""Compare P17 product-native records with separately recorded business execution."""
import base64
import json
import math
import re


class EvidenceMismatch(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceMismatch(message)


def identifier(value, size):
    if isinstance(value, str) and re.fullmatch('[0-9a-fA-F]{' + str(size * 2) + '}', value):
        return value.lower()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise EvidenceMismatch('invalid product span ID')
    require(len(decoded) == size, 'invalid product span ID size')
    return decoded.hex()


def attributes(items):
    result = {}
    for item in items:
        require(item['key'] not in result, 'duplicate span attribute')
        typed = item['value']
        if 'stringValue' in typed:
            result[item['key']] = typed['stringValue']
        elif 'intValue' in typed:
            result[item['key']] = int(typed['intValue'])
        elif 'boolValue' in typed:
            result[item['key']] = typed['boolValue']
    return result


def verify_case(case, products):
    ledger = case['ledger']
    expected_stages = ['authenticate']
    if case['principal'] == 'reader':
        expected_stages.append('authorize')
        if case['action'] == 'notice_lookup':
            expected_stages.append('notice_lookup')
    count = int(expected_stages[-1] == 'notice_lookup')
    stop = None if count else expected_stages[-1]
    decision = 'allow' if count else 'block'
    require(case['execution_status'] == 'returned', 'learner did not return')
    require(type(ledger['invocations']) is int and ledger['invocations'] == 1, 'business must run once')
    require(len(ledger['closures']) == 1 and ledger['closures'][0]['closed'] is True, 'business not closed once')
    closure = ledger['closures'][0]
    require(closure['decision'] == decision and closure['stop_stage'] == stop, 'business decision differs')
    require(type(closure['downstream_count']) is int and closure['downstream_count'] == count,
            'business downstream count differs')
    require(len(ledger['downstream_calls']) == count, 'downstream ledger differs')
    require(json.dumps(case['returned'], sort_keys=True, allow_nan=False)
            == json.dumps({k: closure[k] for k in ('decision', 'stop_stage', 'downstream_count', 'result')},
                          sort_keys=True, allow_nan=False), 'learner changed business return')
    require([s['stage'] for s in ledger['stages']] == expected_stages, 'business stages differ')
    request_id = case['request_id']
    trace_id = ledger['stages'][0]['trace_id']
    require(trace_id != '0' * 32, 'business ran outside Trace')
    require(ledger['request_id'] == request_id and closure['request_id'] == request_id,
            'business request identity differs')
    for row in ledger['stages'] + ledger['downstream_calls']:
        require(row['request_id'] == request_id and row['trace_id'] == trace_id, 'foreign business record')
    logs = products['loki']
    require(logs.get('status') == 'success' and logs['data']['resultType'] == 'streams', 'invalid Loki result')
    events = []
    for stream in logs['data']['result']:
        require(stream['stream'].get('service_name') == 'guided-h17-telemetry', 'foreign Log service')
        for row in stream['values']:
            require(case['started_ns'] <= int(row[0]) <= case['finished_ns'], 'Log outside request')
            event = json.loads(row[1])
            expected = {'request_id': request_id, 'trace_id': trace_id, 'decision': decision, 'stop_stage': stop}
            require(all(event.get(key) == value for key, value in expected.items()), 'decision Log differs')
            metadata = {**stream['stream'], **(row[2] if len(row) > 2 else {})}
            require(all(key not in metadata or metadata[key] == value
                        for key, value in (('request_id', request_id), ('trace_id', trace_id))),
                    'Log metadata differs from body')
            events.append(event)
    require(len(events) == 1, 'exactly one current decision Log required')
    spans = []
    for resource in products['tempo'].get('batches', products['tempo'].get('resourceSpans', [])):
        require(attributes(resource['resource']['attributes']).get('service.name') == 'guided-h17-telemetry',
                'foreign Trace service')
        for scope in resource.get('scopeSpans', resource.get('instrumentationLibrarySpans', [])):
            spans.extend(scope.get('spans', []))
    roots = [s for s in spans if s['name'] == 'security.request']
    require(len(roots) == 1 and not roots[0].get('parentSpanId'), 'one request root required')
    root = roots[0]
    root_id = identifier(root['spanId'], 8)
    root_attrs = attributes(root['attributes'])
    require(root_attrs.get('decision') == decision and root_attrs.get('stop_stage') == (stop or '')
            and type(root_attrs.get('stage_count')) is int and root_attrs['stage_count'] == len(expected_stages),
            'root decision or stage count differs')
    require(len(spans) == len(expected_stages) + 1, 'missing or extra Span')
    seen = set()
    for span in spans:
        attrs = attributes(span['attributes'])
        span_id = identifier(span['spanId'], 8)
        require(span_id not in seen, 'duplicate Span')
        seen.add(span_id)
        require(identifier(span['traceId'], 16) == trace_id and attrs.get('request_id') == request_id,
                'foreign Span identity')
        require(case['started_ns'] <= int(span['startTimeUnixNano']) <= int(span['endTimeUnixNano'])
                <= case['finished_ns'], 'Span outside request')
        if span is root:
            continue
        require(identifier(span.get('parentSpanId'), 8) == root_id, 'wrong Span parent')
        sequence = attrs.get('sequence')
        require(type(sequence) is int and 1 <= sequence <= len(expected_stages), 'invalid Span sequence')
        actual = ledger['stages'][sequence - 1]
        require(span_id == actual['span_id'] and span['name'] == actual['stage'], 'Span not from actual stage')
    return {'request_id': request_id, 'trace_id': trace_id, 'decision': decision,
            'stop_stage': stop, 'downstream_count': count, 'stages': expected_stages}


def counter_values(response):
    require(response.get('status') == 'success' and response['data']['resultType'] == 'vector', 'invalid Metric result')
    rows = response['data']['result']
    require(len(rows) == 2, 'two decision series required')
    result = {}
    for row in rows:
        labels = row['metric']
        require(set(labels) <= {'__name__', 'decision', 'job', 'instance'}, 'unexpected Metric labels')
        decision = labels.get('decision')
        require(decision in ('allow', 'block') and decision not in result, 'duplicate or invalid decision series')
        require(labels.get('__name__') == 'guided_p17_decisions_total', 'foreign Metric')
        value = float(row['value'][1])
        require(math.isfinite(value) and value >= 0, 'invalid Counter value')
        result[decision] = value
    return result
