"""Read current P19 product records; preserve raw responses and normalized rows."""
import base64
import copy
import json
import re
import time
import uuid

import httpx


class NotReady(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identifier(value, size):
    if isinstance(value, str) and re.fullmatch('[0-9a-fA-F]{' + str(size * 2) + '}', value):
        return value.lower()
    decoded = base64.b64decode(value, validate=True)
    require(len(decoded) == size, 'invalid span identifier')
    return decoded.hex()


def attributes(items):
    values = {}
    for item in items:
        key, typed = item['key'], item['value']
        require(key not in values, 'duplicate attribute')
        if 'stringValue' in typed:
            values[key] = typed['stringValue']
        elif 'intValue' in typed:
            values[key] = int(typed['intValue'])
        elif 'boolValue' in typed:
            values[key] = typed['boolValue']
    return values


def normalize(products, case):
    identity = {key: case[key] for key in ('request_id', 'trace_id')}
    loki = products['loki']
    require(loki.get('status') == 'success' and loki.get('data', {}).get('resultType') == 'streams',
            'invalid Loki response')
    logs = []
    for stream in loki['data']['result']:
        require(stream['stream'].get('service_name') == 'guided-h19-investigation', 'foreign service log')
        for row in stream['values']:
            require(case['started_ns'] <= int(row[0]) <= case['finished_ns'], 'log outside request')
            event = json.loads(row[1])
            metadata = {**stream['stream'], **(row[2] if len(row) > 2 else {})}
            require(all(key not in metadata or metadata[key] == value for key, value in identity.items()),
                    'log metadata differs from body')
            require(all(event.get(key) == value for key, value in identity.items()), 'foreign log identity')
            require(event.get('decision') == case['decision'] and event.get('stop_stage') == case['stop_stage'],
                    'decision log differs from execution')
            logs.append({**identity, 'decision': event['decision'], 'stop_stage': event['stop_stage']})
    if not logs:
        raise NotReady('current log not collected')
    require(len(logs) == 1, 'duplicate decision log')
    spans = []
    for resource in products['tempo'].get('batches', products['tempo'].get('resourceSpans', [])):
        require(attributes(resource.get('resource', {}).get('attributes', [])).get('service.name')
                == 'guided-h19-investigation', 'foreign Trace service')
        for scope in resource.get('scopeSpans', resource.get('instrumentationLibrarySpans', [])):
            spans.extend(scope.get('spans', []))
    if not spans:
        raise NotReady('current Trace not collected')
    roots = [span for span in spans if span.get('name') == 'security.request']
    if not roots:
        raise NotReady('request root not collected')
    require(len(roots) == 1 and not roots[0].get('parentSpanId'), 'one request root is required')
    root = roots[0]
    root_id = identifier(root['spanId'], 8)
    root_attrs = attributes(root.get('attributes', []))
    require(root_attrs.get('decision') == case['decision']
            and root_attrs.get('stop_stage') == (case['stop_stage'] or ''), 'root decision differs')
    count = root_attrs.get('stage_count')
    require(type(count) is int and 1 <= count <= 3, 'invalid exported stage count')
    if count > len(spans) - 1:
        raise NotReady('request stages not collected')
    require(count == len(spans) - 1, 'extra stage export')
    normalized = []
    seen = set()
    for span in spans:
        attrs = attributes(span.get('attributes', []))
        require(identifier(span['traceId'], 16) == case['trace_id']
                and attrs.get('request_id') == case['request_id'], 'foreign span identity')
        span_id = identifier(span['spanId'], 8)
        require(span_id not in seen, 'duplicate span')
        seen.add(span_id)
        require(case['started_ns'] <= int(span['startTimeUnixNano']) <= int(span['endTimeUnixNano'])
                <= case['finished_ns'], 'span outside request')
        if span is root:
            continue
        require(identifier(span.get('parentSpanId'), 8) == root_id, 'broken parent span link')
        normalized.append({**identity, 'stage': span['name'], 'sequence': attrs.get('sequence')})
    return logs, normalized


def collect(cases, downstream_calls, *, client=None, timeout=15):
    owned = client is None
    client = client or httpx.Client(timeout=3, trust_env=False)
    deadline = time.monotonic() + timeout
    try:
        while True:
            products, logs, spans = [], [], []
            try:
                for case in cases:
                    require(str(uuid.UUID(case['request_id'])) == case['request_id'], 'invalid request ID')
                    require(bool(re.fullmatch('[0-9a-f]{32}', case['trace_id'])), 'invalid Trace ID')
                    require(0 <= case['finished_ns'] - case['started_ns'] <= 60_000_000_000, 'invalid interval')
                    query = '{service_name="guided-h19-investigation"} | request_id = "' + case['request_id'] + '"'
                    log = client.get('http://loki:3100/loki/api/v1/query_range', params={
                        'query': query, 'start': case['started_ns'], 'end': case['finished_ns'], 'limit': 20})
                    log.raise_for_status()
                    trace = client.get('http://tempo:3200/api/traces/' + case['trace_id'])
                    if trace.status_code == 404:
                        raise NotReady('current Trace not collected')
                    trace.raise_for_status()
                    raw = {'loki': log.json(), 'tempo': trace.json()}
                    own_logs, own_spans = normalize(raw, case)
                    logs.extend(own_logs)
                    spans.extend(own_spans)
                    products.append({'request_id': case['request_id'], 'query': query, **raw})
                return {'products': products, 'bundle': {
                    'logs': logs, 'spans': spans, 'closures': copy.deepcopy(cases),
                    'downstream_calls': copy.deepcopy(downstream_calls)}}
            except NotReady:
                if time.monotonic() >= deadline:
                    raise TimeoutError('P19 product collection incomplete')
                time.sleep(0.25)
    finally:
        if owned:
            client.close()
