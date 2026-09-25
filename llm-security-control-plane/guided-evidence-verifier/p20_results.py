"""P20 raw-product checks. These checks alone are not the complete course verdict."""
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import uuid


class EvidenceMismatch(ValueError):
    pass


def require(value, message):
    if not value:
        raise EvidenceMismatch(message)


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'timestamp has no timezone')
    return parsed.timestamp()


def check_build(receipt, current, runner_digests):
    saved = receipt.get('build')
    require(isinstance(saved, dict) and saved == current, 'execution configuration changed or missing')
    require(set(saved) == {'source_digest', 'artifact_digests', 'runner_digests'}, 'invalid build record')
    artifacts = saved['artifact_digests']
    require(set(artifacts) == {'rules.yaml', 'dashboard.json'}, 'missing learner artifact digest')
    require(set(runner_digests) == {'server.py', 'workflow.py', 'execution.py'} and saved['runner_digests'] == runner_digests,
            'provided runner changed')
    require(all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
                for v in [*artifacts.values(), *runner_digests.values()]), 'invalid artifact digest')
    digest = hashlib.sha256(json.dumps(artifacts, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(saved['source_digest'] == digest, 'invalid combined source digest')
    return digest


def check_identity(receipt, suite_id, started_at, now=None):
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    issued = timestamp(started_at)
    require(str(uuid.UUID(suite_id)) == suite_id, 'invalid suite ID')
    require(receipt['suite_id'] == suite_id and receipt['started_at'] == started_at, 'foreign execution')
    require((receipt['activity_id'], receipt['internal_activity_id'], receipt['contract_version'])
            == ('P20', 'H20', 2), 'wrong activity contract')
    require(0 <= now - issued <= 180, 'stale execution')
    return issued, now


def check_receipt(receipt, suite_id, started_at, now=None):
    issued, now = check_identity(receipt, suite_id, started_at, now)
    require(not receipt.get('execution_error') and receipt.get('execution_status', 'manual') in ('manual', 'complete'),
            'execution failed or still running')
    require(receipt['closed'] is True and receipt['requests_closed'] is True, 'observation not closed')
    end = receipt['observation_closed_ns']
    require(type(end) is int and issued <= end / 1e9 <= now, 'invalid observation end')
    cases = receipt['cases']
    expected = [('normal', 0, 'P20', 'notice_lookup', 'allow', 1),
                *[('normal', n, 'background', 'notice_publish', 'block', 0) for n in (1, 2, 3)],
                *[('risk', n, 'P20', 'notice_publish', 'block', 0) for n in (0, 1)],
                ('recovery', 0, 'P20', 'notice_lookup', 'allow', 1)]
    require(len(cases) == 7, 'seven business requests required')
    seen, previous = set(), issued
    for case, contract in zip(cases, expected):
        request_id = case['request_id']
        require(str(uuid.UUID(request_id)) == request_id and request_id not in seen, 'duplicate or invalid request')
        seen.add(request_id)
        require(case['suite_id'] == suite_id, 'foreign request')
        require(type(case['ordinal']) is int and type(case['downstream_count']) is int,
                'invalid ordinal or downstream count')
        require(tuple(case[k] for k in ('phase', 'ordinal', 'practice', 'operation', 'decision', 'downstream_count'))
                == contract, 'business decision or actual downstream differs')
        finished = case['finished_ns']
        require(type(finished) is int and previous <= finished / 1e9 <= end / 1e9, 'request outside observation')
        previous = finished / 1e9
    require((cases[4]['finished_ns'] - cases[3]['finished_ns']) / 1e9 >= 8,
            'normal observation interval too short')
    return cases


def counter_values(raw, at):
    require(raw['status'] == 'success' and raw['data']['resultType'] == 'vector', 'invalid Counter response')
    values = {}
    for row in raw['data']['result']:
        labels = row['metric']
        require(labels.get('__name__') == 'guided_p20_decisions_total'
                and set(labels) <= {'__name__', 'practice', 'decision', 'job', 'instance'}, 'foreign Counter labels')
        key = (labels.get('practice'), labels.get('decision'))
        require(key[0] in ('P20', 'background') and key[1] in ('allow', 'block') and key not in values,
                'duplicate or invalid Counter series')
        instant, raw_value = row['value']
        require(abs(float(instant) - at) < 0.002, 'Counter timestamp differs')
        number = float(raw_value)
        require(math.isfinite(number) and number >= 0 and number.is_integer(), 'invalid Counter value')
        values[key] = number
    require(len(values) == 4, 'four business Counter series required')
    return values


def panel_values(raw, at_ms):
    require(set(raw['results']) == {'A'}, 'unexpected panel result')
    result = raw['results']['A']
    require(result.get('status') == 200 and not result.get('error'), 'panel query failed')
    values = {}
    for frame in result['frames']:
        fields, data = frame['schema']['fields'], frame['data']['values']
        require(len(fields) == len(data) == 2, 'unexpected panel frame')
        times = [i for i, f in enumerate(fields) if f['type'] == 'time']
        numbers = [i for i, f in enumerate(fields) if f['type'] == 'number']
        require(len(times) == len(numbers) == 1 and data[times[0]] == [at_ms], 'panel timestamp differs')
        field = fields[numbers[0]]
        labels = field.get('labels', {})
        decision = labels.get('decision')
        require(set(labels) <= {'decision', 'practice', 'job', 'instance', '__name__'}
                and labels.get('practice', 'P20') == 'P20'
                and decision in ('allow', 'block') and decision not in values,
                'panel must return two decision series')
        sample = data[numbers[0]]
        require(len(sample) == 1 and type(sample[0]) in (int, float)
                and math.isfinite(sample[0]) and sample[0] >= 0, 'invalid panel count')
        values[decision] = sample[0]
    require(set(values) == {'allow', 'block'}, 'missing panel decision')
    return values


def alert_history(raw, cases, start, end):
    require(raw['status'] == 'success' and raw['data']['resultType'] == 'matrix', 'invalid alert history')
    series = {}
    risk, recovery = cases[4]['finished_ns'] / 1e9, cases[6]['finished_ns'] / 1e9
    for row in raw['data']['result']:
        labels = row['metric']
        state = labels.get('alertstate')
        require(state in ('pending', 'firing') and state not in series, 'missing or duplicate alert state')
        expected = {'__name__': 'ALERTS', 'alertname': 'GuidedP20BlockedRequests',
                    'practice': 'P20', 'severity': 'warning', 'alertstate': state}
        require(all(labels.get(k) == v for k, v in expected.items()), 'foreign alert')
        samples = row['values']
        require(bool(samples), 'empty alert state')
        times = [float(sample[0]) for sample in samples]
        require(all(math.isfinite(t) and start <= t <= end and t >= risk for t in times),
                'alert outside risk interval or false positive during normal requests')
        require(all(float(sample[1]) == 1 for sample in samples), 'invalid alert value')
        require(all(abs(b-a-1) < 0.002 for a, b in zip(times, times[1:])), 'alert history gap')
        series[state] = times
    require(set(series) == {'pending', 'firing'}, 'both pending and firing required')
    pending, firing = series['pending'], series['firing']
    require(3 <= pending[-1]-pending[0] <= 4 and 4 <= firing[0]-pending[0] <= 5
            and pending[-1] < firing[0], 'pending duration or transition differs')
    require(firing[0]-1 <= recovery <= firing[-1]+1, 'normal request was not observed during firing')
    return series


def notification_pair(items, cases, series, end):
    risk = cases[4]['finished_ns'] / 1e9
    firing = {}
    pairs = []
    previous = risk
    for item in items:
        received = item['received_ns'] / 1e9
        require(previous <= received <= end, 'notification outside observation or out of order')
        previous = received
        for alert in item['body'].get('alerts', []):
            expected = {'alertname': 'GuidedP20BlockedRequests', 'practice': 'P20', 'severity': 'warning'}
            require(all(alert['labels'].get(k) == v for k, v in expected.items()), 'foreign notification')
            onset = timestamp(alert['startsAt'])
            fingerprint = alert['fingerprint']
            require(isinstance(fingerprint, str) and bool(fingerprint), 'missing alert fingerprint')
            require(risk <= onset <= received and abs(onset-series['firing'][0]) <= 1.1,
                    'notification does not match current firing')
            key = (fingerprint, alert['startsAt'])
            if alert['status'] == 'firing':
                firing.setdefault(key, received)
            elif alert['status'] == 'resolved':
                resolved = timestamp(alert['endsAt'])
                require(key in firing and onset < resolved <= received and firing[key] <= resolved,
                        'resolved alert lacks matching firing')
                require(0 <= resolved-series['firing'][-1] <= 2.1, 'resolve time differs from history')
                require(17 <= resolved-cases[5]['finished_ns'] / 1e9 <= 23,
                        'alert did not resolve after the 20-second risk window')
                pairs.append(key)
            else:
                raise EvidenceMismatch('unknown notification status')
    require(len(set(pairs)) == 1 and set(pairs) == set(firing), 'one complete alert lifecycle required')
    return {'fingerprint': pairs[0][0], 'startsAt': pairs[0][1]}
