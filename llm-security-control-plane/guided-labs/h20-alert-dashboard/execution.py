"""Bounded P20 orchestration. This runner records execution, never a course grade."""
import json
import math
import time

import httpx


def execute(workflow, suite_id, started_at, *, prometheus_url, alertmanager_url,
            client=None, clock=time.monotonic, sleep=time.sleep):
    if client is None:
        with httpx.Client(timeout=3, trust_env=False, follow_redirects=False) as owned:
            return execute(workflow, suite_id, started_at, prometheus_url=prometheus_url,
                           alertmanager_url=alertmanager_url, client=owned, clock=clock, sleep=sleep)
    overall = clock() + 120

    def get(url, **kwargs):
        with client.stream('GET', url, **kwargs) as response:
            response.raise_for_status()
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > 262144:
                    raise ValueError('product response too large')
        return json.loads(raw)

    def poll(read, accept, label, seconds=15):
        deadline = min(overall, clock() + seconds)
        while clock() < deadline:
            value = read()
            if clock() >= deadline:
                break
            if accept(value):
                return value
            sleep(0.25)
        raise TimeoutError(label)

    def counters():
        raw = get(prometheus_url + '/api/v1/query', params={'query': 'guided_p20_decisions_total'})
        if raw['status'] != 'success' or raw['data']['resultType'] != 'vector':
            raise ValueError('invalid Counter response')
        values = {}
        for row in raw['data']['result']:
            labels = row['metric']
            key = (labels.get('practice'), labels.get('decision'))
            number = float(row['value'][1])
            if (key not in {(p, d) for p in ('P20', 'background') for d in ('allow', 'block')}
                    or key in values or not math.isfinite(number) or number < 0 or not number.is_integer()):
                raise ValueError('invalid Counter series')
            values[key] = number
        return values

    def alert_state():
        raw = get(prometheus_url + '/api/v1/alerts')
        if raw['status'] != 'success':
            raise ValueError('alert query failed')
        alerts = raw['data']['alerts']
        if not alerts:
            return 'inactive'
        if len(alerts) != 1:
            raise ValueError('unexpected alerts')
        alert = alerts[0]
        if (alert['labels'].get('alertname') != 'GuidedP20BlockedRequests'
                or alert['labels'].get('practice') != 'P20'
                or alert['labels'].get('severity') != 'warning'
                or alert['state'] not in ('pending', 'firing')):
            raise ValueError('unexpected alert identity')
        return alert['state']

    baseline = poll(counters, lambda values: len(values) == 4, 'initial scrape missing')
    poll(alert_state, lambda state: state == 'inactive', 'previous alert still active', seconds=30)
    workflow.run_phase(suite_id, started_at, 'prepare')
    workflow.run_phase(suite_id, started_at, 'normal')
    normal_at = clock()
    expected = dict(baseline)
    expected[('P20', 'allow')] += 1
    expected[('background', 'block')] += 3

    def normal_observation():
        if alert_state() != 'inactive':
            raise ValueError('normal or background requests caused an alert')
        return counters()

    poll(normal_observation, lambda values: clock() - normal_at >= 8.1 and values == expected,
         'normal requests not observed')
    workflow.mark_checkpoint(suite_id, started_at, 'normal')
    workflow.run_phase(suite_id, started_at, 'risk')
    poll(alert_state, lambda state: state == 'pending', 'pending not observed')
    poll(alert_state, lambda state: state == 'firing', 'firing not observed')
    poll(lambda: get(alertmanager_url + '/api/v2/alerts'),
         lambda rows: any(row['labels'].get('alertname') == 'GuidedP20BlockedRequests'
                          and row['labels'].get('practice') == 'P20'
                          and row['status']['state'] == 'active' for row in rows),
         'Alertmanager did not receive firing')
    # Recovery must occur while the alert is still firing; the verifier checks its timestamp.
    if alert_state() != 'firing':
        raise ValueError('alert ended before recovery request')
    workflow.run_phase(suite_id, started_at, 'recovery')
    expected[('P20', 'allow')] += 1
    expected[('P20', 'block')] += 2
    poll(counters, lambda values: values == expected, 'recovery request not observed', seconds=5)
    workflow.mark_checkpoint(suite_id, started_at, 'after_requests')
    poll(alert_state, lambda state: state == 'inactive', 'alert did not resolve', seconds=35)

    def close():
        try:
            return workflow.close_observation(suite_id, started_at)
        except ValueError as exc:
            if str(exc) != 'current firing and resolved notifications not observed':
                raise
            return None

    return poll(close, lambda receipt: receipt is not None, 'matching resolved webhook missing')
