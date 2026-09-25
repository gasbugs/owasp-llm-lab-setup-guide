"""Bounded P20 product probe; not yet the course's independent grading endpoint."""
from datetime import datetime, timezone
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

import httpx


def main():
    output = Path(sys.argv[1])
    proof = {'scope': __doc__ + ' Synthetic notice requests, no AWS or Browser.', 'observations': []}
    with httpx.Client(timeout=5, trust_env=False) as client:
        def get(base, path, **kwargs):
            response = client.get(base + path, **kwargs)
            response.raise_for_status()
            return response.json()

        def poll(read, accept, label, timeout=45):
            deadline = time.monotonic() + timeout
            while True:
                value = read()
                if accept(value):
                    proof['observations'].append({'label': label, 'observed_ns': time.time_ns(), 'raw': value})
                    return value
                if time.monotonic() >= deadline:
                    raise TimeoutError(label)
                time.sleep(0.25)

        prom = 'http://prometheus:9090'
        grafana = 'http://grafana:3000'
        app = 'http://p20:8000'
        auth = ('p20-reader', 'publisher-test-reader')
        verification_headers = {'Authorization': 'Bearer publisher-test-verifier'}

        def query(expr, at=None):
            params = {'query': expr}
            if at is not None:
                params['time'] = at
            return get(prom, '/api/v1/query', params=params)

        def counters():
            return query('guided_p20_decisions_total')

        def values(raw):
            return {(r['metric']['practice'], r['metric']['decision']): float(r['value'][1])
                    for r in raw['data']['result']}

        def alerts():
            return get(prom, '/api/v1/alerts')

        def state(raw):
            current = raw['data']['alerts']
            if not current:
                return 'inactive'
            assert len(current) == 1, 'unexpected or duplicate alert'
            labels = current[0]['labels']
            assert labels['alertname'] == 'GuidedP20BlockedRequests'
            assert labels['practice'] == 'P20' and labels['severity'] == 'warning'
            return current[0]['state']

        suite = str(uuid.uuid4())
        started = datetime.now(timezone.utc).isoformat()
        start_ns = time.time_ns()
        proof.update(suite_id=suite, started_at=started, start_ns=start_ns)

        def phase(name):
            response = client.post(app + '/v1/scenarios', json={
                'suite_id': suite, 'started_at': started, 'phase': name},
                headers={'Authorization': 'Bearer publisher-test-control'})
            response.raise_for_status()
            proof[name + '_receipt'] = response.json()
            return response.json()

        def notifications():
            return get(app, '/v1/notifications', headers=verification_headers,
                       params={'start_ns': start_ns, 'end_ns': time.time_ns()})

        def has_notification(items, expected):
            return any(a.get('status') == expected and a.get('labels', {}).get('alertname') == 'GuidedP20BlockedRequests'
                       for item in items for a in item['body'].get('alerts', []))

        def checkpoint(name):
            response = client.post(app + '/v1/observations/checkpoint', json={
                'suite_id': suite, 'started_at': started, 'name': name},
                headers={'Authorization': 'Bearer publisher-test-control'})
            response.raise_for_status()
            return response.json()['checkpoints'][name]

        def panel_snapshot(label, expected, at_ms):
            dashboard = get(grafana, '/api/dashboards/uid/guided-p20', auth=auth)
            panel = dashboard['dashboard']['panels'][0]
            assert panel['datasource'] == {'type': 'prometheus', 'uid': 'p20'}
            assert len(panel['targets']) == 1
            expr = panel['targets'][0]['expr']
            body = {'from': str(at_ms), 'to': str(at_ms), 'queries': [{
                'refId': 'A', 'expr': expr, 'datasource': panel['datasource'], 'instant': True,
                'range': False, 'format': 'time_series', 'intervalMs': 1000, 'maxDataPoints': 1}]}
            response = client.post(grafana + '/api/ds/query', auth=auth, json=body)
            response.raise_for_status()
            raw = response.json()
            frames = raw['results']['A']['frames']
            counts = {}
            for frame in frames:
                for index, field in enumerate(frame['schema']['fields']):
                    if field['type'] == 'number':
                        decision = field.get('labels', {}).get('decision')
                        assert decision in ('allow', 'block') and decision not in counts
                        samples = frame['data']['values'][index]
                        assert len(samples) == 1
                        counts[decision] = samples[0]
            assert counts == expected, (label, counts, expected)
            direct = query(expr, at_ms / 1000)
            assert {r['metric']['decision']: float(r['value'][1]) for r in direct['data']['result']} == counts
            proof[label] = {'dashboard': dashboard, 'request': body, 'response': raw,
                            'direct_prometheus': direct, 'counts': counts}

        try:
            deadline = time.monotonic() + 90
            urls = [prom + '/-/ready', 'http://alertmanager:9093/-/ready', app + '/readyz',
                    grafana + '/api/dashboards/uid/guided-p20']
            while urls:
                for url in list(urls):
                    try:
                        if client.get(url, auth=auth if url.startswith(grafana + '/') else None).status_code == 200:
                            urls.remove(url)
                    except httpx.HTTPError:
                        pass
                if time.monotonic() >= deadline:
                    raise TimeoutError('product readiness')
                if urls:
                    time.sleep(0.25)
            baseline = poll(counters, lambda r: len(r['data']['result']) == 4, 'initial scrape')
            assert set(values(baseline).values()) == {0}
            rule = get(prom, '/api/v1/rules')
            proof['active_rules'] = rule
            rules = [r for group in rule['data']['groups'] for r in group['rules']]
            assert len(rules) == 1 and rules[0]['duration'] == 4
            assert state(alerts()) == 'inactive'
            prepared = phase('prepare')
            panel_snapshot('panel_baseline', {'allow': 0, 'block': 0}, prepared['checkpoints']['baseline'])

            phase('normal')
            normal_at = time.time()
            # Observe actual rule evaluations throughout the negative control, not a blind sleep.
            def normal_observation():
                raw = {'alerts': alerts(), 'rules': get(prom, '/api/v1/rules'), 'counter': counters()}
                assert state(raw['alerts']) == 'inactive', 'background/normal requests caused a P20 alert'
                return raw
            normal = poll(normal_observation,
                lambda r: time.time() - normal_at >= 8.1 and values(r['counter']).get(('background', 'block')) == 3,
                'normal maintained and background ignored', timeout=15)
            assert values(normal['counter'])[('P20', 'allow')] == 1
            panel_snapshot('panel_normal', {'allow': 1, 'block': 0}, checkpoint('normal'))
            phase('risk')
            poll(alerts, lambda r: state(r) == 'pending', 'pending observed', timeout=15)
            firing = poll(alerts, lambda r: state(r) == 'firing', 'firing observed', timeout=15)
            proof['firing'] = firing
            poll(lambda: get('http://alertmanager:9093', '/api/v2/alerts'),
                 lambda r: any(a['labels'].get('alertname') == 'GuidedP20BlockedRequests'
                               and a['status']['state'] == 'active' for a in r), 'Alertmanager active', timeout=15)
            firing_notifications = poll(notifications, lambda r: has_notification(r, 'firing'), 'firing webhook', timeout=15)
            phase('recovery')
            recovery = get(app, '/v1/receipts/H20/' + suite, headers=verification_headers)
            assert recovery['requests_closed'] and not recovery['closed']
            overlapping = client.post(app + '/v1/scenarios', json={
                'suite_id': str(uuid.uuid4()), 'started_at': datetime.now(timezone.utc).isoformat(),
                'phase': 'normal'}, headers={'Authorization': 'Bearer publisher-test-control'})
            assert overlapping.status_code == 409
            proof['overlap_rejected_status'] = overlapping.status_code
            poll(counters, lambda r: values(r).get(('P20', 'allow')) == 2, 'normal allowed during alert', timeout=5)
            panel_snapshot('panel_after_requests', {'allow': 2, 'block': 2}, checkpoint('after_requests'))
            poll(alerts, lambda r: state(r) == 'inactive', 'Prometheus resolved', timeout=35)
            final_notifications = poll(notifications, lambda r: has_notification(r, 'resolved'), 'resolved webhook', timeout=20)
            fired = [a for item in firing_notifications for a in item['body']['alerts'] if a['status'] == 'firing']
            resolved = [a for item in final_notifications for a in item['body']['alerts'] if a['status'] == 'resolved']
            assert fired and resolved
            assert fired[0]['fingerprint'] == resolved[-1]['fingerprint']
            assert fired[0]['startsAt'] == resolved[-1]['startsAt']
            assert datetime.fromisoformat(resolved[-1]['endsAt'].replace('Z', '+00:00')) > datetime.fromisoformat(fired[0]['startsAt'].replace('Z', '+00:00'))
            closed = client.post(app + '/v1/observations/close', json={
                'suite_id': suite, 'started_at': started},
                headers={'Authorization': 'Bearer publisher-test-control'})
            closed.raise_for_status()
            receipt = get(app, '/v1/receipts/H20/' + suite, headers=verification_headers)
            assert closed.json() == receipt
            assert receipt['closed'] and [r['downstream_count'] for r in receipt['cases']] == [1, 0, 0, 0, 0, 0, 1]
            proof['final_receipt'] = receipt
            proof['alert_history'] = get(prom, '/api/v1/query_range', params={
                'query': 'ALERTS{alertname="GuidedP20BlockedRequests",practice="P20"}',
                'start': start_ns / 1e9, 'end': time.time(), 'step': 1})
            history = proof['alert_history']['data']['result']
            assert {r['metric']['alertstate'] for r in history} == {'pending', 'firing'}
            verifier_path = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-evidence-verifier/p20_verification.py'
            spec = importlib.util.spec_from_file_location('p20_verification', verifier_path)
            verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier)
            proof['independent_product_check'] = {}
            verifier.collect_and_verify(suite, started, client=client,
                app_url=app, prometheus_url=prom, grafana_url=grafana,
                runner_digests={name: hashlib.sha256((Path(__file__).resolve().parents[2]
                    / 'llm-security-control-plane/guided-labs/h20-alert-dashboard' / name).read_bytes()).hexdigest()
                    for name in ('server.py', 'workflow.py', 'execution.py')},
                verifier_token='publisher-test-verifier', grafana_auth=auth,
                result=proof['independent_product_check'])
            proof['product_checks_completed'] = True
            print(json.dumps({'suite_id': suite, 'product_checks_completed': True,
                              'scope': proof['scope']}), flush=True)
        finally:
            output.write_text(json.dumps(proof, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
