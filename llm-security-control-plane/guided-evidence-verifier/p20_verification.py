"""Read-only product re-query for P20; execution-build binding is a separate gate."""
import importlib.util
from pathlib import Path
import uuid

spec = importlib.util.spec_from_file_location('p20_results', Path(__file__).with_name('p20_results.py'))
RESULTS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RESULTS)
require = RESULTS.require
binding_spec = importlib.util.spec_from_file_location('p20_binding', Path(__file__).with_name('p20_binding.py'))
BINDING = importlib.util.module_from_spec(binding_spec)
binding_spec.loader.exec_module(BINDING)


def collect_and_verify(suite_id, started_at, *, client, app_url,
                       prometheus_url, grafana_url, verifier_token, grafana_auth, runner_digests, result):
    result['product_contract_verified'] = False
    require(str(uuid.UUID(suite_id)) == suite_id, 'invalid suite ID')
    def get(url, **kwargs):
        response = client.get(url, **kwargs)
        response.raise_for_status()
        return response.json()

    headers = {'Authorization': 'Bearer ' + verifier_token}
    receipt = get(app_url + '/v1/receipts/H20/' + suite_id, headers=headers)
    RESULTS.check_identity(receipt, suite_id, started_at)
    result['receipt'] = receipt
    build = get(app_url + '/v1/buildinfo', headers=headers)
    result['build'] = build
    result['source_digest'] = RESULTS.check_build(receipt, build, runner_digests)
    cases = RESULTS.check_receipt(receipt, suite_id, started_at)
    checkpoints = receipt['checkpoints']
    require(set(checkpoints) == {'baseline', 'normal', 'after_requests'}
            and all(type(v) is int for v in checkpoints.values()), 'invalid observation checkpoints')
    times = {key: value / 1000 for key, value in checkpoints.items()}
    start, end = times['baseline'], receipt['observation_closed_ns'] / 1e9
    require(RESULTS.timestamp(started_at) <= start < cases[0]['finished_ns'] / 1e9
            and cases[3]['finished_ns'] / 1e9 + 8 <= times['normal'] < cases[4]['finished_ns'] / 1e9
            and cases[6]['finished_ns'] / 1e9 <= times['after_requests'] <= end,
            'checkpoints outside current phases')
    rules_raw = get(prometheus_url + '/api/v1/rules')
    result['rules'] = rules_raw
    require(rules_raw['status'] == 'success', 'rule query failed')
    rules = [rule for group in rules_raw['data']['groups'] for rule in group['rules']]
    require(len(rules) == 1, 'one current rule required')
    rule = rules[0]
    require(rule['type'] == 'alerting' and rule['name'] == 'GuidedP20BlockedRequests'
            and rule['duration'] == 4 and rule['health'] == 'ok' and not rule.get('lastError')
            and rule['labels'].get('practice') == 'P20' and rule['labels'].get('severity') == 'warning',
            'rule contract differs')
    dashboard = get(grafana_url + '/api/dashboards/uid/guided-p20', auth=grafana_auth)
    result['dashboard'] = dashboard
    result['configuration_continuity'] = BINDING.verify_snapshots(receipt, rules_raw, dashboard, require)
    result['native_config'] = BINDING.verify_artifacts(build, rule, dashboard, client=client,
        app_url=app_url, prometheus_url=prometheus_url, headers=headers, require=require)
    panels = dashboard['dashboard']['panels']
    require(len(panels) == 1, 'one decision panel required')
    panel = panels[0]
    require(panel.get('datasource') == {'type': 'prometheus', 'uid': 'p20'}
            and len(panel['targets']) == 1, 'wrong panel datasource or target count')
    target = panel['targets'][0]
    require(not target.get('hide') and target.get('refId') == 'A'
            and target.get('datasource', panel['datasource']) == panel['datasource'],
            'hidden or overridden panel query')
    expr = target['expr']
    require(isinstance(expr, str) and 0 < len(expr) <= 4096, 'invalid panel expression')
    result['snapshots'] = {}
    counts = {}
    for name in ('baseline', 'normal', 'after_requests'):
        at_ms = checkpoints[name]
        raw_counter = get(prometheus_url + '/api/v1/query', params={
            'query': 'guided_p20_decisions_total', 'time': at_ms / 1000})
        counts[name] = RESULTS.counter_values(raw_counter, at_ms / 1000)
        body = {'from': str(at_ms), 'to': str(at_ms), 'queries': [{
            'refId': 'A', 'expr': expr, 'datasource': panel['datasource'], 'instant': True,
            'range': False, 'format': 'time_series', 'intervalMs': 1000, 'maxDataPoints': 1}]}
        response = client.post(grafana_url + '/api/ds/query', auth=grafana_auth, json=body)
        response.raise_for_status()
        panel_raw = response.json()
        result['snapshots'][name] = {'counter': raw_counter, 'panel_request': body, 'panel': panel_raw}
        actual = RESULTS.panel_values(panel_raw, at_ms)
        require(actual == {decision: counts[name][('P20', decision)] for decision in ('allow', 'block')},
                'panel differs from actual P20 Counter')
    normal_delta = {key: counts['normal'][key]-value for key, value in counts['baseline'].items()}
    final_delta = {key: counts['after_requests'][key]-value for key, value in counts['baseline'].items()}
    require(normal_delta == {('P20', 'allow'): 1, ('P20', 'block'): 0,
                             ('background', 'allow'): 0, ('background', 'block'): 3}, 'normal Counter delta differs')
    require(final_delta == {('P20', 'allow'): 2, ('P20', 'block'): 2,
                            ('background', 'allow'): 0, ('background', 'block'): 3}, 'final Counter delta differs')
    history = get(prometheus_url + '/api/v1/query_range', params={
        'query': 'ALERTS{alertname="GuidedP20BlockedRequests",practice="P20"}',
        'start': start, 'end': end, 'step': 1})
    result['alert_history'] = history
    series = RESULTS.alert_history(history, cases, start, end)
    resolved = get(prometheus_url + '/api/v1/query', params={
        'query': 'ALERTS{alertname="GuidedP20BlockedRequests",practice="P20"}', 'time': end})
    result['resolved_alerts'] = resolved
    require(resolved['status'] == 'success' and resolved['data']['resultType'] == 'vector'
            and resolved['data']['result'] == [], 'alert not resolved at observation end')
    notifications = get(app_url + '/v1/notifications', headers=headers, params={
        'start_ns': cases[4]['finished_ns'], 'end_ns': receipt['observation_closed_ns']})
    result['notifications'] = notifications
    result['alert_identity'] = RESULTS.notification_pair(notifications, cases, series, end)
    result['product_contract_verified'] = True
    result['scope'] = 'Artifact/native configuration identity and re-fetched products; course endpoint still required'
