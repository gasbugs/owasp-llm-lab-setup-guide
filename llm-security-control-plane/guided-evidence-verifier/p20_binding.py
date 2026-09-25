"""Bind learner artifact bytes to the configurations reported by native products."""
import hashlib
import json
import re

import yaml


def native_configuration(raw):
    rules = raw['rules']
    if rules['status'] != 'success':
        raise ValueError('rule query failed')
    groups = []
    for group in rules['data']['groups']:
        saved = {key: value for key, value in group.items()
                 if key not in ('rules', 'lastEvaluation', 'evaluationTime')}
        saved['rules'] = [{key: value for key, value in rule.items()
                          if key not in ('state', 'alerts', 'health', 'lastError',
                                         'lastEvaluation', 'evaluationTime')}
                         for rule in group['rules']]
        groups.append(saved)
    # Dashboard metadata describes access/UI state; the complete model is configuration.
    return {'groups': groups, 'dashboard': raw['dashboard']['dashboard']}


def verify_snapshots(receipt, rules, dashboard, require):
    snapshots = receipt.get('product_snapshots')
    require(isinstance(snapshots, dict) and set(snapshots) == {'before', 'after'},
            'missing server product snapshots')
    before, after = snapshots['before'], snapshots['after']
    require(type(before.get('observed_ns')) is int and type(after.get('observed_ns')) is int,
            'invalid product snapshot times')
    from datetime import datetime
    issued_ns = int(datetime.fromisoformat(receipt['started_at']).timestamp() * 1e9)
    require(issued_ns <= before['observed_ns'] < (receipt['checkpoints']['baseline'] + 1) * 1_000_000
            and receipt['cases'][-1]['finished_ns'] <= after['observed_ns'] <= receipt['observation_closed_ns'],
            'product snapshots outside execution')
    current = native_configuration({'rules': rules, 'dashboard': dashboard})
    require(native_configuration(before['body']) == native_configuration(after['body']) == current,
            'native product configuration changed across execution')
    return {'before_ns': before['observed_ns'], 'after_ns': after['observed_ns'], 'unchanged': True}


def duration_seconds(value):
    if value == '0':
        return 0
    units = {'ms': .001, 's': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800, 'y': 31536000}
    tokens = re.findall(r'(\d+)(ms|s|m|h|d|w|y)', value)
    if not tokens or ''.join(number + unit for number, unit in tokens) != value:
        raise ValueError('invalid rule duration')
    return sum(int(number) * units[unit] for number, unit in tokens)


def verify_artifacts(build, rule, dashboard, *, client, app_url, prometheus_url, headers, require):
    sources = {}
    for name in ('rules.yaml', 'dashboard.json'):
        response = client.get(app_url + '/v1/artifacts/' + name, headers=headers)
        response.raise_for_status()
        raw = response.content
        require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == build['artifact_digests'][name],
                'learner artifact bytes differ from execution build')
        sources[name] = raw
    rules = yaml.safe_load(sources['rules.yaml'])
    expected = [item for group in rules['groups'] for item in group['rules']]
    require(len(expected) == 1, 'one declared rule required')
    expected = expected[0]
    require(expected['alert'] == rule['name'] and expected.get('labels', {}) == rule['labels']
            and duration_seconds(expected.get('for', '0s')) == rule['duration']
            and duration_seconds(expected.get('keep_firing_for', '0s')) == rule.get('keepFiringFor', 0),
            'active rule metadata differs from learner artifact')
    formatted = []
    for query in (expected['expr'], rule['query']):
        require(isinstance(query, str) and 0 < len(query) <= 4096, 'invalid rule expression')
        response = client.get(prometheus_url + '/api/v1/format_query', params={'query': query})
        response.raise_for_status()
        raw = response.json()
        require(raw['status'] == 'success' and isinstance(raw['data'], str), 'rule formatting failed')
        formatted.append(raw['data'])
    require(formatted[0] == formatted[1], 'active rule expression differs from learner artifact')
    declared = json.loads(sources['dashboard.json'])
    active = dashboard['dashboard']
    require(declared['uid'] == active['uid'] == 'guided-p20', 'dashboard identity differs')
    require(declared['panels'] == active['panels'], 'active panel differs from learner artifact')
    # A dashboard may change displayed data without changing the target expression.
    for key in ('templating', 'time', 'timepicker', 'timezone'):
        require(declared.get(key) == active.get(key), 'active dashboard context differs')
    return {'artifact_digests': dict(build['artifact_digests']),
            'formatted_rule': formatted[0], 'dashboard_uid': active['uid'], 'native_config_matches': True}
