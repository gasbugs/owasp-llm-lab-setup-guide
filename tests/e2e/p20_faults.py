"""Publisher-only product faults, applied to a disposable build context."""
import json

FAULTS = ('always-on', 'always-off', 'background-scope', 'constant-panel', 'notification-loss')


def apply_fault(directory, name):
    if name not in FAULTS:
        raise ValueError('unknown P20 fault')
    if name == 'constant-panel':
        path = directory / 'dashboard.json'
        dashboard = json.loads(path.read_text())
        dashboard['panels'][0]['targets'][0]['expr'] = 'vector(0)'
        path.write_text(json.dumps(dashboard))
    elif name == 'notification-loss':
        path = directory / 'alertmanager.yaml'
        source = path.read_text()
        original = 'http://guided-h20-alerts:8000/v1/notifications'
        if source.count(original) != 1:
            raise ValueError('notification fixture no longer matches')
        path.write_text(source.replace(original, original + '-missing'))
    else:
        path = directory / 'rules.yaml'
        source = path.read_text()
        original = 'sum(increase(guided_p20_decisions_total{practice="P20",decision="block"}[20s])) > 0'
        if source.count(original) != 1:
            raise ValueError('rule fixture no longer matches')
        expression = {'always-on': 'vector(1)', 'always-off': 'vector(0) > 0',
                      'background-scope': 'sum(increase(guided_p20_decisions_total{decision="block"}[20s])) > 0'}[name]
        path.write_text(source.replace(original, expression))
