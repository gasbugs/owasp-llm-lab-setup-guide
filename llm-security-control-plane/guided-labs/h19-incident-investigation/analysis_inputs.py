"""Server-owned analysis cases; no answer code or expected return values."""
import copy
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def canonical(bundle):
    return {key: sorted(copy.deepcopy(rows), key=lambda row: json.dumps(row, sort_keys=True))
            for key, rows in bundle.items()}


def build_inputs(bundle, request_ids):
    baseline = canonical(bundle)
    cases = []
    for index, request_id in enumerate(request_ids):
        for order in ('collected', 'reversed'):
            value = copy.deepcopy(baseline)
            if order == 'reversed':
                value = {key: list(reversed(rows)) for key, rows in value.items()}
            cases.append({'case_id': f'{index}-{order}', 'request_id': request_id,
                          'expected_invalid': False, 'bundle': value})
    request_id = request_ids[0]
    for damage in ('missing-log', 'foreign-trace', 'open-ledger', 'duplicate-span'):
        value = copy.deepcopy(baseline)
        if damage == 'missing-log':
            value['logs'] = [row for row in value['logs'] if row['request_id'] != request_id]
        elif damage == 'foreign-trace':
            next(row for row in value['spans'] if row['request_id'] == request_id)['trace_id'] = '0' * 32
        elif damage == 'open-ledger':
            next(row for row in value['closures'] if row['request_id'] == request_id)['closed'] = False
        else:
            value['spans'].append(copy.deepcopy(next(row for row in value['spans'] if row['request_id'] == request_id)))
        cases.append({'case_id': damage, 'request_id': request_id,
                      'expected_invalid': True, 'bundle': value})
    return [{**case, 'input_digest': digest(case['bundle'])} for case in cases]
