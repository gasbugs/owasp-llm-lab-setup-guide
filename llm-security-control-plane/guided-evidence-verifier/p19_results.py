"""P19 normalized-evidence contract, owned by the read-only verifier.

The collector must bind these records to current product responses and closed
provider ledgers before using this contract. This does not attest their origin.
"""


class EvidenceMismatch(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceMismatch(reason)


def expected_analysis(bundle, request_id):
    require(isinstance(bundle, dict), 'evidence bundle must be an object')
    require(isinstance(request_id, str) and bool(request_id), 'request ID is missing')
    selected = {}
    for key in ('logs', 'spans', 'closures', 'downstream_calls'):
        rows = bundle.get(key)
        require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows),
                f'{key} must contain records')
        selected[key] = [row for row in rows if row.get('request_id') == request_id]
    require(len(selected['logs']) == len(selected['closures']) == 1,
            'one decision log and one closure are required')
    log, closure = selected['logs'][0], selected['closures'][0]
    trace_id = log.get('trace_id')
    require(isinstance(trace_id, str) and bool(trace_id), 'Trace ID is missing')
    require(all(row.get('trace_id') == trace_id for rows in selected.values() for row in rows),
            'request records refer to different Traces')
    require(closure.get('closed') is True, 'request ledger is not closed')
    count = closure.get('downstream_count')
    require(type(count) is int and count >= 0 and count == len(selected['downstream_calls']),
            'downstream ledger count differs')
    spans = selected['spans']
    require(bool(spans), 'request spans are missing')
    require(all(type(row.get('sequence')) is int and row['sequence'] > 0
                and isinstance(row.get('stage'), str) and bool(row['stage']) for row in spans),
            'stage or sequence is invalid')
    spans = sorted(spans, key=lambda row: row['sequence'])
    require([row['sequence'] for row in spans] == list(range(1, len(spans) + 1)),
            'stage sequences are incomplete or duplicated')
    stages = [row['stage'] for row in spans]
    decision = log.get('decision')
    require(decision in ('allow', 'block') and 'stop_stage' in log, 'decision is missing')
    stop = log['stop_stage']
    require((decision == 'allow' and stop is None)
            or (decision == 'block' and stop == stages[-1]), 'stop stage contradicts execution')
    return {'request_id': request_id, 'trace_id': trace_id, 'decision': decision,
            'stages': stages, 'stop_stage': stop, 'downstream_count': count}


def check_analysis(bundle, request_id, execution, *, expected_invalid=False):
    """Fail closed; damaged teaching copies must be marked by the server only."""
    try:
        expected = expected_analysis(bundle, request_id)
    except EvidenceMismatch:
        if not expected_invalid:
            raise
        require(execution.get('execution_status') == 'invalid_evidence',
                'incomplete evidence was not rejected')
        return {'input_kind': 'damaged_copy', 'analysis_correct': True}
    require(not expected_invalid, 'negative fixture is not damaged')
    require(execution.get('execution_status') == 'returned', 'analysis did not return a result')
    actual = execution.get('value')
    require(isinstance(actual, dict) and set(actual) == set(expected), 'analysis fields differ')
    require(type(actual.get('downstream_count')) is int, 'call count must be an integer')
    require(actual == expected, 'analysis differs from the current request evidence')
    return {'input_kind': 'current_evidence', 'analysis_correct': True, 'analysis': expected}
