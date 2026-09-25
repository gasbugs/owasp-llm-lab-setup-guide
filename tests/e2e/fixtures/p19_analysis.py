"""Publisher-only alternative implementation; never included in learner images."""


def analyze_incident(bundle, request_id):
    if not isinstance(bundle, dict) or not isinstance(request_id, str) or not request_id:
        raise ValueError('invalid input')
    records = {}
    for kind in ('logs', 'spans', 'closures', 'downstream_calls'):
        rows = bundle.get(kind)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError('invalid records')
        records[kind] = [row for row in rows if row.get('request_id') == request_id]
    if len(records['logs']) != 1 or len(records['closures']) != 1:
        raise ValueError('ambiguous request')
    log = records['logs'][0]
    trace = log.get('trace_id')
    if not isinstance(trace, str) or not trace:
        raise ValueError('missing trace')
    for rows in records.values():
        if any(row.get('trace_id') != trace for row in rows):
            raise ValueError('mixed traces')
    closure = records['closures'][0]
    count = closure.get('downstream_count')
    if closure.get('closed') is not True or type(count) is not int:
        raise ValueError('unfinished ledger')
    if count != len(records['downstream_calls']):
        raise ValueError('inconsistent calls')
    ordered = {}
    for span in records['spans']:
        number, stage = span.get('sequence'), span.get('stage')
        if type(number) is not int or number < 1 or number in ordered:
            raise ValueError('invalid sequence')
        if not isinstance(stage, str) or not stage:
            raise ValueError('missing stage')
        ordered[number] = stage
    if not ordered or set(ordered) != set(range(1, len(ordered) + 1)):
        raise ValueError('missing spans')
    stages = [ordered[number] for number in range(1, len(ordered) + 1)]
    if 'stop_stage' not in log:
        raise ValueError('missing stop')
    decision, stop = log.get('decision'), log['stop_stage']
    if decision == 'allow':
        if stop is not None:
            raise ValueError('allow cannot stop')
    elif decision == 'block':
        if stop != stages[-1]:
            raise ValueError('wrong stop')
    else:
        raise ValueError('invalid decision')
    return dict(request_id=request_id, trace_id=trace, decision=decision,
                stages=stages, stop_stage=stop, downstream_count=count)
