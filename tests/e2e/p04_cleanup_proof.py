"""Read-only local ownership prerequisite for publisher P04 cleanup.

This is not deletion authorization: the caller must stop its test writers,
audit current AWS identity/policy/tags/versions/timestamps, and delete only
the proven ID. Failed, reused, stale, or unfinished runs require inspection.
No AWS clients or destructive operations belong in this module.
"""
from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
import time

from p04_contract import canonical
from p04_ledger import identifier
from p04_resource_contract import template
from p04_suites import resource_snapshot


def require(condition):
    if not condition:
        raise ValueError('P04 cleanup ownership is not established')


def stamp(value):
    require(type(value) in (int, float) and math.isfinite(value) and value > 0)
    return value


def request_ids(values, minimum):
    require(isinstance(values, list) and minimum <= len(values) <= 200)
    require(all(isinstance(value, str) and value.isascii() and 1 <= len(value) <= 256
                for value in values))
    require(len(set(values)) == len(values))
    return values


def validate_local_ownership(preflight, prepared, journal_path, *, now=time.time):
    """Bind trusted publisher receipts to the latest unmodified local journal.

    Open the existing SQLite file read-only; never initialize missing tables.
    Require cleanup within two hours and preparation within five minutes of
    preflight. These are publisher safety bounds, not learner time limits.
    """
    try:
        require(isinstance(preflight, dict) and isinstance(prepared, dict))
        identifier(preflight['preflight_id'])
        identifier(prepared['operation_id'])
        specification = template(prepared['account_id'])
        require(preflight['account_id'] == prepared['account_id'])
        require(preflight['region'] == 'us-east-1' and preflight['name'] == specification['name'])
        require(preflight['resources_absent'] is True)
        require(preflight['scope'] == 'read-only P04 absence preflight; no creation or cleanup authorization')
        require(preflight['template_digest'] == prepared['template_digest'] == specification['template_digest'])
        before, observed = stamp(preflight['started_at']), stamp(preflight['finished_at'])
        started, finished, current = stamp(prepared['started_at']), stamp(prepared['finished_at']), stamp(now())
        require(before <= observed <= started <= finished <= current)
        require(observed - before < 90 and started - observed <= 300
                and finished - started <= 300 and current - before <= 7200)
        evidence = prepared['evidence']
        require(isinstance(evidence, dict) and set(evidence) == {'created', 'aws_request_ids'})
        require(prepared['practice_id'] == 'P04' and prepared['state'] == 'ready' and evidence['created'] is True)
        ids = request_ids(preflight['aws_request_ids'], 2) + request_ids(evidence['aws_request_ids'], 3)
        require(len(set(ids)) == len(ids))
        snapshot = resource_snapshot(prepared['resources'])
        require(snapshot['provider_mode'] == 'aws'
                and snapshot['policy_digest'] == specification['template_digest']
                and snapshot['guardrail_arn'].split(':')[4] == prepared['account_id'])
        path = Path(journal_path).resolve(strict=True)
        require(path.is_file())
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            db.execute('BEGIN')
            row = db.execute('SELECT * FROM p04_preparations ORDER BY sequence DESC LIMIT 1').fetchone()
            require(row is not None)
            actual = dict(row)
            actual.pop('sequence')
            actual['resources'] = json.loads(actual.pop('snapshot_json'))
            actual['evidence'] = json.loads(actual.pop('evidence_json'))
            require(canonical({'practice_id': 'P04', **actual}) == canonical(prepared))
            require(db.execute('SELECT COUNT(*) FROM p04_executions WHERE closed_at IS NULL').fetchone()[0] == 0)
            require(db.execute("SELECT COUNT(*) FROM p04_calls WHERE state='pending' OR finished_at IS NULL").fetchone()[0] == 0)
        return {'scope': 'local P04 ownership prerequisite; live AWS audit still required',
                'preflight_id': preflight['preflight_id'], 'operation_id': prepared['operation_id'],
                'account_id': prepared['account_id'], 'resources': snapshot,
                'preparation_started_at': started, 'preparation_finished_at': finished,
                'checked_at': current}
    except Exception:
        raise ValueError('P04 cleanup ownership is not established') from None
