"""P20's provided, deterministic authorization workflow and durable raw evidence.

This is a synthetic notice service, not an LLM or injection detector. Metrics are
derived from committed requests; neither the learner nor a timer sets a risk gauge.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import uuid

from prometheus_client.core import CounterMetricFamily


PHASES = {
    'prepare': [],
    'normal': [('P20', 'notice_lookup'), *[('background', 'notice_publish')] * 3],
    'risk': [('P20', 'notice_publish'), ('P20', 'notice_publish')],
    'recovery': [('P20', 'notice_lookup')],
}


class Conflict(ValueError):
    pass


class Workflow:
    def __init__(self, database, artifact_dir=None, observe_products=None):
        self.database = str(database)
        self.observe_products = observe_products
        self.artifact_dir = Path(artifact_dir) if artifact_dir else Path(__file__).resolve().parent
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS suites (
                    suite_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, phase TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY, suite_id TEXT NOT NULL, phase TEXT NOT NULL,
                    ordinal INTEGER NOT NULL, practice TEXT NOT NULL, operation TEXT NOT NULL,
                    decision TEXT NOT NULL, finished_ns INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS downstream (
                    request_id TEXT PRIMARY KEY, notice_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY, received_ns INTEGER NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS observations (
                    suite_id TEXT PRIMARY KEY, closed_ns INTEGER);
                CREATE TABLE IF NOT EXISTS execution_builds (
                    suite_id TEXT PRIMARY KEY, build_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS checkpoints (
                    suite_id TEXT NOT NULL, name TEXT NOT NULL, at_ms INTEGER NOT NULL,
                    PRIMARY KEY(suite_id,name));
                CREATE TABLE IF NOT EXISTS product_snapshots (
                    suite_id TEXT NOT NULL, stage TEXT NOT NULL, observed_ns INTEGER NOT NULL,
                    body TEXT NOT NULL, PRIMARY KEY(suite_id,stage));
                CREATE TABLE IF NOT EXISTS runs (
                    suite_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
                    status TEXT NOT NULL, error TEXT, build_json TEXT NOT NULL);
            ''')

    def buildinfo(self):
        artifacts = {name: hashlib.sha256((self.artifact_dir / name).read_bytes()).hexdigest()
                     for name in ('rules.yaml', 'dashboard.json')}
        runners = {name: hashlib.sha256((Path(__file__).resolve().parent / name).read_bytes()).hexdigest()
                   for name in ('server.py', 'workflow.py', 'execution.py')}
        digest = hashlib.sha256(json.dumps(artifacts, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return {'source_digest': digest, 'artifact_digests': artifacts, 'runner_digests': runners}

    def require_current_build(self, db, suite_id):
        row = db.execute('SELECT build_json FROM execution_builds WHERE suite_id=?', (suite_id,)).fetchone()
        if not row or json.loads(row['build_json']) != self.buildinfo():
            raise Conflict('configuration or runner changed after execution started')

    def snapshot_products(self, db, suite_id, stage):
        # Unit-only workflows may omit products; the verifier rejects missing snapshots.
        if self.observe_products is None:
            return
        body = self.observe_products()
        encoded = json.dumps(body, allow_nan=False, sort_keys=True)
        if not isinstance(body, dict) or set(body) != {'rules', 'dashboard'} or len(encoded.encode()) > 262144:
            raise ValueError('invalid product snapshot')
        db.execute('INSERT INTO product_snapshots VALUES (?,?,?,?)',
                   (suite_id, stage, time.time_ns(), encoded))

    def claim_run(self, suite_id, started_at):
        if str(uuid.UUID(suite_id)) != suite_id:
            raise ValueError('invalid suite')
        started = datetime.fromisoformat(started_at)
        if started.tzinfo is None or not 0 <= (datetime.now(timezone.utc) - started).total_seconds() <= 180:
            raise ValueError('stale suite')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if (db.execute('SELECT 1 FROM runs WHERE suite_id=?', (suite_id,)).fetchone()
                    or db.execute('SELECT 1 FROM suites WHERE suite_id=?', (suite_id,)).fetchone()):
                raise Conflict('suite already exists')
            self.require_no_other_run(db, suite_id)
            db.execute('INSERT INTO runs VALUES (?,?,?,NULL,?)',
                       (suite_id, started_at, 'running', json.dumps(self.buildinfo(), sort_keys=True)))

    def require_no_other_run(self, db, suite_id):
        for row in db.execute("SELECT suite_id,started_at FROM runs WHERE status != 'complete'"):
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(row['started_at'])).total_seconds()
            if row['suite_id'] != suite_id and age < 180:
                raise Conflict('another run owns the observation window')

    def finish_run(self, suite_id, error=None):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            run = db.execute('SELECT status FROM runs WHERE suite_id=?', (suite_id,)).fetchone()
            if not run or run['status'] != 'running':
                raise Conflict('run is missing or already finished')
            observation = db.execute('SELECT closed_ns FROM observations WHERE suite_id=?', (suite_id,)).fetchone()
            if error is None and (not observation or observation['closed_ns'] is None):
                raise Conflict('observation is not closed')
            db.execute('UPDATE runs SET status=?,error=? WHERE suite_id=?',
                       ('error' if error else 'complete', error, suite_id))

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def run_phase(self, suite_id, started_at, phase):
        if str(uuid.UUID(suite_id)) != suite_id or phase not in PHASES:
            raise ValueError('invalid suite or phase')
        started = datetime.fromisoformat(started_at)
        if started.tzinfo is None or not 0 <= (datetime.now(timezone.utc) - started).total_seconds() <= 180:
            raise ValueError('stale suite')
        previous = {'prepare': None, 'normal': 'prepare', 'risk': 'normal', 'recovery': 'risk'}[phase]
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM suites WHERE suite_id=?', (suite_id,)).fetchone()
            if phase == 'prepare' and not row:
                self.require_no_other_run(db, suite_id)
                # A previous unfinished suite owns the short observation window.
                for active in db.execute('''SELECT s.started_at FROM suites s
                        LEFT JOIN observations o USING(suite_id) WHERE o.closed_ns IS NULL'''):
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(active['started_at'])).total_seconds()
                    if age < 180:
                        raise Conflict('another suite is in progress')
                db.execute('INSERT INTO suites VALUES (?,?,?)', (suite_id, started_at, phase))
                db.execute('INSERT INTO observations VALUES (?,NULL)', (suite_id,))
                db.execute('INSERT INTO execution_builds VALUES (?,?)',
                           (suite_id, json.dumps(self.buildinfo(), sort_keys=True)))
                self.snapshot_products(db, suite_id, 'before')
                db.execute('INSERT INTO checkpoints VALUES (?,?,?)',
                           (suite_id, 'baseline', time.time_ns() // 1_000_000))
            elif not row or row['started_at'] != started_at or row['phase'] != previous:
                raise Conflict('invalid phase order or execution identity')
            else:
                self.require_current_build(db, suite_id)
            for ordinal, (practice, operation) in enumerate(PHASES[phase]):
                request_id = str(uuid.uuid4())
                # The server owns the reader principal. Publish never reaches the notice store.
                allowed = operation == 'notice_lookup'
                if allowed:
                    self.lookup_notice(db, request_id)
                db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?)',
                           (request_id, suite_id, phase, ordinal, practice, operation,
                            'allow' if allowed else 'block', time.time_ns()))
            db.execute('UPDATE suites SET phase=? WHERE suite_id=?', (phase, suite_id))
        return self.receipt(suite_id)

    def mark_checkpoint(self, suite_id, started_at, name):
        if str(uuid.UUID(suite_id)) != suite_id or name not in ('normal', 'after_requests'):
            raise ValueError('invalid checkpoint')
        started = datetime.fromisoformat(started_at)
        if started.tzinfo is None or not 0 <= (datetime.now(timezone.utc)-started).total_seconds() <= 180:
            raise ValueError('stale checkpoint')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('''SELECT s.*, o.closed_ns FROM suites s
                JOIN observations o USING(suite_id) WHERE suite_id=?''', (suite_id,)).fetchone()
            expected_phase = 'normal' if name == 'normal' else 'recovery'
            if (not row or row['started_at'] != started_at or row['phase'] != expected_phase
                    or row['closed_ns'] is not None):
                raise Conflict('checkpoint outside active phase')
            self.require_current_build(db, suite_id)
            saved = dict(db.execute('SELECT name,at_ms FROM checkpoints WHERE suite_id=?', (suite_id,)))
            if set(saved) != ({'baseline'} if name == 'normal' else {'baseline', 'normal'}):
                raise Conflict('checkpoint missing, repeated or out of order')
            at_ms = time.time_ns() // 1_000_000
            last = db.execute('SELECT MAX(finished_ns) FROM requests WHERE suite_id=?', (suite_id,)).fetchone()[0]
            if last is None or at_ms * 1_000_000 < last + (8_000_000_000 if name == 'normal' else 0):
                raise Conflict('observation interval not finished')
            db.execute('INSERT INTO checkpoints VALUES (?,?,?)', (suite_id, name, at_ms))
        return self.receipt(suite_id)

    @staticmethod
    def lookup_notice(db, request_id):
        # This row is a side-effect ledger written by the actual synthetic store call.
        db.execute('INSERT INTO downstream VALUES (?,?)', (request_id, 'training-notice'))
        return {'notice_id': 'training-notice', 'text': '교육용 공지입니다.'}

    def receipt(self, suite_id):
        if str(uuid.UUID(suite_id)) != suite_id:
            raise ValueError('invalid suite')
        with self.connection() as db:
            row = db.execute('SELECT * FROM suites WHERE suite_id=?', (suite_id,)).fetchone()
            run = db.execute('SELECT * FROM runs WHERE suite_id=?', (suite_id,)).fetchone()
            if not row:
                if not run:
                    raise KeyError('suite not found')
                return {'suite_id': suite_id, 'started_at': run['started_at'], 'activity_id': 'P20',
                        'internal_activity_id': 'H20', 'contract_version': 2, 'cases': [],
                        'closed': False, 'requests_closed': False,
                        'build': json.loads(run['build_json']), 'execution_status': run['status'],
                        'execution_error': run['error']}
            cases = [dict(r) for r in db.execute('''SELECT r.*,
                (SELECT COUNT(*) FROM downstream d WHERE d.request_id=r.request_id) AS downstream_count
                FROM requests r WHERE suite_id=? ORDER BY finished_ns, ordinal''', (suite_id,))]
            observation = db.execute('SELECT closed_ns FROM observations WHERE suite_id=?',
                                     (suite_id,)).fetchone()
            closed_ns = observation['closed_ns'] if observation else None
            build = db.execute('SELECT build_json FROM execution_builds WHERE suite_id=?', (suite_id,)).fetchone()
            return {**dict(row), 'activity_id': 'P20', 'internal_activity_id': 'H20',
                    'execution_status': run['status'] if run else 'manual',
                    'execution_error': run['error'] if run else None,
                    'checkpoints': dict(db.execute('SELECT name,at_ms FROM checkpoints WHERE suite_id=?', (suite_id,))),
                    'build': json.loads(build['build_json']) if build else None,
                    'product_snapshots': {r['stage']: {'observed_ns': r['observed_ns'],
                        'body': json.loads(r['body'])} for r in db.execute(
                            'SELECT * FROM product_snapshots WHERE suite_id=?', (suite_id,))},
                    'contract_version': 2, 'cases': cases, 'requests_closed': row['phase'] == 'recovery',
                    'observation_closed_ns': closed_ns, 'closed': closed_ns is not None}

    def close_observation(self, suite_id, started_at):
        if str(uuid.UUID(suite_id)) != suite_id:
            raise ValueError('invalid suite')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('''SELECT s.*, o.closed_ns FROM suites s
                JOIN observations o USING(suite_id) WHERE suite_id=?''', (suite_id,)).fetchone()
            if not row or row['started_at'] != started_at or row['phase'] != 'recovery':
                raise Conflict('invalid observation identity or requests unfinished')
            self.require_current_build(db, suite_id)
            if row['closed_ns'] is not None:
                return self.receipt(suite_id)
            now = time.time_ns()
            start = datetime.fromisoformat(started_at).timestamp()
            if not 0 <= now / 1e9 - start <= 180:
                raise Conflict('observation expired')
            risk = db.execute("SELECT MIN(finished_ns) FROM requests WHERE suite_id=? AND phase='risk'",
                              (suite_id,)).fetchone()[0]
            fired = {}
            matched = False
            for saved in db.execute('''SELECT * FROM notifications WHERE received_ns BETWEEN ? AND ?
                    ORDER BY id''', (risk, now)):
                alerts = json.loads(saved['body']).get('alerts', [])
                if not isinstance(alerts, list):
                    continue
                for alert in alerts:
                    try:
                        labels = alert['labels']
                        if (labels.get('alertname') != 'GuidedP20BlockedRequests'
                                or labels.get('practice') != 'P20' or labels.get('severity') != 'warning'):
                            continue
                        onset = datetime.fromisoformat(alert['startsAt'].replace('Z', '+00:00'))
                        fingerprint = alert['fingerprint']
                        if (not isinstance(fingerprint, str) or not fingerprint or onset.tzinfo is None
                                or not risk / 1e9 <= onset.timestamp() <= saved['received_ns'] / 1e9):
                            continue
                        key = (fingerprint, alert['startsAt'])
                        if alert['status'] == 'firing':
                            fired.setdefault(key, saved['received_ns'])
                        elif alert['status'] == 'resolved' and key in fired:
                            end = datetime.fromisoformat(alert['endsAt'].replace('Z', '+00:00'))
                            if (end.tzinfo is not None and onset < end
                                    and fired[key] / 1e9 <= end.timestamp() <= saved['received_ns'] / 1e9):
                                matched = True
                    except (KeyError, ValueError, TypeError, AttributeError):
                        continue
            if not matched:
                raise Conflict('current firing and resolved notifications not observed')
            self.snapshot_products(db, suite_id, 'after')
            now = time.time_ns()
            if not 0 <= now / 1e9 - start <= 180:
                raise Conflict('observation expired during product collection')
            db.execute('UPDATE observations SET closed_ns=? WHERE suite_id=?', (now, suite_id))
        return self.receipt(suite_id)

    def notification(self, body):
        encoded = json.dumps(body, separators=(',', ':'), ensure_ascii=False)
        if len(encoded.encode()) > 65536 or not isinstance(body, dict):
            raise ValueError('invalid notification')
        with self.connection() as db:
            db.execute('INSERT INTO notifications(received_ns,body) VALUES (?,?)', (time.time_ns(), encoded))

    def notifications(self, start_ns, end_ns):
        if not 0 <= start_ns <= end_ns or end_ns - start_ns > 180_000_000_000:
            raise ValueError('invalid observation window')
        with self.connection() as db:
            return [{'received_ns': r['received_ns'], 'body': json.loads(r['body'])}
                    for r in db.execute('''SELECT received_ns,body FROM notifications
                        WHERE received_ns BETWEEN ? AND ? ORDER BY id LIMIT 200''', (start_ns, end_ns))]

    def collect(self):
        metric = CounterMetricFamily('guided_p20_decisions', 'Committed synthetic notice decisions',
                                     labels=['practice', 'decision'])
        with self.connection() as db:
            counts = {(r['practice'], r['decision']): r['count'] for r in db.execute(
                'SELECT practice,decision,COUNT(*) AS count FROM requests GROUP BY practice,decision')}
        for practice in ('P20', 'background'):
            for decision in ('allow', 'block'):
                metric.add_metric([practice, decision], counts.get((practice, decision), 0))
        yield metric
