"""Installation-local completion history, written only from server verification."""
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone


class ProgressStore:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.db:
            self.db.execute('''CREATE TABLE IF NOT EXISTS progress (
                problem TEXT PRIMARY KEY, attempt TEXT NOT NULL, needs_check INTEGER NOT NULL,
                execution TEXT, digest TEXT, completed_at TEXT)''')

    def begin(self, problem):
        attempt = uuid.uuid4().hex
        with self.lock, self.db:
            self.db.execute('''INSERT INTO progress(problem, attempt, needs_check) VALUES (?, ?, 1)
                ON CONFLICT(problem) DO UPDATE SET attempt=excluded.attempt, needs_check=1''',
                (problem, attempt))
        return attempt

    def finish(self, problem, attempt, payload):
        if (payload.get('activity_id') != problem or payload.get('task_completed') is not True
                or payload.get('course_verdict') not in {'PASS', 'HIT'}
                or payload.get('verified_by') != 'guided-evidence-verifier'
                or payload.get('resource_ready') or not payload.get('execution_id')):
            return
        result = payload.get('result') or {}
        digest = (payload.get('source_digest') or result.get('source_digest')
                  or (result.get('receipt') or {}).get('source_digest') or result.get('config_digest'))
        if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
            digest = None
        with self.lock, self.db:
            self.db.execute('''UPDATE progress SET execution=?, digest=?, completed_at=?, needs_check=0
                WHERE problem=? AND attempt=?''', (payload['execution_id'], digest,
                datetime.now(timezone.utc).isoformat(), problem, attempt))

    def history(self):
        with self.lock:
            return [dict(row) for row in self.db.execute(
                'SELECT problem, execution, digest, completed_at, needs_check FROM progress '
                'WHERE completed_at IS NOT NULL ORDER BY problem')]

    def mark_changed(self, problem, execution):
        with self.lock, self.db:
            self.db.execute('UPDATE progress SET needs_check=1 WHERE problem=? AND execution=?',
                            (problem, execution))
