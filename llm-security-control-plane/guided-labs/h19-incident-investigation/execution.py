"""Bound a local learner function; this is failure isolation, not a code sandbox.

The caller owns evidence collection. This module neither grades results nor
substitutes an implementation. Never import learner code into the API process.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

SOURCE_LIMIT = 64 * 1024
INPUT_LIMIT = 256 * 1024
OUTPUT_LIMIT = 64 * 1024


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')


def reject_constant(value):
    raise ValueError('non-finite JSON value')


def execute(source_path, bundle, request_id, *, timeout=3):
    source = Path(source_path).read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    base = {'source_digest': digest}
    if len(source) > SOURCE_LIMIT:
        return {**base, 'execution_status': 'source_limit'}
    try:
        payload = encode({'bundle': bundle, 'request_id': request_id})
        if len(payload) > INPUT_LIMIT:
            return {**base, 'execution_status': 'input_limit'}
        envelope = encode({'source': source.decode('utf-8'), 'input': json.loads(payload)})
    except (UnicodeError, ValueError, TypeError):
        return {**base, 'execution_status': 'invalid_input'}
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(
            [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--child'],
            stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
            env={}, start_new_session=True,
        )
        try:
            process.communicate(envelope, timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return {**base, 'execution_status': 'timeout'}
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        if process.returncode:
            return {**base, 'execution_status': 'runtime_error'}
        output.seek(0)
        raw = output.read(OUTPUT_LIMIT + 1)
    if len(raw) > OUTPUT_LIMIT:
        return {**base, 'execution_status': 'output_limit'}
    try:
        result = json.loads(raw, parse_constant=reject_constant)
        if not isinstance(result, dict) or result.get('execution_status') not in {
            'returned', 'invalid_evidence', 'not_implemented', 'runtime_error', 'output_limit'
        }:
            raise ValueError('invalid runner response')
        return {**result, **base}
    except (ValueError, TypeError):
        return {**base, 'execution_status': 'runtime_error'}


def child():
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    envelope = json.load(sys.stdin)
    try:
        namespace = {'__name__': 'p19_learner'}
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink):
            exec(compile(envelope['source'], 'investigation.py', 'exec'), namespace)
            try:
                value = namespace['analyze_incident'](**envelope['input'])
            except ValueError:
                sys.__stdout__.buffer.write(encode({'execution_status': 'invalid_evidence'}))
                return
        if not isinstance(value, dict):
            raise TypeError('return value must be an object')
        result = {'execution_status': 'returned', 'value': value}
        raw = encode(result)
        if len(raw) > OUTPUT_LIMIT:
            result = {'execution_status': 'output_limit'}
    except NotImplementedError:
        result = {'execution_status': 'not_implemented'}
    except BaseException as exc:
        result = {'execution_status': 'runtime_error', 'error_type': type(exc).__name__}
    sys.stdout.buffer.write(encode(result))


if __name__ == '__main__' and sys.argv[1:] == ['--child']:
    child()
