"""Execute the actual learner pipeline in a bounded child, not a security sandbox.

Only per-execution service credentials enter the worker. The caller must never
include control/verifier/AWS credentials. Downstream ledgers remain authoritative.
"""
import asyncio
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
INPUT_LIMIT = 128 * 1024
OUTPUT_LIMIT = 128 * 1024


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode()


def reject_constant(_value):
    raise ValueError("non-finite value")


def execute(source_path, request, configuration, *, timeout=150):
    if not 0 < timeout <= 150:
        raise ValueError("bounded execution timeout required")
    with Path(source_path).open("rb") as source_file:
        source = source_file.read(SOURCE_LIMIT + 1)
    base = {"source_digest": hashlib.sha256(source).hexdigest() if len(source) <= SOURCE_LIMIT else None, "calls": None}
    if len(source) > SOURCE_LIMIT:
        return {**base, "execution_status": "source_limit"}
    try:
        if set(configuration) != {"suite_id", "execution_id", "origins", "tokens", "capabilities"}:
            raise ValueError("invalid worker configuration")
        if set(configuration["tokens"]) != {"context", "privacy", "nemo"}:
            raise ValueError("only invocation credentials enter worker")
        if set(request) != {"credential", "tenant", "message"} or any(not isinstance(value, str) for value in request.values()):
            raise ValueError("invalid request")
        payload = encode({"request": request, "configuration": configuration})
        if len(payload) > INPUT_LIMIT:
            return {**base, "execution_status": "input_limit"}
        envelope = encode({"source": source.decode(), "input": json.loads(payload)})
    except (ValueError, TypeError, UnicodeError):
        return {**base, "execution_status": "invalid_input"}
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
                                 stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                                 env={}, start_new_session=True)
        try:
            child.communicate(envelope, timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            return {**base, "execution_status": "timeout"}
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
        if child.returncode:
            return {**base, "execution_status": "runtime_error"}
        output.seek(0)
        raw = output.read(OUTPUT_LIMIT + 1)
    if len(raw) > OUTPUT_LIMIT:
        return {**base, "execution_status": "output_limit"}
    try:
        result = json.loads(raw, parse_constant=reject_constant)
        if not isinstance(result, dict) or result.get("execution_status") not in {
                "returned", "not_implemented", "runtime_error", "service_error", "invalid_return", "output_limit"}:
            raise ValueError("invalid worker response")
        return {**result, "source_digest": base["source_digest"]}
    except (ValueError, TypeError):
        return {**base, "execution_status": "runtime_error"}


def child():
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    sys.path.insert(0, str(Path(__file__).parent))
    from service_client import ServiceClient, ServiceError
    services = None
    result = {"execution_status": "runtime_error", "calls": None}
    try:
        envelope = json.load(sys.stdin)
        services = ServiceClient(**envelope["input"]["configuration"])
        namespace = {"__name__": "p12_learner"}
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink):
            exec(compile(envelope["source"], "pipeline.py", "exec"), namespace)
            function = namespace.get("handle_request")
            if function is None:
                raise NotImplementedError
            value = asyncio.run(function(envelope["input"]["request"], services))
        if (not isinstance(value, dict) or set(value) != {"status", "text"}
                or type(value["status"]) is not int or value["status"] not in {200, 401, 403, 404}
                or not isinstance(value["text"], str) or len(value["text"]) > 16000
                or (value["status"] == 200 and not value["text"].strip())
                or (value["status"] != 200 and value["text"] != "")):
            result = {"execution_status": "invalid_return"}
        else:
            result = {"execution_status": "returned", "result": {"status": value["status"],
                "text_digest": hashlib.sha256(value["text"].encode()).hexdigest(), "text_bytes": len(value["text"].encode())}}
    except NotImplementedError:
        result = {"execution_status": "not_implemented"}
    except ServiceError:
        result = {"execution_status": "service_error"}
    except BaseException:
        result = {"execution_status": "runtime_error"}
    result["calls"] = services.calls if services else None
    raw = encode(result)
    if len(raw) > OUTPUT_LIMIT:
        raw = encode({"execution_status": "output_limit", "calls": None})
    sys.stdout.buffer.write(raw)


if __name__ == "__main__" and sys.argv[1:] == ["--child"]:
    child()
