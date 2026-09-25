"""Execute the P04 learner function in a bounded child; this is not a security sandbox."""
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
from uuid import UUID

SOURCE_LIMIT = 65536
INPUT_LIMIT = 65536
OUTPUT_LIMIT = 65536


class LearnerRejected(Exception):
    pass


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode()


def execute(source_path, body, guardrail, configuration, *, timeout=75):
    if type(timeout) not in (int, float) or not 0 < timeout <= 75:
        raise ValueError("bounded timeout required")
    with Path(source_path).open("rb") as stream:
        source = stream.read(SOURCE_LIMIT + 1)
    base = {"source_digest": hashlib.sha256(source).hexdigest() if len(source) <= SOURCE_LIMIT else None,
            "calls": None}
    if len(source) > SOURCE_LIMIT:
        return {**base, "execution_status": "source_limit"}
    try:
        if set(configuration) != {"suite_id", "execution_id", "origin", "capability"}:
            raise ValueError("only invocation configuration enters worker")
        execution_id = str(UUID(configuration["execution_id"]))
        if execution_id != configuration["execution_id"]:
            raise ValueError("invalid execution identity")
        if (not isinstance(guardrail, dict)
                or set(guardrail) != {"guardrailIdentifier", "guardrailVersion"}
                or not isinstance(guardrail["guardrailIdentifier"], str)
                or not guardrail["guardrailIdentifier"].isascii()
                or not 1 <= len(guardrail["guardrailIdentifier"]) <= 2048
                or not guardrail["guardrailIdentifier"].strip()
                or guardrail["guardrailVersion"] != "DRAFT"):
            raise ValueError("invalid server-issued Guardrail reference")
        payload = encode({"body": body, "guardrail": guardrail, "configuration": configuration})
        if len(payload) > INPUT_LIMIT:
            return {**base, "execution_status": "input_limit"}
        envelope = encode({"source": source.decode(), "input": json.loads(payload)})
    except (ValueError, TypeError, AttributeError):
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
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get("execution_status") not in {
            "returned", "rejected", "not_implemented", "runtime_error", "service_error", "invalid_return", "output_limit"
        }:
            raise ValueError()
        encode(result)
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
    try:
        envelope = json.load(sys.stdin)
        configuration = envelope["input"]["configuration"]
        services = ServiceClient(**configuration)
        namespace = {"__name__": "p04_learner"}
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink):
            exec(compile(envelope["source"], "learner.py", "exec"), namespace)
            function = namespace.get("invoke_guarded")
            if function is None:
                raise NotImplementedError()
            try:
                value = asyncio.run(function(envelope["input"]["body"], envelope["input"]["guardrail"], services))
            except ValueError:
                raise LearnerRejected() from None
        if not isinstance(value, dict):
            result = {"execution_status": "invalid_return"}
        else:
            result = {"execution_status": "returned", "result": value}
    except NotImplementedError:
        result = {"execution_status": "not_implemented"}
    except ServiceError:
        result = {"execution_status": "service_error"}
    except LearnerRejected:
        result = {"execution_status": "rejected"}
    except BaseException:
        result = {"execution_status": "runtime_error"}
    result["calls"] = services.calls if services else None
    try:
        raw = encode(result)
    except (ValueError, TypeError):
        raw = encode({"execution_status": "invalid_return", "calls": result["calls"]})
    if len(raw) > OUTPUT_LIMIT:
        raw = encode({"execution_status": "output_limit", "calls": None})
    sys.stdout.buffer.write(raw)


if __name__ == "__main__" and sys.argv[1:] == ["--child"]:
    child()
