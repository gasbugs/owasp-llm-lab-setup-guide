"""File-backed NeMo input/output rails with native execution evidence."""

import hashlib

from nemoguardrails import LLMRails, RailsConfig


STAGES = {
    "input_rail": ("input", "self_check_input", "self check input", "user"),
    "output_rail": ("output", "self_check_output", "self check output", "assistant"),
}
CONFIG = RailsConfig.from_path("/app/nemo-policy")


async def check_text(stage, text, model, *, config=None):
    if stage not in STAGES or not isinstance(text, str) or not text.strip() or len(text) > 8000:
        raise ValueError("invalid rail input")
    kind, task, flow, role = STAGES[stage]
    rails = LLMRails(config if config is not None else CONFIG, llm=model)
    messages = [{"role": role, "content": text}]
    if kind == "output":
        messages.insert(0, {"role": "user", "content": ""})
    generated = await rails.generate_async(
        messages=messages,
        options={"rails": [kind], "log": {"activated_rails": True, "llm_calls": True}},
    )
    calls = list(generated.log.llm_calls if generated.log else [])
    activated = list(generated.log.activated_rails if generated.log else [])
    checks = [rail for rail in activated if rail.name == flow]
    if len(calls) != 1 or calls[0].task != task or len(checks) != 1:
        raise ValueError("native rail evidence missing")
    answer = calls[0].completion
    if answer not in {"Yes", "No"}:
        raise ValueError("classifier answer invalid")
    stopped = bool(checks[0].stop)
    if stopped != (answer == "Yes"):
        raise ValueError("classifier and rail disagree")
    return {
        "allowed": not stopped,
        "evidence": {
            "stage": stage,
            "input_digest": hashlib.sha256(text.encode()).hexdigest(),
            "classifier_answer": answer,
            "native_stop": stopped,
            "rail": checks[0].name,
            "task": calls[0].task,
        },
    }
