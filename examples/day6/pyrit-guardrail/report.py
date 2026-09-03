"""Project the PyRIT memory into Application-owned security evidence."""

import json

from pyrit.memory import CentralMemory


def print_result(result) -> None:
    memory = CentralMemory.get_memory_instance()
    observed = {}
    response_errors = []
    for conversation_id in result.get_all_conversation_ids():
        messages = memory.get_conversation_messages(conversation_id=conversation_id)
        for index, message in enumerate(messages[1:], start=1):
            try:
                response = json.loads(message.get_value())
            except json.JSONDecodeError:
                continue
            if "application_decision" not in response:
                if "http_status" in response:
                    response_errors.append(response["http_status"])
                continue
            candidate = (message.get_piece().timestamp, messages[index - 1], response)
            previous = observed.get(response["request_id"])
            if previous is None or len(candidate[1].get_value()) < len(previous[1].get_value()):
                observed[response["request_id"]] = candidate

    turns = []
    for number, (_, prompt, response) in enumerate(sorted(observed.values()), start=1):
        blocked = next(
            (stage["stage"] for stage in response["guardrail"]["stages"] if stage["decision"] == "block"),
            None,
        )
        turns.append(
            {
                "turn": number,
                "prompt": prompt.get_value(),
                "request_id": response["request_id"],
                "application_decision": response["application_decision"],
                "blocking_reason": response["blocking_reason"],
                "upstream_called": response["upstream_called"],
                "detected_stage": blocked,
                "reply": response["reply"],
            }
        )

    if result.executed_turns and not turns:
        print(json.dumps({
            "pyrit_outcome": "error",
            "course_verdict": "ERR",
            "error_type": "ApplicationEvidenceMissing",
            "http_status": response_errors[-1] if response_errors else None,
        }))
        raise SystemExit(1)

    print(
        json.dumps(
            {
                "pyrit_outcome": result.outcome.value,
                "executed_turns": result.executed_turns,
                "objective_score": result.last_score.get_value(),
                "turns": turns,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
