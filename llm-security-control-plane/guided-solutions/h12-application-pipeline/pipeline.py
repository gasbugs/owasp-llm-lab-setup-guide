"""H12 solution: one ordered, fail-closed Application path."""


def stage_order() -> tuple[str, ...]:
    return ("authenticate", "authorize", "input_privacy", "input_rail", "retrieval", "main", "output_rail", "output_privacy")


def may_continue(status_code: int) -> bool:
    return status_code == 200
