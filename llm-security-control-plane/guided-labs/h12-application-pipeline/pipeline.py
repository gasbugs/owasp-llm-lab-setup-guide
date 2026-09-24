"""Learner-owned H12 orchestration policy. Starter retrieves before authentication."""


def stage_order() -> tuple[str, ...]:
    # 취약한 Starter: 검색이 인증보다 먼저이고 실패 뒤에도 다음 단계를 실행합니다.
    return ("retrieval", "authenticate", "authorize", "input_privacy", "input_rail", "main", "output_rail", "output_privacy")


def may_continue(status_code: int) -> bool:
    return True
