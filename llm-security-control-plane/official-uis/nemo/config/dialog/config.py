from nemoguardrails import LLMRails
from nemoguardrails.actions import action


@action(is_system_action=True)
async def get_security_contact() -> str:
    """상태를 바꾸지 않는 합성 연락처만 돌려준다."""
    return "보안팀 연락처: security@example.com"


def init(app: LLMRails) -> None:
    app.register_action(get_security_contact, "get_security_contact")
