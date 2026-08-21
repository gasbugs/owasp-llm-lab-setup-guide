from nemoguardrails import LLMRails
from nemoguardrails.actions import action


@action(is_system_action=True)
async def get_security_contact() -> str:
    """Return a synthetic, read-only contact used by the course."""

    return "보안팀 연락처: security@example.invalid"


def init(app: LLMRails) -> None:
    app.register_action(get_security_contact, "get_security_contact")
