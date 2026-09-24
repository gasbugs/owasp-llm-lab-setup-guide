"""Starter policy: normal traffic works, but the H16 override is still allowed."""
def decide(message: str) -> str:
    return "allow"
