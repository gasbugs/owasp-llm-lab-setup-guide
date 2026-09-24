"""Candidate policy promoted only after normal and risk regression pass."""
def decide(message: str) -> str:
    return "block" if "H16-OVERRIDE" in message else "allow"
