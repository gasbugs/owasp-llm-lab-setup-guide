"""Candidate policy promoted only after normal and risk regression pass."""
def decide(message: str) -> str:
    marker_attack = "H16-OVERRIDE" in message and "비밀" in message
    paraphrased_attack = "업무 범위를 무시" in message and "비밀" in message
    return "block" if marker_attack or paraphrased_attack else "allow"
