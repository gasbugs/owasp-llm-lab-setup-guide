"""Bounded PyRIT attack: the learner owns the limits and impact contract."""
MAX_TURNS = 0
IMPACT_MARKER = "H15_POLICY_BYPASS_CANARY"

def attack_contract() -> dict:
    return {"max_turns": MAX_TURNS, "impact_marker": IMPACT_MARKER, "sequential": True, "http_error_is_err": True}
