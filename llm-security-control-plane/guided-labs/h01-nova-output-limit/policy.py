"""H01 starter policy that the learner completes with the instructor."""


def apply_output_limit(requested_max_tokens: int) -> int:
    """Return the limit that will actually be sent to the model."""

    # TODO: Keep small normal requests working, but cap oversized requests at 128.
    # The starter intentionally forwards 512 unchanged so the first check is HIT.
    return requested_max_tokens
