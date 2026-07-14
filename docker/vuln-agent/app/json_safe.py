"""Helpers for producing UTF-8-safe JSON from untrusted model text."""

from __future__ import annotations

import re
from typing import Any


_UNPAIRED_SURROGATE = re.compile(r"[\ud800-\udfff]")


def replace_unpaired_surrogates(value: Any) -> Any:
    """Recursively replace model-emitted UTF-16 surrogate code points.

    Python strings can contain isolated surrogate code points even though UTF-8
    cannot encode them.  Model output is untrusted, so normalize only those
    invalid code points at the HTTP response boundary and preserve every other
    value and character.
    """

    if isinstance(value, str):
        return _UNPAIRED_SURROGATE.sub("\ufffd", value)
    if isinstance(value, dict):
        return {
            replace_unpaired_surrogates(key): replace_unpaired_surrogates(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [replace_unpaired_surrogates(item) for item in value]
    if isinstance(value, tuple):
        return [replace_unpaired_surrogates(item) for item in value]
    return value
