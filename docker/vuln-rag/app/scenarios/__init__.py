"""Load vulnerable RAG scenarios used throughout the course."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

SCENARIO_NAMES = ("day1", "day2", "day3", "day4", "day5")


@dataclass
class Scenario:
    id: str
    title: str
    intro: str
    warning: str
    build_system_prompt: Callable[..., str]
    retrieve: Callable[[str], List[str]] = field(default=lambda _q: [])
    add_doc: Callable[..., None] = field(default=lambda **_: None)
    list_docs: Callable[[], List[str]] = field(default=lambda: [])
    delete_doc: Callable[[int], str | None] = field(default=lambda _index: None)
    expose_system_prompt: bool = False


def load_scenario(name: str) -> Scenario:
    if name == "day1":
        from app.scenarios.day1 import scenario
    elif name == "day2":
        from app.scenarios.day2 import scenario
    elif name == "day3":
        from app.scenarios.day3 import scenario
    elif name == "day4":
        from app.scenarios.day4 import scenario
    elif name == "day5":
        from app.scenarios.day5 import scenario
    else:
        from app.scenarios.day1 import scenario
    return scenario


def list_scenarios() -> List[Scenario]:
    return [load_scenario(name) for name in SCENARIO_NAMES]
