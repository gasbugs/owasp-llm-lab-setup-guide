"""SCENARIO 환경변수로 매일 다른 시나리오를 로드한다."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List


@dataclass
class Scenario:
    id: str
    title: str
    intro: str
    warning: str
    build_system_prompt: Callable[..., str]
    retrieve: Callable[[str], List[str]] = field(default=lambda _q: [])
    add_doc: Callable[..., None] = field(default=lambda **_: None)
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
