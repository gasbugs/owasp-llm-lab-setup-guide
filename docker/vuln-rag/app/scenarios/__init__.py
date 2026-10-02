"""Load vulnerable RAG scenarios used throughout the course."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

SCENARIO_NAMES = ("prompt", "data", "llm04", "output", "knowledge", "resource")

KOREAN_PARTICLES = (
    "으로부터",
    "로부터",
    "에게서",
    "한테서",
    "에서는",
    "에게",
    "한테",
    "으로",
    "라고",
    "까지",
    "부터",
    "처럼",
    "보다",
    "에서",
    "에는",
    "은",
    "는",
    "이",
    "가",
    "을",
    "를",
    "의",
    "에",
    "로",
    "와",
    "과",
    "도",
    "만",
)


def query_tokens(query: str) -> set[str]:
    tokens: set[str] = set()
    for raw in query.split():
        token = raw.strip(" \t\r\n.,!?;:\"'`()[]{}<>").lower()
        if len(token) <= 1:
            continue
        tokens.add(token)
        for particle in KOREAN_PARTICLES:
            if token.endswith(particle) and len(token) > len(particle) + 1:
                tokens.add(token[: -len(particle)])
                break
    return tokens


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
    if name == "prompt":
        from app.scenarios.prompt import scenario
    elif name == "data":
        from app.scenarios.data import scenario
    elif name == "llm04":
        from app.scenarios.llm04 import scenario
    elif name == "output":
        from app.scenarios.output import scenario
    elif name == "knowledge":
        from app.scenarios.knowledge import scenario
    elif name == "resource":
        from app.scenarios.resource import scenario
    else:
        from app.scenarios.prompt import scenario
    return scenario


def list_scenarios() -> List[Scenario]:
    return [load_scenario(name) for name in SCENARIO_NAMES]
