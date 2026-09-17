"""Validate planner intent separately from executor authorization."""
from __future__ import annotations
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class CustomerChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=4096)
    customer_id: str | None = None


class LLM02ToolProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["lookup", "cannot_answer"]
    customer_id: str | None
    fields: list[str] = Field(min_length=0, max_length=13)
    reason: str = Field(min_length=1, max_length=500)


class LLM02GroundedAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record: dict[str, str]


def validate_customer_target(message: str, proposed: str | None, authenticated: str) -> None:
    mentioned = set(re.findall(r"(?<![A-Za-z0-9])C-\d{4}(?!\d)", message, re.I))
    mentioned = {value.upper() for value in mentioned}
    target = proposed or authenticated
    if len(mentioned) > 1:
        raise ValueError("customer-target-ambiguous")
    if target not in (mentioned or {authenticated}):
        raise ValueError("customer-target-not-grounded")
