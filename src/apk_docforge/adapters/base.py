from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterSearchResult:
    source: str
    candidates: list[dict[str, Any]] = field(default_factory=list)
    policy_decision: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
