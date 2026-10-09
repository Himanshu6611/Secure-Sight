"""Internal validated signal schema and explicit failure codes."""
from dataclasses import dataclass, asdict

class RiskError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code

@dataclass(frozen=True)
class Signal:
    signal_id: str
    category: str
    group: str
    name: str
    value: object
    normalized_value: object
    weight: float
    severity: str
    source: str
    confidence: float
    reason: str
    state: str
    selected: bool = False
    contribution: float = 0.0

    def to_dict(self):
        return asdict(self)
