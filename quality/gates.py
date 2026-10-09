"""Typed fail-closed quality decisions; missing evidence cannot pass a gate."""
from dataclasses import asdict, dataclass
import math
from typing import Literal

Status = Literal["PASS", "FAIL", "UNAVAILABLE"]


@dataclass(frozen=True)
class Gate:
    name: str
    status: Status
    required: bool
    detail: str

    def record(self) -> dict[str, object]:
        return asdict(self)


def numeric_gate(name: str, value: float | None, boundary: float, *, minimum: bool = True,
                 required: bool = True) -> Gate:
    if value is None or not math.isfinite(value):
        return Gate(name, "UNAVAILABLE", required, "Finite measurement missing")
    good = value >= boundary if minimum else value <= boundary
    direction = ">=" if minimum else "<="
    return Gate(name, "PASS" if good else "FAIL", required, f"{value:.6g} {direction} {boundary:.6g}")


def all_required_pass(gates: list[Gate]) -> bool:
    required = [g for g in gates if g.required]
    return bool(required) and all(g.status == "PASS" for g in required)


def wilson(successes: int, total: int) -> tuple[float, float] | None:
    """95% binomial interval; row independence is an explicit limitation."""
    if total < 0 or successes < 0 or successes > total:
        raise ValueError("Invalid binomial counts")
    if total == 0:
        return None
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    half = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator
    return max(0.0, center - half), min(1.0, center + half)
