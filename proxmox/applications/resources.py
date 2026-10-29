"""Finite positive resource limits shared by application renderers."""

import math


def positive(value, name, minimum=1):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < minimum
    ):
        raise ValueError(f"{name} must be a positive number")
    return value
