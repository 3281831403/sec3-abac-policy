"""Public surface of the ABAC policy engine."""

from .eval import (
    MISSING,
    abac_batch,
    combine,
    compare,
    eval_condition,
    eval_rule,
    parse_policy,
    resolve_attr,
    validate_policy,
)

__all__ = [
    "MISSING",
    "abac_batch",
    "combine",
    "compare",
    "eval_condition",
    "eval_rule",
    "parse_policy",
    "resolve_attr",
    "validate_policy",
]