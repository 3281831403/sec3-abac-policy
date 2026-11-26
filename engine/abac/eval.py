"""Attribute based access control policy evaluation.

A policy is a mapping with a list of rules, a combination strategy and the
attributes the policy depends on.  Conditions are either boolean groups or
atomic comparisons over a request context.
"""

from __future__ import annotations

from collections.abc import Mapping

MISSING = object()

_KNOWN_OPS = frozenset(
    {
        "eq",
        "ne",
        "in",
        "not_in",
        "has",
        "has_any",
        "prefix",
        "gt",
        "gte",
        "lt",
        "lte",
    }
)
_ORDER_OPS = frozenset({"gt", "gte", "lt", "lte"})
_COMBINE_MODES = frozenset(
    {"deny_overrides", "allow_overrides", "first_applicable"}
)


def _is_number(value):
    """Return True for real numbers, excluding booleans."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _as_collection(value):
    """Return the value when it behaves as an unordered collection."""
    if isinstance(value, (list, tuple, set, frozenset)):
        return value
    return None


def _normalise_value(value):
    """Return a stable representation for a policy literal."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return value


def _parse_condition(condition):
    if condition is None:
        return None
    if not isinstance(condition, Mapping):
        raise TypeError("condition must be a mapping")
    if "all" in condition:
        return {"all": [_parse_condition(item) for item in condition["all"]]}
    if "any" in condition:
        return {"any": [_parse_condition(item) for item in condition["any"]]}
    if "not" in condition:
        return {"not": _parse_condition(condition["not"])}
    return {
        "attr": condition.get("attr"),
        "op": condition.get("op", "eq"),
        "value": _normalise_value(condition.get("value")),
    }


def parse_policy(policy) -> dict:
    """Normalise a policy document for evaluation."""
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")
    raw_rules = policy.get("rules") or []
    rules = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, Mapping):
            raise TypeError("each rule must be a mapping")
        rules.append(
            {
                "id": raw.get("id", f"r{index + 1}"),
                "effect": raw.get("effect", "deny"),
                "condition": _parse_condition(raw.get("condition")),
            }
        )
    required = policy.get("required_attributes") or []
    return {
        "rules": rules,
        "combine": policy.get("combine", "deny_overrides"),
        "required_attributes": list(required),
    }


def resolve_attr(ctx, name) -> object:
    """Read an attribute from the context, or return the missing sentinel."""
    if not isinstance(ctx, Mapping) or not isinstance(name, str):
        return MISSING
    if "." not in name:
        return ctx.get(name, MISSING)
    node = ctx
    for part in name.split("."):
        if not isinstance(node, Mapping):
            return MISSING
        node = node.get(part, MISSING)
        if node is MISSING:
            return MISSING
    return node


def _missing_required(context, policy):
    required = policy.get("required_attributes") or []
    if not isinstance(required, (list, tuple)):
        return False
    return any(resolve_attr(context, name) is MISSING for name in required)


def _values_equal(left, right):
    if _is_number(left) and _is_number(right):
        return left == right
    if isinstance(left, str) and isinstance(right, str):
        return left.startswith(right)
    if isinstance(left, (list, tuple, set, frozenset)):
        return False
    if isinstance(right, (list, tuple, set, frozenset)):
        return False
    return type(left) is type(right) and left == right


def _contains(container, item):
    values = _as_collection(container)
    if values is None:
        return False
    return any(_values_equal(item, value) for value in values)


def compare(op, left, right) -> bool:
    """Compare two values according to the requested operator."""
    if left is MISSING or right is MISSING:
        return False
    if op == "eq":
        return _values_equal(left, right)
    if op == "ne":
        return not _values_equal(left, right)
    if op == "in":
        return _contains(right, left)
    if op == "not_in":
        return not _contains(right, left)
    if op == "has":
        return str(right) in str(left)
    if op == "has_any":
        left_values = _as_collection(left)
        right_values = _as_collection(right)
        if left_values is None or right_values is None:
            return False
        return any(
            _values_equal(left_item, right_item)
            for left_item in left_values
            for right_item in right_values
        )
    if op == "prefix":
        return (
            isinstance(left, str)
            and isinstance(right, str)
            and left.startswith(right)
        )
    if op in _ORDER_OPS:
        if not (_is_number(left) and _is_number(right)):
            return False
        left_text = str(left)
        right_text = str(right)
        if op == "gt":
            return left_text > right_text
        if op == "gte":
            return left_text >= right_text
        if op == "lt":
            return left_text < right_text
        return left_text <= right_text
    return True


def eval_condition(cond, ctx) -> bool:
    """Evaluate a condition against a request context."""
    if cond is None:
        return True
    if not isinstance(cond, Mapping):
        return False
    if "all" in cond:
        values = [eval_condition(item, ctx) for item in cond["all"]]
        return all(values)
    if "any" in cond:
        values = [eval_condition(item, ctx) for item in cond["any"]]
        return any(values)
    if "not" in cond:
        return not eval_condition(cond["not"], ctx)
    left = resolve_attr(ctx, cond.get("attr"))
    if left is MISSING:
        left = ""
    return compare(cond.get("op", "eq"), left, cond.get("value"))


def eval_rule(rule, ctx) -> str:
    """Return the rule conclusion for a context."""
    if not isinstance(rule, Mapping):
        return "not_applicable"
    condition = rule.get("condition")
    if condition is not None and not eval_condition(condition, ctx):
        return "not_applicable"
    effect = rule.get("effect", "deny")
    return "allow" if effect == "allow" else "deny"


def combine(results, policy) -> str:
    """Combine per rule conclusions into a policy conclusion."""
    mode = (
        policy.get("combine", "deny_overrides")
        if isinstance(policy, Mapping)
        else "deny_overrides"
    )
    applicable = [item for item in results if item in ("allow", "deny")]
    if not applicable:
        return "allow"
    if mode == "allow_overrides":
        if "allow" in applicable:
            return "allow"
        return "deny"
    if mode == "first_applicable":
        return applicable[0]
    return applicable[0]


def _iter_atomic_conditions(condition):
    if not isinstance(condition, Mapping):
        return
    if "all" in condition:
        for item in condition["all"]:
            yield from _iter_atomic_conditions(item)
        return
    if "any" in condition:
        for item in condition["any"]:
            yield from _iter_atomic_conditions(item)
        return
    if "not" in condition:
        yield from _iter_atomic_conditions(condition["not"])
        return
    yield condition


def validate_policy(policy) -> list[str]:
    """Return a list of policy problems; an empty list means valid."""
    if not isinstance(policy, Mapping):
        return ["policy must be a mapping"]
    problems = []
    rules = policy.get("rules")
    if not isinstance(rules, (list, tuple)) or not rules:
        problems.append("empty rule set")
        rules = []
    mode = policy.get("combine", "deny_overrides")
    if mode not in _COMBINE_MODES:
        problems.append(f"unknown combine strategy: {mode}")
    for index, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            problems.append(f"rule {index + 1} must be a mapping")
            continue
        rule_id = rule.get("id", f"r{index + 1}")
        effect = rule.get("effect", "deny")
        if effect not in ("allow", "deny"):
            problems.append(f"rule {rule_id} has invalid effect: {effect}")
        for condition in _iter_atomic_conditions(rule.get("condition")):
            op = condition.get("op", "eq")
            if op not in _KNOWN_OPS:
                problems.append(f"rule {rule_id} uses unknown operator: {op}")
    return problems


def abac_batch(requests, policy) -> dict:
    """Evaluate a sequence of requests and return one decision per request."""
    parsed = parse_policy(policy)
    decisions = []
    context = {}
    for index, request in enumerate(requests):
        if isinstance(request, Mapping):
            request_context = request.get("context")
            if not isinstance(request_context, Mapping):
                request_context = request
            context.update(request_context)
            request_id = request.get("id", index)
        else:
            request_id = index
        missing_required = _missing_required(context, parsed)
        results = [eval_rule(rule, context) for rule in parsed["rules"]]
        outcome = "deny" if missing_required else combine(results, parsed)
        decisions.append(
            {
                "id": request_id,
                "decision": "allow" if outcome == "allow" else "deny",
                "rule_results": results,
            }
        )
    return {"decisions": decisions}