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
    """Preserve a policy literal's native type.

    Retained as a compatibility shim for callers of the old private helper;
    literals must never be coerced to strings before type-aware comparison.
    """
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
        # Literals keep their declared type: numbers must stay numbers so
        # comparisons never degrade into string comparison.
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
    """Equality by actual type, never by string coercion."""
    # Numbers compare numerically; booleans are deliberately excluded.
    if _is_number(left) and _is_number(right):
        return left == right
    # Collections are equal only when their types match and they hold the
    # same members (members themselves compared by type-aware equality).
    if _as_collection(left) is not None or _as_collection(right) is not None:
        if type(left) is not type(right):
            return False
        if len(left) != len(right):
            return False
        return all(_contains(left, item) for item in right)
    # Everything else requires an identical type and value.  Strings use
    # exact equality here; prefix matching is the job of the "prefix" op.
    return type(left) is type(right) and left == right


def _contains(container, item):
    """Membership test for collection attributes."""
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
        # left is a member of the right-hand collection.
        return _contains(right, left)
    if op == "not_in":
        return not _contains(right, left)
    if op == "has":
        # Collection attribute judged by exact member, not substring.
        return _contains(left, right)
    if op == "has_any":
        left_values = _as_collection(left)
        right_values = _as_collection(right)
        if left_values is None or right_values is None:
            return False
        return any(_contains(left_values, item) for item in right_values)
    if op == "prefix":
        return (
            isinstance(left, str)
            and isinstance(right, str)
            and left.startswith(right)
        )
    if op in _ORDER_OPS:
        # Ordering is numeric; type mismatches simply do not hold.
        if not (_is_number(left) and _is_number(right)):
            return False
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right
    # Unknown operators never match.
    return False


def _eval_condition(cond, ctx):
    """Evaluate a condition.

    Returns True/False, or the MISSING sentinel whenever an evaluated
    attribute is absent.  ``all``/``any`` short-circuit like the Python
    boolean operators, so branches past the deciding value are not
    evaluated and cannot contribute a missing-attribute result.
    """
    if cond is None:
        return True
    if not isinstance(cond, Mapping):
        return False
    if "all" in cond:
        for item in cond["all"]:
            result = _eval_condition(item, ctx)
            if result is MISSING:
                return MISSING
            if not result:
                return False
        return True
    if "any" in cond:
        for item in cond["any"]:
            result = _eval_condition(item, ctx)
            if result is MISSING:
                return MISSING
            if result:
                return True
        return False
    if "not" in cond:
        result = _eval_condition(cond["not"], ctx)
        if result is MISSING:
            # A missing attribute stays a denial under negation.
            return MISSING
        return not result

    left = resolve_attr(ctx, cond.get("attr"))
    if left is MISSING:
        return MISSING
    return bool(compare(cond.get("op", "eq"), left, cond.get("value")))


def eval_condition(cond, ctx) -> bool:
    """Evaluate a condition against a request context.

    Any evaluated attribute that is missing makes the condition fail
    closed rather than being coerced into an empty value.
    """
    result = _eval_condition(cond, ctx)
    if result is MISSING:
        return False
    return bool(result)


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
        # Nothing applies: fail closed.
        return "deny"
    if mode == "allow_overrides":
        return "allow" if "allow" in applicable else "deny"
    if mode == "first_applicable":
        return applicable[0]
    # deny_overrides (and any unrecognised mode) defaults to denying.
    return "deny" if "deny" in applicable else "allow"


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
    """Evaluate a sequence of requests and return one decision per request.

    Every request is evaluated against its own context: no attribute is
    carried over between requests, and evaluation is deterministic, so the
    same request repeated yields the same decision.
    """
    parsed = parse_policy(policy)
    decisions = []
    for index, request in enumerate(requests):
        if isinstance(request, Mapping):
            request_context = request.get("context")
            if not isinstance(request_context, Mapping):
                request_context = request
            request_id = request.get("id", index)
        else:
            request_context = {}
            request_id = index
        missing_required = _missing_required(request_context, parsed)
        results = [eval_rule(rule, request_context) for rule in parsed["rules"]]
        outcome = "deny" if missing_required else combine(results, parsed)
        decisions.append(
            {
                "id": request_id,
                "decision": "allow" if outcome == "allow" else "deny",
                "rule_results": results,
            }
        )
    return {"decisions": decisions}
