"""Public behaviour checks for the ABAC policy engine."""

from engine.abac.eval import abac_batch, compare, eval_condition, parse_policy


def test_parse_policy_preserves_numeric_values():
    policy = {
        "rules": [
            {
                "id": "r-score",
                "effect": "allow",
                "condition": {"attr": "score", "op": "gt", "value": 2},
            }
        ],
        "combine": "deny_overrides",
        "required_attributes": ["score"],
    }

    parsed = parse_policy(policy)
    condition = parsed["rules"][0]["condition"]

    assert parsed["combine"] == "deny_overrides"
    assert parsed["required_attributes"] == ["score"]
    assert condition["op"] == "gt"
    assert condition["value"] == 2
    assert isinstance(condition["value"], int)


def test_numeric_comparison_uses_numeric_order():
    assert compare("gt", 10, 2) is True
    assert compare("lt", 10, 2) is False
    assert compare("gte", 2, 2) is True


def test_set_membership_requires_exact_member():
    roles = ["finance_readonly"]
    assert compare("has", roles, "finance") is False
    assert compare("has", roles, "finance_readonly") is True


def test_missing_attribute_is_rejected():
    context = {"department": "财务"}
    condition = {"attr": "clearance", "op": "ne", "value": "机密"}

    assert eval_condition(condition, context) is False


def test_batch_requests_do_not_share_context():
    policy = {
        "rules": [
            {
                "id": "r-finance",
                "effect": "allow",
                "condition": {"attr": "department", "op": "eq", "value": "财务"},
            }
        ],
        "combine": "deny_overrides",
        "required_attributes": ["department"],
    }
    requests = [
        {"id": "first", "context": {"department": "财务"}},
        {"id": "second", "context": {"user": "reader"}},
    ]

    output = abac_batch(requests, policy)
    decisions = {item["id"]: item["decision"] for item in output["decisions"]}

    assert decisions["first"] == "allow"
    assert decisions["second"] == "deny"