from pathlib import Path

import pytest

from red_alert.attacks import apply_profile, load_named_template
from red_alert.config import UsageError
from red_alert.profile import (
    CapabilityState,
    StandProfile,
    dump_profile,
    load_profile,
    render_runtime_value,
)


def _memory_profile(**overrides: object) -> StandProfile:
    data: dict[str, object] = {
        "capabilities": {"persistent_memory": {"status": "present", "confidence": "high"}},
        "bindings": {
            "memory-poisoning": {
                "policy": "policy",
                "trigger": "trigger",
                "proof": "proof",
                "target": {
                    "endpoint": "https://agent.test/v1/chat/completions",
                    "bearer_env": "TARGET_TOKEN",
                },
                "eval": {"inherit": "target", "bearer_env": "EVAL_TOKEN"},
                "persist": None,
            }
        },
    }
    data.update(overrides)
    return StandProfile.model_validate(data)


def test_missing_capability_is_unknown() -> None:
    state = StandProfile().capability("vision")
    assert state.status == "unknown"
    assert state.confidence == "low"


def test_dump_profile_keeps_optional_runtime_fields_as_null() -> None:
    dumped = dump_profile(
        StandProfile(
            bindings={
                "system-prompt-leakage": {
                    "target": {"endpoint": "https://agent.test/chat"},
                    "eval": {},
                }
            }
        )
    )
    for value in (
        "context: null",
        "reset: null",
        "bearer_env: null",
        "model: null",
        "prompt: null",
        "custom_body: null",
        "custom_headers: null",
        "persist: null",
    ):
        assert value in dumped


def test_runtime_resolves_eval_inheritance() -> None:
    runtime = _memory_profile().runtime("memory-poisoning")
    assert runtime.eval.endpoint == runtime.target.endpoint
    assert runtime.eval.bearer_env == "EVAL_TOKEN"


def test_runtime_rejects_unknown_fields() -> None:
    profile = _memory_profile()
    profile.bindings["memory-poisoning"]["target"]["unknown"] = True
    with pytest.raises(UsageError, match="runtime-конфигурация"):
        profile.runtime("memory-poisoning")


def _defaults_profile(**binding: object) -> StandProfile:
    return StandProfile.model_validate(
        {
            "defaults": {
                "target": {
                    "endpoint": "https://agent.test/v1/chat/completions",
                    "bearer_env": "RED_ALERT_API_KEY",
                    "custom_body": {
                        "session_id": "${target_session_id}",
                        "auth_mode": "vulnerable",
                    },
                },
                "eval": {
                    "endpoint": "https://agent.test/v1/chat/completions",
                    "bearer_env": "RED_ALERT_VICTIM_API_KEY",
                    "custom_body": {"session_id": "${eval_session_id}"},
                },
                "persist": {
                    "method": "POST",
                    "endpoint": "https://agent.test/sessions/${target_session_id}/finalize",
                    "bearer_from": "target",
                },
            },
            "capabilities": {"persistent_memory": {"status": "present", "confidence": "high"}},
            "bindings": {"probe": binding},
        }
    )


def test_defaults_fill_empty_target_and_eval() -> None:
    runtime = _defaults_profile(eval={"inherit": "defaults"}).runtime("probe")
    assert runtime.target.endpoint == "https://agent.test/v1/chat/completions"
    assert runtime.target.bearer_env == "RED_ALERT_API_KEY"
    assert runtime.target.custom_body == {
        "session_id": "${target_session_id}",
        "auth_mode": "vulnerable",
    }
    assert runtime.eval.bearer_env == "RED_ALERT_VICTIM_API_KEY"
    assert runtime.eval.custom_body == {"session_id": "${eval_session_id}"}


def test_defaults_eval_inherits_target_with_session_override() -> None:
    runtime = _defaults_profile(
        eval={"inherit": "target", "custom_body": {"session_id": "${eval_session_id}"}},
        persist={},
    ).runtime("probe")
    assert runtime.eval.bearer_env == "RED_ALERT_API_KEY"
    assert runtime.eval.custom_body == {
        "session_id": "${eval_session_id}",
        "auth_mode": "vulnerable",
    }
    assert runtime.persist is not None
    assert runtime.persist.endpoint == "https://agent.test/sessions/${target_session_id}/finalize"


def test_binding_overrides_defaults_scalar() -> None:
    runtime = _defaults_profile(
        target={"bearer_env": "OWN_TOKEN"}, eval={"inherit": "target"}
    ).runtime("probe")
    assert runtime.target.bearer_env == "OWN_TOKEN"
    assert runtime.target.endpoint == "https://agent.test/v1/chat/completions"


def test_applicable_false_skips_attack() -> None:
    template = load_named_template("memory-poisoning", Path("attacks"))
    profile = _memory_profile()
    profile.bindings["memory-poisoning"]["applicable"] = False
    instances, skipped = apply_profile([template], profile)
    assert instances == []
    assert "applicable" in skipped[0].reason


def test_runtime_placeholder_substitution() -> None:
    value = {
        "session": "${target_session_id}",
        "token": "${CUSTOM_VALUE}",
    }
    assert render_runtime_value(
        value,
        builtins={"target_session_id": "session-1"},
        environ={"CUSTOM_VALUE": "value"},
    ) == {"session": "session-1", "token": "value"}
    with pytest.raises(UsageError, match="MISSING"):
        render_runtime_value("${MISSING}", builtins={}, environ={})


def test_invalid_profile_is_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "capabilities:\n  tools:\n    status: present\n    confidence: high\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="capability"):
        load_profile(path)


def test_absent_capability_skips_attack() -> None:
    profile = _memory_profile(
        capabilities={"persistent_memory": CapabilityState(status="absent", confidence="high")}
    )
    template = load_named_template("memory-poisoning", Path("attacks"))
    instances, skipped = apply_profile([template], profile)
    assert instances == []
    assert "persistent_memory" in skipped[0].reason


def test_missing_endpoint_or_slot_skips_attack() -> None:
    template = load_named_template("memory-poisoning", Path("attacks"))
    profile = _memory_profile()
    profile.bindings["memory-poisoning"]["target"]["endpoint"] = None
    instances, skipped = apply_profile([template], profile)
    assert instances == []
    assert "target.endpoint" in skipped[0].reason

    profile = _memory_profile()
    profile.bindings["memory-poisoning"]["policy"] = ""
    instances, skipped = apply_profile([template], profile)
    assert instances == []
    assert "слот" in skipped[0].reason
