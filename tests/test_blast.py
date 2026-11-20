from types import SimpleNamespace

from promptguard import blast


def F(i, p, intent):
    return SimpleNamespace(id=i, p=p, intent=intent)


SEND = [F(1, 0.9, "send_message")]


def test_chat_only_agent_cannot_send_mail():
    b = blast.assess(SEND, "chat_only")
    assert b["paths"][0]["status"] == "blocked"
    # a blocked path keeps a small residual weight (design choice), so reach is low but not zero
    assert b["reach"] == 0.25 < blast.assess(SEND, "email_assistant")["reach"]
    assert b["multiplier"] < blast.assess(SEND, "email_assistant")["multiplier"]


def test_agent_with_mail_tools_can():
    b = blast.assess(SEND, "email_assistant")
    assert b["paths"][0]["status"] == "reachable"
    assert b["trifecta"] is True and b["standing_risk"]


def test_unknown_profile_assumes_worst_case():
    b = blast.assess(SEND, "unknown")
    assert b["worst_case"] is True and b["multiplier"] == 1.0


def test_exposure_never_exceeds_worst_case_by_more_than_the_cap():
    for profile in blast.PROFILES:
        assert blast.assess(SEND, profile)["multiplier"] <= 1.25


def test_text_only_intents_work_on_any_agent():
    b = blast.assess([F(1, 0.8, "override_behaviour")], "chat_only")
    assert b["paths"][0]["status"] == "text_only"


def test_custom_capabilities_are_respected_and_unknown_ones_ignored():
    b = blast.assess(SEND, "custom", ["send_messages", "not_a_capability"])
    assert b["paths"][0]["status"] == "reachable"
    assert "not_a_capability" not in b["capabilities"]


def test_no_findings_means_no_paths():
    assert blast.assess([], "email_assistant")["paths"] == []
