from app.services.containment import isolate_host
from app.services.identity_response import suspend_user, revoke_sessions


def test_basic_playbook_action_sequence():
    hostname = "DESKTOP-LAB-01"
    ip_address = "192.168.1.20"
    username = "himanshu"

    actions = []

    host_result = isolate_host(hostname, ip_address)
    actions.append(host_result)

    suspend_result = suspend_user(username)
    actions.append(suspend_result)

    revoke_result = revoke_sessions(username)
    actions.append(revoke_result)

    assert len(actions) == 3

    assert actions[0]["action_type"] == "host_isolation"
    assert actions[0]["status"] == "success"

    assert actions[1]["action_type"] == "user_suspension"
    assert actions[1]["status"] == "success"

    assert actions[2]["action_type"] == "session_revocation"
    assert actions[2]["status"] == "success"


def test_playbook_all_actions_success():
    actions = [
        {"action_type": "host_isolation", "status": "success"},
        {"action_type": "user_suspension", "status": "success"},
        {"action_type": "session_revocation", "status": "success"}
    ]

    failed_actions = [
        action for action in actions
        if action.get("status") != "success"
    ]

    assert len(failed_actions) == 0


def test_playbook_partial_failure_detection():
    actions = [
        {"action_type": "host_isolation", "status": "success"},
        {"action_type": "user_suspension", "status": "failed"},
        {"action_type": "session_revocation", "status": "success"}
    ]

    failed_actions = [
        action for action in actions
        if action.get("status") != "success"
    ]

    assert len(failed_actions) == 1
    assert failed_actions[0]["action_type"] == "user_suspension"