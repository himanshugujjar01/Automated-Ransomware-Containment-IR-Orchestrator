def test_action_result_format():
    action_result = {
        "action_type": "host_isolation",
        "target": "DESKTOP-LAB-01",
        "status": "success",
        "details": "Host isolated successfully using mock EDR API"
    }

    assert action_result["action_type"] == "host_isolation"
    assert action_result["target"] == "DESKTOP-LAB-01"
    assert action_result["status"] == "success"
    assert "Host isolated" in action_result["details"]


def test_user_suspension_action_format():
    action_result = {
        "action_type": "user_suspension",
        "target": "himanshu",
        "status": "success",
        "details": "User account suspended successfully"
    }

    assert action_result["action_type"] == "user_suspension"
    assert action_result["target"] == "himanshu"
    assert action_result["status"] == "success"
    assert "suspended" in action_result["details"]


def test_session_revocation_action_format():
    action_result = {
        "action_type": "session_revocation",
        "target": "himanshu",
        "status": "success",
        "details": "Active sessions revoked successfully"
    }

    assert action_result["action_type"] == "session_revocation"
    assert action_result["target"] == "himanshu"
    assert action_result["status"] == "success"
    assert "revoked" in action_result["details"]