from app.models.action_model import ActionLog


def save_action_log(db, alert_id: str, action_result: dict):
    """
    Saves an automated response action into the action_logs database table.

    Example action_result:
    {
        "action_type": "host_isolation",
        "target": "DESKTOP-LAB-01",
        "status": "success",
        "details": "Host isolated successfully"
    }
    """

    log = ActionLog(
        alert_id=alert_id,
        action_type=action_result.get("action_type"),
        target=action_result.get("target"),
        status=action_result.get("status"),
        details=action_result.get("details")
    )

    db.add(log)
    db.commit()
    db.refresh(log)

    return log