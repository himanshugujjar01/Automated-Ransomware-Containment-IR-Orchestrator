import json

from app.models.alert_model import Alert


def save_defender_alerts_to_db(db, normalized_alerts: list) -> dict:
    """
    Saves normalized Microsoft Defender alerts into the alerts table.
    Duplicate alert IDs are skipped.
    """

    saved_alerts = []
    duplicate_alerts = []

    for alert in normalized_alerts:
        existing_alert = db.query(Alert).filter(
            Alert.alert_id == alert["alert_id"]
        ).first()

        if existing_alert:
            duplicate_alerts.append(alert["alert_id"])
            continue

        db_alert = Alert(
            alert_id=alert["alert_id"],
            severity=alert["severity"],
            detection_type=alert["detection_type"],
            hostname=alert["hostname"],
            ip_address=alert["ip_address"],
            username=alert["username"],
            process_name=alert["process_name"],
            process_hash=alert["process_hash"],
            description=alert["description"],
            status="imported_from_defender",
            raw_payload=json.dumps(alert["raw_payload"])
        )

        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)

        saved_alerts.append(db_alert.alert_id)

    return {
        "saved_count": len(saved_alerts),
        "duplicate_count": len(duplicate_alerts),
        "saved_alerts": saved_alerts,
        "duplicate_alerts": duplicate_alerts
    }