def parse_edr_alert(alert_data: dict) -> dict:
    """
    Parses an EDR alert payload and extracts important ransomware indicators.
    """

    return {
        "alert_id": alert_data.get("alert_id"),
        "severity": alert_data.get("severity", "").lower(),
        "detection_type": alert_data.get("detection_type"),
        "hostname": alert_data.get("hostname"),
        "ip_address": alert_data.get("ip_address"),
        "username": alert_data.get("username"),
        "process_name": alert_data.get("process_name"),
        "process_hash": alert_data.get("process_hash"),
        "description": alert_data.get("description")
    }