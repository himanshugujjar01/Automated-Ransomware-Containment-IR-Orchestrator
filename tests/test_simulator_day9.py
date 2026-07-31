from app.services.ransomware_simulator import (

    generate_fake_alert,

    simulator_status
)


def test_status():

    result = simulator_status()

    assert result["status"] == "ready"


def test_alert():

    alert = generate_fake_alert(

        hostname="LAB-PC",

        username="himanshu",

        severity="critical"

    )

    assert alert["severity"] == "critical"

    assert "alert_id" in alert

    assert "process_hash" in alert

    assert "ip_address" in alert