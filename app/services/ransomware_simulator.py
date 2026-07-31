import random
import secrets
from datetime import datetime


def random_hash():
    return secrets.token_hex(32)


def random_ip():
    return ".".join(
        str(random.randint(1, 254))
        for _ in range(4)
    )


def random_alert_id():
    number = random.randint(1000, 9999)
    return f"SIM-{number}"


def random_process():
    processes = [
        "wannacry.exe",
        "lockbit.exe",
        "blackcat.exe",
        "encryptor.exe",
        "ransom.exe"
    ]
    return random.choice(processes)


def random_note():
    notes = [
        "Your files have been encrypted.",
        "Pay Bitcoin to recover files.",
        "Ransomware activity detected.",
        "Mass encryption behaviour observed."
    ]
    return random.choice(notes)


def generate_fake_alert(hostname, username, severity):

    return {
        "alert_id": random_alert_id(),
        "severity": severity,
        "hostname": hostname,
        "username": username,
        "ip_address": random_ip(),
        "process_name": random_process(),
        "process_hash": random_hash(),
        "description": random_note(),
        "detection_type": "Simulated Ransomware",
        "created_at": datetime.utcnow().isoformat()
    }


# -------------------------------
# Simulation Status
# -------------------------------

def simulator_status():

    return {
        "service": "Ransomware Simulator",
        "status": "ready",
        "supported_modes": [
            "dry_run",
            "demo"
        ],
        "version": "1.0"
    }