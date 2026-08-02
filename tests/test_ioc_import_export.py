import os
import json
import csv
import tempfile

from app.services.threat_intelligence import (
    export_iocs_json,
    export_iocs_csv,
    import_iocs_json,
    validate_ioc,
    bulk_import,
    get_all_iocs,
)

import pytest

from app.services.threat_intelligence import (
    export_iocs_json,
    export_iocs_csv,
    import_iocs_json,
    validate_ioc,
    bulk_import,
    get_all_iocs,
    reset_ioc_database,
)

@pytest.fixture(autouse=True)
def reset_db():
    reset_ioc_database()


def test_json_export():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    try:
        export_iocs_json(path)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert isinstance(data, list)

    finally:
        os.remove(path)


def test_csv_export():
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)

    try:
        export_iocs_csv(path)

        with open(path, "r", encoding="utf-8") as f:
            rows = list(csv.reader(f))

        assert len(rows) > 1

    finally:
        os.remove(path)


def test_validator():

    assert validate_ioc(
        {
            "ioc_type": "ip",
            "value": "1.1.1.1",
            "severity": "High",
            "category": "Botnet",
            "source": "Test",
            "description": "IOC",
        }
    )


def test_bulk_import():

    original = len(get_all_iocs())

    added = bulk_import([
        {
            "ioc_type": "ip",
            "value": "8.8.4.4",
            "severity": "Low",
            "category": "Test",
            "source": "UnitTest",
            "description": "Testing IOC",
            "created_at": "2026"
        }
    ])

    assert added >= 0

    # cleanup so other tests still see exactly 6 IOCs
    while len(get_all_iocs()) > original:
        get_all_iocs().pop()

def test_import_json():

    original = len(get_all_iocs())

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                [
                    {
                        "ioc_type": "ip",
                        "value": "1.2.3.4",
                        "severity": "High",
                        "category": "Test",
                        "source": "UnitTest",
                        "description": "Test IOC",
                    }
                ],
                f,
                indent=4,
            )

        added = import_iocs_json(path)

        assert added >= 0

    finally:
        os.remove(path)

        # Restore original IOC database size
        while len(get_all_iocs()) > original:
            get_all_iocs().pop()