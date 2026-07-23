import os

from app.integrations.local_s3 import (
    create_local_s3_alert_folder,
    upload_to_local_s3,
    upload_multiple_files_to_local_s3
)


def test_create_local_s3_alert_folder():
    alert_id = "TEST-S3-001"

    folder_path = create_local_s3_alert_folder(alert_id)

    assert os.path.exists(folder_path)
    assert "local_s3_bucket" in folder_path
    assert "forensic-evidence" in folder_path
    assert alert_id in folder_path


def test_upload_to_local_s3():
    alert_id = "TEST-S3-002"
    test_file_path = "test_s3_artifact.txt"

    with open(test_file_path, "w", encoding="utf-8") as file:
        file.write("sample forensic artifact data")

    uploaded_path = upload_to_local_s3(alert_id, test_file_path)

    assert os.path.exists(uploaded_path)
    assert "local_s3_bucket" in uploaded_path
    assert "forensic-evidence" in uploaded_path
    assert uploaded_path.endswith("test_s3_artifact.txt")

    os.remove(test_file_path)


def test_upload_multiple_files_to_local_s3():
    alert_id = "TEST-S3-003"

    file_paths = []

    for index in range(2):
        file_path = f"test_s3_artifact_{index}.txt"

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(f"sample forensic artifact data {index}")

        file_paths.append(file_path)

    result = upload_multiple_files_to_local_s3(alert_id, file_paths)

    assert result["status"] == "success"
    assert result["alert_id"] == alert_id
    assert result["storage_type"] == "local_s3_simulation"
    assert result["total_uploaded"] == 2
    assert len(result["uploaded_files"]) == 2

    for uploaded_file in result["uploaded_files"]:
        assert os.path.exists(uploaded_file)

    for file_path in file_paths:
        os.remove(file_path)