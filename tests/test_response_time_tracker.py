from app.database import Base, engine, SessionLocal
from app.services.tabletop_exercise import run_tabletop_exercise

Base.metadata.create_all(bind=engine)


def test_tabletop_exercise_runs_end_to_end():
    db = SessionLocal()

    result = run_tabletop_exercise(
        db=db,
        hostname="TEST-HOST-TT-01",
        username="test.user.tt1",
        severity="critical"
    )

    assert result["exercise_type"] == "simulated_ransomware_tabletop"
    assert result["alert_id"].startswith("SIM-")
    assert result["wall_clock_execution_seconds"] >= 0
    assert result["total_actions_taken"] > 0
    assert result["total_artifacts_collected"] > 0
    assert result["ticket_status"] in ["mock_created", "success"]
    assert result["response_time"]["total_response_time_seconds"] is not None

    db.close()


def test_tabletop_exercise_is_repeatable():
    db = SessionLocal()

    first = run_tabletop_exercise(db=db, hostname="TEST-HOST-TT-02", username="test.user.tt2")
    second = run_tabletop_exercise(db=db, hostname="TEST-HOST-TT-03", username="test.user.tt3")

    assert first["alert_id"] != second["alert_id"]

    db.close()