# Automated Ransomware Containment & Incident Response Orchestrator

![Tests](https://github.com/himanshugujjar01/Automated-Ransomware-Containment-IR-Orchestrator/actions/workflows/tests.yml/badge.svg)

A production-style Security Orchestration, Automation and Response (SOAR) platform built to automatically detect, contain, and investigate ransomware and hands-on-keyboard activity in an enterprise environment.

This project works as an automated incident-response layer between an EDR alert and a fully documented, contained incident. It ingests an EDR alert, runs an automated containment playbook, collects forensic evidence with chain-of-custody logging, files an incident ticket, notifies the on-call team, and reports exactly how fast it did all of it — with a built-in web dashboard for running and demonstrating the whole flow.

---

## Project Information

**Project Title:** Automated Ransomware Containment & Incident Response Orchestrator
**Student Name:** Himanshu
**Course / Branch:** B.Tech. CSE (Cyber Security)
**Internship Company:** Zaalima Development Pvt. Ltd.
**Project Number:** Project 3 of 4 (production-level cybersecurity project series)
**Repository:** <https://github.com/himanshugujjar01/Automated-Ransomware-Containment-IR-Orchestrator.git>
**Branch:** main

---

## Problem Statement

When ransomware or hands-on-keyboard activity is detected on a network, every second of dwell time increases the damage — more hosts get encrypted, more data gets exfiltrated, and the attacker gets more time to move laterally.

In most organizations the response to that detection is still manual: a Tier 1 or 2 SOC analyst has to isolate the infected host, suspend the compromised identity, revoke its active sessions, collect forensic evidence, open an incident ticket, and notify the on-call team — often across five or six different tools, taking anywhere from twenty minutes to several hours depending on analyst availability and tooling.

This project solves that problem by implementing an orchestrator that automatically executes the entire containment-to-ticket workflow the moment an alert is ingested, with strict safety gating so it never takes a real destructive action by accident.

---

## Objective

The main objective of this project is to build an automated IR orchestrator that can:

- Ingest EDR alerts through a secure, authenticated webhook
- Parse alert data into hostname, IP address, username, and process hash
- Automatically isolate the affected host through an EDR integration
- Automatically suspend the affected identity and revoke its active sessions
- Run a full containment playbook combining host and identity response
- Collect forensic evidence using KAPE and Volatility integration points
- Store evidence in WORM-locked S3 storage with SHA-256 chain-of-custody logging
- File an incident ticket automatically through Jira, ServiceNow, or a mock provider
- Notify the on-call team through Slack or Microsoft Teams
- Measure and report response time at every stage of the incident lifecycle
- Provide a repeatable table-top simulation for demos, drills, and load testing
- Gate every real/destructive action behind dry-run previews, approval codes, and host/user allowlists
- Provide a web dashboard for running, inspecting, and demonstrating the whole pipeline
- Support both a local FastAPI deployment and a serverless AWS Lambda + Step Functions deployment
- Maintain complete GitHub version control

---

## Key Features

| Feature | Status |
|---|---|
| FastAPI Orchestration Engine | Completed |
| Secure EDR Webhook Ingestion | Completed |
| Alert Parsing (host / IP / user / hash) | Completed |
| Automated Host Isolation Playbook | Completed |
| Automated Identity Suspension + Session Revocation | Completed |
| Dry-Run / Preview Safety Gating | Completed |
| Approval-Code Gated Real Actions | Completed |
| Sandbox Host/User Allowlisting | Completed |
| KAPE Forensic Collection Integration | Completed |
| Volatility Memory Analysis Integration | Completed |
| WORM S3 Evidence Storage | Completed |
| SHA-256 Chain-of-Custody Logging | Completed |
| Jira / ServiceNow / Mock Ticketing | Completed |
| Slack / Microsoft Teams Notifications | Completed |
| Response-Time Stage Tracking | Completed |
| Table-Top / Live Simulation Endpoint | Completed |
| Executive & SOC Dashboards | Completed |
| MITRE ATT&CK Mapping | Completed |
| Threat Intelligence / IOC Feed Sync | Completed |
| Incident Search Engine | Completed |
| Ops Console Web Dashboard | Completed |
| AWS Lambda + Step Functions Deployment | Built and Unit-Tested (not yet deployed to a live AWS account) |
| CrowdStrike Falcon Connector | Completed |
| CI Pipeline for Automated Test Runs | Completed |
| Pytest Testing (220+ tests) | Completed |
| GitHub Commit/Push | Completed |

---

## Technology Stack

| Category | Technology |
|---|---|
| Programming Language | Python 3 |
| Backend Framework | FastAPI |
| Frontend | Single-file HTML / CSS / JS Ops Console, served by FastAPI (no build step) |
| Database | SQLAlchemy ORM over SQLite (swappable to PostgreSQL) |
| Forensics | KAPE, Volatility integration points |
| Evidence Storage | AWS S3 (WORM / Object Lock) with a local-filesystem simulator for offline dev |
| Serverless Orchestration | AWS Step Functions + AWS Lambda, deployed via AWS SAM |
| EDR Integration | Microsoft Defender for Endpoint + CrowdStrike Falcon (mock + preview modes) |
| Identity Integration | Microsoft Graph / Azure AD (mock + preview modes) |
| Ticketing | Jira, ServiceNow, mock provider |
| Notifications | Slack, Microsoft Teams |
| Testing | Pytest, Swagger UI |
| CI/CD | GitHub Actions (automated test runs on every push and pull request) |
| Version Control | Git and GitHub |
| Development Tools | VS Code, Uvicorn, Swagger UI |

---

## System Architecture

The system follows an alert-driven orchestration architecture. An EDR alert arrives through a webhook, gets parsed, and is fanned out into parallel containment and forensic actions before being logged, ticketed, and reported on.

```
EDR Alert (webhook / API)
        |
        v
Alert Parser
        |
        v
Playbook Engine
        |
        |-- Host Isolation (mock EDR / Defender, dry-run gated)
        |-- Identity Response (mock IdP / Azure AD, dry-run gated)
        |-- Forensic Collection (KAPE / Volatility)
        |
        v
Chain-of-Custody Logging (SHA-256)
        |
        v
WORM S3 Evidence Storage
        |
        |-- Ticketing (Jira / ServiceNow / Mock)
        |-- Notifications (Slack / Teams)
        |-- Response-Time Report
        |
        v
SOC / Executive Dashboards + Ops Console
```

The same `playbook_engine.py` logic also runs as ten independent AWS Lambda functions wired together by an AWS Step Functions state machine, for a serverless production deployment path.

---

## Project Structure

```
Automated-Ransomware-Containment-IR-Orchestrator/
│
├── app/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── lambda_app.py
│   │
│   ├── models/
│   │   ├── alert_model.py
│   │   ├── action_model.py
│   │   ├── artifact_model.py
│   │   └── ticket_model.py
│   │
│   ├── schemas/
│   │   ├── edr_schema.py
│   │   ├── simulation_request.py
│   │   └── simulation_response.py
│   │
│   ├── integrations/
│   │   ├── defender_edr.py
│   │   ├── falcon_edr.py
│   │   ├── mock_edr.py
│   │   ├── azure_ad.py
│   │   ├── mock_idp.py
│   │   ├── aws_s3.py
│   │   ├── local_s3.py
│   │   ├── ticketing_client.py
│   │   ├── slack_client.py
│   │   └── teams_client.py
│   │
│   ├── services/
│   │   ├── playbook_engine.py
│   │   ├── alert_parser.py
│   │   ├── containment.py
│   │   ├── identity_response.py
│   │   ├── authorized_host_isolation.py
│   │   ├── authorized_identity_response.py
│   │   ├── approved_containment_runner.py
│   │   ├── forensics.py
│   │   ├── kape_runner.py
│   │   ├── volatility_runner.py
│   │   ├── chain_of_custody.py
│   │   ├── s3_evidence_service.py
│   │   ├── ticketing_service.py
│   │   ├── notification_service.py
│   │   ├── response_time_tracker.py
│   │   ├── tabletop_exercise.py
│   │   ├── ransomware_simulator.py
│   │   ├── safety_guard.py
│   │   ├── production_readiness.py
│   │   ├── validation_report.py
│   │   ├── executive_dashboard.py
│   │   ├── security_metrics.py
│   │   ├── soc_dashboard.py
│   │   ├── incident_summary.py
│   │   ├── threat_intelligence.py
│   │   ├── ioc_feed_sync.py
│   │   └── dashboard_service.py
│   │
│   └── lambda_handlers/
│       ├── parse_alert_handler.py
│       ├── host_isolation_handler.py
│       ├── identity_response_handler.py
│       ├── merge_containment_handler.py
│       ├── forensic_collection_handler.py
│       ├── chain_of_custody_handler.py
│       ├── evidence_upload_handler.py
│       ├── ticketing_handler.py
│       ├── notification_handler.py
│       └── response_time_report_handler.py
│
├── frontend/
│   └── index.html                 # Ops Console web dashboard
│
├── infrastructure/
│   ├── template.yaml              # AWS SAM template
│   └── step_functions/
│       └── ransomware_containment_state_machine.json
│
├── sample_alerts/
│   └── ransomware_alert.json
│
├── tests/
│   ├── test_playbook_engine.py
│   ├── test_containment.py
│   ├── test_identity_response.py
│   ├── test_forensics.py
│   ├── test_chain_of_custody.py
│   ├── test_safety_guard.py
│   ├── test_tabletop_exercise.py
│   ├── test_lambda_handlers.py
│   ├── test_response_time_tracker.py
│   ├── test_soc_dashboard.py
│   ├── test_executive_dashboard.py
│   └── ... (220+ tests covering every service module and Lambda handler)
│
├── requirements.txt
├── .env.example
└── README.md
```

---

## Main Modules

### 1. FastAPI Orchestration Engine

The main application is implemented in:

```
app/main.py
```

It exposes every endpoint below and serves the Ops Console dashboard at `/dashboard`.

---

### 2. Secure EDR Webhook Ingestion

Alerts are ingested through:

```
POST /webhooks/edr
```

Requests must include a matching `x-webhook-secret` header, verified in `app/services/alert_parser.py` before the payload is parsed into a stored `Alert` record.

---

### 3. Playbook Engine

Implemented in:

```
app/services/playbook_engine.py
```

Given an `alert_id`, it runs host isolation, identity suspension, session revocation, forensic collection, chain-of-custody logging, evidence upload, and ticketing in sequence, recording a timestamped `Action` for every step.

---

### 4. Safety Guard

Implemented in:

```
app/services/safety_guard.py
```

Enforces four layers of protection before anything "real" can happen:

- Mock mode by default (`USE_REAL_EDR`, `USE_REAL_IDP`, `USE_REAL_AWS`, `USE_REAL_TICKETING`, `USE_REAL_NOTIFICATIONS` all `false`)
- Dry-run previews on every integration-facing endpoint
- Approval-code gating (`REAL_ACTION_APPROVAL_CODE`) plus explicit `execute_real=True` / `dry_run=False` flags
- Allowlisted test hosts and users (`ALLOWED_TEST_HOSTS`, `ALLOWED_TEST_USERS`) for anything approved to run for real

Current posture is always visible at `GET /safety/config` and `GET /readiness/production`, or in the **Safety & Readiness** tab of the Ops Console.

---

### 5. Forensics & Chain of Custody

Implemented in:

```
app/services/forensics.py
app/services/kape_runner.py
app/services/volatility_runner.py
app/services/chain_of_custody.py
app/services/s3_evidence_service.py
```

Runs KAPE triage collection and Volatility memory analysis, hashes every artifact with SHA-256, and uploads it to WORM-locked S3 storage (or a local-filesystem simulator for offline dev) so evidence cannot be altered or deleted after the fact.

---

### 6. Response-Time Tracking

Implemented in:

```
app/services/response_time_tracker.py
```

Computes five stage timings directly from the database's own timestamps, with no extra instrumentation on the hot path:

1. Detection → first action
2. Detection → containment complete
3. Detection → evidence collected
4. Detection → ticket filed
5. Total response time

---

### 7. Table-Top Simulation

Implemented in:

```
app/services/tabletop_exercise.py
app/services/ransomware_simulator.py
```

Endpoint:

```
POST /simulation/tabletop-exercise
```

Generates a synthetic EDR alert and runs it through the exact same code path a real webhook would use — safe to run repeatedly for demos, drills, or load testing.

---

### 8. Dashboards

Implemented in:

```
app/services/executive_dashboard.py
app/services/security_metrics.py
app/services/soc_dashboard.py
app/services/incident_summary.py
app/services/dashboard_service.py
```

Provide executive-level KPIs, SOC-level MITRE ATT&CK mapping, per-incident timelines, and fleet-wide response-time SLA summaries.

---

### 9. Ops Console (Web Dashboard)

```
frontend/index.html
```

A single-file, no-build-step web dashboard served directly by FastAPI at `/dashboard`. It covers alert intake, containment, forensics, ticketing, response-time SLA tracking, the table-top simulation, and the safety/readiness posture — all from one screen, calling the live API endpoints below. If the API isn't reachable, it falls back to clearly-labeled sample data so the UI is still browsable offline.

---

### 10. Multi-Vendor EDR Connectors (Microsoft Defender + CrowdStrike Falcon)

Implemented in:

```
app/integrations/defender_edr.py
app/integrations/falcon_edr.py
```

Two independent EDR connectors, both following the same safety pattern: unconfigured credentials report `credentials_pending` rather than failing, every isolation/containment action defaults to a dry-run preview, and each exposes a status endpoint (`/integrations/defender/status`, `/integrations/falcon/status`) that feeds directly into `/readiness/production` and the Ops Console's **Safety & Readiness** tab. Falcon adds host lookup, containment preview, and real host containment (`contain-host`), plus detection-to-alert normalization, mirroring Defender's machine isolation and alert normalization one-for-one.

---

### 11. CI Pipeline

Implemented in:

```
.github/workflows/tests.yml
```

A GitHub Actions workflow that runs the full `pytest` suite on every push and pull request to `main`, across multiple Python versions. This is what keeps the 220+ test suite enforced automatically rather than relying on manual `pytest` runs before a commit.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/webhooks/edr` | Secure EDR alert intake |
| GET | `/alerts` | List ingested alerts |
| GET | `/alerts/{alert_id}` | Get a single alert |
| POST | `/playbooks/{alert_id}/run` | Run the full containment + forensics playbook |
| GET | `/actions/{alert_id}` | Full action history for an incident |
| POST | `/edr/defender/machines/isolate-preview` | Dry-run host isolation preview |
| POST | `/edr/defender/machines/isolate-authorized` | Approval-gated real host isolation |
| GET | `/integrations/defender/status` | Microsoft Defender connector status |
| POST | `/edr/falcon/hosts/contain-preview` | Dry-run Falcon host containment preview |
| GET | `/integrations/falcon/status` | CrowdStrike Falcon connector status |
| POST | `/idp/azure/users/suspend-preview` | Dry-run user suspension preview |
| POST | `/idp/azure/users/suspend-approved` | Approval-gated real user suspension |
| POST | `/idp/azure/users/revoke-sessions-preview` | Dry-run session revocation preview |
| POST | `/response/full-containment-approved` | Host isolation + suspension + revocation in one call |
| POST | `/forensics/kape/run` | Run KAPE triage collection |
| POST | `/forensics/volatility/run` | Run Volatility memory analysis |
| POST | `/evidence/{alert_id}/upload-s3` | WORM S3 evidence upload |
| POST | `/tickets/{alert_id}/create` | Create a Jira / ServiceNow / mock ticket |
| GET | `/tickets/{alert_id}` | List tickets for an alert |
| GET | `/integrations/slack/status` | Slack integration status |
| GET | `/integrations/teams/status` | Teams integration status |
| GET | `/response-time/{alert_id}` | Stage-by-stage timing for one incident |
| GET | `/response-time/fleet/summary` | Average / fastest / slowest across recent incidents |
| POST | `/simulation/tabletop-exercise` | Full end-to-end simulated incident with timing |
| GET | `/dashboard/executive` | Executive KPI dashboard |
| GET | `/dashboard/security-metrics` | Security metrics dashboard |
| GET | `/dashboard/timeline/{alert_id}` | Per-incident event timeline |
| GET | `/safety/config` | Current safety guard configuration |
| GET | `/readiness/production` | Production-readiness / integration status report |
| GET | `/validation` | Overall system validation report |
| GET | `/dashboard` | Ops Console web UI |

Full interactive documentation for every endpoint (including request/response schemas) is available at `/docs` once the server is running.

---

## Installation and Setup

### Step 1: Clone Repository

```
git clone https://github.com/himanshugujjar01/Automated-Ransomware-Containment-IR-Orchestrator.git
cd Automated-Ransomware-Containment-IR-Orchestrator
```

---

### Step 2: Create Virtual Environment

```
python -m venv venv
```

Activate virtual environment on Windows:

```
venv\Scripts\activate
```

Activate virtual environment on macOS/Linux:

```
source venv/bin/activate
```

---

### Step 3: Install Requirements

```
pip install -r requirements.txt
```

---

### Step 4: Configure Environment Variables

```
cp .env.example .env
```

Safe defaults work out of the box — every real integration flag starts `false`, so no credentials are required to run the project locally. Example values:

```
USE_REAL_EDR=false
USE_REAL_IDP=false
USE_REAL_AWS=false
USE_REAL_TICKETING=false
USE_REAL_NOTIFICATIONS=false
REAL_ACTION_APPROVAL_CODE=
ALLOWED_TEST_HOSTS=WIN-LAB-01,WIN-LAB-02
ALLOWED_TEST_USERS=lab.user1,lab.user2
DATABASE_URL=sqlite:///./orchestrator.db
```

Do not push real API keys or secret values to GitHub.

---

## Run Project Locally

Start the FastAPI server:

```
uvicorn app.main:app --reload
```

Open Swagger UI:

```
http://127.0.0.1:8000/docs
```

Open the Ops Console dashboard:

```
http://127.0.0.1:8000/dashboard
```

---

## Testing With Swagger / the Ops Console

Open `http://127.0.0.1:8000/docs` (or use the Ops Console for the same actions with a UI).

### Test 1: Run a Full Table-Top Exercise

Endpoint:

```
POST /simulation/tabletop-exercise
```

Expected response:

```json
{
  "exercise_type": "simulated_ransomware_tabletop",
  "alert_id": "SIM-2188",
  "wall_clock_execution_seconds": 0.176,
  "playbook_status": "forensics_completed",
  "total_actions_taken": 6,
  "total_artifacts_collected": 5,
  "ticket_status": "mock_created",
  "response_time": {
    "detection_to_first_action_seconds": 0.03,
    "detection_to_containment_seconds": 0.05,
    "detection_to_evidence_collected_seconds": 0.12,
    "detection_to_ticket_filed_seconds": 0.16,
    "total_response_time_seconds": 0.16
  }
}
```

---

### Test 2: Ingest a Real EDR Alert

Endpoint:

```
POST /webhooks/edr
```

Header:

```
x-webhook-secret: <value from your .env>
```

Request body: see `sample_alerts/ransomware_alert.json`.

Expected: a new alert is stored and visible at `GET /alerts`.

---

### Test 3: Run the Containment Playbook

Endpoint:

```
POST /playbooks/{alert_id}/run
```

Expected: the alert's `status` moves to `contained`, and `GET /actions/{alert_id}` shows `host_isolation`, `user_suspension`, and `session_revocation` actions, each marked `success`.

---

### Test 4: Dry-Run Host Isolation Preview

Endpoint:

```
POST /edr/defender/machines/isolate-preview?hostname=WIN-CORP-0231
```

Expected response:

```json
{
  "status": "success",
  "dry_run": true,
  "message": "Preview — no real system was contacted"
}
```

---

### Test 5: Safety Configuration Check

Endpoint:

```
GET /safety/config
```

Expected: `use_real_edr` and `use_real_idp` both `false` on a fresh checkout, confirming nothing real can be touched without explicit configuration.

---

## Response-Time & Dashboard Endpoints

Fleet-wide SLA summary:

```
GET /response-time/fleet/summary
```

Example response:

```json
{
  "incidents_measured": 4,
  "average_total_response_seconds": 0.21,
  "fastest_total_response_seconds": 0.16,
  "slowest_total_response_seconds": 0.29
}
```

Executive dashboard:

```
GET /dashboard/executive
```

Shows total/contained/open alert counts, severity breakdown, and the latest incident timeline — the same data rendered in the Ops Console's **Overview** tab.

---

## Run Tests

Run:

```
pytest
```

Expected result:

```
220+ passed
```

Test coverage includes every service module in `app/services/`, every integration client, and every one of the ten Lambda handlers (`tests/test_lambda_handlers.py` chains all ten exactly as Step Functions would and asserts on the final response-time report).

---

## Serverless Deployment (AWS Lambda + Step Functions)

The same containment playbook (`playbook_engine.py`) is also broken into ten independent, stateless Lambda functions in `app/lambda_handlers/`, wired together by `infrastructure/step_functions/ransomware_containment_state_machine.json` — an Amazon States Language definition that mirrors the plan exactly: parse alert → parallel host isolation + identity response → forensic collection → chain of custody → WORM S3 upload → ticketing → notification → response-time report.

`app/lambda_app.py` wraps the same FastAPI app (dashboards, ticketing, forensics endpoints, the simulation endpoint, and the Ops Console) with Mangum, so it can run behind API Gateway on Lambda with no code changes.

Deploy with AWS SAM:

```
cd infrastructure
sam build
sam deploy --guided
```

This provisions the API Gateway + FastAPI Lambda, the ten step Lambdas, and the Step Functions state machine, all defined in `infrastructure/template.yaml`.

Note:

```
sam deploy has not been run against a live AWS account in this environment
(no credentials available). The template and handlers are built and unit-tested
locally with no AWS account needed, but not yet deployed to a live account.
Swap DATABASE_URL to Postgres/RDS Proxy before deploying for real — SQLite does
not support concurrent Lambda invocations.
```

---

## Security & Safety Controls Implemented

| Control | Description |
|---|---|
| Webhook Authentication | Validates `x-webhook-secret` header before parsing any alert |
| Mock-Mode Default | Every real integration flag (`USE_REAL_*`) starts `false` |
| Dry-Run Previews | Real-integration endpoints always default to `dry_run=True` |
| Approval-Code Gating | Real/destructive actions require a matching server-side approval code |
| Host/User Allowlisting | Even approved real actions are restricted to allowlisted test hosts and users |
| Chain-of-Custody Hashing | Every forensic artifact is SHA-256 hashed on collection |
| WORM Evidence Storage | Evidence in S3 is stored with Object Lock so it cannot be altered or deleted |
| Action Audit Trail | Every playbook step is logged as a timestamped `Action` record |
| Production Readiness Report | `/readiness/production` reports exactly which real integrations are actually configured |

---

## Testing Summary

| Test Area | Result |
|---|---|
| Alert Parsing | Passed |
| Playbook Engine | Passed |
| Host Isolation (mock + authorized) | Passed |
| CrowdStrike Falcon Connector | Passed |
| Identity Response (mock + authorized) | Passed |
| Safety Guard Gating | Passed |
| Forensics (KAPE / Volatility) | Passed |
| Chain of Custody | Passed |
| S3 / Local Evidence Storage | Passed |
| Ticketing (Jira / ServiceNow / Mock) | Passed |
| Notifications (Slack / Teams) | Passed |
| Response-Time Tracker | Passed |
| Table-Top Exercise | Passed |
| Executive / SOC Dashboards | Passed |
| Production Readiness Report | Passed |
| Lambda Handlers (chained end-to-end) | Passed |
| Pytest (full suite) | Passed |
| CI Pipeline (GitHub Actions, on push/PR) | Passed |
| GitHub Commit/Push | Passed |

---

## GitHub Version Control

Repository:

```
https://github.com/himanshugujjar01/Automated-Ransomware-Containment-IR-Orchestrator.git
```

Branch:

```
main
```

---

## Important Git Ignore Note

Do not commit secrets, local databases, or virtual environment files.

Recommended `.gitignore` entries:

```
.env
*.db
__pycache__/
*.pyc
.pytest_cache/
.venv/
venv/
app/__pycache__/
.aws-sam/
```

---

## Challenges Faced

- Designing a safety-gating model (mock mode, dry-run, approval codes, allowlists) rigorous enough that "real" integration code paths are safe to leave in the codebase at all
- Keeping the FastAPI service and the ten-Lambda serverless implementation running the exact same playbook logic without duplicating it
- Computing accurate response-time stage timings directly from database timestamps without adding instrumentation overhead to the hot path
- Structuring chain-of-custody logging so forensic evidence integrity is verifiable after the fact
- Testing all ten Lambda handlers chained together, end-to-end, without requiring a live AWS account
- Building a single-file frontend that degrades gracefully to sample data when no backend is reachable, so it stays useful for demos even offline

---

## Learning Outcomes

Through this project, I learned:

- How SOAR platforms automate real-world SOC incident response
- How to design layered safety controls for anything capable of taking a destructive action
- How to build and structure a FastAPI backend around a multi-stage orchestration engine
- How chain-of-custody and WORM evidence storage work in a forensic investigation
- How to measure and report response-time SLAs from raw database timestamps
- How to mirror the same business logic across a monolithic FastAPI service and a serverless AWS Lambda + Step Functions architecture
- How to write and run a large Pytest suite covering services, integrations, and Lambda handlers
- How to build a dependency-free web frontend that talks directly to a REST API
- How to add a second EDR vendor connector without duplicating safety logic, by mirroring an existing connector's structure exactly
- How to set up a GitHub Actions CI pipeline to enforce automated test runs on every push and pull request
- How to maintain project code using GitHub

---

## Future Scope

Future improvements can include:

- Verifying the CrowdStrike Falcon connector against a live Falcon tenant (currently built and tested in mock/credentials-pending mode only)
- A live `sam deploy` against a real AWS account, with Postgres/RDS Proxy replacing SQLite
- Role-based access control and authenticated login for the Ops Console
- Real-time alerting through email, in addition to Slack and Teams
- CSV/PDF export of incident and SLA reports
- Deeper MITRE ATT&CK technique coverage in the SOC dashboard

---

## Conclusion

The Automated Ransomware Containment & Incident Response Orchestrator is a functional cybersecurity project that demonstrates how organizations can automate the most time-critical part of ransomware response — containment — while keeping every "real" action safely gated behind dry-run previews, approval codes, and allowlists.

It provides EDR webhook ingestion, dual-vendor EDR connectors (Microsoft Defender and CrowdStrike Falcon), automated host and identity containment, KAPE/Volatility forensic collection, chain-of-custody logging, WORM evidence storage, Jira/ServiceNow/mock ticketing, Slack/Teams notifications, response-time SLA tracking, a repeatable table-top simulation, executive and SOC dashboards, a serverless AWS Lambda + Step Functions deployment path, a dependency-free web dashboard, Pytest validation enforced by a GitHub Actions CI pipeline, and full GitHub version control.

The project is complete for internship-level demonstration and submission.

---

## Author

**Himanshu**
B.Tech. CSE Cyber Security
Internship Project at Zaalima Development Pvt. Ltd.