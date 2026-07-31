from app.integrations.slack_client import (
    send_slack_alert,
    get_slack_status
)

from app.integrations.teams_client import (
    send_teams_alert,
    get_teams_status
)


def notify_soc(alert):

    slack_result = send_slack_alert(alert)

    teams_result = send_teams_alert(alert)

    return {

        "workflow": "soc_notification",

        "slack": slack_result,

        "teams": teams_result
    }


def notification_status():

    return {

        "workflow": "soc_notification",

        "slack": get_slack_status(),

        "teams": get_teams_status()
    }