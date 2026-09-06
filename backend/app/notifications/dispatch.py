"""Single dispatch point from a NotificationConfig row to the right
client — used by both the scan-completed trigger
(app.notifications.scan_notifications) and the "test this config" API
route (app.api.routes.notification_configs), so the two never drift on
how a provider's stored fields map to a real send.
"""

import json

from app.integrations.outlook.client import OutlookClient, OutlookNotificationError
from app.integrations.slack.client import SlackClient, SlackNotificationError
from app.integrations.teams.client import TeamsClient, TeamsNotificationError
from app.models.notification_config import NotificationConfig
from app.vault.credential_vault import decrypt_secret

NotificationDispatchError = (SlackNotificationError, TeamsNotificationError, OutlookNotificationError)


async def send_notification(config: NotificationConfig, text: str) -> None:
    if config.provider == "slack":
        webhook_url = decrypt_secret(config.encrypted_webhook_url)
        await SlackClient(webhook_url).post_message(text)
    elif config.provider == "teams":
        webhook_url = decrypt_secret(config.encrypted_webhook_url)
        await TeamsClient(webhook_url).post_message(text)
    elif config.provider == "outlook":
        smtp_config = json.loads(decrypt_secret(config.encrypted_config_json))
        client = OutlookClient(
            smtp_host=smtp_config["smtp_host"],
            smtp_port=smtp_config["smtp_port"],
            smtp_username=smtp_config["smtp_username"],
            smtp_password=smtp_config["smtp_password"],
            from_address=smtp_config["from_address"],
            to_address=smtp_config["to_address"],
        )
        await client.send_message(text)
    else:
        raise ValueError(f"Unknown NotificationConfig.provider: {config.provider!r}")
