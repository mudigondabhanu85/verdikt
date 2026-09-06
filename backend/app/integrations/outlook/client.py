"""Outlook/email notifications via plain SMTP — the build spec's own
documented "simpler fallback" to the Microsoft Graph API, which needs an
Azure app registration we don't have to test against in this environment.
Any mail provider speaking standard SMTP (including Outlook/Office 365's
own smtp.office365.com:587 with an app password) works through this same
client — nothing Outlook-specific in the wire protocol itself.

Uses stdlib smtplib (no new dependency) wrapped in asyncio.to_thread so it
composes with the rest of this codebase's async adapters without adding
aiosmtplib as a dependency.
"""

import asyncio
import smtplib
from email.message import EmailMessage


class OutlookNotificationError(RuntimeError):
    pass


class OutlookClient:
    def __init__(
        self,
        *,
        smtp_host: str,
        smtp_port: int,
        smtp_username: str,
        smtp_password: str,
        from_address: str,
        to_address: str,
        use_tls: bool = True,
        timeout: float = 10.0,
    ):
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._smtp_username = smtp_username
        self._smtp_password = smtp_password
        self._from_address = from_address
        self._to_address = to_address
        self._use_tls = use_tls
        self._timeout = timeout

    def _send_sync(self, subject: str, body: str) -> None:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self._from_address
        message["To"] = self._to_address
        message.set_content(body)

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=self._timeout) as smtp:
                if self._use_tls:
                    smtp.starttls()
                if self._smtp_username:
                    smtp.login(self._smtp_username, self._smtp_password)
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise OutlookNotificationError(f"Could not send notification via SMTP: {exc}") from exc

    async def send_message(self, text: str, *, subject: str = "Verdikt notification") -> None:
        await asyncio.to_thread(self._send_sync, subject, text)
