"""Email Delivery — sends threat intel reports via Microsoft Graph API.

Uses the existing service principal credentials to send emails through
Microsoft Graph without requiring a separate mail provider.

Usage:
    sender = EmailSender(
        tenant_id="...",
        client_id="...",
        client_secret="...",
        sender_email="agent@purplestratus.onmicrosoft.com",
    )
    sender.send_report(
        to=["analyst@company.com"],
        subject="[THREAT INTEL] North Korea Supply Chain Attack",
        html_body=report_html,
    )
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
GRAPH_SEND_URL = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"


class EmailSender:
    """Send emails via Microsoft Graph API using client credentials."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        sender_email: str,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._sender = sender_email
        self._token: str | None = None

    def _get_token(self) -> str:
        """Acquire an access token for Microsoft Graph."""
        if self._token:
            return self._token

        url = GRAPH_TOKEN_URL.format(tenant_id=self._tenant_id)
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }

        resp = httpx.post(url, data=data, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"Graph token request failed: {resp.status_code} {resp.text[:200]}")

        self._token = resp.json()["access_token"]
        return self._token

    def send_report(
        self,
        to: list[str],
        subject: str,
        html_body: str,
        cc: list[str] | None = None,
        importance: str = "high",
    ) -> bool:
        """Send an HTML email report.

        Args:
            to: List of recipient email addresses
            subject: Email subject line
            html_body: Full HTML body
            cc: Optional CC recipients
            importance: "low", "normal", or "high"

        Returns:
            True if sent successfully, False otherwise
        """
        token = self._get_token()
        url = GRAPH_SEND_URL.format(sender=self._sender)

        to_recipients = [{"emailAddress": {"address": addr}} for addr in to]
        cc_recipients = [{"emailAddress": {"address": addr}} for addr in (cc or [])]

        payload = {
            "message": {
                "subject": subject,
                "importance": importance,
                "body": {
                    "contentType": "HTML",
                    "content": html_body,
                },
                "toRecipients": to_recipients,
                "ccRecipients": cc_recipients,
            },
            "saveToSentItems": True,
        }

        try:
            resp = httpx.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )

            if resp.status_code == 202:
                logger.info("Email sent successfully to %s: %s", to, subject)
                return True
            else:
                logger.warning(
                    "Email send failed: %d %s",
                    resp.status_code, resp.text[:200],
                )
                return False

        except Exception as exc:
            logger.warning("Email delivery failed: %s", exc)
            return False

    def send_intel_report(
        self,
        to: list[str],
        report: Any,
        html_body: str,
        cc: list[str] | None = None,
    ) -> bool:
        """Send a formatted intel assessment report.

        Builds the subject line from the report metadata.
        """
        verdict_tag = report.verdict.replace("_", " ").upper()
        risk_tag = report.risk_level.upper()
        subject = f"[THREAT INTEL] {report.intel_event_title} — {verdict_tag} ({risk_tag})"

        # Cap subject at 150 chars
        if len(subject) > 150:
            subject = subject[:147] + "..."

        return self.send_report(
            to=to,
            subject=subject,
            html_body=html_body,
            cc=cc,
            importance="high" if report.risk_level in ("critical", "high") else "normal",
        )
