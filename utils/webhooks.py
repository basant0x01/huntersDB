"""
utils/webhooks.py — Async notification dispatch (Discord, Slack, Telegram).
Async port of the original send_webhook().
"""
import asyncio
import json
import logging
from typing import Optional

import aiohttp

from utils.settings import load_settings

logger = logging.getLogger("utils.webhooks")


async def send_webhook(title: str, body: str, severity: str = "info") -> None:
    """
    Send alert to all configured notification channels.
    Fires and forgets — does not raise on failure.
    """
    s = load_settings()
    tasks = []

    if s.get("discord_webhook_url", "").strip():
        tasks.append(_send_discord(s["discord_webhook_url"], title, body, severity))
    if s.get("slack_webhook_url", "").strip():
        tasks.append(_send_slack(s["slack_webhook_url"], title, body, severity))
    if (s.get("telegram_bot_token", "").strip()
            and s.get("telegram_chat_id", "").strip()):
        tasks.append(_send_telegram(
            s["telegram_bot_token"], s["telegram_chat_id"], title, body))

    if not tasks:
        return

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            logger.warning("Webhook delivery error: %s", r)


async def _send_discord(url: str, title: str, body: str, severity: str) -> None:
    color_map = {"critical": 0xFF0000, "high": 0xFF6600,
                 "medium": 0xFFCC00, "low": 0x0099FF, "info": 0x777777}
    color = color_map.get(severity, 0x777777)
    payload = {"embeds": [{"title": title, "description": body[:2000], "color": color}]}
    async with aiohttp.ClientSession() as s:
        async with s.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status not in (200, 204):
                logger.warning("Discord webhook status %d", r.status)


async def _send_slack(url: str, title: str, body: str, severity: str) -> None:
    payload = {"text": f"*{title}*\n{body[:2000]}"}
    async with aiohttp.ClientSession() as s:
        async with s.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status != 200:
                logger.warning("Slack webhook status %d", r.status)


async def _send_telegram(token: str, chat_id: str, title: str, body: str) -> None:
    text = f"*{title}*\n{body[:4000]}"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    async with aiohttp.ClientSession() as s:
        async with s.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status != 200:
                logger.warning("Telegram webhook status %d", r.status)
