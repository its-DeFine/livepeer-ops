"""Minimal PostHog capture helper for low-volume lifecycle analytics."""
from __future__ import annotations

import logging
from typing import Any, Mapping

import httpx


DEFAULT_POSTHOG_HOST = "https://us.posthog.com"
_TIMEOUT = httpx.Timeout(2.0, connect=1.0)
_LOGGER = logging.getLogger(__name__)


async def capture_event(
    *,
    settings: Any,
    event: str,
    distinct_id: str,
    properties: Mapping[str, Any],
    logger: logging.Logger | None = None,
) -> None:
    """Capture one PostHog event without ever breaking the caller."""

    if not distinct_id:
        return

    api_key = str(getattr(settings, "posthog_project_api_key", "") or "").strip()
    if not api_key:
        return

    log = logger or _LOGGER
    host = str(getattr(settings, "posthog_host", DEFAULT_POSTHOG_HOST) or DEFAULT_POSTHOG_HOST).strip()
    host = host.rstrip("/") or DEFAULT_POSTHOG_HOST
    if bool(getattr(settings, "posthog_virtual_mode", False)):
        log.debug("PostHog virtual mode enabled; skipping external capture for %s", event)
        return

    payload = {
        "api_key": api_key,
        "event": event,
        "distinct_id": distinct_id,
        "properties": dict(properties),
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(f"{host}/capture/", json=payload)
        if response.status_code >= 400:
            log.warning("PostHog capture returned %s for %s", response.status_code, event)
    except Exception as exc:  # pragma: no cover - defensive network guard
        log.warning("PostHog capture failed for %s: %s", event, exc)
