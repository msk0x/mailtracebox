"""Gravatar profile lookup plugin."""

from __future__ import annotations

import hashlib
from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.models.social import SocialProfile
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.gravatar")


class GravatarPlugin(BasePlugin):
    """Look up Gravatar profile for the target email address."""

    @property
    def name(self) -> str:
        return "gravatar"

    @property
    def description(self) -> str:
        return "Gravatar profile and avatar lookup by email hash."

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def tags(self) -> list[str]:
        return ["social", "email", "passive"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        email = context.target_email
        if not email:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()

        # Use HEAD request to check avatar existence (avoids binary decode crash)
        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        avatar_resp = await http_client.head(avatar_url)

        if avatar_resp.status == 404:
            logger.info("No Gravatar profile for %s", email)
            return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED, items_found=0)

        # Fetch full profile as JSON
        profile_url = f"https://www.gravatar.com/{email_hash}.json"
        resp = await http_client.get(profile_url, use_cache=True)

        if not resp.ok or resp.is_binary:
            # No JSON profile — but avatar exists, so record that
            profile = SocialProfile(
                platform="gravatar", username=email_hash[:12],
                url=f"https://gravatar.com/{email_hash}",
                profile_image_url=f"https://www.gravatar.com/avatar/{email_hash}",
                source="gravatar", confidence=0.8,
            )
            await context.social_profiles.add(profile)
            return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED, items_found=1)

        try:
            data = resp.json()
            entries = data.get("entry", [])
            if not entries:
                # Avatar exists but no profile data
                profile = SocialProfile(
                    platform="gravatar", username=email_hash[:12],
                    url=f"https://gravatar.com/{email_hash}",
                    profile_image_url=f"https://www.gravatar.com/avatar/{email_hash}",
                    source="gravatar", confidence=0.7,
                )
                await context.social_profiles.add(profile)
                return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED, items_found=1)

            entry = entries[0]
            accounts = entry.get("accounts", [])
            for acct in accounts:
                acct_profile = SocialProfile(
                    platform=acct.get("shortname", acct.get("domain", "unknown")),
                    username=acct.get("username", acct.get("display", "")),
                    url=acct.get("url", ""), display_name=acct.get("display", ""),
                    source="gravatar", confidence=0.8,
                )
                await context.social_profiles.add(acct_profile)

            photos = entry.get("photos", [])
            profile = SocialProfile(
                platform="gravatar", username=email_hash[:12],
                url=entry.get("profileUrl", f"https://gravatar.com/{email_hash}"),
                display_name=entry.get("displayName") or None,
                bio=entry.get("aboutMe") or None,
                location=entry.get("currentLocation") or None,
                profile_image_url=photos[0]["value"] if photos else f"https://www.gravatar.com/avatar/{email_hash}",
                source="gravatar", confidence=0.85,
            )
            await context.social_profiles.add(profile)

            items = 1 + len(accounts)
            logger.info("Gravatar profile found for %s: %s (%d linked accounts)", email, entry.get("displayName"), len(accounts))
            return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED, items_found=items)

        except Exception as exc:
            logger.warning("Failed to parse Gravatar profile: %s", exc)
            return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED, items_found=1, warnings=[str(exc)])
