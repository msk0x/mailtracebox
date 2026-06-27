"""Social media username enumeration plugin."""

from __future__ import annotations

from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.models.social import SocialProfile
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.social_check")


def _generate_candidates(local_part: str) -> list[str]:
    """Generate username candidates from an email local-part."""
    candidates: list[str] = []
    base = local_part.lower().strip()
    candidates.append(base)
    no_dots = base.replace(".", "")
    if no_dots != base:
        candidates.append(no_dots)
    if "+" in base:
        before_plus = base.split("+")[0]
        candidates.append(before_plus)
        candidates.append(before_plus.replace(".", ""))
    if "." in base:
        candidates.append(base.replace(".", "_"))
        candidates.append(base.replace(".", "-"))
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c and c not in seen and len(c) >= 2:
            seen.add(c)
            unique.append(c)
    return unique[:8]


class SocialCheckPlugin(BasePlugin):
    """Enumerate social media profiles from email username candidates."""

    @property
    def name(self) -> str:
        return "social_check"

    @property
    def description(self) -> str:
        return "Social media username enumeration via public APIs (GitHub, Reddit)."

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def tags(self) -> list[str]:
        return ["social", "username", "passive"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        local_part = context.target_local
        if not local_part:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        candidates = _generate_candidates(local_part)
        items_found = 0

        for username in candidates:
            # GitHub
            try:
                gh = await http_client.get(
                    f"https://api.github.com/users/{username}",
                    headers={"Accept": "application/vnd.github.v3+json"}, use_cache=True,
                )
                if gh.ok:
                    d = gh.json_or({})
                    await context.social_profiles.add(SocialProfile(
                        platform="github", username=d.get("login", username),
                        url=d.get("html_url", f"https://github.com/{username}"),
                        display_name=d.get("name"), bio=d.get("bio"),
                        followers=d.get("followers"), following=d.get("following"),
                        profile_image_url=d.get("avatar_url"), location=d.get("location"),
                        source="social_check", confidence=0.4,
                    ))
                    items_found += 1
                    logger.info("GitHub profile found: %s", username)
            except Exception as exc:
                logger.debug("GitHub check failed for %s: %s", username, exc)

            # Reddit
            try:
                rd = await http_client.get(
                    f"https://www.reddit.com/user/{username}/about.json",
                    headers={"User-Agent": "mailtracebox/0.1.0"}, use_cache=True,
                )
                if rd.ok:
                    data = rd.json_or({}).get("data", {})
                    if data.get("name"):
                        await context.social_profiles.add(SocialProfile(
                            platform="reddit", username=data.get("name", username),
                            url=f"https://www.reddit.com/user/{username}",
                            profile_image_url=data.get("icon_img", "").split("?")[0] or None,
                            source="social_check", confidence=0.35,
                        ))
                        items_found += 1
                        logger.info("Reddit profile found: %s", username)
            except Exception as exc:
                logger.debug("Reddit check failed for %s: %s", username, exc)

        return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED, items_found=items_found, confidence=0.3)
