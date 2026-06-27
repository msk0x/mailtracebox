"""Account discovery plugin — finds accounts across platforms.

Three-phase OSINT strategy:
  Phase 1: Email-based lookups     —  4 requests, highest confidence
  Phase 2: Primary username        — ~39 concurrent requests, one pass
  Phase 3: Variant sweep           — GitHub + Instagram, sequential

Total: ~40 Phase-2 requests + ~16 Phase-3 requests. ~36s total.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.account_discovery")


# ═══════════════════════════════════════════════════════════════════════
#  USERNAME VARIANT GENERATION
# ═══════════════════════════════════════════════════════════════════════

def _get_username_variants(local: str) -> list[str]:
    """Generate realistic username variants.

    People typically use:
      - Exact email local part
      - Drop leading initial(s)
      - Underscore before trailing numbers
      - Initials of name parts + numbers  (e.g. msk1601)
      - First name + numbers              (e.g. mohan1601)
      - Short nickname + numbers          (e.g. gmmo1601)
    """
    result: list[str] = []
    seen: set[str] = set()

    def _add(v: str) -> None:
        v = v.strip().lower()
        if v and 3 <= len(v) <= 40 and v not in seen:
            seen.add(v)
            result.append(v)

    # ── Extract trailing numbers and core name ───────────────────────
    num_match = re.search(r"(\d+)\s*$", local)
    numbers = num_match.group(1) if num_match else ""
    name = local[: local.rfind(numbers)].rstrip("_.-") if numbers else local

    # ── 1. Exact local part ─────────────────────────────────────────
    _add(local)

    # ── 2. Name without trailing numbers ────────────────────────────
    if numbers and name != local and len(name) >= 3:
        _add(name)

    # ── 3. Drop leading initial(s) ──────────────────────────────────
    for trim in (1, 2):
        base = name[trim:]
        if len(base) >= 4:
            _add(base)
            if numbers:
                _add(f"{base}{numbers}")
                _add(f"{base}_{numbers}")

    # ── 4. Initials from plausible name splits ──────────────────────
    #    Strip leading initials (gm) to get core name
    #    e.g. gmmohansaikrishna -> mohansaikrishna
    #    Split: mohan + sai + krishna -> msk
    best = name[2:] if len(name) > 5 else name
    n = len(best)

    if n >= 8:
        initials: dict[str, float] = {}

        # 3-letter initials: find splits where first part is 4-6 chars
        # (typical first name) and rest breaks into 2 more parts
        for first_len in range(4, min(7, n - 6)):
            rest = best[first_len:]
            for mid_len in range(3, min(6, len(rest) - 3)):
                last = rest[mid_len:]
                if len(last) >= 3:
                    init = best[0] + rest[0] + last[0]
                    # Score: prefer even-ish splits
                    # Prefer first_len 5-6 (mohan, pranav, johns)
                    balance = 2.0 if first_len in (5, 6) else 1.0

                    initials[init] = max(initials.get(init, 0), balance)

        # 2-letter initials: first part 4-6 chars, rest >= 5 chars
        for first_len in range(4, min(7, n - 4)):
            rest = best[first_len:]
            if len(rest) >= 5:
                init = best[0] + rest[0]
                balance = 2.0 if first_len in (5, 6) else 1.0
                initials[init] = max(initials.get(init, 0), balance)

        # Sort by score, keep top 4
        ranked = sorted(initials, key=lambda x: -initials[x])[:4]
        for init in ranked:
            _add(init)
            if numbers:
                _add(f"{init}{numbers}")
                _add(f"{init}_{numbers}")

    # ── 5. Common first-name lengths ────────────────────────────────
    if n >= 8:
        for first_len in (4, 5, 6):
            if first_len < n - 3:
                first = best[:first_len]
                _add(first)
                if numbers:
                    _add(f"{first}{numbers}")

    # ── 6. first_last combo ─────────────────────────────────────────
    if n >= 10:
        for sp in (4, 5, 6):
            if sp < n - 3:
                first = best[:sp]
                last = best[sp:]
                if len(first) >= 3 and len(last) >= 4:
                    _add(f"{first}_{last}")
                    break

    # ── 7. Short nicknames from original name ───────────────────────
    for ln in (4, 5):
        if len(name) > ln:
            nick = name[:ln]
            _add(nick)
            if numbers:
                _add(f"{nick}{numbers}")

    return result



# ═══════════════════════════════════════════════════════════════════════
#  SHARED HTTP HELPERS
# ═══════════════════════════════════════════════════════════════════════

async def _check(
    http: HttpClient,
    url: str,
    *,
    expect_json: bool = False,
    expect_status: int = 200,
    body_must_contain: str = "",
    body_must_not_contain: str = "",
    headers: dict[str, str] | None = None,
    no_retry: bool = False,
) -> tuple[bool, Any]:
    """Generic GET check. Returns (found, response_data)."""
    try:
        kwargs: dict[str, Any] = {"use_cache": True, "no_retry": no_retry}
        if headers:
            kwargs["headers"] = headers
        resp = await http.get(url, **kwargs)
        if resp.status != expect_status:
            return False, None
        if body_must_contain and body_must_contain.lower() not in resp.body.lower():
            return False, None
        if body_must_not_contain and body_must_not_contain.lower() in resp.body.lower():
            return False, None
        if expect_json:
            data = resp.json_or(None)
            if data is None:
                return False, None
            return True, data
        return True, resp.body
    except Exception as exc:
        logger.debug("Check failed for %s: %s", url, exc)
        return False, None


async def _post_json(
    http: HttpClient,
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> tuple[bool, Any]:
    """POST JSON helper. Serialises manually — HttpClient.post()
    does not accept a ``json`` keyword argument."""
    try:
        body = json.dumps(payload)
        merged = {"Content-Type": "application/json", **(headers or {})}
        resp = await http.post(url, data=body, headers=merged)
        if not resp.ok:
            return False, None
        data = resp.json_or(None)
        if data is None:
            return False, None
        return True, data
    except Exception as exc:
        logger.debug("POST failed for %s: %s", url, exc)
        return False, None


# ═══════════════════════════════════════════════════════════════════════
#  PLUGIN
# ═══════════════════════════════════════════════════════════════════════

class AccountDiscoveryPlugin(BasePlugin):
    """Discover accounts via email-based and username-based lookups."""
    api_key_env_var = "GITHUB_TOKEN"
    """Discover accounts via email-based and username-based lookups."""
    @property
    def name(self) -> str:
        return "account_discovery"

    @property
    def description(self) -> str:
        return "Discovers accounts across development, professional, and social platforms"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def tags(self) -> list[str]:
        return ["osint", "accounts", "social"]

    # ── helper ──────────────────────────────────────────────────────

    async def _safe(
        self, platform: str, category: str, coro
    ) -> dict[str, str] | None:
        try:
            result = await coro
            if result and isinstance(result, dict):
                result["category"] = category
                return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("%s: %s", platform, exc)
        return None

    # ── main entry ──────────────────────────────────────────────────

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        email = context.target_email
        if not email:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        local = context.target_local
        usernames = _get_username_variants(local)
        logger.debug("Username variants (%d): %s", len(usernames), usernames)

        found: list[dict[str, str]] = []
        found_platforms: set[str] = set()
        http = http_client

        # GitHub token for higher rate limits (5000/hr vs 60/hr)
        gh_token = config.get("GITHUB_TOKEN")
        self._gh_headers = {"Authorization": f"token {gh_token}"} if gh_token else None

        # ═══════════════════════════════════════════════════════════
        #  PHASE 1 — Email-based lookups (highest confidence)
        # ═══════════════════════════════════════════════════════════
        email_tasks = [
            self._safe("GitHub",   "Development",  self._github_email(email, http)),
            self._safe("GitLab",   "Development",  self._gitlab_email(email, http)),
            self._safe("Keybase",  "Professional", self._keybase_email(email, http)),
            self._safe("Gravatar", "Professional", self._gravatar_email(email, http)),
        ]
        for r in await asyncio.gather(*email_tasks, return_exceptions=True):
            if isinstance(r, dict):
                found.append(r)
                found_platforms.add(r["platform"])

        # ═══════════════════════════════════════════════════════════
        #  PHASE 2 — Primary username, all platforms, concurrent
        # ═══════════════════════════════════════════════════════════
        primary = usernames[0]
        sem = asyncio.Semaphore(8)
        platform_tasks: list[asyncio.Task] = []

        def _add_task(platform: str, category: str, coro) -> None:
            async def _run():
                async with sem:
                    return await self._safe(platform, category, coro)
            platform_tasks.append(asyncio.create_task(_run()))

        # ── Development ──────────────────────────────────────────
        if "GitHub" not in found_platforms:
            _add_task("GitHub",     "Development", self._github_user(primary, http))
        _add_task("Docker Hub",     "Development", self._dockerhub(primary, http))
        _add_task("Bitbucket",      "Development", self._bitbucket(primary, http))
        _add_task("npm",            "Development", self._npm(primary, http))
        _add_task("PyPI",           "Development", self._pypi(primary, http))
        _add_task("crates.io",      "Development", self._cratesio(primary, http))
        _add_task("Codeberg",       "Development", self._codeberg(primary, http))
        _add_task("Packagist",      "Development", self._packagist(primary, http))
        _add_task("RubyGems",       "Development", self._rubygems(primary, http))
        _add_task("HackerOne",      "Development", self._hackerone(primary, http))
        _add_task("DEV.to",         "Development", self._devto(primary, http))

        # ── Coding platforms ─────────────────────────────────────
        _add_task("Codeforces",     "Development", self._codeforces(primary, http))
        _add_task("LeetCode",       "Development", self._leetcode(primary, http))
        _add_task("HackerRank",     "Development", self._hackerrank(primary, http))
        _add_task("CodeChef",       "Development", self._codechef(primary, http))
        _add_task("TopCoder",       "Development", self._topcoder(primary, http))

        # ── Professional ─────────────────────────────────────────
        _add_task("Linktree",       "Professional", self._linktree(primary, http))
        _add_task("About.me",       "Professional", self._about_me(primary, http))
        _add_task("Calendly",       "Professional", self._calendly(primary, http))
        _add_task("Polywork",       "Professional", self._polywork(primary, http))
        _add_task("Peerlist",       "Professional", self._peerlist(primary, http))

        # ── Freelance ────────────────────────────────────────────
        _add_task("Fiverr",         "Professional", self._fiverr(primary, http))
        _add_task("Upwork",         "Professional", self._upwork(primary, http))
        _add_task("Freelancer",     "Professional", self._freelancer(primary, http))

        # ── Social ───────────────────────────────────────────────
        _add_task("Instagram",      "Social", self._instagram(primary, http))
        _add_task("Reddit",         "Social", self._reddit(primary, http))
        _add_task("Mastodon",       "Social", self._mastodon(primary, http))
        _add_task("Bluesky",        "Social", self._bluesky(primary, http))
        _add_task("Lemmy",          "Social", self._lemmy(primary, http))

        # ── Creative / Video / Gaming ────────────────────────────
        _add_task("ArtStation",     "Creative", self._artstation(primary, http))
        _add_task("Dailymotion",    "Video",    self._dailymotion(primary, http))
        _add_task("Modrinth",       "Gaming",   self._modrinth(primary, http))

        # ── Subdomain-based ──────────────────────────────────────
        _add_task("Hashnode",       "Development", self._hashnode(primary, http))
        _add_task("Substack",       "Writing",     self._substack(primary, http))
        _add_task("Ghost",          "Writing",     self._ghost(primary, http))
        _add_task("itch.io",        "Gaming",      self._itchio(primary, http))
        _add_task("Bandcamp",       "Music",       self._bandcamp(primary, http))

        # ── Page-based ───────────────────────────────────────────
        _add_task("Snapchat",       "Social",    self._snapchat(primary, http))
        _add_task("Telegram",       "Messaging", self._telegram(primary, http))
        _add_task("VK",             "Social",    self._vk(primary, http))

        for r in await asyncio.gather(*platform_tasks, return_exceptions=True):
            if isinstance(r, dict):
                found.append(r)
                found_platforms.add(r["platform"])

        # ═══════════════════════════════════════════════════════════
        #  PHASE 3 — Variant sweep on GitHub + Instagram
        #            Sequential, stops when each platform is found
        # ═══════════════════════════════════════════════════════════
        sweep_checkers: list[tuple[str, str, Any]] = [
            ("GitHub",   "Development",  self._github_user),
            ("Instagram", "Social",      self._instagram),
        ]
        sweep_needed: dict[str, Any] = {
            name: func for name, _cat, func in sweep_checkers
            if name not in found_platforms
        }

        if sweep_needed:
            # Longest variants first (more specific, fewer false positives)
            for variant in sorted(usernames[1:], key=lambda v: -len(v)):
                if not sweep_needed:
                    break

                sweep_tasks = []
                for pname in list(sweep_needed):
                    cat = "Social" if pname == "Instagram" else "Development"
                    sweep_tasks.append(
                        self._safe(pname, cat, sweep_needed[pname](variant, http))
                    )

                for r in await asyncio.gather(*sweep_tasks, return_exceptions=True):
                    if isinstance(r, dict):
                        r["method"] = "username variant"
                        found.append(r)
                        found_platforms.add(r["platform"])
                        sweep_needed.pop(r["platform"], None)

        # ═══════════════════════════════════════════════════════════
        #  Deduplicate and save
        # ═══════════════════════════════════════════════════════════
        seen: set[str] = set()
        deduped: list[dict[str, str]] = []
        for acct in found:
            key = acct.get("platform", "")
            if key and key not in seen:
                seen.add(key)
                deduped.append(acct)

        if deduped:
            await context.set_custom("account_discovery", deduped)

        logger.info(
            "Account discovery: %d variants, %d platforms, %d found",
            len(usernames), len(platform_tasks), len(deduped),
        )

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.COMPLETED,
            items_found=len(deduped),
            confidence=0.8,
        )

    # ═════════════════════════════════════════════════════════════════
    #  PHASE 1 — EMAIL-BASED (highest confidence)
    # ═════════════════════════════════════════════════════════════════

    async def _github_email(self, email: str, http: HttpClient):
        found, data = await _check(http,
            f"https://api.github.com/search/users?q={email}+in:email",
            expect_json=True, body_must_contain="items",
            headers=self._gh_headers)
        if found and data:
            items = data.get("items", [])
            if items:
                u = items[0]
                return {"platform": "GitHub", "username": u.get("login", ""),
                        "url": u.get("html_url", ""), "confidence": "high",
                        "method": "email search API"}
        return None

    async def _gitlab_email(self, email: str, http: HttpClient):
        found, data = await _check(http,
            f"https://gitlab.com/api/v4/users?search={email}",
            expect_json=True)
        if found and isinstance(data, list) and data:
            u = data[0]
            return {"platform": "GitLab", "username": u.get("username", ""),
                    "url": u.get("web_url", ""), "confidence": "high",
                    "method": "email search API"}
        return None

    async def _keybase_email(self, email: str, http: HttpClient):
        found, data = await _check(http,
            f"https://keybase.io/_/api/1.0/user/lookup.json?email={email}",
            expect_json=True)
        if found and data:
            them = data.get("them", [])
            if them:
                user = them[0] if isinstance(them, list) else them
                basics = user.get("basics", {}) if isinstance(user, dict) else {}
                username = basics.get("username", "")
                if username:
                    return {"platform": "Keybase", "username": username,
                            "url": f"https://keybase.io/{username}",
                            "confidence": "high", "method": "email lookup"}
        return None

    async def _gravatar_email(self, email: str, http: HttpClient):
        h = hashlib.md5(email.lower().strip().encode()).hexdigest()
        found, data = await _check(http,
            f"https://en.gravatar.com/{h}.json", expect_json=True)
        if found and data:
            entry = data.get("entry", [])
            if entry:
                p = entry[0] if isinstance(entry, list) else entry
                display = p.get("displayName", "")
                uname = p.get("preferredUsername", "")
                return {"platform": "Gravatar", "username": uname or display,
                        "url": f"https://gravatar.com/{uname}" if uname else "",
                        "confidence": "high", "method": "email hash lookup"}
        return None

    # ═════════════════════════════════════════════════════════════════
    #  PHASE 2 — USERNAME-BASED (one username, concurrent)
    # ═════════════════════════════════════════════════════════════════

    # ── Development ──────────────────────────────────────────────

    async def _github_user(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://api.github.com/users/{username}",
            expect_json=True, body_must_contain="login",
            headers=self._gh_headers)
        if found and data and data.get("login"):
            return {"platform": "GitHub", "username": data["login"],
                    "url": data.get("html_url", f"https://github.com/{username}"),
                    "confidence": "medium", "method": "username lookup"}
        return None

    async def _dockerhub(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://hub.docker.com/v2/users/{username}/",
            expect_json=True, body_must_contain="username")
        if found and data and data.get("username"):
            return {"platform": "Docker Hub", "username": data["username"],
                    "url": f"https://hub.docker.com/u/{username}",
                    "confidence": "medium", "method": "user API"}
        return None

    async def _bitbucket(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://api.bitbucket.org/2.0/users/{username}",
            expect_json=True, body_must_contain="username")
        if found and data and data.get("username"):
            href = data.get("links", {}).get("html", {}).get(
                "href", f"https://bitbucket.org/{username}")
            return {"platform": "Bitbucket", "username": data["username"],
                    "url": href, "confidence": "medium", "method": "user API"}
        return None

    async def _npm(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://registry.npmjs.org/-/v1/search?text=maintainer:{username}&size=3",
            expect_json=True)
        if found and data:
            for obj in data.get("objects", []):
                for m in obj.get("package", {}).get("maintainers", []):
                    if m.get("username", "").lower() == username.lower():
                        return {"platform": "npm", "username": m["username"],
                                "url": f"https://www.npmjs.com/~{m['username']}",
                                "confidence": "medium", "method": "maintainer search"}
        return None

    async def _pypi(self, username: str, http: HttpClient):
        found, body = await _check(http,
            f"https://pypi.org/user/{username}/",
            body_must_not_contain="client challenge")
        if found:
            found2, _ = await _check(http,
                f"https://pypi.org/user/{username}/",
                body_must_contain="package-snippet",
                body_must_not_contain="client challenge")
            if found2:
                return {"platform": "PyPI", "username": username,
                        "url": f"https://pypi.org/user/{username}/",
                        "confidence": "medium", "method": "user page"}
        return None

    async def _cratesio(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://crates.io/api/v1/users/{username}",
            expect_json=True, body_must_contain="user")
        if found and data:
            user = data.get("user", {})
            if user.get("login"):
                return {"platform": "crates.io", "username": user["login"],
                        "url": f"https://crates.io/users/{username}",
                        "confidence": "medium", "method": "user API"}
        return None

    async def _codeberg(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://codeberg.org/api/v1/users/{username}",
            expect_json=True, body_must_contain="login")
        if found and data and data.get("login"):
            return {"platform": "Codeberg", "username": data["login"],
                    "url": f"https://codeberg.org/{username}",
                    "confidence": "medium", "method": "user API"}
        return None

    async def _packagist(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://packagist.org/packages.json?vendor={username}",
            expect_json=True)
        if found and data:
            pkgs = data.get("packageNames", [])
            if pkgs:
                return {"platform": "Packagist", "username": username,
                        "url": f"https://packagist.org/packages/{username}/",
                        "confidence": "medium", "method": "vendor search"}
        return None

    async def _rubygems(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://rubygems.org/api/v1/owners/{username}/gems.json",
            expect_json=True)
        if found and isinstance(data, list) and data:
            return {"platform": "RubyGems", "username": username,
                    "url": f"https://rubygems.org/profiles/{username}",
                    "confidence": "medium", "method": "owner API"}
        return None

    async def _hackerone(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://hackerone.com/{username}",
            body_must_contain="hacker profile",
            body_must_not_contain="page not found")
        if found:
            return {"platform": "HackerOne", "username": username,
                    "url": f"https://hackerone.com/{username}",
                    "confidence": "medium", "method": "profile page"}
        return None

    async def _devto(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://dev.to/api/articles?username={username}&per_page=1",
            expect_json=True)
        if found and isinstance(data, list) and data:
            user = data[0].get("user", {})
            return {"platform": "DEV.to", "username": user.get("username", username),
                    "url": f"https://dev.to/{username}",
                    "confidence": "medium", "method": "articles API"}
        return None

    # ── Coding platforms ─────────────────────────────────────────

    async def _codeforces(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://codeforces.com/api/user.info?handles={username}",
            expect_json=True, body_must_contain="status")
        if found and data and data.get("status") == "OK":
            users = data.get("result", [])
            if users:
                u = users[0]
                return {"platform": "Codeforces",
                        "username": u.get("handle", username),
                        "url": f"https://codeforces.com/profile/{username}",
                        "confidence": "high", "method": "user.info API"}
        return None

    async def _leetcode(self, username: str, http: HttpClient):
        payload = {
            "query": (
                "query getUserProfile($username: String!) {"
                "  matchedUser(username: $username) {"
                "    username"
                "    profile { ranking }"
                "  }"
                "}"
            ),
            "variables": {"username": username},
        }
        found, data = await _post_json(http,
            "https://leetcode.com/graphql", payload)
        if found and data:
            matched = data.get("data", {}).get("matchedUser")
            if matched and matched.get("username"):
                return {"platform": "LeetCode",
                        "username": matched["username"],
                        "url": f"https://leetcode.com/{username}",
                        "confidence": "high", "method": "GraphQL API"}
        return None

    async def _hackerrank(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://www.hackerrank.com/rest/contests/master/hackers/{username}/profile",
            expect_json=True, body_must_contain="username")
        if found and data and data.get("username"):
            return {"platform": "HackerRank", "username": data["username"],
                    "url": f"https://www.hackerrank.com/{username}",
                    "confidence": "high", "method": "REST API"}
        return None

    async def _codechef(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://www.codechef.com/api/users/{username}",
            expect_json=True, body_must_contain="username")
        if found and data and data.get("username"):
            return {"platform": "CodeChef", "username": data["username"],
                    "url": f"https://www.codechef.com/users/{username}",
                    "confidence": "high", "method": "user API"}
        return None

    async def _topcoder(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://api.topcoder.com/v5/members/{username}",
            expect_json=True, body_must_contain="handle")
        if found and data and data.get("handle"):
            return {"platform": "TopCoder", "username": data["handle"],
                    "url": f"https://www.topcoder.com/members/{username}",
                    "confidence": "high", "method": "members API"}
        return None

    # ── Professional ─────────────────────────────────────────────

    async def _linktree(self, username: str, http: HttpClient):
        found, body = await _check(http,
            f"https://linktr.ee/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="page not found")
        if found and isinstance(body, str):
            if "link" in body.lower() or "profile" in body.lower():
                return {"platform": "Linktree", "username": username,
                        "url": f"https://linktr.ee/{username}",
                        "confidence": "low", "method": "profile page"}
        return None

    async def _about_me(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://about.me/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="page not found")
        if found:
            return {"platform": "About.me", "username": username,
                    "url": f"https://about.me/{username}",
                    "confidence": "low", "method": "profile page"}
        return None

    async def _calendly(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://calendly.com/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="page not found")
        if found:
            return {"platform": "Calendly", "username": username,
                    "url": f"https://calendly.com/{username}",
                    "confidence": "low", "method": "scheduling page"}
        return None

    async def _polywork(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://polywork.com/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="not found")
        if found:
            return {"platform": "Polywork", "username": username,
                    "url": f"https://polywork.com/{username}",
                    "confidence": "low", "method": "profile page"}
        return None

    async def _peerlist(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://peerlist.io/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="not found")
        if found:
            return {"platform": "Peerlist", "username": username,
                    "url": f"https://peerlist.io/{username}",
                    "confidence": "low", "method": "profile page"}
        return None

    # ── Freelance ────────────────────────────────────────────────

    async def _fiverr(self, username: str, http: HttpClient):
        found, body = await _check(http,
            f"https://www.fiverr.com/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="page not found")
        if found and isinstance(body, str):
            bl = body.lower()
            if "seller" in bl or "gig" in bl or "level" in bl:
                return {"platform": "Fiverr", "username": username,
                        "url": f"https://www.fiverr.com/{username}",
                        "confidence": "low", "method": "seller profile"}
        return None

    async def _upwork(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://www.upwork.com/freelancers/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="not found")
        if found:
            return {"platform": "Upwork", "username": username,
                    "url": f"https://www.upwork.com/freelancers/{username}",
                    "confidence": "low", "method": "freelancer page"}
        return None

    async def _freelancer(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://www.freelancer.com/api/users/0.1/users?usernames[]={username}",
            expect_json=True)
        if found and data:
            users = data.get("result", {}).get("users", {})
            if users and username.lower() in [u.lower() for u in users.keys()]:
                return {"platform": "Freelancer.com", "username": username,
                        "url": f"https://www.freelancer.com/u/{username}",
                        "confidence": "medium", "method": "user API"}
        return None

    # ── Social ───────────────────────────────────────────────────

    async def _instagram(self, username: str, http: HttpClient):
        """Instagram: profile pages embed og:description for SEO."""
        found, body = await _check(http,
            f"https://www.instagram.com/{username}/",
            body_must_contain="og:description",
            body_must_not_contain="Sorry, this page")
        if found and isinstance(body, str):
            return {"platform": "Instagram", "username": username,
                    "url": f"https://www.instagram.com/{username}/",
                    "confidence": "medium", "method": "profile page"}
        return None

    async def _reddit(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://www.reddit.com/user/{username}/about.json",
            expect_json=True,
            headers={"User-Agent": "mailtracebox/6.0"})
        if found and data:
            ud = data.get("data", {})
            if ud.get("name"):
                return {"platform": "Reddit", "username": ud["name"],
                        "url": f"https://www.reddit.com/user/{ud['name']}",
                        "confidence": "medium", "method": "user API"}
        return None

    async def _mastodon(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://mastodon.social/api/v1/accounts/lookup?acct={username}",
            expect_json=True)
        if found and data and data.get("username"):
            return {"platform": "Mastodon", "username": data["username"],
                    "url": data.get("url", f"https://mastodon.social/@{username}"),
                    "confidence": "medium", "method": "account lookup API"}
        return None

    async def _bluesky(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors"
            f"?term={username}&limit=3",
            expect_json=True)
        if found and data:
            for actor in data.get("actors", []):
                handle = actor.get("handle", "")
                if username.lower() in handle.lower():
                    return {"platform": "Bluesky", "username": handle,
                            "url": f"https://bsky.app/profile/{handle}",
                            "confidence": "medium", "method": "actor search API"}
        return None

    async def _lemmy(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://lemmy.world/api/v3/user?username={username}",
            expect_json=True)
        if found and data:
            person = data.get("person_view", {}).get("person", {})
            if person.get("name"):
                return {"platform": "Lemmy", "username": person["name"],
                        "url": f"https://lemmy.world/u/{username}",
                        "confidence": "medium", "method": "user API"}
        return None

    # ── Creative / Video / Gaming ────────────────────────────────

    async def _artstation(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://www.artstation.com/users/{username}/quick.json",
            expect_json=True, body_must_contain="username")
        if found and data and data.get("username"):
            return {"platform": "ArtStation", "username": data["username"],
                    "url": f"https://www.artstation.com/{username}",
                    "confidence": "medium", "method": "user API"}
        return None

    async def _dailymotion(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://api.dailymotion.com/user/{username}"
            f"?fields=id,username,screenname",
            expect_json=True)
        if found and data and data.get("username"):
            return {"platform": "Dailymotion", "username": data["username"],
                    "url": f"https://www.dailymotion.com/{username}",
                    "confidence": "medium", "method": "user API"}
        return None

    async def _modrinth(self, username: str, http: HttpClient):
        found, data = await _check(http,
            f"https://api.modrinth.com/v2/user/{username}",
            expect_json=True, body_must_contain="username")
        if found and data and data.get("username"):
            return {"platform": "Modrinth", "username": data["username"],
                    "url": f"https://modrinth.com/user/{username}",
                    "confidence": "medium", "method": "user API"}
        return None

    # ── Subdomain-based ──────────────────────────────────────────

    async def _hashnode(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://{username}.hashnode.dev",
            body_must_contain=username.lower(),
            no_retry=True)
        if found:
            return {"platform": "Hashnode", "username": username,
                    "url": f"https://{username}.hashnode.dev",
                    "confidence": "low", "method": "blog subdomain"}
        return None

    async def _substack(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://{username}.substack.com",
            body_must_contain=username.lower(),
            no_retry=True)
        if found:
            return {"platform": "Substack", "username": username,
                    "url": f"https://{username}.substack.com",
                    "confidence": "low", "method": "subdomain check"}
        return None

    async def _ghost(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://{username}.ghost.io",
            body_must_contain=username.lower(),
            no_retry=True)
        if found:
            return {"platform": "Ghost", "username": username,
                    "url": f"https://{username}.ghost.io",
                    "confidence": "low", "method": "blog subdomain"}
        return None

    async def _itchio(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://{username}.itch.io",
            body_must_contain=username.lower(),
            no_retry=True)
        if found:
            return {"platform": "itch.io", "username": username,
                    "url": f"https://{username}.itch.io",
                    "confidence": "low", "method": "profile subdomain"}
        return None

    async def _bandcamp(self, username: str, http: HttpClient):
        found, body = await _check(http,
            f"https://{username}.bandcamp.com",
            body_must_contain=username.lower(),
            body_must_not_contain="signup",
            no_retry=True)
        if found and isinstance(body, str):
            bl = body.lower()
            if "band name" in bl or "album" in bl or "track" in bl:
                return {"platform": "Bandcamp", "username": username,
                        "url": f"https://{username}.bandcamp.com",
                        "confidence": "medium", "method": "subdomain check"}
        return None

    # ── Page-based ───────────────────────────────────────────────

    async def _snapchat(self, username: str, http: HttpClient):
        found, body = await _check(http,
            f"https://www.snapchat.com/add/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="not found")
        if found and isinstance(body, str):
            if "snapcode" in body.lower():
                return {"platform": "Snapchat", "username": username,
                        "url": f"https://www.snapchat.com/add/{username}",
                        "confidence": "low", "method": "add page"}
        return None

    async def _telegram(self, username: str, http: HttpClient):
        found, body = await _check(http,
            f"https://t.me/{username}",
            body_must_contain="tgme_page_title",
            body_must_not_contain="can preview")
        if found:
            return {"platform": "Telegram", "username": username,
                    "url": f"https://t.me/{username}",
                    "confidence": "low", "method": "t.me page"}
        return None

    async def _vk(self, username: str, http: HttpClient):
        found, _ = await _check(http,
            f"https://vk.com/{username}",
            body_must_contain=username.lower(),
            body_must_not_contain="page not found")
        if found:
            return {"platform": "VK", "username": username,
                    "url": f"https://vk.com/{username}",
                    "confidence": "low", "method": "profile page"}
        return None
