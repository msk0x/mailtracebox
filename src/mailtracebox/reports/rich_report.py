"""Rich terminal report renderer using the Rich library.

Produces a clean, structured terminal output with panels, tables,
and trees for all intelligence collected during a scan.
"""

from __future__ import annotations

import textwrap
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger

logger = get_logger("reports.rich")


def _sync_list(collection: Any) -> list:
    """Extract items from an EntityCollection."""
    if hasattr(collection, "_items"):
        return list(collection._items.values())
    return []


class RichReporter:
    """Render scan results as a Rich terminal report.

    Parameters
    ----------
    console:
        Rich Console instance for output.
    """

    def __init__(self, console: Console) -> None:
        self._console = console

    def display(self, context: Context, report_config: Any = None) -> None:
        """Render the full report.

        Parameters
        ----------
        context:
            Scan context with all collected intelligence.
        report_config:
            Report configuration from the app config.
        """
        console = self._console

        # ── Header ───────────────────────────────────────────────────
        duration = context.duration
        duration_str = f"{duration:.1f}s" if duration is not None else "N/A"

        console.print()
        console.print(
            Panel(
                f"[bold]Target:[/bold]  {context.target}\n"
                f"[bold]Scan ID:[/bold] {context.scan_id}\n"
                f"[bold]Duration:[/bold] {duration_str}",
                title="[bold cyan]Email Intelligence Report[/bold cyan]",
                border_style="cyan",
            )
        )

        # ── Email addresses ──────────────────────────────────────────
        emails = _sync_list(context.emails)
        if emails:
            table = Table(title="Email Addresses", show_lines=True)
            table.add_column("Address", style="green")
            table.add_column("Source")
            table.add_column("Confidence", justify="right")
            table.add_column("Flags")
            for e in emails:
                flags = ", ".join(f for f in ("disposable" if e.is_disposable else "", "role" if e.is_role_account else "") if f) or "—"
                table.add_row(e.address, e.source, f"{e.confidence:.0%}", flags)
            console.print(table)

        # ── DNS ──────────────────────────────────────────────────────
        dns_data = context._custom.get("dns_records")
        if dns_data:
            tree = Tree(f"[bold]{dns_data.get('domain', 'Domain')}[/bold]")
            for a in dns_data.get("a_records", []):
                tree.add(f"A: {a}")
            aaaa = dns_data.get("aaaa_records")
            if aaaa:
                for a in aaaa:
                    tree.add(f"AAAA: {a}")
            mx_branch = tree.add("MX Records")
            for mx in dns_data.get("mx_records", []):
                mx_branch.add(f"{mx['host']} (priority {mx['priority']})")
            spf = dns_data.get("spf")
            if spf:
                tree.add(f"SPF: {spf}")
            dmarc = dns_data.get("dmarc")
            if dmarc:
                tree.add(f"DMARC: {dmarc}")
            console.print(Panel(tree, border_style="cyan"))

        # ── TLS Certificates ─────────────────────────────────────────
        certs = _sync_list(context.certificates)
        if certs:
            table = Table(title="TLS Certificates", show_lines=True)
            table.add_column("Subject", style="cyan")
            table.add_column("Issuer")
            table.add_column("Valid From")
            table.add_column("Valid Until")
            table.add_column("SANs")
            for c in certs:
                sans = ", ".join(c.sans[:5]) if c.sans else "—"
                if c.sans and len(c.sans) > 5:
                    sans += f" (+{len(c.sans) - 5} more)"
                valid_from = c.not_before.strftime("%Y-%m-%d") if c.not_before else "—"
                valid_until = c.not_after.strftime("%Y-%m-%d") if c.not_after else "—"
                table.add_row(c.subject, c.issuer[:60], valid_from, valid_until, sans)
            console.print(table)

        # ── Breaches ─────────────────────────────────────────────────
        breaches = _sync_list(context.breaches)
        if breaches:
            # Risk summary
            risk_score = context._custom.get("breach_risk_score", "")
            risk_label = context._custom.get("breach_risk_label", "")
            if risk_score:
                console.print(
                    Panel(
                        f"[bold red]Risk Score: {risk_score}[/bold red]  |  "
                        f"[bold yellow]Risk Level: {risk_label}[/bold yellow]  |  "
                        f"[bold]Breaches Found: {len(breaches)}[/bold]",
                        title="[bold red]Breach Intelligence[/bold red]",
                        border_style="red",
                    )
                )

            for b in breaches:
                date_str = b.breach_date.strftime("%Y-%m-%d") if b.breach_date else "Unknown"
                count = f"{b.pwn_count:,}" if b.pwn_count else "Unknown"
                verified = (
                    "[green]Verified[/green]" if b.is_verified else "[dim]Unverified[/dim]"
                )

                tree = Tree(f"[bold red]{b.name}[/bold red] — {date_str}")
                tree.add(f"Records Exposed: [bold]{count}[/bold]")
                tree.add(f"Status: {verified}")
                if b.domain:
                    tree.add(f"Domain: {b.domain}")

                # Description — word-wrap cleanly
                if b.description:
                    desc = b.description.strip()
                    if len(desc) > 300:
                        desc = desc[:300] + "..."
                    wrapped = textwrap.fill(desc, width=88)
                    for line in wrapped.split("\n"):
                        tree.add(f"[dim]{line}[/dim]")

                # Data classes — split into individual items
                if b.data_classes:
                    all_types: list[str] = []
                    for dc in b.data_classes:
                        for item in dc.replace(";", ",").split(","):
                            item = item.strip()
                            if item:
                                all_types.append(item)
                    dc_branch = tree.add(
                        f"[bold]Data Compromised ({len(all_types)} types)[/bold]"
                    )
                    for dc in all_types:
                        dc_branch.add(f"[red]{dc}[/red]")

                # Metadata
                if b.metadata:
                    m = b.metadata
                    if m.get("industry"):
                        tree.add(f"Industry: {m['industry']}")
                    if m.get("password_risk"):
                        pr = str(m["password_risk"]).strip().lower()
                        if "plain" in pr:
                            color = "red"
                            label = "PLAINTEXT — passwords stored without hashing"
                        elif "easy" in pr:
                            color = "red"
                            label = "Easily Crackable — weak hashing used"
                        elif "strong" in pr:
                            color = "green"
                            label = "Strong Hash — passwords properly hashed"
                        else:
                            color = "yellow"
                            label = str(m["password_risk"]).strip()
                        tree.add(f"Password Risk: [{color}]{label}[/{color}]")

                console.print(Panel(tree, border_style="red", padding=(0, 2)))
            console.print()

        # ── Social Profiles ──────────────────────────────────────────
        profiles = _sync_list(context.social_profiles)
        if profiles:
            table = Table(title="Social Profiles", show_lines=True)
            table.add_column("Platform", style="magenta")
            table.add_column("Username")
            table.add_column("URL", style="blue")
            table.add_column("Extra")
            for p in profiles:
                extra_parts = []
                if p.display_name:
                    extra_parts.append(p.display_name)
                if p.followers is not None:
                    extra_parts.append(f"{p.followers} followers")
                extra = " | ".join(extra_parts) if extra_parts else ""
                table.add_row(p.platform, p.username, p.url, extra)
            console.print(table)

        # ── Mail Servers ─────────────────────────────────────────────
        mx_info = context._custom.get("mx_ip_info")
        if mx_info and isinstance(mx_info, list):
            table = Table(title="Mail Servers", show_lines=True)
            table.add_column("Host", style="cyan")
            table.add_column("IP")
            table.add_column("Location")
            table.add_column("Org")
            for mx in mx_info:
                table.add_row(
                    mx.get("host", ""),
                    mx.get("ip", ""),
                    mx.get("location", ""),
                    mx.get("org", ""),
                )
            console.print(table)

        # ── Custom plugin findings ───────────────────────────────────
        custom = context._custom
        if custom:
            _already_shown = {
                "dns_records", "mx_ip_info", "crtsh_subdomains",
                "breach_risk_score", "breach_risk_label",
                "smtp_verify_result", "smtp_verify_catch_all", "smtp_verify_note","account_discovery",
            }
            grouped: dict[str, dict[str, object]] = {}
            for key, value in custom.items():
                if key in _already_shown:
                    continue
                parts = key.split("_", 1)
                prefix = parts[0] if len(parts) == 2 else "misc"
                rest = parts[1] if len(parts) == 2 else key
                grouped.setdefault(prefix, {})[rest] = value

            for prefix, items in grouped.items():
                if not items:
                    continue
                tree = Tree(f"[bold]{prefix.replace('_', ' ').title()}[/bold]")
                for label, value in items.items():
                    display_label = label.replace("_", " ").title()
                    if isinstance(value, list):
                        branch = tree.add(f"{display_label} ({len(value)})")
                        for item in value[:15]:
                            branch.add(str(item))
                        if len(value) > 15:
                            branch.add(f"[dim]... +{len(value) - 15} more[/dim]")
                    elif isinstance(value, dict):
                        branch = tree.add(display_label)
                        for k, v in value.items():
                            branch.add(f"{k}: {v}")
                    else:
                        tree.add(f"{display_label}: {value}")
                console.print(Panel(tree, border_style="yellow"))
            console.print()

                # ── Plugin Execution ─────────────────────────────────────────
        results = list(context._plugin_results.values())
        if results:
            table = Table(title="Plugin Execution", show_lines=True)
            table.add_column("Plugin", style="bold")
            table.add_column("Status")
            table.add_column("Duration", justify="right")
            table.add_column("Items", justify="right")
            table.add_column("Errors")
            for r in results:
                status = r.status.value if hasattr(r.status, "value") else str(r.status)
                if status == "completed":
                    status_display = f"[green]{status}[/green]"
                elif status == "failed":
                    status_display = f"[red]{status}[/red]"
                elif status == "timeout":
                    status_display = f"[yellow]{status}[/yellow]"
                elif status == "skipped":
                    status_display = f"[dim]{status}[/dim]"
                else:
                    status_display = status
                # Use duration_seconds — the actual field name on PluginResult
                dur = r.duration_seconds
                duration = f"{dur:.2f}s" if dur else "—"
                errors = "; ".join(r.errors[:3]) if r.errors else "—"
                table.add_row(
                    r.plugin_name, status_display, duration, str(r.items_found), errors,
                )
            console.print(table)


                # ── Account Discovery ────────────────────────────────────────
        accounts = context._custom.get("account_discovery", [])
        if accounts and isinstance(accounts, list):
            # Group by category
            by_category: dict[str, list[dict[str, str]]] = {}
            for acct in accounts:
                cat = acct.get("category", "Other")
                by_category.setdefault(cat, []).append(acct)

            # Category order and icons
            cat_order = [
                "Development", "Professional", "Social", "Creative",
                "Music", "Video", "Gaming", "Messaging",
                "Writing", "Finance", "Other",
            ]

            console.print(f"[bold]Account Discovery[/bold] — "
                          f"{len(accounts)} accounts found across "
                          f"{len(by_category)} categories")
            console.print()

            for cat in cat_order:
                cat_accounts = by_category.get(cat, [])
                if not cat_accounts:
                    continue

                table = Table(title=f"{cat}", show_lines=True, border_style="green")
                table.add_column("Platform", style="green", min_width=15)
                table.add_column("Username", min_width=15)
                table.add_column("URL", style="blue")
                table.add_column("Confidence", justify="center", min_width=10)
                table.add_column("Method", style="dim")

                for acct in cat_accounts:
                    conf = acct.get("confidence", "")
                    if conf == "high":
                        conf_display = "[green]HIGH[/green]"
                    elif conf == "medium":
                        conf_display = "[yellow]MED[/yellow]"
                    else:
                        conf_display = "[dim]LOW[/dim]"
                    table.add_row(
                        acct.get("platform", ""),
                        acct.get("username", ""),
                        acct.get("url", ""),
                        conf_display,
                        acct.get("method", ""),
                    )
                console.print(table)
                console.print()

        # ── Footer ───────────────────────────────────────────────────
        console.print()
        console.print("[dim]Generated by mailtracebox[/dim]")
        console.print()
