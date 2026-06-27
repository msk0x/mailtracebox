"""CSV report generator."""

from __future__ import annotations

import csv
import io

from mailtracebox.config.schema import ReportsConfig
from mailtracebox.core.context import Context
from mailtracebox.reports.base import BaseReporter
from mailtracebox.reports.markdown_report import _sync_list


class CsvReporter(BaseReporter):
    @property
    def format_name(self) -> str:
        return "csv"

    @property
    def file_extension(self) -> str:
        return ".csv"

    def generate(self, context: Context, config: ReportsConfig) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["# Email Intelligence Report"])
        writer.writerow(["# Target", context.target])
        writer.writerow(["# Scan ID", context.scan_id])
        writer.writerow([])

        emails = _sync_list(context.emails)
        if emails:
            writer.writerow(["## Emails"])
            writer.writerow(["address", "local_part", "domain", "source", "confidence", "is_disposable", "is_role_account"])
            for e in emails:
                writer.writerow([e.address, e.local_part, e.domain, e.source, f"{e.confidence:.2f}", e.is_disposable, e.is_role_account])
            writer.writerow([])

        domains = _sync_list(context.domains)
        if domains:
            writer.writerow(["## Domains"])
            writer.writerow(["domain", "registrar", "a_records", "mx_count", "spf", "dmarc"])
            for d in domains:
                writer.writerow([d.domain, d.registrar or "", ";".join(d.a_records), len(d.mx_records), d.spf_record or "", d.dmarc_record or ""])
            writer.writerow([])

        plugin_results = list(context._plugin_results.values())
        if plugin_results:
            writer.writerow(["## Plugin Results"])
            writer.writerow(["plugin", "status", "duration_s", "items_found", "errors"])
            for pr in plugin_results:
                writer.writerow([pr.plugin_name, pr.status.value, f"{pr.duration_seconds:.2f}" if pr.duration_seconds else "", pr.items_found, "; ".join(pr.errors)])

        return output.getvalue()
