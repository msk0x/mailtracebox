"""JSON report generator."""

from __future__ import annotations

import json

from mailtracebox.config.schema import ReportsConfig
from mailtracebox.core.context import Context
from mailtracebox.reports.base import BaseReporter


class JsonReporter(BaseReporter):
    @property
    def format_name(self) -> str:
        return "json"

    @property
    def file_extension(self) -> str:
        return ".json"

    def generate(self, context: Context, config: ReportsConfig) -> str:
        data = {
            "report": {
                "title": "Email Intelligence Report", "target": context.target,
                "scan_id": context.scan_id, "started_at": context.started_at.isoformat(),
                "completed_at": context.completed_at.isoformat() if context.completed_at else None,
                "duration_seconds": context.duration,
            },
            "summary": {"target_email": context.target_email, "target_domain": context.target_domain},
        }
        if config.include_statistics:
            data["statistics"] = {"plugin_results": len(context._plugin_results)}
        if config.include_errors:
            data["errors"] = [e.model_dump() for e in context._errors]
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)
