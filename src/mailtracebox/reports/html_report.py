"""HTML report generator with an embedded Jinja2 template."""

from __future__ import annotations

from mailtracebox.config.schema import ReportsConfig
from mailtracebox.core.context import Context
from mailtracebox.reports.base import BaseReporter
from mailtracebox.reports.markdown_report import _sync_list

try:
    from jinja2 import Environment, BaseLoader
except ImportError:
    Environment = None  # type: ignore[assignment,misc]
    BaseLoader = None  # type: ignore[assignment,misc]


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Email Intelligence Report</title>
<style>
:root{--bg:#0c0c14;--surface:#15151f;--border:#23233a;--text:#e0e0e6;--muted:#6e6e8a;--accent:#6c8aff;--success:#4ade80;--warn:#fbbf24;--danger:#f87171}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem;max-width:1100px;margin:0 auto}
h1{font-size:2rem;font-weight:700;margin-bottom:.25rem}
h2{font-size:1.35rem;font-weight:600;margin:2rem 0 .75rem;color:var(--accent)}
.meta{color:var(--muted);font-size:.875rem;margin-bottom:2rem}
.meta span+span{margin-left:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:1.25rem;margin-bottom:1rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:.6rem .8rem;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:999px;font-size:.75rem;font-weight:600}
.badge-ok{background:rgba(74,222,128,.15);color:var(--success)}
.badge-fail{background:rgba(248,113,113,.15);color:var(--danger)}
.badge-warn{background:rgba(251,191,36,.15);color:var(--warn)}
code{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.85em;background:var(--surface);padding:.15em .35em;border-radius:.25rem}
.footer{margin-top:3rem;color:var(--muted);font-size:.8rem;text-align:center;border-top:1px solid var(--border);padding-top:1rem}
a{color:var(--accent);text-decoration:none}
</style></head><body>
<h1>Email Intelligence Report</h1>
<div class="meta"><span>Target: <strong>{{ target }}</strong></span>
<span>Scan: <code>{{ scan_id }}</code></span>
<span>Duration: {{ "%.1f"|format(duration) }}s</span></div>

{% if emails %}<h2>Email Addresses</h2><div class="card"><table>
<tr><th>Address</th><th>Source</th><th>Confidence</th><th>Flags</th></tr>
{% for e in emails %}<tr><td><code>{{ e.address }}</code></td><td>{{ e.source or '—' }}</td>
<td>{{ "%.0f"|format(e.confidence*100) }}%</td>
<td>{% if e.is_disposable %}<span class="badge badge-fail">disposable</span>{% endif %}
{% if e.is_role_account %}<span class="badge badge-warn">role</span>{% endif %}</td></tr>{% endfor %}
</table></div>{% endif %}

{% if domains %}<h2>Domains</h2>{% for d in domains %}<div class="card"><h3>{{ d.domain }}</h3>
{% if d.registrar %}<p>Registrar: {{ d.registrar }}</p>{% endif %}
{% if d.a_records %}<p>A: {{ d.a_records|join(', ') }}</p>{% endif %}
{% if d.spf_record %}<p>SPF: <code>{{ d.spf_record }}</code></p>{% endif %}
{% if d.dmarc_record %}<p>DMARC: <code>{{ d.dmarc_record }}</code></p>{% endif %}
{% if d.mx_records %}<table><tr><th>Priority</th><th>Host</th></tr>
{% for mx in d.mx_records %}<tr><td>{{ mx.priority }}</td><td><code>{{ mx.host }}</code></td></tr>
{% endfor %}</table>{% endif %}</div>{% endfor %}{% endif %}

{% if social_profiles %}<h2>Social Profiles</h2><div class="card"><table>
<tr><th>Platform</th><th>Username</th><th>URL</th></tr>
{% for p in social_profiles %}<tr><td>{{ p.platform }}</td><td><code>{{ p.username }}</code></td>
<td><a href="{{ p.url }}">{{ p.url }}</a></td></tr>{% endfor %}</table></div>{% endif %}

{% if breaches %}<h2>Data Breaches</h2><div class="card"><table>
<tr><th>Name</th><th>Date</th><th>Records</th><th>Verified</th></tr>
{% for b in breaches %}<tr><td>{{ b.name }}</td>
<td>{{ b.breach_date.strftime('%Y-%m-%d') if b.breach_date else '—' }}</td>
<td>{{ "{:,}".format(b.pwn_count) if b.pwn_count else '—' }}</td>
<td>{% if b.is_verified %}<span class="badge badge-ok">Yes</span>{% else %}<span class="badge badge-warn">No</span>{% endif %}</td></tr>
{% endfor %}</table></div>{% endif %}

{% if plugin_results %}<h2>Plugin Execution</h2><div class="card"><table>
<tr><th>Plugin</th><th>Status</th><th>Duration</th><th>Items</th></tr>
{% for pr in plugin_results %}<tr><td>{{ pr.plugin_name }}</td>
<td>{% if pr.status.value=='completed' %}<span class="badge badge-ok">{{ pr.status.value }}</span>
{% elif pr.status.value=='failed' %}<span class="badge badge-fail">{{ pr.status.value }}</span>
{% else %}<span class="badge badge-warn">{{ pr.status.value }}</span>{% endif %}</td>
<td>{{ "%.2f"|format(pr.duration_seconds) if pr.duration_seconds else '—' }}s</td>
<td>{{ pr.items_found }}</td></tr>{% endfor %}</table></div>{% endif %}

{% if errors %}<h2>Errors</h2><div class="card"><ul>{% for e in errors %}<li>{{ e }}</li>{% endfor %}</ul></div>{% endif %}
<div class="footer">Generated by <strong>mailtracebox</strong></div></body></html>"""


class HtmlReporter(BaseReporter):
    @property
    def format_name(self) -> str:
        return "html"

    @property
    def file_extension(self) -> str:
        return ".html"

    def generate(self, context: Context, config: ReportsConfig) -> str:
        if Environment is None:
            raise ImportError("jinja2 is required for HTML reports.")
        env = Environment(loader=BaseLoader(), autoescape=True)
        template = env.from_string(_HTML_TEMPLATE)
        return template.render(
            target=context.target, scan_id=context.scan_id,
            started=context.started_at.isoformat(),
            completed=context.completed_at.isoformat() if context.completed_at else "—",
            duration=context.duration or 0,
            emails=_sync_list(context.emails), domains=_sync_list(context.domains),
            social_profiles=_sync_list(context.social_profiles),
            breaches=_sync_list(context.breaches),
            plugin_results=list(context._plugin_results.values()),
            errors=[e.message for e in context._errors] if config.include_errors else [],
        )
