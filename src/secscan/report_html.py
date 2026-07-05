"""Build the HTML (and plain-text) security report for email delivery.

Pure functions, no I/O. The HTML is a full standalone document with all styling
inline on the elements themselves, because most email clients (Gmail, Outlook)
strip or ignore <head> CSS. Every user-supplied string goes through html.escape —
finding titles/descriptions come from reviewed repositories and are untrusted.
"""

from __future__ import annotations

import html
from typing import Iterable

from .state import RepoRecord

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SEVERITY_COLORS = {
    "critical": "#b71c1c",
    "high": "#e65100",
    "medium": "#f9a825",
    "low": "#2e7d32",
    "info": "#546e7a",
}

_DESCRIPTION_MAX = 500

# Shared inline styles (email clients need styles on the elements).
_BODY = "font-family:Arial,Helvetica,sans-serif;color:#212121;margin:0;padding:24px;background-color:#f5f5f5;"
_CARD = "max-width:880px;margin:0 auto;background-color:#ffffff;border:1px solid #e0e0e0;border-radius:6px;padding:24px;"
_H1 = "font-size:20px;margin:0 0 4px 0;color:#212121;"
_MUTED = "color:#757575;font-size:12px;margin:0 0 16px 0;"
_H2 = "font-size:16px;margin:24px 0 8px 0;color:#212121;"
_TABLE = "border-collapse:collapse;width:100%;font-size:13px;"
_TH = "text-align:left;padding:6px 10px;border-bottom:2px solid #bdbdbd;background-color:#fafafa;white-space:nowrap;"
_TD = "padding:6px 10px;border-bottom:1px solid #eeeeee;vertical-align:top;"


def severity_sort_key(row: dict) -> tuple:
    """Critical first, then high/medium/low/info; ties broken by repo name."""
    return (
        _SEVERITY_ORDER.get(str(row.get("severity", "")).lower(), 99),
        str(row.get("repo_full_name", "")),
        str(row.get("title", "")),
    )


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _severity_badge(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity.lower(), "#546e7a")
    style = (
        f"display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;"
        f"font-weight:bold;color:#ffffff;background-color:{color};text-transform:uppercase;"
    )
    return f'<span style="{style}">{_e(severity)}</span>'


def _truncate(text: str, limit: int = _DESCRIPTION_MAX) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _totals(records: Iterable[RepoRecord]) -> dict:
    records = list(records)
    return {
        "repos": len(records),
        "critical": sum(r.critical_count for r in records),
        "high": sum(r.high_count for r in records),
        "cost": sum(r.cost_usd for r in records),
        "failed": sum(1 for r in records if r.status.value == "failed"),
    }


def default_subject(records: list[RepoRecord]) -> str:
    t = _totals(records)
    return (
        f"secscan report: {t['critical']} critical, {t['high']} high "
        f"across {t['repos']} repos"
    )


def build_report_html(
    records: list[RepoRecord],
    findings: list[dict],
    generated_at: str,
    title: str = "secscan security report",
) -> str:
    """Render the full HTML report: summary table + top findings."""
    t = _totals(records)

    summary_rows = []
    for r in records:
        crit_style = _TD + ("color:#b71c1c;font-weight:bold;" if r.critical_count else "")
        high_style = _TD + ("color:#e65100;font-weight:bold;" if r.high_count else "")
        summary_rows.append(
            "<tr>"
            f'<td style="{_TD}">{_e(r.full_name)}</td>'
            f'<td style="{_TD}">{_e(r.status.value)}</td>'
            f'<td style="{crit_style}">{r.critical_count}</td>'
            f'<td style="{high_style}">{r.high_count}</td>'
            f'<td style="{_TD}">{r.total_findings}</td>'
            f'<td style="{_TD}">${r.cost_usd:.3f}</td>'
            f'<td style="{_TD}">{_e(r.reviewed_at)}</td>'
            "</tr>"
        )

    finding_blocks = []
    for f in findings:
        location = _e(f.get("file_path", ""))
        if f.get("line_range"):
            location += f":{_e(f['line_range'])}"
        meta_bits = [b for b in (_e(f.get("repo_full_name", "")), location, _e(f.get("category", ""))) if b]
        finding_blocks.append(
            f'<div style="border:1px solid #e0e0e0;border-left:4px solid '
            f'{_SEVERITY_COLORS.get(str(f.get("severity", "")).lower(), "#546e7a")};'
            f'border-radius:4px;padding:10px 14px;margin:0 0 10px 0;">'
            f'<p style="margin:0 0 4px 0;font-size:14px;">'
            f'{_severity_badge(str(f.get("severity", "")))} '
            f'<strong>{_e(f.get("title", ""))}</strong></p>'
            f'<p style="margin:0 0 6px 0;color:#757575;font-size:12px;">{" · ".join(meta_bits)}</p>'
            f'<p style="margin:0;font-size:13px;">{_e(_truncate(f.get("description", "")))}</p>'
            + (
                f'<p style="margin:6px 0 0 0;font-size:13px;"><strong>Recommendation:</strong> '
                f'{_e(_truncate(f.get("recommendation", "")))}</p>'
                if f.get("recommendation")
                else ""
            )
            + "</div>"
        )

    findings_section = (
        "\n".join(finding_blocks)
        if finding_blocks
        else '<p style="font-size:13px;color:#757575;">No high or critical findings stored.</p>'
    )

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{_e(title)}</title></head>
<body style="{_BODY}">
<div style="{_CARD}">
<h1 style="{_H1}">{_e(title)}</h1>
<p style="{_MUTED}">Generated {_e(generated_at)} ·
{t["repos"]} repos · {t["critical"]} critical · {t["high"]} high ·
{t["failed"]} failed · total review cost ${t["cost"]:.3f}</p>
<h2 style="{_H2}">Repository summary</h2>
<table style="{_TABLE}">
<tr>
<th style="{_TH}">Repository</th><th style="{_TH}">Status</th>
<th style="{_TH}">Critical</th><th style="{_TH}">High</th>
<th style="{_TH}">Total</th><th style="{_TH}">Cost</th>
<th style="{_TH}">Reviewed at</th>
</tr>
{"".join(summary_rows)}
</table>
<h2 style="{_H2}">Findings</h2>
{findings_section}
<p style="{_MUTED}">Sent by secscan — autonomous Claude Code security reviews.</p>
</div>
</body>
</html>
"""


def build_report_text(
    records: list[RepoRecord], findings: list[dict], generated_at: str
) -> str:
    """Plain-text alternative for clients that do not render HTML."""
    t = _totals(records)
    lines = [
        "secscan security report",
        f"Generated {generated_at}",
        f"{t['repos']} repos | {t['critical']} critical | {t['high']} high | "
        f"{t['failed']} failed | total cost ${t['cost']:.3f}",
        "",
        "Repository summary:",
    ]
    for r in records:
        lines.append(
            f"  {r.full_name}: {r.status.value}, {r.critical_count} critical, "
            f"{r.high_count} high, {r.total_findings} total (${r.cost_usd:.3f})"
        )
    lines += ["", "Findings:"]
    if not findings:
        lines.append("  (no high or critical findings stored)")
    for f in findings:
        location = f.get("file_path", "")
        if f.get("line_range"):
            location += f":{f['line_range']}"
        lines.append(
            f"  [{str(f.get('severity', '')).upper()}] {f.get('title', '')} — "
            f"{f.get('repo_full_name', '')} {location}".rstrip()
        )
        if f.get("description"):
            lines.append(f"      {_truncate(f['description'], 300)}")
    return "\n".join(lines) + "\n"
