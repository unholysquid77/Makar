"""Suspicious-activity reporting.

The problem statement asks for a readable report covering totals by tampering
type, a ranked list of suspicious records *with the evidence behind each
flag*, affected owners and locations, and a suspected attack timeline. That is
a deliverable in its own right, separate from the dashboard, so it is rendered
here as Markdown and JSON that can be committed, diffed and handed to someone
who will never run the UI.
"""

from reporting.report import build_report_payload, render_markdown

__all__ = ["build_report_payload", "render_markdown"]
