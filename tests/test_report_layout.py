import re
import unittest

from lib.reports import apply_report_layout_overrides, generate_html_report


def _minimal_payload() -> dict:
    return {
        "target_url": "https://example.com",
        "scan_mode": "wordpress",
        "scan_started_at": "2026-08-26T09:00:00+08:00",
        "scan_duration_seconds": 12,
        "include_manual_assessment": False,
        "findings": [],
        "summary": {
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "executive_summary": ["Automated assessment summary."],
            "overall_risk": "high",
        },
        "overview": {
            "requested_profile": "wordpress",
            "effective_profile": "wordpress",
            "fingerprint": {},
            "discovery": {},
            "tool_runs": [],
        },
    }


def _style_blocks(html: str) -> tuple[str, str]:
    match = re.search(r"<style>(.*?)</style>", html, re.S)
    style = match.group(1) if match else ""
    screen, _, print_css = style.partition("@media print")
    return screen, print_css


class ReportLayoutTest(unittest.TestCase):
    def setUp(self):
        self.html = generate_html_report(_minimal_payload())
        self.screen_css, self.print_css = _style_blocks(self.html)

    def test_on_screen_report_is_centered_and_readable_width(self):
        self.assertIn("align-items: center", self.screen_css)
        self.assertRegex(self.screen_css, r"max-width:\s*960px")
        self.assertNotIn("max-width: 210mm", self.screen_css)
        self.assertNotIn("width: min(210mm", self.screen_css)

    def test_print_uses_a4_without_forcing_210mm_document_width(self):
        self.assertIn("size: A4", self.print_css)
        self.assertNotRegex(self.print_css, r"html,\s*body\s*\{[^}]*width:\s*210mm")
        self.assertIn("width: auto !important", self.print_css)

    def test_print_stacks_priority_findings_and_hides_wide_index(self):
        self.assertIn("priority-table", self.html)
        self.assertIn("findings-index-card", self.html)
        self.assertIn("table.priority-table tr", self.print_css)
        self.assertIn(".findings-index-card", self.print_css)

    def test_print_action_expands_paginated_content(self):
        self.assertIn("Print / Save as PDF", self.html)
        self.assertIn("beforeprint", self.html)
        self.assertIn("afterprint", self.html)

    def test_legacy_html_gets_centered_a4_overrides(self):
        legacy = """<!DOCTYPE html><html><head><style>
        .wrap { width: min(210mm, 100%); max-width: 210mm; margin: 24px auto; }
        @media print { html, body { width: 210mm; } }
        </style></head><body><div class="wrap">Legacy report</div></body></html>"""
        patched = apply_report_layout_overrides(legacy)
        self.assertIn("data-report-layout-fix", patched)
        self.assertIn("align-items: center !important", patched)
        self.assertIn("Print / Save as PDF", patched)
        self.assertIn("beforeprint", patched)
        self.assertIn("size: A4", patched)

    def test_current_html_is_not_double_patched(self):
        patched = apply_report_layout_overrides(self.html)
        self.assertEqual(patched, self.html)


if __name__ == "__main__":
    unittest.main()
