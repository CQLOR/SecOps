try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with: python3 -m pip install requests")
    raise SystemExit
    # No-op placeholder to satisfy tool format

from datetime import datetime
from requests.exceptions import RequestException
from enum import Enum
import json
import html as html_escape
from collections import defaultdict
import csv

# Your Mockaroo API endpoint
API_URL = "https://my.api.mockaroo.com/ironclad/cmdb.json"

# API key (from your curl headers)
API_KEY = "cf7bbbd0"


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CaseStatus(Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Artifact:
    def __init__(self, raw: dict):
        self.raw = raw
        # Map real CMDB fields into artifact attributes
        self.asset_id = raw.get("asset_id")
        self.hostname = raw.get("hostname")
        # Use hostname as the case identifier, fallback to asset_id
        if self.hostname:
            self.case_id = str(self.hostname)
        elif self.asset_id is not None:
            self.case_id = f"asset-{self.asset_id}"
        else:
            self.case_id = "UNKNOWN_CASE"

        # Represent the primary type/value for the artifact
        self.artifact_type = raw.get("asset_type", raw.get("type", "asset"))
        self.value = self.hostname or (str(self.asset_id) if self.asset_id is not None else raw.get("value", ""))

        # Populate extra metadata used for severity decisions
        self.criticality = (raw.get("criticality") or "").lower()
        self.internet_exposed = bool(raw.get("internet_exposed"))

        # Build a short note from common CMDB fields
        notes = []
        if raw.get("os"):
            notes.append(raw.get("os"))
        if raw.get("environment"):
            notes.append(raw.get("environment"))
        if raw.get("owner_team"):
            notes.append(raw.get("owner_team"))
        self.note = ", ".join(notes)

        # allow overriding artifact_type/value when creating derived artifacts
        if raw.get("_derived_type"):
            self.artifact_type = raw.get("_derived_type")
        if raw.get("_derived_value"):
            self.value = raw.get("_derived_value")

    def is_internal_ip(self) -> bool:
        if self.artifact_type != "ip":
            return False
        return self.value.startswith(("10.", "192.168."))

    def __str__(self) -> str:
        extra = f" ({self.note})" if self.note else ""
        return f"{self.artifact_type}:{self.value}{extra}"


import re


def _looks_like_hash(s: str) -> bool:
    if not isinstance(s, str):
        return False
    s = s.strip().lower()
    return bool(re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", s))


def _looks_like_domain(s: str) -> bool:
    if not isinstance(s, str):
        return False
    s = s.strip()
    # avoid pure IPs
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", s):
        return False
    # simple domain pattern
    return bool(re.search(r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", s))


def extract_artifacts_from_record(record: dict) -> list:
    """Return a list of Artifact objects derived from a single record.
    Includes the primary asset artifact plus any detected domain/hash artifacts found
    in string fields of the record.
    """
    artifacts = []
    # primary
    primary = Artifact(record)
    artifacts.append(primary)

    # scan values for domains/hashes
    for k, v in record.items():
        if isinstance(v, str):
            if _looks_like_hash(v):
                derived = dict(asset_id=record.get("asset_id"), hostname=record.get("hostname"))
                derived["_derived_type"] = "file_hash"
                derived["_derived_value"] = v.strip()
                derived["_derived_note"] = f"found_in:{k}"
                a = Artifact(derived)
                # put note in a.note
                a.note = derived.get("_derived_note")
                artifacts.append(a)
            elif _looks_like_domain(v):
                derived = dict(asset_id=record.get("asset_id"), hostname=record.get("hostname"))
                derived["_derived_type"] = "domain"
                derived["_derived_value"] = v.strip()
                derived["_derived_note"] = f"found_in:{k}"
                a = Artifact(derived)
                a.note = derived.get("_derived_note")
                artifacts.append(a)

    return artifacts


class Case:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.status = CaseStatus.NEW
        self.severity = Severity.LOW
        self.artifacts: list[Artifact] = []
        self.notes: list[str] = []

    def add_artifact(self, artifact: Artifact):
        self.artifacts.append(artifact)
        self.recalculate_severity()

    def add_note(self, note: str):
        self.notes.append(note)

    def recalculate_severity(self):
        # HIGH if explicit hash present
        has_hash = any(a.artifact_type in ["file_hash", "hash", "sha256"] or _looks_like_hash(a.value) for a in self.artifacts)
        if has_hash:
            self.severity = Severity.HIGH
            return

        # HIGH if any artifact carries a high criticality flag
        has_high_criticality = any(getattr(a, "criticality", "") in ["high", "critical"] for a in self.artifacts)
        if has_high_criticality:
            self.severity = Severity.HIGH
            return

        # MEDIUM if internet-exposed or external IP or suspicious domain
        has_internet_exposed = any(getattr(a, "internet_exposed", False) for a in self.artifacts)
        has_external_ip = any(a.artifact_type == "ip" and not a.is_internal_ip() for a in self.artifacts)
        has_suspicious_domain = any(
            a.artifact_type == "domain" and any(word in a.value.lower() for word in ["login", "verify", "secure"]) for a in self.artifacts
        )

        if has_internet_exposed or has_external_ip or has_suspicious_domain:
            self.severity = Severity.MEDIUM
        else:
            self.severity = Severity.LOW

    def summary(self) -> str:
        return f"{self.case_id} | {self.status.value} | {self.severity.value} | artifacts={len(self.artifacts)}"

    def __str__(self) -> str:
        lines = [self.summary(), "-" * 48, "Artifacts:"]
        for a in self.artifacts:
            lines.append(f"  - {a}")
        if self.notes:
            lines.append("Notes:")
            for n in self.notes:
                lines.append(f"  * {n}")
        return "\n".join(lines)


def fetch_mockaroo(url: str, api_key: str, timeout: int = 10):
    headers = {"X-API-Key": api_key}
    params = {"key": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, params=params)
    except RequestException as e:
        print("Request error:", str(e))
        raise

    print("Status:", resp.status_code)
    if resp.status_code != 200:
        snippet = resp.text[:800]
        print("Request failed (status {}):\n".format(resp.status_code), snippet)
        raise SystemExit

    try:
        return resp.json()
    except ValueError:
        print("Failed to decode JSON. Response preview:")
        print(resp.text[:800])
        raise SystemExit


def main():
    data = fetch_mockaroo(API_URL, API_KEY)
    print("JSON type:", type(data))
    print("Records:", len(data) if isinstance(data, list) else "N/A")

    if not (isinstance(data, list) and data):
        print("Unexpected JSON structure. Expected a list of records.")
        raise SystemExit

    print("First record preview:")
    print(data[0])

    # Print fields in the first record if it's a dict
    if isinstance(data[0], dict):
        print("\nFields in record:")
        for k in data[0].keys():
            print("-", k)

    # Create a test artifact for quick inspection
    test_artifact = Artifact(data[0])
    print("\nTest artifact:")
    print(test_artifact)

    # Build cases and capture raw records per case
    cases_by_id: dict[str, Case] = {}
    records_by_case: dict[str, list] = defaultdict(list)
    for record in data:
        artifacts = extract_artifacts_from_record(record)
        # first artifact is primary
        primary = artifacts[0]
        cid = primary.case_id
        records_by_case[cid].append(record)

        if cid not in cases_by_id:
            cases_by_id[cid] = Case(cid)

        for art in artifacts:
            cases_by_id[cid].add_artifact(art)

    # Aggregate detected domains and hashes across all cases
    domains: dict[str, set] = defaultdict(set)
    hashes: dict[str, set] = defaultdict(set)
    for cid, case in cases_by_id.items():
        for a in case.artifacts:
            if a.artifact_type == "domain":
                domains[a.value].add(cid)
            if a.artifact_type in ("file_hash", "hash") or _looks_like_hash(a.value):
                hashes[a.value].add(cid)

    print("\n=== Case Summaries ===")
    for c in cases_by_id.values():
        print(c.summary())

    # Write a titled, numbered report with centered, larger title and author
    title_width = 80
    title_text = "SECOPS CASE REPORT"
    author_text = "Author: Lenny Coulter"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_cases = len(cases_by_id)

    with open("case_report.txt", "w", encoding="utf-8") as out:
        out.write("\n")
        out.write(title_text.center(title_width) + "\n")
        out.write(("=" * len(title_text)).center(title_width) + "\n")
        out.write("\n")
        out.write(author_text.center(title_width) + "\n")
        out.write(f"Generated: {generated_at}".center(title_width) + "\n")
        out.write(f"Total cases: {total_cases}".center(title_width) + "\n")
        out.write("\n" + ("=" * title_width) + "\n\n")

        # Sort cases by case_id for deterministic ordering
        # Summary of detected indicators
        out.write("SUMMARY OF DETECTED INDICATORS:\n")
        out.write("Domains:\n")
        if domains:
            for d, cids in sorted(domains.items()):
                out.write(f" - {d}: found in {len(cids)} case(s): {', '.join(sorted(cids))}\n")
        else:
            out.write(" - None\n")

        out.write("Hashes:\n")
        if hashes:
            for h, cids in sorted(hashes.items()):
                out.write(f" - {h}: found in {len(cids)} case(s): {', '.join(sorted(cids))}\n")
        else:
            out.write(" - None\n")

        out.write("\n")

        # Iterate cases with compact raw-record table per case
        for idx, (case_id, case_obj) in enumerate(sorted(cases_by_id.items()), start=1):
            out.write(f"Case {idx}: {case_id}\n")
            out.write(str(case_obj))
            out.write("\n")

            # compact table of raw records (selected fields)
            raws = records_by_case.get(case_id, [])
            if raws:
                out.write("Raw records (compact):\n")
                headers = ["asset_id", "hostname", "asset_type", "os", "environment", "owner_team", "internet_exposed", "criticality", "last_seen"]
                out.write(" | ".join(headers) + "\n")
                out.write("-" * 80 + "\n")
                for r in raws:
                    row = [str(r.get(h, "")) for h in headers]
                    out.write(" | ".join(row) + "\n")
                out.write("\n")

            out.write("\n")

    print("\nWrote titled report to case_report.txt")

    # Also export JSON and CSV structured exports
    json_out = {
        "generated": generated_at,
        "total_cases": total_cases,
        "cases": [],
        "detected_domains": {d: sorted(list(cids)) for d, cids in domains.items()},
        "detected_hashes": {h: sorted(list(cids)) for h, cids in hashes.items()},
    }

    for case_id, case_obj in sorted(cases_by_id.items()):
        json_case = {
            "case_id": case_id,
            "summary": case_obj.summary(),
            "severity": case_obj.severity.value,
            "status": case_obj.status.value,
            "artifacts": [{"type": a.artifact_type, "value": a.value, "note": a.note} for a in case_obj.artifacts],
            "raw_records": records_by_case.get(case_id, []),
        }
        json_out["cases"].append(json_case)

    with open("case_report.json", "w", encoding="utf-8") as jf:
        json.dump(json_out, jf, indent=2, ensure_ascii=False)

    # CSV: one artifact per row
    with open("case_report.csv", "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["case_id", "artifact_type", "value", "note", "severity", "status"])
        for case_id, case_obj in sorted(cases_by_id.items()):
            for a in case_obj.artifacts:
                writer.writerow([case_id, a.artifact_type, a.value, a.note, case_obj.severity.value, case_obj.status.value])

    print("Wrote structured exports: case_report.json, case_report.csv")

    # Attempt to create an email-ready PDF from the text report using ReportLab.
    try:
        from reportlab.platypus import SimpleDocTemplate, Preformatted, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.pagesizes import letter

        def write_pdf_from_text(input_txt_path: str, output_pdf_path: str):
            with open(input_txt_path, "r", encoding="utf-8") as f:
                text = f.read()

            doc = SimpleDocTemplate(output_pdf_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            style = styles.get("Code", styles.get("Normal"))
            story = []
            # Add a small spacer then the full preformatted report to preserve layout
            story.append(Spacer(1, 6))
            story.append(Preformatted(text, style))
            doc.build(story)

        write_pdf_from_text("case_report.txt", "case_report.pdf")
        print("Wrote PDF: case_report.pdf")
    except Exception as e:
        if isinstance(e, ImportError):
            print("ReportLab not installed. Install with: python3 -m pip install reportlab")
        else:
            print("PDF generation failed:", str(e))

    # Generate an HTML version (email-friendly) and try to produce a downloadable PDF
    def generate_html(json_out, output_path="case_report.html"):
        css = """
        :root { --accent: #2b6cb0; --muted: #6b7280; --bg: #ffffff; --card:#f9fafb; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; margin: 0; background: #f3f4f6; color: #111827; }
        .container { max-width: 1100px; margin: 28px auto; background: var(--bg); padding: 24px 28px; box-shadow: 0 2px 8px rgba(15,23,42,0.06); border-radius: 8px; }
        .title { text-align: center; font-size: 32px; font-weight: 700; letter-spacing: 1px; color: var(--accent); }
        .meta { text-align: center; color: var(--muted); margin-bottom: 18px; }
        .toc { margin: 18px 0 8px 0; padding: 12px; background: var(--card); border-radius: 6px; }
        .toc ul { margin: 0; padding-left: 18px; }
        .summary { margin: 18px 0; }
        .indicator-list { display:flex; gap:16px; flex-wrap:wrap; }
        .indicator { background:#fff; border:1px solid #e6e9ef; padding:8px 10px; border-radius:6px; font-size:14px; }
        .cases { margin-top: 16px; }
        .case { border:1px solid #e6e9ef; padding:14px; border-radius:8px; margin-bottom:12px; background:#fff }
        .case h3 { margin: 0 0 10px 0; display:flex; justify-content:space-between; align-items:center; gap:12px }
        .badge { padding:4px 8px; border-radius:999px; font-size:12px; color:#fff; font-weight:600 }
        .badge-low { background: #10b981 }
        .badge-medium { background: #f59e0b }
        .badge-high { background: #ef4444 }
        .artifacts ul { margin:6px 0 10px 18px }
        table { border-collapse: collapse; width: 100%; font-size:13px }
        th, td { border: 1px solid #eef2f7; padding: 8px; }
        th { background: #f8fafc; text-align:left }
        tr:nth-child(even) { background: #fbfdff }
        .artifact { font-family: monospace; color:#0f172a }
        .actions { text-align: center; margin-bottom: 20px; }
        .btn { display: inline-block; padding: 8px 16px; background: var(--accent); color: white; text-decoration: none; border-radius: 4px; margin-right: 10px; font-weight: 500; transition: background 0.2s; }
        .btn:hover { background-color: #1e4b8a; }
        @media print { .container { box-shadow:none } .case { page-break-inside: avoid } .actions { display: none; } }
        """

        def severity_badge_class(sev):
            s = (sev or '').lower()
            if s == 'high':
                return 'badge badge-high'
            if s == 'medium':
                return 'badge badge-medium'
            return 'badge badge-low'

        parts = []
        parts.append(f"<html><head><meta charset=\"utf-8\"><title>SECOPS CASE REPORT</title><style>{css}</style></head><body>")
        parts.append('<div class="container">')
        parts.append(f"<div class=\"title\">SECOPS CASE REPORT</div>")
        parts.append(f"<div class=\"meta\">Author: Lenny Coulter &nbsp;|&nbsp; Generated: {html_escape.escape(str(json_out.get('generated')))} &nbsp;|&nbsp; Total cases: {json_out.get('total_cases')} </div>")

        # Download buttons
        parts.append('<div class="actions">')
        parts.append('<a href="/download/pdf" class="btn" target="_blank">Download PDF</a>')
        parts.append('<a href="/download/json" class="btn" target="_blank">Download JSON</a>')
        parts.append('</div>')

        # TOC
        parts.append('<div class="toc"><strong>Contents</strong>')
        parts.append('<ul>')
        for case in json_out.get('cases', []):
            cid = html_escape.escape(case['case_id'])
            parts.append(f"<li><a href=\"#case-{cid}\">{cid} — {html_escape.escape(case.get('summary',''))}</a></li>")
        parts.append('</ul></div>')

        # Indicator summary
        parts.append('<div class="summary"><h2>Detected Indicators</h2>')
        parts.append('<div class="indicator-list">')
        if json_out.get('detected_domains'):
            parts.append('<div class="indicator"><strong>Domains</strong><ul>')
            for d, cids in sorted(json_out['detected_domains'].items()):
                parts.append(f"<li>{html_escape.escape(d)} — {len(cids)} case(s)</li>")
            parts.append('</ul></div>')
        if json_out.get('detected_hashes'):
            parts.append('<div class="indicator"><strong>Hashes</strong><ul>')
            for h, cids in sorted(json_out['detected_hashes'].items()):
                parts.append(f"<li>{html_escape.escape(h)} — {len(cids)} case(s)</li>")
            parts.append('</ul></div>')
        if not json_out.get('detected_domains') and not json_out.get('detected_hashes'):
            parts.append('<div class="indicator">None</div>')
        parts.append('</div></div>')

        # Cases
        parts.append('<div class="cases">')
        for case in json_out.get('cases', []):
            cid = html_escape.escape(case['case_id'])
            sev = case.get('severity', 'LOW')
            badge_cls = severity_badge_class(sev)
            parts.append(f"<div id=\"case-{cid}\" class=\"case\"><h3><span>{cid}</span><span><span class=\"{badge_cls}\">{html_escape.escape(sev)}</span></span></h3>")
            parts.append(f"<div class=\"meta\"><small>{html_escape.escape(case.get('summary',''))}</small></div>")
            parts.append('<div class="artifacts"><h4>Artifacts</h4><ul>')
            for a in case['artifacts']:
                atype = html_escape.escape(a.get('type',''))
                val = html_escape.escape(a.get('value',''))
                note = html_escape.escape(a.get('note',''))
                parts.append(f"<li class=\"artifact\">{atype}: {val}{(' — ' + note) if note else ''}</li>")
            parts.append('</ul></div>')

            parts.append('<h4>Raw records (compact)</h4>')
            parts.append('<table>')
            headers = ["asset_id", "hostname", "asset_type", "os", "environment", "owner_team", "internet_exposed", "criticality", "last_seen"]
            parts.append('<tr>' + ''.join(f'<th>{h}</th>' for h in headers) + '</tr>')
            for r in case.get('raw_records', []):
                parts.append('<tr>' + ''.join(f'<td>{html_escape.escape(str(r.get(h,'')))}</td>' for h in headers) + '</tr>')
            parts.append('</table>')
            parts.append('</div>')

        parts.append('</div>')
        parts.append('</div>')
        parts.append('</body></html>')

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(parts))

    # build html from JSON out and try conversion
    try:
        generate_html(json_out, 'case_report.html')
        print('Wrote HTML: case_report.html')

        # Try pdf conversion via pdfkit (wkhtmltopdf) or weasyprint
        converted = False
        try:
            import pdfkit
            pdfkit.from_file('case_report.html', 'case_report.pdf')
            print('Converted HTML to PDF via pdfkit: case_report.pdf')
            converted = True
        except Exception:
            try:
                from weasyprint import HTML
                HTML('case_report.html').write_pdf('case_report.pdf')
                print('Converted HTML to PDF via WeasyPrint: case_report.pdf')
                converted = True
            except Exception:
                converted = False

        if not converted:
            # fallback: generate simple text-PDF if possible (ReportLab)
            try:
                from reportlab.platypus import SimpleDocTemplate, Preformatted, Spacer
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.lib.pagesizes import letter

                with open('case_report.html', 'r', encoding='utf-8') as f:
                    html_text = f.read()

                doc = SimpleDocTemplate('case_report.pdf', pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
                styles = getSampleStyleSheet()
                style = styles.get('Code', styles.get('Normal'))
                story = [Spacer(1, 6), Preformatted(html_text, style)]
                doc.build(story)
                print('Wrote fallback PDF from HTML text via ReportLab: case_report.pdf')
                converted = True
            except Exception:
                print('Could not convert HTML to PDF automatically. To create a PDF, install wkhtmltopdf and pdfkit, or weasyprint, or reportlab.')

    except Exception as e:
        print('HTML generation failed:', str(e))


if __name__ == "__main__":
    main()