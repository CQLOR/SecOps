# SOC Case Builder & Analysis

Scope
- This repo contains a small SOC case builder and reporting tool that:
  - Ingests CMDB-style records (the script currently fetches mock data),
  - Groups artifacts into cases by hostname/asset,
  - Applies simple severity heuristics (LOW / MEDIUM / HIGH),
  - Exports reports: HTML, PDF, JSON, CSV and a plain-text summary.

Features
- Case grouping and artifact extraction
- Severity scoring based on hashes, domains, exposure, and criticality
- Outputs: `case_report.html`, `case_report.pdf`, `case_report.json`, `case_report.csv`, `case_report.txt`
- Lightweight web viewer (Express) with download endpoints and client-side filtering, sorting, search and pagination

Prerequisites
- Python 3.8+ (use `python3` on macOS)
- Node.js 14+
- `pip` and `npm`

Setup
1. Install Python dependencies (requests required; `reportlab` optional for PDF):

```bash
python3 -m pip install --user requests reportlab
```

2. Install Node dependencies for the small web server:

```bash
npm install
```

Usage
1) Generate or regenerate reports (creates JSON / CSV / TXT / PDF / HTML):

```bash
python3 soc_case_builder.py
```

2) Start the web server (serves `case_report.html` and download endpoints):

```bash
npm start
# or: node server.js
```

3) Open the report in a browser:

  http://localhost:3000

Web interface notes
- Download endpoints:
  - `/download/pdf` → `case_report.pdf`
  - `/download/csv` → `case_report.csv`
  - `/download/json` → `case_report.json`
- The HTML report includes client-side filters for severity, OS and owner team, hostname search, sorting, pagination, and visible-count indicators.

Troubleshooting
- If downloads return "not found" or the files are outdated, re-run the Python generator above.
- If PDF generation fails, ensure `reportlab` is installed; the script will still write JSON/CSV/TXT without it.

Project layout
- `soc_case_builder.py` — main Python generator
- `server.js` — small Express server that serves static files and download routes
- `package.json` — Node config and `npm start` script
- `case_report.*` — generated artifacts

If you want a different default page size, a table view, or additional export formats, open an issue or request the change.

Quick Start

Anyone can clone and run the project with:

```bash
git clone https://github.com/CQLOR/SecOps.git
cd SecOps
npm install
python3 soc_case_builder.py
npm start
```

Then open http://localhost:3000 in your browser.
