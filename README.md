# Web-misconfiguration-scanner

### Automated Website Misconfiguration Scanner

A beginner-friendly Flask dashboard for reviewing common web configuration issues on **local loopback test sites**. It stores scan history and findings in SQLite and generates JSON, HTML, and PDF reports.

> **Scope and safety:** This build intentionally accepts only `localhost`, `127.0.0.0/8`, and `::1` targets. It does not scan public websites or other devices, even if you have authorization. Requests and redirects are revalidated, checks use fixed paths, responses have a size limit, and Nuclei runs only the bundled, non-intrusive HTTP-header template. Do not remove these controls to scan arbitrary targets.

## What it checks

- HTTP methods advertised by `OPTIONS`; risky methods are presented as review guidance, not automatically treated as vulnerabilities.
- Directory indexes at `/uploads/`, `/backup/`, `/images/`, `/files/`, and `/documents/`.
- A short predefined list of default or diagnostic pages.
- Signatures for selected exposed configuration and backup files. Response contents are examined only in memory and never saved to findings or reports.
- One bundled Nuclei check for the `X-Content-Type-Options: nosniff` response header. Nuclei is optional; the other checks work without it.

Severity is assigned from recognizable evidence, not from an HTTP status alone. Findings are observations that should be verified before remediation. The scanner is not an exhaustive audit.

## Requirements

- Python 3.9 or later
- Nuclei (optional, for the bundled header check)
- Windows PowerShell, macOS Terminal, or a Linux shell

## Install

Open a terminal in this project folder.

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use `.\.venv\Scripts\python.exe` instead of activating the environment.

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Flask creates `database/scanner.sqlite3` on the first application start. No separate migration or paid API is required.

## Install Nuclei (optional)

Install the official ProjectDiscovery Nuclei binary using the instructions for your operating system at <https://docs.projectdiscovery.io/tools/nuclei/install>. Confirm it is available on `PATH`:

```text
nuclei -version
```

The application invokes Nuclei with the project-owned `nuclei-templates/safe-headers.yaml` only. It does not load a downloaded community template set. If Nuclei is not installed, the report notes that the check was skipped.

On Windows, a user-local install at `%LOCALAPPDATA%\Programs\Nuclei\nuclei.exe` is detected automatically. Other installations should be available on `PATH`.

## Run the dashboard

From the project directory:

```text
python app.py
```

Open <http://127.0.0.1:5000>. The Flask dashboard binds to loopback only. Enter `http://127.0.0.1:8000` or `http://localhost:8000`, confirm authorization, and start a scan.

## Try the intentionally misconfigured local demo

Open a second terminal in the project directory, activate the same virtual environment, then run:

```text
python tests/local_test_app.py
```

This demo binds only to `127.0.0.1:8000` and deliberately exposes a dummy environment file, an uploads index, and a diagnostic-looking page. It contains no real credentials and is for local learning only. Scan `http://127.0.0.1:8000` from the dashboard. Stop the demo with `Ctrl+C`.

## Run tests

```text
python -m unittest discover -s tests -v
```

The automated tests verify target restrictions, dashboard rendering, authorization checks, and report route validation.

## Reports and data

- The dashboard displays scan progress and recent scan history.
- Each scan detail page provides JSON, HTML, and PDF report downloads.
- Scan records and findings are stored in `database/scanner.sqlite3`.
- Generated reports are saved in `reports/`.
- Scan comparison reports new, resolved, and persistent findings for two scan records.

The app is intended for a local development environment. Do not expose the Flask development server to a network.
