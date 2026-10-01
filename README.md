# AI Security Research Platform

An AI-assisted cybersecurity research platform for defensive analysis. It combines rule-based checks with optional large language model explanations so a researcher can review phishing URLs, prompt-injection attempts, retrieval-augmented generation behavior, network reconnaissance output, and honeypot sessions from one project.

The web console is a local research interface. It is not an authenticated production security operations center.

## Problem statement

Security review work is spread across raw tool output, model responses, and notes. A URL score, an Nmap XML file, or a suspicious prompt is hard to explain in an interview or a lab report when the result is only an unstructured paragraph.

This project keeps the existing analysis modules and presents their real results in a consistent structure: risk level, finding, evidence, explanation, and recommendation. It does not invent scan data when a module has nothing to report.

## Objectives

- Give each research module a clear web or command-line entry point.
- Keep rule-based findings even when the configured model is offline.
- Validate inputs and return safe error messages.
- Store analysis history in MySQL when a database is configured.
- Keep secrets in environment variables and out of Git.

## Features

| Module | What it does | How to open it |
|---|---|---|
| Dashboard | Shows stored counts, recent analyses, and which local APIs respond | `frontend/index.html` |
| Phishing detection | Scores a URL from structural indicators and optionally asks Gemini to explain them | `frontend/phishing.html` |
| Prompt Guard | Flags suspicious prompt patterns and can add a model assessment | `frontend/prompt-guard.html` |
| RAG assistant | Answers from the local lab knowledge base | `frontend/rag.html` |
| Recon AI | Parses authorized Nmap XML and summarizes exposed services | `frontend/recon.html` |
| Security reports | Drafts a defensive report from recon assessment data | `frontend/report.html` |
| LLM honeypot | Logs and classifies sessions against decoy personas | `honeypot` CLI |
| Prompt injection lab | Runs the project's labeled research cases | `injection-lab` CLI |
| RAG poison lab | Compares clean and poisoned retrieval behavior in the lab dataset | `rag-poison` CLI |
| Adversarial IDS | Separate research package for model robustness experiments | `adversarial_ids/` |

The honeypot, injection lab, RAG poison lab, and adversarial IDS package stay command-line tools. The dashboard does not pretend they are web services.

## Architecture

```text
Browser UI (frontend/)
    |
    +-- Main API          127.0.0.1:5000   phishing, dashboard, RAG
    +-- Prompt Guard API  127.0.0.1:5001
    +-- Recon AI API      127.0.0.1:5002
    +-- Report API        127.0.0.1:5003
            |
            +-- Rule-based analyzers
            +-- core/llm_client.py   Ollama, Groq, Hugging Face, or Gemini
            +-- Optional MySQL history
```

Each API binds to loopback. The browser is allowed to call localhost and 127.0.0.1. Analysis results are still returned when MySQL is down; they are simply not stored.

Phishing analysis does not fetch the submitted URL. It inspects the string. Recon AI accepts an uploaded Nmap XML document. It does not run Nmap.

## Technology stack

- Python 3.10+
- Flask and Flask-CORS for the local APIs
- HTML, CSS, and JavaScript for the console
- HTTPX for model requests
- python-dotenv for configuration
- MySQL, through `mysql-connector-python`, for optional history
- ChromaDB for the RAG lab store
- Rich and Click for the command-line modules

## Project structure

```text
api.py                      Main API: phishing, dashboard, RAG
prompt_guard_api.py         Prompt Guard API
recon_ai_api.py             Recon AI API
security_report_api.py      Report API
core/                       Model client, validation, history
database/schema.sql         MySQL tables
frontend/                   Dashboard and module pages
phishing_detector/          URL rules and samples
prompt_guard/               Pattern detector and corpus
prompt_injection_lab/       Labeled injection research cases
rag_poison_lab/             Retrieval lab and datasets
recon_ai/                   Nmap parser and service review
llm_honeypot/               Decoy personas and session logs
adversarial_ids/            Separate IDS robustness package
reports/                    Generated report output, gitignored
tests/test_safety.py        Validation and API safety checks
```

## Installation

```powershell
git clone https://github.com/Raresney/AI-Security-Research.git
cd AI-Security-Research
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`pip install -e .` installs the same dependencies and the command-line entry points.

## Environment variables

Copy the template and add keys only for providers you use:

```powershell
copy .env.example .env
```

| Variable | Purpose |
|---|---|
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Local model. Tried first by the automatic client |
| `GROQ_API_KEY`, `GROQ_MODEL` | Groq API |
| `HF_API_TOKEN`, `HF_MODEL` | Hugging Face API |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | Gemini. Used by the phishing, recon, and report web APIs |
| `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE` | Optional history database |
| `CORS_EXTRA_ORIGINS` | Extra browser origins, comma-separated |

Leave unused keys blank. Placeholder values that start with `your_` are ignored by the automatic provider check.

## Database setup

MySQL is optional. To store history:

```sql
CREATE DATABASE ai_security_platform CHARACTER SET utf8mb4;
CREATE USER 'ai_security_user'@'127.0.0.1' IDENTIFIED BY 'choose-a-password';
GRANT ALL PRIVILEGES ON ai_security_platform.* TO 'ai_security_user'@'127.0.0.1';
```

Put that password in `.env` as `MYSQL_PASSWORD`. Then load the tables:

```powershell
mysql -u ai_security_user -p ai_security_platform < database/schema.sql
```

The APIs also run `CREATE TABLE IF NOT EXISTS` when they can connect. Existing `phishing_analysis` rows remain readable. New phishing results are stored in both `phishing_analysis` and `security_analyses`. Other modules write only to `security_analyses`.

`security_analyses` stores the analysis id, module, target, timestamp, risk level, score, finding, evidence, explanation, and recommendation. Uploaded Nmap XML is not stored. Prompt Guard stores only a short target preview.

## How to run

Start only the APIs you need, from the project root, with the virtual environment active. Keep `debug` off.

```powershell
python api.py
python prompt_guard_api.py
python recon_ai_api.py
python security_report_api.py
```

Open `frontend/index.html` in a browser. Pages opened from disk or from localhost can call the loopback APIs.

Health checks:

```text
GET http://127.0.0.1:5000/api/health
GET http://127.0.0.1:5001/api/prompt-guard/health
GET http://127.0.0.1:5002/api/recon/health
GET http://127.0.0.1:5003/api/security-report/health
```

## How each module works

### Phishing detection

`POST /api/phishing/analyze` with `{"url": "https://example.com"}`.

The rules look at scheme, length, IP literals, `@`, repeated hyphens, and a fixed keyword list. The score is capped at 100. A score of 70 or more is HIGH, 40 to 69 is MEDIUM, 1 to 39 is LOW, and 0 is INFO. Gemini may explain that evidence. If the model fails or times out, the rule result is still returned. The response includes the original fields plus `risk_level`, `finding`, `evidence`, `explanation`, and `recommendation`.

### Prompt Guard

`POST /api/prompt-guard/scan` with `{"text": "..."}` on port 5001.

Pattern matches supply the evidence. The model assessment is optional. Text is limited to 8,000 characters.

### RAG assistant

`POST /api/rag/ask` with `{"question": "..."}` on port 5000.

The API loads the lab knowledge base into a temporary vector store and answers from retrieved passages. Questions are limited to 2,000 characters.

### Recon AI

`POST /api/recon/analyze` with `{"xml": "<nmaprun>...</nmaprun>"}` on port 5002.

The parser accepts Nmap XML only, rejects document-type and entity declarations, and limits the upload size. Service findings come from the ports present in the file. If Gemini fails, the rule-based findings are still returned. An empty host list is an empty result, not a fabricated network.

Use this only on scans you are authorized to assess. The included `sample_nmap.xml` is a local sample.

### Security reports

`POST /api/security-report/generate` on port 5003 with the recon assessment JSON. The writer is instructed to use only supplied hosts, services, and observations. Reports are written under `reports/security/`.

### Command-line research modules

```powershell
phish-detect --help
prompt-guard --help
recon-ai --help
injection-lab --help
rag-poison --help
honeypot --help
```

Run these in a lab. Do not point them at systems, inboxes, or networks you do not have permission to test.

## Example workflow

1. Start `python api.py`.
2. Open the dashboard. Counts show an em dash until a result is stored. If MySQL is offline, the page says history is unavailable instead of showing a zero that looks like a completed scan.
3. Open Phishing Detection and submit `https://example.com`.
4. Read the structured assessment. A normal HTTPS URL with no keyword hits should come back as INFO or LOW, with the indicators that were actually found.
5. Submit an `http://` URL that uses an IP address. The evidence list should name the checks that fired.
6. Return to the dashboard. After MySQL is connected, the new row appears under recent activity and the counts change to match the database.
7. Start the Recon API and upload `sample_nmap.xml` only if you want to demo the parser. Review the returned hosts. Do not treat heuristic port notes as proof of compromise.

## Screenshots

Add current captures here after you run the console. Do not include API keys, passwords, or real customer data.

- `docs/screenshots/dashboard.png` — dashboard with real history, or the empty state
- `docs/screenshots/phishing-result.png` — structured URL assessment
- `docs/screenshots/prompt-guard.png` — prompt scan
- `docs/screenshots/recon-findings.png` — findings from an authorized or sample scan
- `docs/screenshots/honeypot_report.png` — existing honeypot report image
- `docs/screenshots/rag_poison_results.png` — existing RAG lab image

## Security considerations

- The APIs listen on 127.0.0.1 and have no login. Do not expose them to a network.
- Browser access is limited to localhost, 127.0.0.1, and `null` origins used by local files. Add other origins only through `CORS_EXTRA_ORIGINS`.
- Error responses do not include stack traces, exception text, or configuration.
- `.env` is gitignored. `.env.example` contains empty keys.
- Database statements use parameters.
- Nmap XML entity declarations are rejected before parsing.
- The phishing module does not download the submitted URL.
- Model prompts for recon ask for defensive review and tell the model not to provide exploit steps.
- This repository is for research, education, and authorized defensive testing.

## Limitations

- Four API processes are started separately. A stopped process shows as Offline on the dashboard.
- There is no user authentication or multi-user tenancy.
- Phishing scores are heuristics. They do not prove that a site is malicious or safe.
- Recon notes are based on port and service observations. They are not a vulnerability scan.
- Model text can be wrong. The structured fields show what the rules returned and label the explanation as model output.
- History requires MySQL. Without it, results are shown once and not saved.
- The command-line labs are research tools. They are not hardened production services.

## Future enhancements

- One process for all web APIs.
- Authentication in front of any non-local deployment.
- Stronger phishing features that still avoid fetching arbitrary URLs by default.
- Saved report comparison.
- Automated tests around the command-line labs.

## Author

Bighiu Rares

Repository: [https://github.com/Raresney/AI-Security-Research](https://github.com/Raresney/AI-Security-Research)

Copyright (c) 2026 Bighiu Rares

Use this project only with permission, in a controlled lab, and within the law and your organization's rules.
