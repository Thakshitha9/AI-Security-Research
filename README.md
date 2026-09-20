
# AI Security Research Lab

An AI-powered cybersecurity research and analysis platform designed to explore security threats, identify suspicious activity, and support defensive security assessments.

The platform combines **Artificial Intelligence, cybersecurity analysis, rule-based detection, network reconnaissance, and security-focused web interfaces** into a unified research environment.

It provides tools for phishing URL analysis, prompt injection research, RAG security experimentation, and AI-assisted network reconnaissance.

> **Project Status:** Active development  
> **Purpose:** Cybersecurity research, education, and authorized defensive security testing

---

## Overview

The AI Security Research Lab is a modular cybersecurity platform that combines rule-based security analysis with AI-powered explanations and assessment.

The project currently includes browser-based interfaces and Python backend services for analyzing suspicious URLs and network reconnaissance data.

The platform is designed to help users:

- Identify suspicious URL characteristics.
- Analyze potential phishing indicators.
- Inspect network reconnaissance results.
- Review exposed services and associated security risks.
- Explore prompt injection and RAG security concepts.
- Generate AI-assisted security explanations and recommendations.
- Understand security findings through a centralized web interface.

The system is intended for use in authorized, controlled, and educational environments.

---

## Key Features

### 1. Phishing Website Detection

Analyzes a submitted URL using rule-based URL feature extraction and security indicators.

The analyzer checks characteristics such as:

- URL length.
- HTTPS usage.
- IP address usage.
- Suspicious keywords.
- Hyphens and special characters.
- Potentially suspicious URL patterns.
- Domain and URL structure.

The system calculates a rule-based risk score and returns detected indicators.

An AI explanation can also be generated through the configured Gemini provider when the AI service is available.

**Current implementation:**

- Flask API backend.
- Browser-based phishing analysis interface.
- Rule-based URL analysis.
- Risk score generation.
- Suspicious indicator detection.
- AI-generated explanation with fallback handling.
- Analysis storage through the project database layer.

**API endpoint:**

```http
POST /api/phishing/analyze
```

**Example request:**

```json
{
  "url": "https://www.google.com"
}
```

**Example response structure:**

```json
{
  "url": "https://www.google.com",
  "risk_score": 0,
  "indicators": [],
  "ai_explanation": "..."
}
```

> The risk score is an automated assessment based on configured indicators. It does not independently prove that a website is malicious or safe.

---

### 2. Recon AI

Recon AI analyzes network reconnaissance data, including Nmap XML scan results.

The tool is designed to assist with defensive security assessment by identifying exposed services, assigning risk classifications, and generating security recommendations.

**Supported functionality:**

- Nmap XML file upload.
- Network host parsing.
- Exposed port and service identification.
- Heuristic security findings.
- Host-level risk scores.
- AI-assisted security analysis.
- Defensive remediation recommendations.
- Browser-based report presentation.

**Recon API health endpoint:**

```http
GET /api/recon/health
```

**Example response:**

```json
{
  "status": "online",
  "service": "Recon AI"
}
```

**Example input:**

```text
sample_nmap.xml
```

The Recon AI interface can display information such as:

- Hosts analyzed.
- Total findings.
- High-risk findings.
- Hostnames and IP addresses.
- Exposed ports.
- Detected services.
- Risk levels.
- Defensive recommendations.
- AI-generated security analysis.

> Recon results must be reviewed by a security professional or system administrator. Detected services and heuristic findings require validation against the actual environment.

---

### 3. Prompt Guard

Prompt Guard is intended to support research into detecting suspicious or potentially malicious prompt content.

The research area includes identifying patterns associated with prompt injection, instruction override attempts, and other manipulation techniques.

Potential detection categories include:

- Instruction override.
- Role manipulation.
- Information extraction.
- Delimiter manipulation.
- Encoding-based attempts.
- Authority impersonation.

The exact available functionality depends on the implementation and configuration of the Prompt Guard module.

---

### 4. RAG Security Research

The project includes research-oriented work related to Retrieval-Augmented Generation security and knowledge-base poisoning.

The purpose of this research is to understand how manipulated documents or instructions may influence retrieval-based AI systems.

Research areas include:

- RAG knowledge-base security.
- Malicious document injection.
- Context manipulation.
- Retrieval integrity.
- AI response evaluation.
- Defensive safeguards for retrieved content.

Experiments must be performed only against local, test, or explicitly authorized knowledge bases.

---

## System Architecture

```text
                    AI SECURITY RESEARCH LAB
                              |
                +-------------+-------------+
                |                           |
          Web Frontend                Python Backend
        HTML / CSS / JavaScript            |
                |                           |
                +-------------+-------------+
                              |
                         Flask APIs
                              |
       +----------------------+----------------------+
       |                      |                      |
 Phishing Analysis       Recon AI              Other Modules
       |                      |                      |
 URL Feature           Nmap XML Parser       Prompt Guard
 Extraction             and Analyzer         RAG Research
       |                      |
 Rule-Based             Risk Findings
 Detection              and AI Analysis
       |                      |
       +-------------+------+
                     |
               LLM Provider
                     |
               Gemini API
                     |
             AI Explanation
                     |
              Database Layer
```

---

## Project Structure

```text
AI-Security-Research/
│
├── api.py
├── recon_ai_api.py
├── pyproject.toml
├── README.md
├── .env.example
│
├── core/
│   ├── config.py
│   ├── llm_client.py
│   └── utils.py
│
├── phishing_detector/
│   └── url_analyzer.py
│
├── frontend/
│   ├── index.html
│   ├── phishing.html
│   ├── recon.html
│   ├── prompt-guard.html
│   ├── rag.html
│   │
│   └── js/
│       ├── phishing.js
│       └── recon.js
│
├── sample_nmap.xml
│
└── .venv/
```

> The project structure may contain additional files and directories depending on the current development branch. The structure above highlights the components used in the implemented web-based workflow.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and security analysis |
| Flask | Backend API services |
| HTML | Web page structure |
| CSS | User interface styling |
| JavaScript | Frontend interaction and API communication |
| Gemini API | AI-assisted security explanations |
| HTTPX | HTTP requests to AI providers |
| Python-dotenv | Environment variable management |
| Nmap XML | Network reconnaissance input |
| Database layer | Storage of security analysis results |

---

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Raresney/AI-Security-Research.git
```

Move into the project directory:

```bash
cd AI-Security-Research
```

---

### 2. Create a Virtual Environment

On Windows:

```powershell
python -m venv .venv
```

Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, use an appropriate environment policy permitted by your system administrator.

---

### 3. Install Dependencies

```powershell
pip install -e .
```

If the project provides a requirements file, install it using:

```powershell
pip install -r requirements.txt
```

Use the dependency file that exists in your local project.

---

### 4. Configure Environment Variables

Create a `.env` file in the project root.

Example:

```env
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-3.5-flash
```

Do not commit the `.env` file or expose API keys in screenshots, logs, GitHub repositories, or public documentation.

The model name should match a model currently available to your configured API account. If the configured model becomes unavailable, update the model according to the provider's current documentation.

---

## Running the Application

### Start the Main Flask API

From the project root, activate the virtual environment and run:

```powershell
python -c "from api import app; app.run(host='127.0.0.1', port=5000, debug=False)"
```

The main backend will be available at:

```text
http://127.0.0.1:5000
```

The phishing analysis endpoint is:

```text
http://127.0.0.1:5000/api/phishing/analyze
```

The endpoint accepts `POST` requests with a JSON body.

---

### Start the Recon AI API

Run the Recon AI service:

```powershell
python recon_ai_api.py
```

The Recon AI service runs on:

```text
http://127.0.0.1:5002
```

Check the service status:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5002/api/recon/health" -Method GET
```

Expected response:

```json
{
  "status": "online",
  "service": "Recon AI"
}
```

---

## Using the Web Interface

### Open the Phishing Detection Interface

```powershell
Start-Process ".\frontend\phishing.html"
```

Enter a URL and submit it for analysis.

The interface displays:

- Submitted URL.
- Risk score.
- Detected indicators.
- AI explanation when available.
- Fallback information when the AI provider is unavailable.

---

### Open the Recon AI Interface

```powershell
Start-Process ".\frontend\recon.html"
```

Upload an Nmap XML file generated from an authorized assessment.

Example input:

```text
sample_nmap.xml
```

The Recon AI interface presents the parsed results and the associated security analysis.

---

## API Examples

### Phishing URL Analysis

PowerShell:

```powershell
$body = @{
    url = "https://www.google.com"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://127.0.0.1:5000/api/phishing/analyze" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

The request must contain a `url` field.

The API validates that the URL field exists and is not empty before running the analysis.

---

### Recon AI Health Check

```powershell
Invoke-RestMethod `
    -Uri "http://127.0.0.1:5002/api/recon/health" `
    -Method GET
```

---

## Phishing Detection Workflow

```text
User submits a URL
        |
        v
Frontend sends POST request
        |
        v
Flask API validates the request
        |
        v
URL feature extraction
        |
        v
Rule-based indicator analysis
        |
        v
Risk score calculation
        |
        v
AI explanation generation
        |
        +---- AI available
        |          |
        |          v
        |    AI explanation
        |
        +---- AI unavailable
                   |
                   v
          Fallback explanation
        |
        v
Store analysis result
        |
        v
Return JSON response
```

---

## Recon AI Workflow

```text
User uploads Nmap XML file
        |
        v
Frontend sends scan data
        |
        v
Recon API validates and parses input
        |
        v
Hosts and services are extracted
        |
        v
Heuristic findings are generated
        |
        v
Risk levels and host scores are calculated
        |
        v
AI-assisted security analysis
        |
        v
Defensive recommendations
        |
        v
Results displayed in the frontend
```

---

## AI Provider Configuration

The project includes a shared LLM client and provider configuration.

The provider configuration supports multiple provider options in the codebase. The web phishing workflow currently uses the configured Gemini provider.

| Provider | Usage |
|---|---|
| Gemini | AI-assisted phishing explanations and security analysis |
| Ollama | Provider option available in the shared LLM configuration |
| Groq | Provider option available in the shared LLM configuration |
| Hugging Face | Provider option available in the shared LLM configuration |

Provider availability depends on the implementation, environment variables, model availability, and API limits.

### AI Fallback Behavior

When the AI provider is unavailable or returns an error, the phishing workflow is designed to retain the rule-based URL analysis and provide a fallback explanation.

This ensures that a temporary AI provider failure does not necessarily prevent the URL analysis from being completed.

---

## Security Considerations

### API Key Protection

- Keep API keys in `.env`.
- Do not commit secrets to GitHub.
- Do not share API keys in screenshots or terminal output.
- Rotate a key immediately if it is accidentally exposed.
- Use separate development and production credentials.

### Authorized Testing

Only analyze:

- Systems you own.
- Systems for which you have written authorization.
- Local test environments.
- Purpose-built cybersecurity training targets.

Do not scan or test external systems without permission.

### AI Output Limitations

AI-generated explanations may be incomplete, inaccurate, or affected by provider availability.

AI output should be reviewed alongside:

- Actual scan results.
- Rule-based findings.
- Application logs.
- Security configuration.
- Relevant system documentation.

The platform does not guarantee that a URL, host, or service is completely safe or malicious.

---

## Testing and Validation

The following components have been tested during development:

- Main Flask application startup.
- Phishing analysis API request structure.
- Rule-based URL analysis.
- Phishing risk indicator generation.
- Recon AI API health endpoint.
- Nmap XML-based Recon workflow.
- AI provider connectivity through the shared LLM client.

Additional validation should be performed before treating the platform as production-ready.

Recommended future tests include:

- Unit tests for URL feature extraction.
- API validation tests.
- Error-handling tests.
- Database storage verification.
- AI provider failure tests.
- Malformed Nmap XML tests.
- Frontend and backend integration tests.
- Security testing of input handling.

---

## Current Limitations

- AI provider availability depends on external API services and model availability.
- AI explanations may fail temporarily due to API errors, rate limits, or service availability.
- Rule-based phishing analysis should not be treated as a complete phishing detection solution.
- Recon findings are heuristic and require validation.
- The project is intended for research and educational use rather than unrestricted production deployment.
- Some research modules may require additional configuration or implementation validation.

---

## Future Enhancements

Potential improvements include:

- Improved URL feature extraction.
- Additional phishing detection models.
- Automated unit and integration testing.
- More detailed database analytics.
- Authentication and role-based access control.
- Improved API error handling.
- Security report export to PDF and JSON.
- Recon report history and comparison.
- Enhanced prompt injection benchmarking.
- RAG security evaluation dashboards.
- Centralized application logging.
- Docker-based deployment.
- CI/CD security checks.
- Improved model fallback and retry handling.

Future enhancements will be implemented and documented as they become available.

---

## Project Attribution

Original repository:

[AI Security Research](https://github.com/Raresney/AI-Security-Research)

Copyright:

```text
Copyright (c) 2026 Bighiu Rares
```

Repository ownership and attribution should be preserved according to the original project's license and contribution requirements.

---

## Disclaimer

This project is intended for **cybersecurity research, education, and authorized defensive testing only**.

Do not use the tools to access, scan, manipulate, or exploit systems without explicit permission.

The authors and contributors are not responsible for unauthorized use, damage, data loss, or security incidents resulting from the misuse of this project.

Always perform experiments in controlled environments and follow applicable laws, organizational policies, and responsible disclosure practices.