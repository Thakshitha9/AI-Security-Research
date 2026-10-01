
from flask import Flask, request, jsonify

from core.llm_client import LLMClient
from core.config import LLMProvider
from core.platform import MAX_REPORT_CHARS, install_api_guards

from pathlib import Path
from datetime import datetime
import json
import re
import time


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)
install_api_guards(app, max_bytes=MAX_REPORT_CHARS + 50_000)

REPORTS_DIR = Path("reports/security")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# REPORT SECTIONS
# ============================================================

REPORT_SECTIONS = [

{
    "title": "Assessment Summary",
    "instructions": """
Write a factual assessment summary using ONLY the supplied
Recon AI assessment data.

Include only:
- Assessment status, if provided
- Total hosts evaluated, if provided
- Host addresses explicitly present in the data
- A short statement about the purpose of the assessment

STRICT REQUIREMENTS:

1. Do not create an "Assessment Target" field.
2. Do not create a "Scope" field.
3. Do not invent a CIDR range.
4. Do not describe the network as internal, external, public,
   or private unless explicitly stated in the assessment data.
5. Do not invent an organization, asset owner, assessment date,
   network range, or testing scope.
6. Do not claim that the entire network was scanned.
7. Do not claim that any system was compromised.
8. Do not introduce any host address that is absent from the data.
9. Do not add a report title or heading.
10. Return only 3 to 5 concise bullet points.
11. If a required detail is unavailable, write:
    "Not provided in the assessment data."

Return only the summary content.
"""
},
    {
        "title": "1. Executive Summary",
        "instructions": """
Write two concise paragraphs explaining:
- What was assessed
- The main security observations
- The overall defensive security concern

Mention only services and hosts present in the assessment data.
"""
    },
    {
        "title": "2. Security Risk Overview",
        "instructions": """
Explain the risk associated with the findings in the assessment data.

Use the supplied risk classifications when available.
Do not invent vulnerabilities or unsupported risk levels.
"""
    },
    {
        "title": "3. Key Findings",
        "instructions": """
List the most important findings from the assessment data.

For each finding, include:
- Finding
- Risk level
- Security impact
- Recommended defensive action

Use only detected services, ports, scripts, and observations.
"""
    },
    {
        "title": "4. Exposed Services",
        "instructions": """
Summarize the open services detected in the assessment.

Where available, include:
- Host address
- Port
- Service name
- Version
- Defensive security consideration

Mention only services actually present in the assessment.
"""
    },
    {
        "title": "5. Security Impact",
        "instructions": """
Explain the potential defensive security impact of the observed
network exposure and configuration indicators.

Clearly distinguish:
- Directly observed information
- General security considerations

Do not claim that any system was compromised.
"""
    },
    {
        "title": "6. Recommended Remediation",
        "instructions": """
Provide practical defensive recommendations based on the actual findings.

Consider relevant areas such as:
- Firewall restrictions
- Network segmentation
- Authentication controls
- Database access restrictions
- Secure service configuration
- Patch and version review
- Removal of unnecessary services

Only include recommendations relevant to the supplied assessment data.
"""
    },
    {
        "title": "7. Security Priorities",
        "instructions": """
Create exactly these three subsections:

### High Priority

### Medium Priority

### Low Priority

Prioritize defensive actions using the risk levels and observations
in the assessment data.
"""
    },
    {
        "title": "8. Final Assessment",
        "instructions": """
Write a concise conclusion covering:
- Overall observed security posture
- Main remediation focus
- Recommended next defensive actions

Do not claim that the environment is fully secure.
Do not introduce findings that are not present in the data.
"""
    }
]


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_ai_output(text):
    """
    Clean common model formatting artifacts.
    """

    if not text:
        return ""

    text = str(text).strip()

    text = re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    text = text.replace("```markdown", "")
    text = text.replace("```md", "")
    text = text.replace("```", "")

    return text.strip()


def remove_duplicate_heading(text, title):
    """
    Remove a duplicate heading returned by Gemini.
    """

    if not text:
        return ""

    pattern = rf"^\s*#+\s*{re.escape(title)}\s*:?\s*"

    return re.sub(
        pattern,
        "",
        text.strip(),
        count=1,
        flags=re.IGNORECASE
    ).strip()


# ============================================================
# ASSESSMENT DATA
# ============================================================

def prepare_assessment_data(scan_data):
    """
    Convert Recon AI data into readable JSON.
    """

    return json.dumps(
        scan_data,
        indent=2,
        ensure_ascii=False
    )


# ============================================================
# FALLBACK CONTENT
# ============================================================

def fallback_content(title, scan_data):
    """
    Return safe content when an AI section cannot be generated.
    """

    if title == "Assessment Summary":
        host_count = scan_data.get("host_count", "Not provided")

        hosts = scan_data.get("hosts", [])

        host_addresses = []

        if isinstance(hosts, list):
            for host in hosts:
                if isinstance(host, dict):
                    address = (
                        host.get("address")
                        or host.get("ip")
                        or host.get("host")
                    )

                    if address:
                        host_addresses.append(str(address))

        host_text = ", ".join(host_addresses)

        return (
            "- Assessment status: Completed\n"
            f"- Total hosts evaluated: {host_count}\n"
            f"- Hosts evaluated: {host_text or 'Not provided in the assessment data.'}\n"
            "- Assessment purpose: Defensive review of the supplied "
            "Recon AI findings.\n"
            "- Complete network scope: Not provided in the assessment data."
        )

    if title == "1. Executive Summary":
        return (
            "The Recon AI service supplied network assessment data "
            "for defensive security review. The assessment includes "
            "host information, exposed services, and risk findings.\n\n"
            "The results should be reviewed by the system administrator "
            "to confirm whether detected services are required and "
            "whether access is appropriately restricted."
        )

    if title == "2. Security Risk Overview":
        return (
            "The security risk overview is based on the risk levels "
            "and findings included in the Recon AI assessment. "
            "High-risk findings should be reviewed first, followed "
            "by verification of service exposure and configuration."
        )

    if title == "3. Key Findings":
        return (
            "The key findings are available in the Recon AI response. "
            "Review each finding's port, service, risk level, description, "
            "and defensive recommendation."
        )

    if title == "4. Exposed Services":
        return (
            "The exposed services are listed in the Recon AI assessment. "
            "The system administrator should verify whether each service "
            "is required and restrict access to authorized networks."
        )

    if title == "5. Security Impact":
        return (
            "The observed services and configuration indicators may "
            "increase the security exposure of the evaluated hosts. "
            "The actual impact depends on service configuration, "
            "authentication controls, network accessibility, and patch status.\n\n"
            "No system compromise is established by the supplied assessment data. "
            "The system owner should validate the findings and apply "
            "appropriate defensive controls."
        )

    if title == "6. Recommended Remediation":
        return (
            "- Review whether every exposed service is required.\n"
            "- Restrict unnecessary network access with firewall rules.\n"
            "- Review authentication and service configuration.\n"
            "- Apply relevant security updates.\n"
            "- Use network segmentation where appropriate."
        )

    if title == "7. Security Priorities":
        return (
            "### High Priority\n\n"
            "- Review high-risk findings and restrict unnecessary exposure.\n\n"
            "### Medium Priority\n\n"
            "- Review authentication, firewall rules, and service configuration.\n\n"
            "### Low Priority\n\n"
            "- Document approved services and perform periodic security reviews."
        )

    if title == "8. Final Assessment":
        return (
            "The final assessment is based on the services and findings "
            "supplied by Recon AI. The main remediation focus is to reduce "
            "unnecessary network exposure and verify the configuration "
            "of required services.\n\n"
            "Further validation should be performed by the system owner "
            "before considering the environment adequately hardened."
        )

    return "No additional information was available for this section."
# ============================================================
# GENERATE ONE AI SECTION
# ============================================================

def generate_ai_section(client, title, instructions, scan_data):

    assessment_data = prepare_assessment_data(scan_data)

    prompt = f"""
You are a defensive cybersecurity analyst.

Generate content for ONLY this report section:

{title}

SECTION INSTRUCTIONS:
{instructions}

STRICT RULES:

1. Use only the supplied assessment data.
2. Do not invent hosts, ports, services, versions, or vulnerabilities.
3. Do not claim that a system was compromised.
4. Do not provide exploitation instructions or attack payloads.
5. Do not write the section heading.
6. Do not write any other report section.
7. Use concise professional language.
8. Complete this section.
9. If information is unavailable, state that it was not provided.
10. Return only the section content.

AUTHORIZED ASSESSMENT DATA:

{assessment_data}
""".strip()

    response = client.generate(
        prompt,
        system_prompt=(
            "You are a defensive cybersecurity report analyst. "
            "Produce accurate and evidence-based security content. "
            "Do not invent findings or provide offensive instructions."
        ),
        temperature=0.1
    )

    response = clean_ai_output(response)
    response = remove_duplicate_heading(response, title)

    return response.strip()


# ============================================================
# SAFE SECTION GENERATION WITH RETRY
# ============================================================

def generate_section_with_fallback(
    client,
    title,
    instructions,
    scan_data,
    max_retries=2
):
    """
    Try AI generation a limited number of times.

    If generation fails, return fallback content so the complete
    report can still be assembled.
    """

    last_error = None

    for attempt in range(1, max_retries + 1):

        try:

            print(
                f"    AI attempt {attempt}/{max_retries}: {title}",
                flush=True
            )

            content = generate_ai_section(
                client=client,
                title=title,
                instructions=instructions,
                scan_data=scan_data
            )

            if content:

                return content

            print(
                f"    Empty AI response for: {title}",
                flush=True
            )

        except Exception as error:

            last_error = error

            print(
                f"    AI error for {title}, attempt {attempt}: "
                f"{type(error).__name__}",
                flush=True
            )

            if attempt < max_retries:

                time.sleep(1)

    print(
        f"    Using fallback content for: {title}",
        flush=True
    )

    if last_error:

        print(
            f"    Last error for {title}: "
            f"{type(last_error).__name__}",
            flush=True
        )

    return fallback_content(
        title=title,
        scan_data=scan_data
    )


# ============================================================
# GENERATE COMPLETE REPORT
# ============================================================

def _clip(value, limit=500):
    text = "" if value is None else str(value).strip()
    return text[:limit]


def _plain(value):
    """Return supplied text without a per-field character limit.

    Descriptions, evidence, and recommendations are preserved in full.
    The generate endpoint rejects a JSON body larger than MAX_REPORT_CHARS.
    That request limit is the stability bound. These fields are not clipped.
    """

    if value is None:
        return ""
    return str(value).strip()


def _risk_label(value, score=None):
    label = _clip(value, 32).upper()

    if label in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return label

    try:
        number = int(score)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if number >= 70:
        return "HIGH"
    if number >= 40:
        return "MEDIUM"
    if number > 0:
        return "LOW"
    return "INFO"


def _severity_counts(rows):
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for row in rows:
        label = row.get("severity")
        if label in counts:
            counts[label] += 1

    return counts


def _highest_risk(labels):
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    best = "UNKNOWN"

    for label in labels:
        if order.get(label, 0) > order.get(best, 0):
            best = label

    return best


def _host_target(host):
    address = _clip(
        host.get("ip") or host.get("address") or host.get("host"),
        128,
    ) or "Unknown host"
    hostname = _clip(host.get("hostname"), 128)
    if hostname:
        return f"{address} ({hostname})"
    return address


def _collect_findings(scan_data):
    """Return targets, finding rows, host-list presence, and empty hosts.

    An empty findings list stays an empty assessment result. It is not
    turned into a security finding.
    """

    hosts = scan_data.get("hosts") if isinstance(scan_data, dict) else None
    hosts_present = isinstance(hosts, list)
    if not hosts_present:
        hosts = []

    targets = []
    rows = []
    hosts_without_findings = []

    for host in hosts:
        if not isinstance(host, dict):
            continue

        target = _host_target(host)
        targets.append(target)
        findings = host.get("findings")
        host_rows = []

        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                port = _plain(finding.get("port")) or "Not provided"
                service = _plain(finding.get("service")) or "Not provided"
                detail = _plain(
                    finding.get("description") or finding.get("finding"),
                ) or "No finding text was returned."
                recommendation = _plain(
                    finding.get("recommendation"),
                ) or "No recommendation was returned."
                observed = f"Port {port} / {service}"
                evidence = _plain(finding.get("evidence")) or observed

                host_rows.append({
                    "title": observed,
                    "target": target,
                    "severity": _risk_label(
                        finding.get("risk_level"),
                        finding.get("risk_score"),
                    ),
                    "evidence": evidence,
                    "recommendation": recommendation,
                    "detail": detail,
                })

        if host_rows:
            rows.extend(host_rows)
        else:
            hosts_without_findings.append(target)

    return targets, rows, hosts_present, hosts_without_findings


def _empty_findings_note(hosts_without_findings):
    """Status text for hosts that were assessed and had no findings."""

    if not hosts_without_findings:
        return ""

    listed = ", ".join(hosts_without_findings)
    return (
        "Hosts assessed with no findings: "
        f"{listed}. An empty findings list is an empty assessment result "
        "and is not a discovered security finding."
    )


def build_report_package(scan_data):
    """Markdown and display fields from supplied findings only."""

    targets, rows, hosts_present, hosts_without_findings = _collect_findings(
        scan_data
    )
    timestamp = datetime.now().isoformat(timespec="seconds")
    overall = _highest_risk(row["severity"] for row in rows)
    target_text = ", ".join(targets[:8]) if targets else (
        "Not provided in the assessment data."
    )
    if len(targets) > 8:
        target_text += f", and {len(targets) - 8} more"

    if not hosts_present:
        assessment_status = "incomplete"
        summary = (
            "The supplied assessment is incomplete. "
            "It did not include a host list."
        )
    elif not targets:
        assessment_status = "completed"
        summary = (
            "The assessment completed and did not include any hosts."
        )
    elif not rows:
        assessment_status = "completed"
        summary = (
            f"The assessment completed for {len(targets)} host(s) and "
            "did not include any findings."
        )
    else:
        assessment_status = "completed"
        summary = (
            f"The assessment completed for {len(targets)} host(s) and "
            f"lists {len(rows)} finding(s) from the supplied data. "
            f"The highest risk label in that data is {overall}."
        )

    limitations = [
        "Only hosts, services, risk labels, and recommendations present in the supplied assessment are listed.",
        "These observations do not prove that a system was compromised.",
        "The AI-generated narrative is separate from this factual assessment and may be unavailable.",
    ]

    finding_blocks = []
    evidence_lines = []
    recommendation_lines = []

    for index, row in enumerate(rows, start=1):
        finding_blocks.append(
            "\n".join([
                f"### {index}. {row['title']}",
                f"- Target: {row['target']}",
                f"- Severity: {row['severity']}",
                f"- Finding: {row['detail']}",
                f"- Evidence: {row['evidence']}",
                f"- Recommendation: {row['recommendation']}",
            ])
        )
        evidence_lines.append(f"- {index}. {row['target']}: {row['evidence']}")
        recommendation_lines.append(
            f"- {index}. {row['target']}: {row['recommendation']}"
        )

    severity_counts = _severity_counts(rows)
    finding_count = len(rows)
    count_lines = [
        f"- Critical: {severity_counts['CRITICAL']}",
        f"- High: {severity_counts['HIGH']}",
        f"- Medium: {severity_counts['MEDIUM']}",
        f"- Low: {severity_counts['LOW']}",
        f"- Informational: {severity_counts['INFO']}",
        f"- Findings: {finding_count}",
    ]

    note = _empty_findings_note(hosts_without_findings)

    if rows:
        findings_text = "\n\n".join(finding_blocks)
        evidence_text = "\n".join(evidence_lines)
        recommendation_text = "\n".join(recommendation_lines)
    else:
        findings_text = "No findings were present in the supplied assessment."
        evidence_text = "No evidence was present in the supplied assessment."
        recommendation_text = "No recommendations were returned."

    if note:
        findings_text = f"{findings_text}\n\n{note}"

    markdown = "\n".join([
        "# Defensive Security Report",
        "",
        "## Executive Summary",
        "",
        summary,
        "",
        "## Assessment Details",
        "",
        "- Module: Recon AI",
        f"- Target: {target_text}",
        f"- Assessment: {assessment_status}",
        "- Report: generated",
        "",
        "## Risk Level",
        "",
        overall,
        "",
        "## Finding summary",
        "",
        "\n".join(count_lines),
        "",
        "## Findings",
        "",
        findings_text,
        "",
        "## Evidence",
        "",
        evidence_text,
        "",
        "## Recommendations",
        "",
        recommendation_text,
        "",
        "## Limitations",
        "",
        "\n".join(f"- {item}" for item in limitations),
        "",
        "## Timestamp",
        "",
        timestamp,
        "",
    ])

    return {
        "markdown": markdown,
        "view": {
            "module": "Recon AI",
            "target": target_text,
            "assessment_status": assessment_status,
            "report_status": "generated",
            "risk_level": overall,
            "summary": summary,
            "timestamp": timestamp,
            "finding_count": finding_count,
            "severity_counts": severity_counts,
            "findings": rows,
            "hosts_without_findings": hosts_without_findings,
            "finding_status": note,
            "evidence": evidence_lines or [
                "No evidence was present in the supplied assessment."
            ],
            "recommendations": recommendation_lines or [
                "No recommendations were returned."
            ],
            "limitations": limitations,
        },
    }


def build_factual_report(scan_data):
    """Build a report from supplied findings only. No model text is copied."""

    return build_report_package(scan_data)["markdown"]


def generate_security_report(client, scan_data):

    generated_sections = []

    total_sections = len(REPORT_SECTIONS)

    for index, section in enumerate(REPORT_SECTIONS, start=1):

        title = section["title"]

        print(
            f"[{index}/{total_sections}] "
            f"Generating: {title}",
            flush=True
        )

        content = generate_section_with_fallback(
            client=client,
            title=title,
            instructions=section["instructions"],
            scan_data=scan_data
        )

        if not content:

            content = fallback_content(
                title=title,
                scan_data=scan_data
            )

        generated_sections.append(
            f"## {title}\n\n{content}"
        )

        print(
            f"[{index}/{total_sections}] "
            f"Completed: {title}",
            flush=True
        )

    report = (
        "# Defensive Infrastructure Security Assessment Report\n\n"
        + "\n\n---\n\n".join(generated_sections)
        + "\n"
    )

    return report


# ============================================================
# REPORT VALIDATION
# ============================================================

def validate_report(report):

    missing_sections = []

    for section in REPORT_SECTIONS:

        title = section["title"]

        if f"## {title}" not in report:

            missing_sections.append(title)

    return {
        "complete": len(missing_sections) == 0,
        "missing_sections": missing_sections
    }


FACTUAL_SECTIONS = (
    "Executive Summary",
    "Assessment Details",
    "Risk Level",
    "Finding summary",
    "Findings",
    "Evidence",
    "Recommendations",
    "Limitations",
    "Timestamp",
)


def factual_report_status(markdown, assessment_status):
    """Factual completeness does not depend on the model narrative.

    The assessment is factually complete when a host list was supplied and
    every factual section is present. Narrative availability stays on
    narrative_status.
    """

    missing = [
        title for title in FACTUAL_SECTIONS
        if f"## {title}" not in markdown
    ]

    if assessment_status != "completed":
        missing.append("host list")

    return not missing, missing


# ============================================================
# GENERATE REPORT ENDPOINT
# ============================================================

@app.route(
    "/api/security-report/generate",
    methods=["POST"]
)
def generate_report():

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:

        return jsonify({
            "status": "error",
            "error": "Valid Recon assessment data is required."
        }), 400

    try:
        encoded = json.dumps(data)
    except (TypeError, ValueError):
        return jsonify({
            "status": "error",
            "error": "Assessment data must be JSON."
        }), 400

    if len(encoded) > MAX_REPORT_CHARS:
        return jsonify({
            "status": "error",
            "error": "Assessment data is too large."
        }), 400

    print(
        "Received security report request.",
        flush=True
    )

    package = build_report_package(data)
    factual = package["markdown"]
    narrative = ""
    narrative_status = "unavailable"
    message = (
        "AI-generated narrative was unavailable. "
        "The factual security assessment is shown below."
    )

    try:

        print(
            "Initializing Gemini client...",
            flush=True
        )

        with LLMClient(LLMProvider.GEMINI) as llm:

            narrative = generate_security_report(
                client=llm,
                scan_data=data
            )

        narrative_status = "available"
        message = (
            "Security report generated. "
            "The AI-generated narrative is included after the factual assessment."
        )

    except Exception:
        print("SECURITY REPORT ERROR", flush=True)

    if narrative:
        report = (
            factual
            + "\n## AI-generated narrative\n\n"
            + narrative
        )
    else:
        report = factual
    factual_complete, factual_missing = factual_report_status(
        factual,
        package["view"]["assessment_status"],
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = f"security_report_{timestamp}.md"
    report_path = REPORTS_DIR / filename

    try:
        report_path.write_text(
            report,
            encoding="utf-8"
        )
        print("Report saved successfully.", flush=True)
    except Exception:
        print("SECURITY REPORT SAVE ERROR", flush=True)
        filename = ""

    view = package["view"]
    view["narrative_status"] = narrative_status

    return jsonify({
        "status": "success",
        "message": message,
        "assessment_status": view["assessment_status"],
        "report_status": "generated",
        "narrative_status": narrative_status,
        "filename": filename,
        "report": report,
        "view": view,
        "complete": factual_complete,
        "factual_complete": factual_complete,
        "missing_sections": factual_missing
    }), 200


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/api/security-report/health",
    methods=["GET"]
)
def report_health():

    return jsonify({
        "status": "online",
        "service": "AI Security Report"
    }), 200


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print(
        "Starting AI Security Report API...",
        flush=True
    )

    app.run(
        host="127.0.0.1",
        port=5003,
        debug=False
    )