
from flask import Flask, request, jsonify
from flask_cors import CORS

from core.llm_client import LLMClient
from core.config import LLMProvider

from pathlib import Path
from datetime import datetime
import json
import re
import traceback
import time


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)
CORS(app)

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
                f"{type(error).__name__}: {error}",
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
            f"{type(last_error).__name__}: {last_error}",
            flush=True
        )

    return fallback_content(
        title=title,
        scan_data=scan_data
    )


# ============================================================
# GENERATE COMPLETE REPORT
# ============================================================

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

    print(
        "Received security report request.",
        flush=True
    )

    try:

        print(
            "Initializing Gemini client...",
            flush=True
        )

        with LLMClient(LLMProvider.GEMINI) as llm:

            report = generate_security_report(
                client=llm,
                scan_data=data
            )

        validation = validate_report(report)

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = f"security_report_{timestamp}.md"

        report_path = REPORTS_DIR / filename

        report_path.write_text(
            report,
            encoding="utf-8"
        )

        print(
            f"Report saved successfully: {report_path}",
            flush=True
        )

        print(
            f"Report complete: {validation['complete']}",
            flush=True
        )

        if validation["missing_sections"]:

            print(
                "Missing sections:",
                validation["missing_sections"],
                flush=True
            )

        return jsonify({
            "status": "success",
            "message": "Security report generated successfully.",
            "filename": filename,
            "report": report,
            "complete": validation["complete"],
            "missing_sections": validation["missing_sections"]
        }), 200

    except Exception as error:

        print(
            "\nSECURITY REPORT ERROR",
            flush=True
        )

        print(
            f"Error type: {type(error).__name__}",
            flush=True
        )

        print(
            f"Error message: {error}",
            flush=True
        )

        traceback.print_exc()

        return jsonify({
            "status": "error",
            "error": (
                "Security report generation failed. "
                "Check the security_report_api.py terminal."
            ),
            "error_type": type(error).__name__
        }), 500


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