from dataclasses import dataclass, field

from core.llm_client import LLMClient
from .parser import ScanData, Host


# Ports that are inherently high-risk when open
HIGH_RISK_PORTS = {
    21: "FTP — often allows anonymous access or cleartext credentials",
    23: "Telnet — cleartext protocol, highly insecure",
    25: "SMTP — can be abused for email relay",
    445: "SMB — common target for ransomware and lateral movement",
    3389: "RDP — brute force target, frequent exploit vector",
    5900: "VNC — often weak authentication",
    6379: "Redis — commonly exposed without authentication",
    27017: "MongoDB — frequently exposed without auth",
}


MEDIUM_RISK_PORTS = {
    22: "SSH — secure but brute-forceable",
    80: "HTTP — check for web vulnerabilities",
    443: "HTTPS — check for TLS misconfigurations",
    3306: "MySQL — should not be publicly exposed",
    5432: "PostgreSQL — should not be publicly exposed",
    8080: "HTTP Proxy — often misconfigured",
    8443: "HTTPS Alt — check for web vulnerabilities",
}


@dataclass
class Finding:
    port: int
    service: str
    risk_level: str
    description: str
    recommendation: str


@dataclass
class HostAnalysis:
    ip: str
    hostname: str
    risk_score: int
    findings: list[Finding] = field(default_factory=list)
    llm_analysis: str = ""


def analyze_scan(
    client: LLMClient,
    scan_data: ScanData
) -> list[HostAnalysis]:

    results = []

    for host in scan_data.hosts:

        if host.state != "up":
            continue

        analysis = _analyze_host(
            client,
            host
        )

        results.append(analysis)

    return results


def _analyze_host(
    client: LLMClient,
    host: Host
) -> HostAnalysis:

    findings = []

    risk_score = 0

    open_ports = [
        port
        for port in host.ports
        if port.state == "open"
    ]

    # ---------------------------------------------
    # Rule-based security analysis
    # ---------------------------------------------

    for port in open_ports:

        if port.number in HIGH_RISK_PORTS:

            findings.append(
                Finding(
                    port=port.number,
                    service=port.service,
                    risk_level="high",
                    description=HIGH_RISK_PORTS[port.number],
                    recommendation=(
                        f"Consider closing port {port.number} "
                        "or restricting access via firewall."
                    ),
                )
            )

            risk_score += 20

        elif port.number in MEDIUM_RISK_PORTS:

            findings.append(
                Finding(
                    port=port.number,
                    service=port.service,
                    risk_level="medium",
                    description=MEDIUM_RISK_PORTS[port.number],
                    recommendation=(
                        f"Ensure port {port.number} is properly "
                        "configured and access-controlled."
                    ),
                )
            )

            risk_score += 10

    # ---------------------------------------------
    # Prepare scan data for Gemini
    # ---------------------------------------------

    scan_summary = _format_host_for_llm(host)

    # ---------------------------------------------
    # AI security analysis
    # ---------------------------------------------

    llm_analysis = _generate_llm_analysis(
        client,
        scan_summary
    )

    # ---------------------------------------------
    # Final risk score
    # ---------------------------------------------

    risk_score = min(
        100,
        risk_score
    )

    return HostAnalysis(
        ip=host.ip,
        hostname=host.hostname,
        risk_score=risk_score,
        findings=findings,
        llm_analysis=llm_analysis,
    )


def _format_host_for_llm(
    host: Host
) -> str:

    lines = [
        f"Host: {host.ip} "
        f"({host.hostname or 'no hostname'})"
    ]

    if host.os:
        lines.append(
            f"OS: {host.os}"
        )

    lines.append("Open ports:")

    for port in host.ports:

        if port.state != "open":
            continue

        line = (
            f"  {port.number}/"
            f"{port.protocol} — "
            f"{port.service}"
        )

        if port.version:
            line += f" ({port.version})"

        lines.append(line)

        for script in port.scripts:

            lines.append(
                f"    Script: {script}"
            )

    return "\n".join(lines)

def _generate_llm_analysis(
    client: LLMClient,
    scan_summary: str
) -> str:

    prompt = f"""
You are assisting with defensive network security hardening.

Analyze the following Nmap scan from an authorized internal security lab.

Your task is to provide a defensive security summary for the system owner.

Focus on:

1. Exposed network services.
2. Services that should be reviewed or restricted.
3. Configuration and authentication concerns.
4. General security hardening recommendations.
5. Priorities for reducing unnecessary network exposure.

Do NOT provide exploit instructions, attack procedures, payloads,
or step-by-step methods for compromising the systems.

For each important observation, explain:
- What was detected.
- Why it matters from a defensive perspective.
- What the administrator should review or change.

End with a short prioritized hardening checklist.

Nmap scan:

{scan_summary}
""".strip()

    return client.generate(
        prompt,
        system_prompt=(
            "You are a defensive network security analyst. "
            "Your role is to help system administrators understand "
            "network exposure and improve security configuration. "
            "Provide safe, practical hardening recommendations. "
            "Do not provide exploitation instructions or attack procedures."
        ),
        temperature=0.3,
    )