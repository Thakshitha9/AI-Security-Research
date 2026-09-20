from dataclasses import dataclass, field

from core.llm_client import LLMClient


SCENARIOS = ["banking", "it_support", "delivery", "ceo_fraud", "password_reset", "tax_refund"]
DIFFICULTIES = ["obvious", "moderate", "sophisticated"]


@dataclass
class PhishingEmail:
    sender: str = ""
    subject: str = ""
    body: str = ""
    scenario: str = ""
    difficulty: str = ""
    indicators: list[str] = field(default_factory=list)
    training_notes: str = ""


def generate_phishing_email(
    client: LLMClient,
    scenario: str = "banking",
    difficulty: str = "moderate",
) -> PhishingEmail:
    prompt = f"""Generate a simulated phishing email for a security awareness training exercise.

Scenario: {scenario}
Difficulty: {difficulty}
- obvious: many clear red flags (misspellings, urgency, suspicious links)
- moderate: some subtle indicators mixed with legitimate-looking elements
- sophisticated: very convincing with minimal obvious red flags

Generate the email, then analyze it. Use this exact format:

FROM: sender email address
SUBJECT: email subject line
BODY:
(the full email body)
END_BODY
INDICATORS: comma-separated list of phishing indicators present
TRAINING_NOTES: explanation of what makes this email suspicious (for security awareness training)"""

    response = client.generate(
        prompt,
        system_prompt=(
            "You are a security awareness training tool. Generate realistic but clearly "
            "fictional phishing emails for educational purposes only. All generated content "
            "must use obviously fake domains and names. Include a training analysis."
        ),
        temperature=0.7,
    )

    return _parse_generated_email(response, scenario, difficulty)


def _parse_generated_email(response: str, scenario: str, difficulty: str) -> PhishingEmail:
    email = PhishingEmail(scenario=scenario, difficulty=difficulty)
    lines = response.strip().split("\n")
    in_body = False
    body_lines = []

    for line in lines:
        if line.startswith("FROM:"):
            email.sender = line.split(":", 1)[1].strip()
        elif line.startswith("SUBJECT:"):
            email.subject = line.split(":", 1)[1].strip()
        elif line.startswith("BODY:"):
            in_body = True
        elif line.strip() == "END_BODY":
            in_body = False
        elif in_body:
            body_lines.append(line)
        elif line.startswith("INDICATORS:"):
            raw = line.split(":", 1)[1].strip()
            email.indicators = [i.strip() for i in raw.split(",") if i.strip()]
        elif line.startswith("TRAINING_NOTES:"):
            email.training_notes = line.split(":", 1)[1].strip()

    email.body = "\n".join(body_lines).strip()
    return email
