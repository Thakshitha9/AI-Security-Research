from dataclasses import dataclass, field

from core.llm_client import LLMClient


@dataclass
class ClassificationResult:
    label: str  # "phishing" or "legitimate"
    confidence: int  # 0-100
    indicators: list[str] = field(default_factory=list)
    reasoning: str = ""


def classify_message(
    client: LLMClient,
    body: str,
    sender: str = "",
    subject: str = "",
) -> ClassificationResult:
    prompt_parts = []
    if sender:
        prompt_parts.append(f"From: {sender}")
    if subject:
        prompt_parts.append(f"Subject: {subject}")
    prompt_parts.append(f"Body:\n{body}")
    message_text = "\n".join(prompt_parts)

    prompt = f"""Analyze the following message and classify it as either PHISHING or LEGITIMATE.

{message_text}

Respond in this exact format:
LABEL: PHISHING or LEGITIMATE
CONFIDENCE: 0-100
INDICATORS: comma-separated list of suspicious indicators (or "none" if legitimate)
REASONING: one-two sentence explanation"""

    response = client.generate(
        prompt,
        system_prompt=(
            "You are a cybersecurity email analyst specializing in phishing detection. "
            "Analyze messages for phishing indicators: urgency, misspelled domains, "
            "generic greetings, suspicious links, authority impersonation, financial requests, "
            "threatening language. Be thorough but avoid false positives."
        ),
        temperature=0.1,
    )

    return _parse_classification(response)


def classify_batch(
    client: LLMClient,
    messages: list[dict],
) -> list[ClassificationResult]:
    results = []
    for msg in messages:
        result = classify_message(
            client,
            body=msg.get("body", ""),
            sender=msg.get("sender", ""),
            subject=msg.get("subject", ""),
        )
        results.append(result)
    return results


def _parse_classification(response: str) -> ClassificationResult:
    label = "unknown"
    confidence = 50
    indicators = []
    reasoning = ""

    for line in response.strip().split("\n"):
        line = line.strip()
        if line.startswith("LABEL:"):
            raw = line.split(":", 1)[1].strip().lower()
            if "phishing" in raw:
                label = "phishing"
            elif "legitimate" in raw:
                label = "legitimate"
        elif line.startswith("CONFIDENCE:"):
            try:
                confidence = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("INDICATORS:"):
            raw = line.split(":", 1)[1].strip()
            if raw.lower() != "none":
                indicators = [i.strip() for i in raw.split(",") if i.strip()]
        elif line.startswith("REASONING:"):
            reasoning = line.split(":", 1)[1].strip()

    return ClassificationResult(
        label=label,
        confidence=confidence,
        indicators=indicators,
        reasoning=reasoning,
    )
