import re
from dataclasses import dataclass


@dataclass
class PatternMatch:
    pattern_name: str
    category: str
    severity: str
    matched_text: str
    description: str


INJECTION_PATTERNS = {
    "override": {
        "severity": "high",
        "description": "Direct instruction override attempts",
        "patterns": [
            r"ignore (?:all )?(?:previous|prior|above) (?:instructions|rules|guidelines)",
            r"disregard (?:all )?(?:previous|prior|your) (?:instructions|rules|programming)",
            r"forget (?:all )?(?:previous|prior|your) (?:instructions|rules)",
            r"new instructions?:?\s",
            r"override (?:previous|your|all) (?:instructions|rules|settings)",
            r"(?:stop|cease) following (?:previous|your|all) (?:instructions|rules)",
        ],
    },
    "roleplay": {
        "severity": "high",
        "description": "Roleplay-based jailbreak attempts",
        "patterns": [
            r"you are now (?:DAN|an unrestricted|a free|an unfiltered)",
            r"pretend (?:you are|to be|you're) (?:an? )?(?:unrestricted|unfiltered|evil|hacker)",
            r"act as (?:an? )?(?:unrestricted|unfiltered|DAN|jailbroken)",
            r"enter (?:developer|debug|unrestricted|god) mode",
            r"do anything now",
            r"opposite day",
            r"hypothetical (?:AI|scenario|world) (?:with|where) no (?:restrictions|rules|limits)",
        ],
    },
    "extraction": {
        "severity": "critical",
        "description": "System prompt extraction attempts",
        "patterns": [
            r"(?:reveal|show|tell|output|print|display) (?:your |the )?(?:system )?(?:prompt|instructions|configuration|rules)",
            r"what (?:are|is) your (?:system )?(?:prompt|instructions|original instructions|programming|rules)",
            r"(?:repeat|echo|recite) (?:your |the )?(?:system )?(?:prompt|instructions)",
            r"(?:beginning|start) of (?:your |the )?(?:conversation|system prompt|instructions)",
            r"full (?:system )?(?:prompt|instructions|configuration)",
        ],
    },
    "delimiter": {
        "severity": "medium",
        "description": "Delimiter and boundary manipulation",
        "patterns": [
            r"---\s*END\s*(?:OF\s*)?SYSTEM\s*PROMPT\s*---",
            r"---\s*(?:BEGIN|START)\s*(?:USER|NEW)\s*(?:MESSAGE|INSTRUCTIONS?)\s*---",
            r"\[SYSTEM\]",
            r"\[/SYSTEM\]",
            r"<\s*system\s*>",
            r"</\s*system\s*>",
            r"```\s*system",
        ],
    },
    "encoding": {
        "severity": "medium",
        "description": "Encoded or obfuscated instructions",
        "patterns": [
            r"(?:decode|decipher|decrypt) (?:this|the following) (?:base64|rot13|hex|encoded)",
            r"(?:base64|rot13|hex)[\s:]+[A-Za-z0-9+/=]{20,}",
            r"execute (?:the )?(?:decoded|decrypted|hidden) (?:instruction|command|message)",
        ],
    },
    "authority": {
        "severity": "high",
        "description": "Authority impersonation attempts",
        "patterns": [
            r"(?:message|request|order) from (?:the )?(?:admin|developer|OpenAI|Anthropic|system|CEO)",
            r"(?:admin|developer|system|maintenance) (?:override|access|mode|command)",
            r"(?:urgent|emergency|critical) (?:message|request|update) from",
            r"for (?:debugging|testing|maintenance) purposes",
            r"(?:safety|content) (?:module|filter|system) (?:offline|disabled|bypassed)",
        ],
    },
}


def scan_patterns(text: str) -> list[PatternMatch]:
    matches = []
    text_lower = text.lower()

    for category, info in INJECTION_PATTERNS.items():
        for pattern in info["patterns"]:
            for m in re.finditer(pattern, text_lower):
                matches.append(
                    PatternMatch(
                        pattern_name=pattern[:50],
                        category=category,
                        severity=info["severity"],
                        matched_text=m.group(),
                        description=info["description"],
                    )
                )

    return matches
