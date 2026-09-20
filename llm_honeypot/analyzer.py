import json
import re
from dataclasses import dataclass, field

from core.llm_client import LLMClient

# MITRE ATLAS tactic mapping for AI-targeted attacks
MITRE_ATLAS_TACTICS = {
    "prompt_injection": {
        "tactic": "ML Attack Staging",
        "technique": "AML.T0051 — LLM Prompt Injection",
        "description": "Attacker injects instructions into the prompt to override system behavior",
    },
    "jailbreak": {
        "tactic": "ML Attack Staging",
        "technique": "AML.T0054 — LLM Jailbreak",
        "description": "Attacker bypasses safety filters through roleplay, personas, or encoding tricks",
    },
    "system_prompt_extraction": {
        "tactic": "Reconnaissance",
        "technique": "AML.T0056 — LLM Meta-Prompt Extraction",
        "description": "Attacker attempts to reveal the system prompt or internal instructions",
    },
    "credential_extraction": {
        "tactic": "Exfiltration",
        "technique": "AML.T0058 — Exfiltration via ML Inference API",
        "description": "Attacker attempts to extract credentials, secrets, or sensitive data",
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique": "AML.T0057 — LLM Plugin Compromise",
        "description": "Attacker tries to escalate permissions or activate elevated-privilege modes",
    },
    "social_engineering": {
        "tactic": "Initial Access",
        "technique": "AML.T0049 — Exploit Public-Facing ML Application",
        "description": "Attacker uses social manipulation to coerce the AI into policy violations",
    },
    "reconnaissance": {
        "tactic": "Reconnaissance",
        "technique": "AML.T0000 — AI System Discovery",
        "description": "Attacker probes the system to understand its capabilities, access, and constraints",
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique": "AML.T0058 — Data Exfiltration via LLM",
        "description": "Attacker attempts to extract database records, PII, or internal data",
    },
}

# Regex-based quick detection patterns (fast, no LLM needed)
QUICK_PATTERNS: dict[str, list[str]] = {
    "prompt_injection": [
        r"ignore (previous|prior|all|above) instructions?",
        r"disregard (your|the) (previous|system|original)",
        r"forget (everything|all|your instructions)",
        r"new instructions?:",
        r"override (mode|system|instructions?)",
        r"\[system\]",
        r"<\|system\|>",
    ],
    "jailbreak": [
        r"\bdan\b",
        r"do anything now",
        r"jailbreak",
        r"unrestricted (mode|ai|assistant)",
        r"no (restrictions?|limits?|filters?|rules?)",
        r"pretend (you|you're|you are) (a|an|not|without)",
        r"act as (if|though) you (have|are|can|don't)",
        r"developer mode",
        r"god mode",
    ],
    "system_prompt_extraction": [
        r"(show|reveal|print|display|repeat|output|tell me) (your|the) (system|original|initial|first) prompt",
        r"what (are|were) (your|the) instructions?",
        r"what (is|was) (in|your) (the )?system prompt",
        r"repeat (everything|all|your) (above|before|prior)",
        r"output (the )?text (above|before|at the top)",
    ],
    "credential_extraction": [
        r"(password|passwd|credentials?|api[_ ]?key|secret[_ ]?key|token|auth)",
        r"(login|username|user[_ ]name|account)",
        r"(database|db) (password|credentials?|connection)",
        r"(private|secret|confidential) (key|data|info)",
        r"(give|show|tell|provide|share) (me )?(the )?(admin|root|access|full)",
    ],
    "privilege_escalation": [
        r"(sudo|root|admin|elevated|privileged|superuser) (mode|access|privileges?)",
        r"(activate|enable|switch to) (admin|debug|dev|test|unrestricted|maintenance) mode",
        r"(bypass|skip|disable) (security|restrictions?|filters?|checks?|guardrails?)",
        r"you (now have|have been granted|are now|are operating with) (full|elevated|admin)",
    ],
    "social_engineering": [
        r"(trust me|i promise|i'm authorized|i have permission)",
        r"(my (boss|manager|cto|ceo)|the (director|head of)) (said|told|asked)",
        r"this is (urgent|an emergency|critical|time[- ]sensitive)",
        r"(between us|just this once|no one will know|off the record)",
        r"(i'm (an? )?(it|security|admin|developer|engineer))",
    ],
    "reconnaissance": [
        r"(what|which) (systems?|databases?|tools?|apis?|access) do you have",
        r"(what|how much) (can|are you able to|do you) (access|see|read|connect)",
        r"(list|enumerate|show) (all|your|the) (capabilities|functions?|permissions?|access)",
        r"(are you|can you) (connected to|integrated with|linked to)",
    ],
    "data_exfiltration": [
        r"(show|give|export|dump|extract|list) (all |some )?(customer|user|employee|client) (data|records?|info|details)",
        r"(how many|list) (customers?|users?|employees?|accounts?)",
        r"(pii|personal (data|information)|ssn|social security|credit card|payment)",
        r"(first \d+|sample|example) (records?|rows?|entries?|users?|customers?)",
    ],
}


@dataclass
class TurnAnalysis:
    detected_techniques: list[str]
    risk_score: int
    mitre_mappings: list[dict]
    llm_analysis: dict = field(default_factory=dict)


@dataclass
class SessionAnalysis:
    technique_frequency: dict[str, int]
    total_risk_score: int
    peak_risk_turn: int
    attacker_sophistication: str
    primary_objective: str
    mitre_tactics_observed: list[str]
    llm_summary: str
    recommendations: list[str]


RISK_WEIGHTS = {
    "credential_extraction": 25,
    "data_exfiltration": 25,
    "privilege_escalation": 20,
    "system_prompt_extraction": 15,
    "prompt_injection": 15,
    "jailbreak": 15,
    "social_engineering": 10,
    "reconnaissance": 5,
}


class AttackAnalyzer:
    def __init__(self, llm: LLMClient):
        self.llm = llm

    def analyze_turn(self, user_message: str) -> TurnAnalysis:
        detected = self._quick_detect(user_message)
        risk_score = sum(RISK_WEIGHTS.get(t, 5) for t in detected)
        risk_score = min(risk_score, 100)

        mitre_mappings = [
            MITRE_ATLAS_TACTICS[t] for t in detected if t in MITRE_ATLAS_TACTICS
        ]

        return TurnAnalysis(
            detected_techniques=detected,
            risk_score=risk_score,
            mitre_mappings=mitre_mappings,
        )

    def _quick_detect(self, message: str) -> list[str]:
        message_lower = message.lower()
        detected = []
        for technique, patterns in QUICK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    detected.append(technique)
                    break
        return detected

    def analyze_session(self, turns: list[dict]) -> SessionAnalysis:
        technique_freq: dict[str, int] = {}
        total_risk = 0
        peak_risk = 0
        peak_turn = 0

        for i, turn in enumerate(turns, 1):
            for technique in turn.get("detected_techniques", []):
                technique_freq[technique] = technique_freq.get(technique, 0) + 1
            risk = turn.get("risk_score", 0)
            total_risk += risk
            if risk > peak_risk:
                peak_risk = risk
                peak_turn = i

        # Determine sophistication
        unique_techniques = len(technique_freq)
        if unique_techniques >= 4 or total_risk >= 80:
            sophistication = "Advanced"
        elif unique_techniques >= 2 or total_risk >= 40:
            sophistication = "Intermediate"
        else:
            sophistication = "Novice"

        # Determine primary objective
        objective_priority = [
            "credential_extraction", "data_exfiltration", "privilege_escalation",
            "system_prompt_extraction", "jailbreak", "prompt_injection",
            "social_engineering", "reconnaissance"
        ]
        primary_objective = "Unknown"
        for obj in objective_priority:
            if technique_freq.get(obj, 0) > 0:
                primary_objective = obj.replace("_", " ").title()
                break

        # Unique MITRE tactics
        mitre_tactics = list({
            MITRE_ATLAS_TACTICS[t]["tactic"]
            for t in technique_freq
            if t in MITRE_ATLAS_TACTICS
        })

        # LLM deep analysis
        llm_summary = self._llm_session_summary(turns, technique_freq, sophistication)

        recommendations = self._generate_recommendations(technique_freq)

        return SessionAnalysis(
            technique_frequency=technique_freq,
            total_risk_score=total_risk,
            peak_risk_turn=peak_turn,
            attacker_sophistication=sophistication,
            primary_objective=primary_objective,
            mitre_tactics_observed=mitre_tactics,
            llm_summary=llm_summary,
            recommendations=recommendations,
        )

    def _llm_session_summary(
        self, turns: list[dict], technique_freq: dict, sophistication: str
    ) -> str:
        conversation = "\n".join(
            f"[Turn {t['turn_id']}] User: {t['user_message'][:120]}"
            for t in turns
        )
        prompt = (
            f"Analyze this honeypot session log. Attacker sophistication: {sophistication}.\n"
            f"Detected techniques: {json.dumps(technique_freq)}.\n\n"
            f"Conversation:\n{conversation}\n\n"
            "Write a 3-4 sentence threat intelligence summary: "
            "What was the attacker trying to do? What techniques did they use? "
            "How sophisticated were they? What is the likely attacker profile?"
        )
        try:
            return self.llm.generate(
                prompt,
                system_prompt="You are a threat intelligence analyst reviewing honeypot logs.",
                temperature=0.4,
            )
        except Exception:
            return "LLM analysis unavailable."

    def _generate_recommendations(self, technique_freq: dict) -> list[str]:
        recs = []
        if "prompt_injection" in technique_freq or "jailbreak" in technique_freq:
            recs.append("Implement input sanitization and prompt injection detection on all LLM-powered endpoints")
        if "system_prompt_extraction" in technique_freq:
            recs.append("Use system prompt confidentiality measures and output filtering to prevent meta-prompt leakage")
        if "credential_extraction" in technique_freq or "data_exfiltration" in technique_freq:
            recs.append("Enforce strict data access controls — LLM tools should never have direct access to credentials or PII")
        if "privilege_escalation" in technique_freq:
            recs.append("Apply least-privilege principles to AI tool integrations — no elevated permissions for conversational AI")
        if "social_engineering" in technique_freq:
            recs.append("Train AI systems to recognize and resist social engineering patterns regardless of claimed identity")
        if not recs:
            recs.append("Continue monitoring — no high-severity techniques observed in this session")
        return recs
