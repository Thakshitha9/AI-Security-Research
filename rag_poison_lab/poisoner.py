import json
from dataclasses import dataclass, field
from pathlib import Path

from .store import VectorStore

DATASETS_DIR = Path(__file__).parent / "datasets"

TECHNIQUE_DESCRIPTIONS = {
    "direct_override": "Injects explicit instructions that override the LLM's original behavior",
    "indirect_injection": "Hides malicious instructions inside seemingly legitimate policy documents",
    "context_hijacking": "Floods the retrieved context with repeated false statements to dominate the LLM's attention",
    "role_reassignment": "Attempts to redefine the AI assistant's identity or activate a 'privileged mode'",
    "trigger_based": "Embeds conditional instructions that activate only when specific keywords are present",
}


@dataclass
class PoisonResult:
    technique: str
    payloads_injected: int
    payload_ids: list[str] = field(default_factory=list)


class Poisoner:
    def __init__(self, store: VectorStore):
        self.store = store
        self._payloads: list[dict] = []

    def load_payloads(self, path: str | Path | None = None) -> list[dict]:
        path = path or DATASETS_DIR / "poison_payloads.json"
        with open(path) as f:
            self._payloads = json.load(f)
        return self._payloads

    def get_techniques(self) -> list[str]:
        return list(TECHNIQUE_DESCRIPTIONS.keys())

    def get_technique_description(self, technique: str) -> str:
        return TECHNIQUE_DESCRIPTIONS.get(technique, "Unknown technique")

    def inject_all(self) -> PoisonResult:
        if not self._payloads:
            self.load_payloads()

        injected = []
        for payload in self._payloads:
            doc = {
                "id": payload["id"],
                "text": payload["text"],
                "metadata": {**payload.get("metadata", {}), "poisoned": "true", "technique": payload["technique"]},
            }
            self.store.add_documents([doc])
            injected.append(payload["id"])

        return PoisonResult(
            technique="all",
            payloads_injected=len(injected),
            payload_ids=injected,
        )

    def inject_technique(self, technique: str) -> PoisonResult:
        if not self._payloads:
            self.load_payloads()

        matching = [p for p in self._payloads if p["technique"] == technique]
        if not matching:
            raise ValueError(f"No payloads found for technique: {technique}")

        injected = []
        for payload in matching:
            doc = {
                "id": payload["id"],
                "text": payload["text"],
                "metadata": {**payload.get("metadata", {}), "poisoned": "true", "technique": technique},
            }
            self.store.add_documents([doc])
            injected.append(payload["id"])

        return PoisonResult(
            technique=technique,
            payloads_injected=len(injected),
            payload_ids=injected,
        )

    def get_probes_for_technique(self, technique: str) -> list[dict]:
        if not self._payloads:
            self.load_payloads()

        probes = []
        for payload in self._payloads:
            if payload["technique"] == technique:
                for q in payload.get("probe_questions", []):
                    probes.append(
                        {
                            "question": q,
                            "payload_id": payload["id"],
                            "success_indicators": payload.get("success_indicators", []),
                        }
                    )
        return probes

    def get_all_probes(self) -> list[dict]:
        if not self._payloads:
            self.load_payloads()

        probes = []
        for payload in self._payloads:
            for q in payload.get("probe_questions", []):
                probes.append(
                    {
                        "question": q,
                        "technique": payload["technique"],
                        "payload_id": payload["id"],
                        "success_indicators": payload.get("success_indicators", []),
                    }
                )
        return probes
