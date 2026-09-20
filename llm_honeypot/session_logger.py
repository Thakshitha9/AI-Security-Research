import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from core.config import REPORTS_DIR

SESSIONS_DIR = REPORTS_DIR / "honeypot_sessions"


@dataclass
class Turn:
    turn_id: int
    timestamp: str
    user_message: str
    bot_response: str
    detected_techniques: list[str] = field(default_factory=list)
    risk_score: int = 0


@dataclass
class Session:
    session_id: str
    persona: str
    started_at: str
    ended_at: str = ""
    turns: list[Turn] = field(default_factory=list)
    total_risk_score: int = 0
    attacker_profile: dict = field(default_factory=dict)


class SessionLogger:
    def __init__(self, session_id: str, persona: str):
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self.session = Session(
            session_id=session_id,
            persona=persona,
            started_at=datetime.now().isoformat(),
        )
        self._turn_counter = 0

    def log_turn(
        self,
        user_message: str,
        bot_response: str,
        detected_techniques: list[str] | None = None,
        risk_score: int = 0,
    ) -> Turn:
        self._turn_counter += 1
        turn = Turn(
            turn_id=self._turn_counter,
            timestamp=datetime.now().isoformat(),
            user_message=user_message,
            bot_response=bot_response,
            detected_techniques=detected_techniques or [],
            risk_score=risk_score,
        )
        self.session.turns.append(turn)
        self.session.total_risk_score += risk_score
        return turn

    def finalize(self, attacker_profile: dict | None = None) -> Path:
        self.session.ended_at = datetime.now().isoformat()
        self.session.attacker_profile = attacker_profile or {}

        path = SESSIONS_DIR / f"session_{self.session.session_id}.json"
        with open(path, "w") as f:
            json.dump(asdict(self.session), f, indent=2)
        return path

    @property
    def turn_count(self) -> int:
        return self._turn_counter

    @property
    def cumulative_risk(self) -> int:
        return self.session.total_risk_score
