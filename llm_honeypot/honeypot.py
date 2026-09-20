import uuid
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.llm_client import LLMClient
from .personas import Persona
from .analyzer import AttackAnalyzer, TurnAnalysis
from .session_logger import SessionLogger

console = Console()

RISK_COLORS = {range(0, 20): "green", range(20, 50): "yellow", range(50, 80): "orange3", range(80, 101): "red"}


def _risk_color(score: int) -> str:
    for r, color in RISK_COLORS.items():
        if score in r:
            return color
    return "white"


def _risk_bar(score: int, width: int = 20) -> str:
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


class Honeypot:
    def __init__(self, persona: Persona, llm: LLMClient, show_analysis: bool = False):
        self.persona = persona
        self.llm = llm
        self.show_analysis = show_analysis
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        self.logger = SessionLogger(self.session_id, persona.name)
        self.analyzer = AttackAnalyzer(llm)
        self._history: list[dict] = []

    def _build_prompt(self, user_message: str) -> str:
        if not self._history:
            return user_message

        history_str = "\n".join(
            f"{'User' if t['role'] == 'user' else 'Assistant'}: {t['content']}"
            for t in self._history[-6:]
        )
        return f"Previous conversation:\n{history_str}\n\nUser: {user_message}"

    def respond(self, user_message: str) -> tuple[str, TurnAnalysis]:
        analysis = self.analyzer.analyze_turn(user_message)

        prompt = self._build_prompt(user_message)
        response = self.llm.generate(
            prompt,
            system_prompt=self.persona.system_prompt,
            temperature=0.7,
        )

        self._history.append({"role": "user", "content": user_message})
        self._history.append({"role": "assistant", "content": response})

        self.logger.log_turn(
            user_message=user_message,
            bot_response=response,
            detected_techniques=analysis.detected_techniques,
            risk_score=analysis.risk_score,
        )

        return response, analysis

    def print_banner(self) -> None:
        lures = "\n".join(f"  • {l}" for l in self.persona.lure_details)
        vuln_color = {"low": "green", "medium": "yellow", "high": "red"}.get(
            self.persona.vulnerability_level, "white"
        )
        console.print()
        console.print(
            Panel(
                f"[bold cyan]{self.persona.display_name}[/bold cyan]\n"
                f"[dim]{self.persona.description}[/dim]\n\n"
                f"[bold]Claimed access:[/bold]\n{lures}\n\n"
                f"[bold]Vulnerability level:[/bold] [{vuln_color}]{self.persona.vulnerability_level.upper()}[/{vuln_color}]\n"
                f"[dim]Session ID: {self.session_id}[/dim]",
                title="[bold red]⚠ LLM HONEYPOT ACTIVE[/bold red]",
                border_style="red",
            )
        )
        if self.show_analysis:
            console.print(
                "[dim italic]Analysis overlay enabled — attack techniques shown in real time[/dim italic]"
            )
        console.print(
            "[dim]Type your message to interact. Commands: [bold]/quit[/bold] to end session, "
            "[bold]/status[/bold] for session stats[/dim]\n"
        )

    def print_analysis_overlay(self, analysis: TurnAnalysis) -> None:
        if not analysis.detected_techniques:
            console.print("[dim]  ▸ No attack patterns detected[/dim]")
            return

        color = _risk_color(analysis.risk_score)
        techniques_str = ", ".join(analysis.detected_techniques)
        bar = _risk_bar(analysis.risk_score)

        console.print(
            f"  [bold {color}]▸ DETECTED:[/bold {color}] {techniques_str}  "
            f"Risk: [{color}]{bar}[/{color}] {analysis.risk_score}/100"
        )
        for mapping in analysis.mitre_mappings[:2]:
            console.print(
                f"    [dim cyan]MITRE ATLAS:[/dim cyan] [dim]{mapping['technique']}[/dim]"
            )

    def print_status(self) -> None:
        console.print(
            Panel(
                f"[bold]Session:[/bold] {self.session_id}\n"
                f"[bold]Persona:[/bold] {self.persona.display_name}\n"
                f"[bold]Turns:[/bold] {self.logger.turn_count}\n"
                f"[bold]Cumulative risk:[/bold] [{_risk_color(min(self.logger.cumulative_risk, 100))}]"
                f"{self.logger.cumulative_risk}[/]\n"
                f"[bold]Duration:[/bold] {datetime.now().strftime('%H:%M:%S')}",
                title="Session Status",
                border_style="cyan",
            )
        )

    def finalize(self) -> str:
        from .analyzer import SessionAnalysis
        from dataclasses import asdict

        turns = [
            {
                "turn_id": t.turn_id,
                "user_message": t.user_message,
                "detected_techniques": t.detected_techniques,
                "risk_score": t.risk_score,
            }
            for t in self.logger.session.turns
        ]

        profile = {}
        if turns:
            session_analysis = self.analyzer.analyze_session(turns)
            profile = {
                "sophistication": session_analysis.attacker_sophistication,
                "primary_objective": session_analysis.primary_objective,
                "mitre_tactics": session_analysis.mitre_tactics_observed,
                "technique_frequency": session_analysis.technique_frequency,
                "llm_summary": session_analysis.llm_summary,
                "recommendations": session_analysis.recommendations,
            }

        path = self.logger.finalize(attacker_profile=profile)
        return str(path)
