from flask import Flask, request, jsonify

from core.llm_client import LLMClient
from core.config import LLMProvider
from core.history import save_module_analysis
from core.platform import (
    MAX_PROMPT_LENGTH,
    install_api_guards,
    recommendation_for_level,
    risk_level_from_score,
    validate_bounded_text,
)

from prompt_guard.detector import PromptGuard


app = Flask(__name__)
install_api_guards(app, max_bytes=100_000)


# ==========================================
# Prompt Guard API
# ==========================================

@app.route("/api/prompt-guard/scan", methods=["POST"])
def scan_prompt():

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or "text" not in data:
        return jsonify({
            "error": "Text is required"
        }), 400

    text = data["text"] if isinstance(data.get("text"), str) else ""
    text_error = validate_bounded_text(
        text,
        "Text",
        MAX_PROMPT_LENGTH,
    )

    if text_error:
        return jsonify({
            "error": text_error
        }), 400

    text = text.strip()

    try:

        # --------------------------------------
        # Initialize AI client
        # --------------------------------------

        llm_client = None

        try:

            llm_client = LLMClient(
                LLMProvider.HUGGINGFACE
            )

        except Exception:

            print(
                "Prompt Guard AI client unavailable.",
                flush=True,
            )

        # --------------------------------------
        # Initialize Prompt Guard
        # --------------------------------------

        guard = PromptGuard(
            llm_client=llm_client
        )

        # --------------------------------------
        # Scan
        # --------------------------------------

        result = guard.scan(
            text,
            use_llm=llm_client is not None
        )

        # --------------------------------------
        # AI Analysis
        # --------------------------------------

        ai_analysis = result.llm_assessment

        if not ai_analysis:

            ai_analysis = (
                "AI analysis was not available. "
                "The rule-based Prompt Guard "
                "analysis was completed."
            )

        # --------------------------------------
        # Clean Pattern Matches
        # --------------------------------------

        patterns = []

        for match in result.pattern_matches:

            patterns.append({

                "pattern_name":
                    match.pattern_name,

                "category":
                    match.category,

                "severity":
                    match.severity,

                "matched_text":
                    match.matched_text,

                "description":
                    match.description

            })

        risk_level = risk_level_from_score(
            result.risk_score,
            medium_at=30,
        )
        evidence = [
            pattern["matched_text"]
            for pattern in patterns
            if pattern.get("matched_text")
        ]

        if result.is_suspicious and evidence:
            finding = "Potential prompt injection"
        elif result.is_suspicious:
            finding = "Suspicious prompt content"
        else:
            finding = (
                "No significant prompt injection indicators "
                "were detected."
            )

        recommendation = (
            result.recommendation
            or recommendation_for_level(risk_level)
        )

        save_module_analysis(
            module="Prompt Guard",
            target=text[:120],
            risk_level=risk_level,
            risk_score=result.risk_score,
            finding=finding,
            evidence="; ".join(evidence[:8]),
            explanation=ai_analysis,
            recommendation=recommendation,
        )

        # --------------------------------------
        # Return Result
        # --------------------------------------

        return jsonify({

            "text": text,

            "risk_score":
                result.risk_score,

            "risk_level":
                risk_level,

            "suspicious":
                result.is_suspicious,

            "finding":
                finding,

            "evidence":
                evidence,

            "explanation":
                ai_analysis,

            "recommendation":
                recommendation,

            "pattern_matches":
                patterns,

            "ai_analysis":
                ai_analysis

        })

    except Exception:

        print(
            "Prompt Guard analysis failed.",
            flush=True,
        )

        return jsonify({
            "error": "Prompt Guard analysis failed"
        }), 500


# ==========================================
# Health Check
# ==========================================

@app.route(
    "/api/prompt-guard/health",
    methods=["GET"]
)
def prompt_guard_health():

    return jsonify({

        "status":
            "online",

        "service":
            "Prompt Guard"

    })


# ==========================================
# Run Server
# ==========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )