from flask import Flask, request, jsonify
from flask_cors import CORS

from core.llm_client import LLMClient
from core.config import LLMProvider

from prompt_guard.detector import PromptGuard


app = Flask(__name__)
CORS(app)


# ==========================================
# Prompt Guard API
# ==========================================

@app.route("/api/prompt-guard/scan", methods=["POST"])
def scan_prompt():

    data = request.get_json()

    if not data or "text" not in data:
        return jsonify({
            "error": "Text is required"
        }), 400

    text = data["text"].strip()

    if not text:
        return jsonify({
            "error": "Text cannot be empty"
        }), 400

    try:

        # --------------------------------------
        # Initialize AI client
        # --------------------------------------

        llm_client = None

        try:

            llm_client = LLMClient(
                LLMProvider.HUGGINGFACE
            )

        except Exception as e:

            print(
                "LLM CLIENT ERROR:",
                str(e)
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

        # --------------------------------------
        # Return Result
        # --------------------------------------

        return jsonify({

            "text": text,

            "risk_score":
                result.risk_score,

            "suspicious":
                result.is_suspicious,

            "recommendation":
                result.recommendation,

            "pattern_matches":
                patterns,

            "ai_analysis":
                ai_analysis

        })

    except Exception as e:

        print(
            "PROMPT GUARD ERROR:",
            str(e)
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