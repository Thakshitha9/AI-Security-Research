from flask import Flask, request, jsonify
import re

from core.llm_client import LLMClient
from core.config import LLMProvider
from core.history import dashboard_snapshot, save_phishing_analysis
from core.platform import (
    install_api_guards,
    recommendation_for_level,
    risk_level_from_score,
    validate_bounded_text,
    validate_http_url,
    MAX_QUESTION_LENGTH,
)

from phishing_detector.url_analyzer import (
    analyze_url,
    generate_ai_explanation,
)

from pathlib import Path

from rag_poison_lab.store import VectorStore
from rag_poison_lab.evaluator import RAGEvaluator


DATASETS_DIR = (
    Path(__file__).resolve().parent
    / "rag_poison_lab"
    / "datasets"
)


app = Flask(__name__)
install_api_guards(app, max_bytes=100_000)


def save_analysis_to_database(
    url,
    risk_score,
    indicators,
    ai_explanation,
    risk_level,
    finding,
    evidence,
    recommendation,
):
    """Persist a phishing result. Storage failure does not fail the API."""

    save_phishing_analysis(
        url=url,
        risk_score=risk_score,
        indicators=", ".join(indicators),
        ai_explanation=ai_explanation,
        risk_level=risk_level,
        finding=finding,
        evidence=evidence,
        recommendation=recommendation,
    )


# ==========================================
# Health Check
# ==========================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "online",
        "service": "AI Security Platform"
    })


# ==========================================
# Phishing URL Analysis
# ==========================================

@app.route("/api/phishing/analyze", methods=["POST"])
def analyze_phishing_url():

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or "url" not in data:

        return jsonify({
            "error": "URL is required"
        }), 400

    url = data["url"].strip() if isinstance(data.get("url"), str) else ""

    url_error = validate_http_url(url)

    if url_error:

        return jsonify({
            "error": url_error
        }), 400


    # --------------------------------------
    # Step 1: Rule-Based URL Analysis
    # --------------------------------------

    analysis = analyze_url(url)


    # --------------------------------------
    # Step 2: AI Explanation
    # --------------------------------------

    ai_explanation = (
        "AI explanation is currently unavailable. "
        "The rule-based URL analysis was completed successfully."
    )

    try:

        client = LLMClient(
            LLMProvider.GEMINI
        )

        ai_explanation = generate_ai_explanation(
            client,
            analysis
        )

    except Exception:
        print("AI explanation unavailable.", flush=True)

    # --------------------------------------
    # Step 3: Save Result to MySQL
    # --------------------------------------

    risk_level = risk_level_from_score(analysis.risk_score)
    evidence = list(analysis.indicators)

    if evidence:
        finding = evidence[0]
    else:
        finding = (
            "No phishing indicators were detected by the rule checks."
        )

    recommendation = recommendation_for_level(risk_level)

    save_analysis_to_database(
        analysis.url,
        analysis.risk_score,
        analysis.indicators,
        ai_explanation,
        risk_level,
        finding,
        "; ".join(evidence),
        recommendation,
    )


    # --------------------------------------
    # Step 4: Return Result
    # --------------------------------------

    return jsonify({

        "url": analysis.url,

        "risk_score": analysis.risk_score,

        "risk_level": risk_level,

        "indicators": analysis.indicators,

        "finding": finding,

        "evidence": evidence,

        "explanation": ai_explanation,

        "recommendation": recommendation,

        "ai_explanation": ai_explanation

    })


# ==========================================
# Dashboard Statistics
# ==========================================

@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():

    snapshot = dashboard_snapshot()

    return jsonify(snapshot)


# ==========================================
# RAG Security Assistant
# ==========================================

@app.route("/api/rag/ask", methods=["POST"])
def ask_rag():

    data = request.get_json(silent=True)


    # --------------------------------------
    # Validate request
    # --------------------------------------

    if not isinstance(data, dict) or "question" not in data:

        return jsonify({
            "error": "Question is required"
        }), 400


    question = data["question"] if isinstance(data.get("question"), str) else ""

    question_error = validate_bounded_text(
        question,
        "Question",
        MAX_QUESTION_LENGTH,
    )

    if question_error:

        return jsonify({
            "error": question_error
        }), 400

    question = question.strip()


    try:

        # --------------------------------------
        # Initialize RAG system
        # --------------------------------------

        with LLMClient() as llm:

            store = VectorStore(
                collection_name="clean_demo",
                ephemeral=True
            )


            # --------------------------------------
            # Load knowledge base
            # --------------------------------------

            store.load_from_json(
                DATASETS_DIR
                / "knowledge_base.json"
            )


            # --------------------------------------
            # Create evaluator
            # --------------------------------------

            evaluator = RAGEvaluator(
                store,
                llm
            )


            # --------------------------------------
            # Retrieve + Generate
            # --------------------------------------

            response, retrieved = (
                evaluator.query_rag(question)
            )


            # --------------------------------------
            # Remove DeepSeek reasoning
            # --------------------------------------

            if "<think>" in response:

                # Case 1:
                # <think>...</think>Final answer

                if "</think>" in response:

                    response = response.split(
                        "</think>",
                        1
                    )[1]

                # Case 2:
                # Unclosed <think>...</think>
                # DeepSeek sometimes returns
                # an unclosed reasoning block.

                else:

                    match = re.search(
                        r"(Based solely\b.*)",
                        response,
                        flags=re.DOTALL
                    )

                    if match:

                        response = match.group(1)

                    else:

                        response = response.replace(
                            "<think>",
                            ""
                        )


            response = response.strip()


            # --------------------------------------
            # Retrieved documents
            # --------------------------------------

            documents = []


            for doc in retrieved:

                documents.append({

                    "source": doc[
                        "metadata"
                    ].get(
                        "source",
                        "Unknown"
                    ),

                    "text": doc["text"]

                })


        # --------------------------------------
        # Return RAG result
        # --------------------------------------

        return jsonify({

            "question": question,

            "answer": response,

            "retrieved_documents": documents

        })


    except Exception:

        print("RAG analysis failed.", flush=True)

        return jsonify({

            "error": "RAG analysis failed"

        }), 500


# ==========================================
# Run Flask Server
# ==========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )