from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import re

from core.llm_client import LLMClient
from core.config import LLMProvider

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
CORS(app)


# ==========================================
# MySQL Configuration
# ==========================================

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "ai_security_user",
    "password": "",
    "database": "ai_security_platform"
}


# ==========================================
# MySQL Helper
# ==========================================

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# ==========================================
# Save Phishing Analysis
# ==========================================

def save_analysis_to_database(
    url,
    risk_score,
    indicators,
    ai_explanation
):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        query = """
            INSERT INTO phishing_analysis
            (
                url,
                risk_score,
                indicators,
                ai_explanation
            )
            VALUES (%s, %s, %s, %s)
        """

        indicators_text = ", ".join(indicators)

        values = (
            url,
            risk_score,
            indicators_text,
            ai_explanation
        )

        cursor.execute(query, values)

        connection.commit()

        print("Analysis saved to MySQL.")

    except mysql.connector.Error as e:

        print("MYSQL ERROR:", str(e))

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


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

    data = request.get_json()

    if not data or "url" not in data:

        return jsonify({
            "error": "URL is required"
        }), 400

    url = data["url"].strip()

    if not url:

        return jsonify({
            "error": "URL cannot be empty"
        }), 400


    # --------------------------------------
    # Step 1: Rule-Based URL Analysis
    # --------------------------------------

    analysis = analyze_url(url)


    # --------------------------------------
    # Step 2: AI Explanation
    # --------------------------------------

    try:

        client = LLMClient(
            LLMProvider.GEMINI
        )

        ai_explanation = generate_ai_explanation(
            client,
            analysis
        )

    except Exception as e:
        import traceback

        ai_explanation = (
            "AI explanation is currently unavailable. "
            "The rule-based URL analysis was completed successfully."
        )

        error_details = traceback.format_exc()

        with open("gemini_error.txt", "w", encoding="utf-8") as f:
            f.write(error_details)

    print("AI ERROR:", repr(e), flush=True)
    print("AI ERROR TYPE:", type(e).__name__, flush=True)
    print("AI ERROR MESSAGE:", repr(e), flush=True)
    traceback.print_exc()

    # --------------------------------------
    # Step 3: Save Result to MySQL
    # --------------------------------------

    save_analysis_to_database(
        analysis.url,
        analysis.risk_score,
        analysis.indicators,
        ai_explanation
    )


    # --------------------------------------
    # Step 4: Return Result
    # --------------------------------------

    return jsonify({

        "url": analysis.url,

        "risk_score": analysis.risk_score,

        "indicators": analysis.indicators,

        "ai_explanation": ai_explanation

    })


# ==========================================
# Dashboard Statistics
# ==========================================

@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )


        # --------------------------------------
        # Total analyses
        # --------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM phishing_analysis
        """)

        total = cursor.fetchone()["total"]


        # --------------------------------------
        # High-risk analyses
        # --------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS high_risk
            FROM phishing_analysis
            WHERE risk_score >= 70
        """)

        high_risk = cursor.fetchone()["high_risk"]


        # --------------------------------------
        # Medium-risk analyses
        # --------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS medium_risk
            FROM phishing_analysis
            WHERE risk_score >= 40
            AND risk_score < 70
        """)

        medium_risk = cursor.fetchone()["medium_risk"]


        # --------------------------------------
        # Low-risk analyses
        # --------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS low_risk
            FROM phishing_analysis
            WHERE risk_score < 40
        """)

        low_risk = cursor.fetchone()["low_risk"]


        # --------------------------------------
        # Recent analyses
        # --------------------------------------

        cursor.execute("""
            SELECT
                id,
                url,
                risk_score,
                created_at
            FROM phishing_analysis
            ORDER BY id DESC
            LIMIT 10
        """)

        recent_analyses = cursor.fetchall()


        # --------------------------------------
        # Convert datetime
        # --------------------------------------

        for item in recent_analyses:

            if item["created_at"]:

                item["created_at"] = (
                    item["created_at"].isoformat()
                )


        return jsonify({

            "total": total,

            "high_risk": high_risk,

            "medium_risk": medium_risk,

            "low_risk": low_risk,

            "recent_analyses": recent_analyses

        })


    except mysql.connector.Error as e:

        print("MYSQL ERROR:", str(e))

        return jsonify({
            "error": "Unable to fetch dashboard statistics"
        }), 500


    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ==========================================
# RAG Security Assistant
# ==========================================

@app.route("/api/rag/ask", methods=["POST"])
def ask_rag():

    data = request.get_json()


    # --------------------------------------
    # Validate request
    # --------------------------------------

    if not data or "question" not in data:

        return jsonify({
            "error": "Question is required"
        }), 400


    question = data["question"].strip()


    if not question:

        return jsonify({
            "error": "Question cannot be empty"
        }), 400


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


    except Exception as e:

        print("RAG ERROR:", str(e))

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
        debug=True
    )