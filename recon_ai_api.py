
from flask import Flask, request, jsonify
from flask_cors import CORS

from core.llm_client import LLMClient
from core.config import LLMProvider

from recon_ai.parser import parse_nmap_xml
from recon_ai.analyzer import analyze_scan

import tempfile
import os
import traceback


app = Flask(__name__)
CORS(app)


# ==========================================
# Recon AI API
# ==========================================

@app.route("/api/recon/analyze", methods=["POST"])
def recon_analyze():

    print("\n========== RECON REQUEST RECEIVED ==========")

    data = request.get_json(silent=True)

    if not data or "xml" not in data:
        print("ERROR: Nmap XML data is missing")

        return jsonify({
            "error": "Nmap XML data is required"
        }), 400

    xml_data = data["xml"]

    if not isinstance(xml_data, str):
        print("ERROR: XML data is not a string")

        return jsonify({
            "error": "XML data must be a string"
        }), 400

    xml_data = xml_data.strip()

    if not xml_data:
        print("ERROR: XML data is empty")

        return jsonify({
            "error": "Nmap XML data cannot be empty"
        }), 400

    temp_path = None

    try:

        # --------------------------------------
        # Save XML temporarily
        # --------------------------------------

        print("1. Saving XML temporarily...")

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".xml",
            delete=False,
            encoding="utf-8"
        ) as temp_file:

            temp_file.write(xml_data)
            temp_path = temp_file.name

        print(f"XML saved at: {temp_path}")

        # --------------------------------------
        # Parse Nmap XML
        # --------------------------------------

        print("2. Parsing Nmap XML...")

        scan_data = parse_nmap_xml(temp_path)

        print("XML parsing completed")
        print(f"Parsed scan data type: {type(scan_data)}")

        # --------------------------------------
        # Initialize LLM
        # --------------------------------------

        print("3. Initializing Gemini LLM...")

        with LLMClient(LLMProvider.GEMINI) as llm:

            print("Gemini LLM initialized")
            print("4. Running Recon AI analysis...")

            results = analyze_scan(
                llm,
                scan_data
            )

        print("Recon AI analysis completed")
        print(f"Results type: {type(results)}")

        # --------------------------------------
        # Format Results
        # --------------------------------------

        print("5. Formatting results...")

        hosts = []

        for result in results:

            findings = []

            for finding in result.findings:

                findings.append({

                    "port": finding.port,

                    "service": finding.service,

                    "risk_level": finding.risk_level,

                    "description": finding.description,

                    "recommendation": finding.recommendation

                })

            hosts.append({

                "ip": result.ip,

                "hostname": result.hostname,

                "risk_score": result.risk_score,

                "findings": findings,

                "llm_analysis": result.llm_analysis

            })

        print(f"Formatted {len(hosts)} hosts")

        # --------------------------------------
        # Return Result
        # --------------------------------------

        print("6. Sending successful response")

        return jsonify({

            "status": "success",

            "host_count": len(hosts),

            "hosts": hosts

        }), 200

    except Exception as e:

        print("\n========== RECON AI ERROR ==========")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")

        traceback.print_exc()

        print("====================================\n")

        return jsonify({

            "error": "Recon AI analysis failed",

            "details": str(e),

            "error_type": type(e).__name__

        }), 500

    finally:

        # --------------------------------------
        # Delete temporary XML file
        # --------------------------------------

        if temp_path:

            try:

                os.remove(temp_path)

                print("Temporary XML file deleted")

            except OSError as cleanup_error:

                print(
                    "Temporary file cleanup failed:",
                    str(cleanup_error)
                )


# ==========================================
# Health Check
# ==========================================

@app.route("/api/recon/health", methods=["GET"])
def recon_health():

    return jsonify({

        "status": "online",

        "service": "Recon AI"

    }), 200


# ==========================================
# Run Server
# ==========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5002,
        debug=False
    )