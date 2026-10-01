
from flask import Flask, request, jsonify

from core.llm_client import LLMClient
from core.config import LLMProvider
from core.history import save_module_analysis
from core.platform import (
    install_api_guards,
    reject_unsafe_xml,
    risk_level_from_score,
)

from recon_ai.parser import parse_nmap_xml
from recon_ai.analyzer import analyze_scan

import tempfile
import os
import xml.etree.ElementTree as ET


app = Flask(__name__)
install_api_guards(app, max_bytes=2_500_000)


def _store_recon_history(hosts):
    """Store a short summary. The uploaded XML is not kept."""

    if not hosts:
        save_module_analysis(
            module="Recon AI",
            target="Nmap XML upload",
            risk_level="INFO",
            risk_score=0,
            finding="The scan did not contain any hosts.",
            evidence="",
            explanation="",
            recommendation=(
                "No recommendation was returned because "
                "the scan had no hosts."
            ),
        )
        return

    scores = [
        int(host.get("risk_score") or 0)
        for host in hosts
    ]
    top_score = max(scores) if scores else 0
    level = risk_level_from_score(top_score)
    addresses = [
        host.get("ip")
        for host in hosts
        if host.get("ip")
    ]
    top_finding = "Exposed services were observed."
    top_recommendation = ""

    for host in hosts:
        for finding in host.get("findings") or []:
            if not top_recommendation and finding.get("recommendation"):
                top_recommendation = finding["recommendation"]
            if finding.get("description"):
                top_finding = finding["description"]
                break

    save_module_analysis(
        module="Recon AI",
        target=", ".join(addresses[:5]) or "Nmap XML upload",
        risk_level=level,
        risk_score=top_score,
        finding=top_finding,
        evidence=f"{len(hosts)} host(s) in the uploaded scan",
        explanation="",
        recommendation=top_recommendation or (
            "No recommendation was returned by the analysis."
        ),
    )


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

    xml_error = reject_unsafe_xml(xml_data)

    if xml_error:
        print("ERROR: XML rejected")

        return jsonify({
            "error": xml_error
        }), 400

    xml_data = xml_data.strip()

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

        print("Temporary XML file created.")

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

        _store_recon_history(hosts)

        # --------------------------------------
        # Return Result
        # --------------------------------------

        print("6. Sending successful response")

        response = {
            "status": "success",
            "host_count": len(hosts),
            "hosts": hosts,
        }

        if not hosts:
            response["message"] = (
                "The scan did not contain any hosts."
            )

        return jsonify(response), 200

    except ET.ParseError:
        return jsonify({
            "error": "Nmap XML could not be parsed."
        }), 400

    except ValueError as error:
        message = str(error)
        if "Nmap XML" not in message:
            message = "Nmap XML could not be analyzed."

        return jsonify({
            "error": message
        }), 400

    except Exception:
        print("RECON AI ERROR", flush=True)

        return jsonify({
            "error": "Recon AI analysis failed"
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