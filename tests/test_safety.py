"""Safety checks for validation and API error handling."""

import unittest
from unittest.mock import patch

from core.platform import (
    recommendation_for_level,
    reject_unsafe_xml,
    risk_level_from_score,
    validate_bounded_text,
    validate_http_url,
)
from core.history import empty_dashboard


class ValidationTests(unittest.TestCase):
    def test_accepts_http_url(self):
        self.assertIsNone(validate_http_url("https://example.com/login"))

    def test_rejects_non_http_and_empty_urls(self):
        self.assertIsNotNone(validate_http_url(""))
        self.assertIsNotNone(validate_http_url("javascript:alert(1)"))
        self.assertIsNotNone(validate_http_url("file:///etc/passwd"))
        self.assertIsNotNone(validate_http_url("http://"))

    def test_rejects_entity_xml(self):
        self.assertIsNotNone(
            reject_unsafe_xml("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>")
        )
        self.assertIsNotNone(reject_unsafe_xml("<html></html>"))
        self.assertIsNone(reject_unsafe_xml("<nmaprun></nmaprun>"))

    def test_risk_labels_follow_scores(self):
        self.assertEqual(risk_level_from_score(0), "INFO")
        self.assertEqual(risk_level_from_score(10), "LOW")
        self.assertEqual(risk_level_from_score(40), "MEDIUM")
        self.assertEqual(risk_level_from_score(70), "HIGH")
        self.assertIn("caution", recommendation_for_level("MEDIUM").lower())

    def test_text_limit(self):
        self.assertIsNotNone(validate_bounded_text("x" * 20, "Question", 10))
        self.assertIsNone(validate_bounded_text("hello", "Question", 10))


class ApiSafetyTests(unittest.TestCase):
    def test_phishing_rejects_bad_url_without_calling_the_model(self):
        import api

        with patch("api.generate_ai_explanation") as explain:
            response = api.app.test_client().post(
                "/api/phishing/analyze",
                json={"url": "javascript:alert(1)"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("traceback", response.get_json()["error"].lower())
        explain.assert_not_called()

    def test_phishing_returns_rule_result_when_ai_fails(self):
        import api

        with patch("api.generate_ai_explanation", side_effect=RuntimeError("secret key sk-test")), \
             patch("api.save_analysis_to_database"):
            response = api.app.test_client().post(
                "/api/phishing/analyze",
                json={"url": "http://203.0.113.10/login"},
            )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["risk_level"], "MEDIUM")
        self.assertIn("IP address", " ".join(body["evidence"]))
        self.assertNotIn("sk-test", response.get_data(as_text=True))
        self.assertTrue(body["recommendation"])

    def test_dashboard_stays_up_when_database_is_down(self):
        import api

        with patch("api.dashboard_snapshot", return_value=empty_dashboard("offline")):
            response = api.app.test_client().get("/api/dashboard/stats")

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["total"], 0)
        self.assertIsNone(body["average_risk"])
        self.assertEqual(body["recent_analyses"], [])

    def test_recon_hides_exception_details(self):
        import recon_ai_api

        with patch("recon_ai_api.parse_nmap_xml", side_effect=RuntimeError("password=secret")):
            response = recon_ai_api.app.test_client().post(
                "/api/recon/analyze",
                json={"xml": "<nmaprun><host></host></nmaprun>"},
            )

        text = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("password", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("error_type", text)


class FactualReportTests(unittest.TestCase):
    def test_report_lists_only_supplied_findings(self):
        from security_report_api import build_factual_report

        report = build_factual_report({
            "hosts": [
                {
                    "ip": "192.0.2.10",
                    "hostname": "lab-host",
                    "risk_score": 80,
                    "findings": [
                        {
                            "port": 23,
                            "service": "telnet",
                            "risk_level": "high",
                            "description": "Telnet accepts cleartext login.",
                            "recommendation": "Restrict TCP 23.",
                        }
                    ],
                }
            ]
        })

        self.assertIn("192.0.2.10", report)
        self.assertIn("Telnet accepts cleartext login.", report)
        self.assertIn("Restrict TCP 23.", report)
        self.assertIn("## Executive Summary", report)
        self.assertIn("## Assessment Details", report)
        self.assertIn("## Risk Level", report)
        self.assertIn("## Findings", report)
        self.assertIn("## Evidence", report)
        self.assertIn("## Recommendations", report)
        self.assertIn("## Limitations", report)
        self.assertIn("## Timestamp", report)
        self.assertIn("Severity: HIGH", report)
        self.assertNotIn("10.1.1.1", report)

    def test_report_survives_model_failure_without_leaking_it(self):
        import security_report_api

        class BrokenClient:
            def __enter__(self):
                raise RuntimeError("provider failed key=sk-live-secret-value")

            def __exit__(self, *args):
                return False

        with patch("security_report_api.LLMClient", return_value=BrokenClient()):
            response = security_report_api.app.test_client().post(
                "/api/security-report/generate",
                json={
                    "hosts": [
                        {
                            "ip": "192.0.2.20",
                            "findings": [
                                {
                                    "port": 22,
                                    "service": "ssh",
                                    "risk_level": "medium",
                                    "description": "SSH is exposed.",
                                    "recommendation": "Limit SSH sources.",
                                }
                            ],
                        }
                    ]
                },
            )

        body = response.get_json()
        text = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["status"], "success")
        self.assertIn("SSH is exposed.", body["report"])
        self.assertEqual(
            body["message"],
            "AI-generated narrative was unavailable. "
            "The factual security assessment is shown below.",
        )
        self.assertEqual(body["narrative_status"], "unavailable")
        self.assertEqual(body["report_status"], "generated")
        self.assertTrue(body["complete"])
        self.assertTrue(body["factual_complete"])
        self.assertEqual(body["view"]["findings"][0]["severity"], "MEDIUM")
        self.assertNotIn("sk-live-secret-value", text)
        self.assertNotIn("llm_analysis", body["report"])

        from pathlib import Path

        if body.get("filename"):
            saved = Path("reports/security") / body["filename"]
            if saved.exists():
                saved.unlink()

    def test_empty_assessment_is_reported_without_invented_findings(self):
        from security_report_api import build_factual_report

        report = build_factual_report({"hosts": []})

        self.assertIn("did not include any hosts", report)
        self.assertIn("No findings were present", report)
        self.assertIn("do not prove that a system was compromised", report)
        self.assertNotIn("Telnet", report)
        self.assertNotIn("Port 22", report)

    def test_incomplete_assessment_is_labeled(self):
        from security_report_api import build_factual_report

        report = build_factual_report({"status": "success"})

        self.assertIn("incomplete", report)
        self.assertIn("did not include a host list", report)

    def test_invalid_report_input_is_rejected(self):
        import security_report_api

        client = security_report_api.app.test_client()

        empty = client.post(
            "/api/security-report/generate",
            json={},
        )
        invalid = client.post(
            "/api/security-report/generate",
            data="not-json",
            content_type="application/json",
        )

        rejected_list = client.post(
            "/api/security-report/generate",
            json=[],
        )

        self.assertEqual(empty.status_code, 400)
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(rejected_list.status_code, 400)
        self.assertNotIn("traceback", empty.get_data(as_text=True).lower())
        self.assertNotIn("traceback", invalid.get_data(as_text=True).lower())
        self.assertNotIn("traceback", rejected_list.get_data(as_text=True).lower())

    def test_multiple_findings_stay_separate(self):
        from security_report_api import build_factual_report

        report = build_factual_report({
            "hosts": [
                {
                    "ip": "192.0.2.30",
                    "findings": [
                        {
                            "port": 21,
                            "service": "ftp",
                            "risk_level": "high",
                            "description": "FTP is exposed.",
                            "recommendation": "Close FTP.",
                        },
                        {
                            "port": 80,
                            "service": "http",
                            "risk_level": "medium",
                            "description": "HTTP is exposed.",
                            "recommendation": "Review the web service.",
                        },
                    ],
                }
            ]
        })

        self.assertIn("### 1. Port 21 / ftp", report)
        self.assertIn("### 2. Port 80 / http", report)
        self.assertIn("FTP is exposed.", report)
        self.assertIn("HTTP is exposed.", report)
        self.assertIn("- Critical: 0", report)
        self.assertIn("- High: 1", report)
        self.assertIn("- Medium: 1", report)
        self.assertIn("- Low: 0", report)
        self.assertIn("- Informational: 0", report)
        self.assertIn("- Findings: 2", report)

    def test_severity_counts_match_supplied_findings(self):
        from security_report_api import build_report_package

        package = build_report_package({
            "hosts": [
                {
                    "ip": "192.0.2.40",
                    "findings": [
                        {
                            "port": 23,
                            "service": "telnet",
                            "risk_level": "critical",
                            "description": "Cleartext administration.",
                            "recommendation": "Remove Telnet.",
                        },
                        {
                            "port": 443,
                            "service": "https",
                            "risk_level": "info",
                            "description": "HTTPS is present.",
                            "recommendation": "Review the certificate.",
                        },
                    ],
                }
            ]
        })

        counts = package["view"]["severity_counts"]
        self.assertEqual(package["view"]["finding_count"], 2)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"], 0)
        self.assertEqual(counts["MEDIUM"], 0)
        self.assertEqual(counts["LOW"], 0)
        self.assertEqual(counts["INFO"], 1)
        self.assertIn("Cleartext administration.", package["markdown"])
        self.assertIn("Review the certificate.", package["markdown"])

    def test_empty_findings_have_zero_severity_counts(self):
        from security_report_api import build_report_package

        package = build_report_package({"hosts": []})
        counts = package["view"]["severity_counts"]

        self.assertEqual(package["view"]["finding_count"], 0)
        self.assertEqual(sum(counts.values()), 0)

    def test_gemini_success_appends_narrative_without_replacing_findings(self):
        import security_report_api

        class WorkingClient:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        narrative = "## Assessment Summary\n\nNarrative for the supplied host only.\n"

        with patch("security_report_api.LLMClient", return_value=WorkingClient()), \
             patch("security_report_api.generate_security_report", return_value=narrative):
            response = security_report_api.app.test_client().post(
                "/api/security-report/generate",
                json={
                    "hosts": [
                        {
                            "ip": "192.0.2.50",
                            "findings": [
                                {
                                    "port": 22,
                                    "service": "ssh",
                                    "risk_level": "low",
                                    "description": "SSH remains in the factual report.",
                                    "recommendation": "Keep the factual recommendation.",
                                }
                            ],
                        }
                    ]
                },
            )

        body = response.get_json()
        report = body["report"]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["narrative_status"], "available")
        self.assertTrue(body["complete"])
        self.assertTrue(body["factual_complete"])
        self.assertIn("AI-generated narrative is included", body["message"])
        self.assertIn("SSH remains in the factual report.", report)
        self.assertIn("Narrative for the supplied host only.", report)
        self.assertLess(
            report.index("SSH remains in the factual report."),
            report.index("## AI-generated narrative"),
        )
        self.assertNotIn("sk-live-secret-value", response.get_data(as_text=True))

        from pathlib import Path

        if body.get("filename"):
            saved = Path("reports/security") / body["filename"]
            if saved.exists():
                saved.unlink()

    def test_long_finding_content_is_preserved(self):
        from security_report_api import build_report_package

        description = ("D" * 500) + "DESCRIPTION-TAIL"
        recommendation = ("R" * 500) + "RECOMMENDATION-TAIL"
        evidence = ("E" * 500) + "EVIDENCE-TAIL"
        package = build_report_package({
            "hosts": [
                {
                    "ip": "192.0.2.60",
                    "findings": [
                        {
                            "port": 22,
                            "service": "ssh",
                            "risk_level": "low",
                            "description": description,
                            "recommendation": recommendation,
                            "evidence": evidence,
                        }
                    ],
                }
            ]
        })

        finding = package["view"]["findings"][0]
        report = package["markdown"]
        self.assertEqual(finding["detail"], description)
        self.assertEqual(finding["recommendation"], recommendation)
        self.assertEqual(finding["evidence"], evidence)
        self.assertGreater(len(description), 500)
        self.assertGreater(len(recommendation), 500)
        self.assertGreater(len(evidence), 500)
        self.assertIn("DESCRIPTION-TAIL", report)
        self.assertIn("RECOMMENDATION-TAIL", report)
        self.assertIn("EVIDENCE-TAIL", report)
        self.assertEqual(package["view"]["finding_count"], 1)

    def test_empty_findings_list_is_not_a_security_finding(self):
        import security_report_api

        class BrokenClient:
            def __enter__(self):
                raise RuntimeError("provider failed key=sk-live-secret-value")

            def __exit__(self, *args):
                return False

        with patch("security_report_api.LLMClient", return_value=BrokenClient()):
            response = security_report_api.app.test_client().post(
                "/api/security-report/generate",
                json={
                    "hosts": [
                        {
                            "ip": "192.0.2.70",
                            "risk_level": "high",
                            "findings": [],
                        }
                    ]
                },
            )

        body = response.get_json()
        report = body["report"]
        counts = body["view"]["severity_counts"]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["view"]["finding_count"], 0)
        self.assertEqual(body["view"]["findings"], [])
        self.assertEqual(sum(counts.values()), 0)
        self.assertEqual(body["view"]["hosts_without_findings"], ["192.0.2.70"])
        self.assertIn("192.0.2.70", body["view"]["finding_status"])
        self.assertIn("not a discovered security finding", body["view"]["finding_status"])
        self.assertIn("No findings were present", report)
        self.assertNotIn("### 1.", report)
        self.assertNotIn("Severity:", report)
        self.assertNotIn("No port or service evidence was present.", report)
        self.assertNotIn("sk-live-secret-value", response.get_data(as_text=True))
        self.assertTrue(body["complete"])
        self.assertTrue(body["factual_complete"])
        self.assertEqual(body["narrative_status"], "unavailable")
        self.assertEqual(
            body["message"],
            "AI-generated narrative was unavailable. "
            "The factual security assessment is shown below.",
        )

        from pathlib import Path

        if body.get("filename"):
            saved = Path("reports/security") / body["filename"]
            if saved.exists():
                saved.unlink()

    def test_factual_completeness_does_not_require_gemini(self):
        import security_report_api

        class BrokenClient:
            def __enter__(self):
                raise RuntimeError("provider failed key=sk-live-secret-value")

            def __exit__(self, *args):
                return False

        client = security_report_api.app.test_client()

        with patch("security_report_api.LLMClient", return_value=BrokenClient()):
            ready = client.post(
                "/api/security-report/generate",
                json={
                    "hosts": [
                        {
                            "ip": "192.0.2.80",
                            "findings": [
                                {
                                    "port": 443,
                                    "service": "https",
                                    "risk_level": "info",
                                    "description": "HTTPS was observed.",
                                    "recommendation": "Review the certificate.",
                                }
                            ],
                        }
                    ]
                },
            )
            incomplete = client.post(
                "/api/security-report/generate",
                json={"status": "success"},
            )

        ready_body = ready.get_json()
        incomplete_body = incomplete.get_json()
        self.assertEqual(ready.status_code, 200)
        self.assertTrue(ready_body["complete"])
        self.assertTrue(ready_body["factual_complete"])
        self.assertEqual(ready_body["missing_sections"], [])
        self.assertEqual(ready_body["narrative_status"], "unavailable")
        self.assertIn("HTTPS was observed.", ready_body["report"])
        self.assertEqual(
            ready_body["message"],
            "AI-generated narrative was unavailable. "
            "The factual security assessment is shown below.",
        )
        self.assertEqual(incomplete.status_code, 200)
        self.assertFalse(incomplete_body["complete"])
        self.assertFalse(incomplete_body["factual_complete"])
        self.assertIn("host list", incomplete_body["missing_sections"])
        self.assertEqual(incomplete_body["narrative_status"], "unavailable")
        self.assertEqual(
            incomplete_body["message"],
            "AI-generated narrative was unavailable. "
            "The factual security assessment is shown below.",
        )
        combined = ready.get_data(as_text=True) + incomplete.get_data(as_text=True)
        self.assertNotIn("sk-live-secret-value", combined)
        self.assertNotIn("traceback", combined.lower())

        from pathlib import Path

        for payload in (ready_body, incomplete_body):
            if payload.get("filename"):
                saved = Path("reports/security") / payload["filename"]
                if saved.exists():
                    saved.unlink()


class ProviderErrorTests(unittest.TestCase):
    def test_gemini_failure_hides_the_request_and_response(self):
        from core.config import LLMProvider
        from core.llm_client import LLMClient

        secret = "sk-live-secret-value"

        class Response:
            status_code = 401
            text = "denied " + secret

            def json(self):
                return {"error": secret}

        class Client:
            def post(self, url, **kwargs):
                self.url = url
                self.kwargs = kwargs
                return Response()

            def close(self):
                pass

        llm = LLMClient(LLMProvider.GEMINI)
        llm._client = Client()

        with self.assertRaises(RuntimeError) as caught:
            llm.generate("hello", temperature=0)

        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("key=", str(caught.exception))

    def test_prompt_guard_hides_model_errors(self):
        from prompt_guard.detector import PromptGuard

        class BrokenModel:
            def generate(self, *args, **kwargs):
                raise RuntimeError("provider failed key=sk-live-secret-value")

        result = PromptGuard(llm_client=BrokenModel()).scan(
            "hello",
            use_llm=True,
        )

        self.assertNotIn("sk-live-secret-value", result.llm_assessment)
        self.assertIn("unavailable", result.llm_assessment.lower())

    def test_report_fallback_does_not_log_the_exception_text(self):
        import contextlib
        import io

        from security_report_api import generate_section_with_fallback

        class BrokenModel:
            def generate(self, *args, **kwargs):
                raise RuntimeError("provider failed key=sk-live-secret-value")

        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            content = generate_section_with_fallback(
                BrokenModel(),
                "1. Executive Summary",
                "Use only the supplied data.",
                {"hosts": []},
                max_retries=1,
            )

        self.assertTrue(content.strip())
        self.assertNotIn("sk-live-secret-value", output.getvalue())


if __name__ == "__main__":
    unittest.main()
