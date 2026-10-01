"""Shared validation and local API guards.

These helpers do not fetch user-supplied URLs and do not return
exception text to browsers.
"""

import os
import re
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048
MAX_PROMPT_LENGTH = 8000
MAX_QUESTION_LENGTH = 2000
MAX_XML_CHARS = 2_000_000
MAX_REPORT_CHARS = 500_000

_LOCAL_ORIGIN = re.compile(
    r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    re.IGNORECASE,
)


def risk_level_from_score(score, medium_at=40, high_at=70) -> str:
    """Map a numeric score to a label. Unknown scores stay UNKNOWN."""

    try:
        value = int(score)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if value >= high_at:
        return "HIGH"
    if value >= medium_at:
        return "MEDIUM"
    if value > 0:
        return "LOW"
    return "INFO"


def recommendation_for_level(level: str) -> str:
    """Defensive next step based only on the calculated risk label."""

    if level == "HIGH":
        return (
            "Do not enter credentials, open attachments, or trust this "
            "result as a verified compromise. Review the evidence and "
            "confirm the target through an official channel."
        )
    if level == "MEDIUM":
        return (
            "Treat the result with caution. Confirm the target before "
            "continuing, and do not submit sensitive information."
        )
    if level == "LOW":
        return (
            "Few indicators were found. This is not proof that the "
            "target is safe. Verify it before sharing credentials."
        )
    if level == "INFO":
        return (
            "No rule-based indicators were found. This does not prove "
            "the target is safe."
        )
    return "No recommendation could be derived from the analysis."


def validate_http_url(url) -> str | None:
    """Return an error message, or None when the URL may be analyzed."""

    if not isinstance(url, str):
        return "URL must be a string."

    candidate = url.strip()

    if not candidate:
        return "URL cannot be empty."

    if len(candidate) > MAX_URL_LENGTH:
        return f"URL exceeds the {MAX_URL_LENGTH} character limit."

    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return "URL contains invalid control characters."

    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in {"http", "https"}:
        return "Only http and https URLs can be analyzed."

    if not parsed.hostname:
        return "URL must include a hostname."

    return None


def validate_bounded_text(value, field_name: str, limit: int) -> str | None:
    """Return an error message, or None when the text is usable."""

    if not isinstance(value, str):
        return f"{field_name} must be a string."

    text = value.strip()

    if not text:
        return f"{field_name} cannot be empty."

    if len(text) > limit:
        return f"{field_name} exceeds the {limit} character limit."

    return None


def reject_unsafe_xml(xml_data) -> str | None:
    """Reject empty, oversized, or entity-bearing XML before parsing."""

    if not isinstance(xml_data, str):
        return "XML data must be a string."

    xml_data = xml_data.strip()

    if not xml_data:
        return "Nmap XML data cannot be empty."

    if len(xml_data) > MAX_XML_CHARS:
        return "Nmap XML exceeds the size limit."

    prefix = xml_data[:8000].lower()

    if "<!doctype" in prefix or "<!entity" in prefix:
        return "XML entity declarations are not allowed."

    if "<nmaprun" not in prefix and "<host" not in prefix:
        return "Only Nmap XML scan results can be analyzed."

    return None


def configure_local_cors(app):
    """Allow the local web UI, including pages opened from disk."""

    from flask_cors import CORS

    origins = [
        _LOCAL_ORIGIN.pattern,
        r"^null$",
    ]

    extra = os.getenv("CORS_EXTRA_ORIGINS", "")

    for item in extra.split(","):
        item = item.strip()
        if item:
            origins.append(item)

    CORS(app, resources={r"/api/*": {"origins": origins}})


def install_api_guards(app, max_bytes: int):
    """Limit request size and hide unhandled exception details."""

    from flask import jsonify
    from werkzeug.exceptions import HTTPException

    app.config["MAX_CONTENT_LENGTH"] = max_bytes
    configure_local_cors(app)

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "Request is too large."}), 413

    @app.errorhandler(Exception)
    def unhandled(error):
        if isinstance(error, HTTPException):
            return error

        print(
            f"UNHANDLED {type(error).__name__}",
            flush=True,
        )

        return jsonify({
            "error": "The request could not be completed."
        }), 500
