"""Optional MySQL history for analysis results.

The web APIs keep working when MySQL is offline. Connection failures
are logged by exception type only.
"""

import os
import re

PHISHING_MODULE = "Phishing Detection"

PHISHING_TABLE = """
CREATE TABLE IF NOT EXISTS phishing_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    risk_score INT NOT NULL,
    indicators TEXT,
    ai_explanation MEDIUMTEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS security_analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    module VARCHAR(64) NOT NULL,
    target VARCHAR(512) NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    risk_score INT NULL,
    finding TEXT,
    evidence TEXT,
    explanation MEDIUMTEXT,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def db_config() -> dict:
    port = os.getenv("MYSQL_PORT", "3306")

    try:
        port_number = int(port)
    except (TypeError, ValueError):
        port_number = 3306

    return {
        "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
        "port": port_number,
        "user": os.getenv("MYSQL_USER", "ai_security_user"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DATABASE", "ai_security_platform"),
        "connection_timeout": 3,
    }


def _clip(value, limit: int) -> str:
    if value is None:
        return ""
    return str(value)[:limit]


def _connect():
    import mysql.connector

    return mysql.connector.connect(**db_config())


def _log_db_problem(error):
    print(f"MYSQL ERROR: {type(error).__name__}", flush=True)


def ensure_schema(connection) -> None:
    cursor = connection.cursor()

    try:
        cursor.execute(PHISHING_TABLE)
        cursor.execute(HISTORY_TABLE)
        connection.commit()
    finally:
        cursor.close()


def save_phishing_analysis(
    url,
    risk_score,
    indicators,
    ai_explanation,
    risk_level,
    finding,
    evidence,
    recommendation,
) -> None:
    """Write the legacy phishing row and the shared history row."""

    connection = None

    try:
        connection = _connect()
        ensure_schema(connection)
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO phishing_analysis
                (url, risk_score, indicators, ai_explanation)
            VALUES (%s, %s, %s, %s)
            """,
            (
                _clip(url, 2048),
                int(risk_score),
                _clip(indicators, 4000),
                _clip(ai_explanation, 20000),
            ),
        )

        _insert_history(
            cursor,
            PHISHING_MODULE,
            url,
            risk_level,
            risk_score,
            finding,
            evidence,
            ai_explanation,
            recommendation,
        )

        connection.commit()
        cursor.close()

    except Exception as error:
        _log_db_problem(error)

    finally:
        if connection is not None:
            connection.close()


def save_module_analysis(
    module,
    target,
    risk_level,
    risk_score,
    finding,
    evidence,
    explanation,
    recommendation,
) -> None:
    """Store one non-phishing analysis. Failures stay on the server."""

    if module == PHISHING_MODULE:
        return

    connection = None

    try:
        connection = _connect()
        ensure_schema(connection)
        cursor = connection.cursor()
        _insert_history(
            cursor,
            module,
            target,
            risk_level,
            risk_score,
            finding,
            evidence,
            explanation,
            recommendation,
        )
        connection.commit()
        cursor.close()

    except Exception as error:
        _log_db_problem(error)

    finally:
        if connection is not None:
            connection.close()


def _insert_history(
    cursor,
    module,
    target,
    risk_level,
    risk_score,
    finding,
    evidence,
    explanation,
    recommendation,
):
    cursor.execute(
        """
        INSERT INTO security_analyses
            (
                module,
                target,
                risk_level,
                risk_score,
                finding,
                evidence,
                explanation,
                recommendation
            )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            _clip(module, 64),
            _clip(target, 512),
            _clip(risk_level, 16),
            int(risk_score) if risk_score is not None else None,
            _clip(finding, 4000),
            _clip(evidence, 4000),
            _clip(explanation, 20000),
            _clip(recommendation, 4000),
        ),
    )


def empty_dashboard(message: str) -> dict:
    return {
        "total": 0,
        "high_risk": 0,
        "medium_risk": 0,
        "low_risk": 0,
        "average_risk": None,
        "recent_analyses": [],
        "database": "unavailable",
        "message": message,
    }


def dashboard_snapshot() -> dict:
    """Counts and recent rows from stored analyses. Never raises."""

    unavailable = empty_dashboard(
        "Analysis history is unavailable because the database "
        "is not connected. Analyses can still run, but they "
        "will not be stored."
    )

    try:
        connection = _connect()
    except Exception as error:
        _log_db_problem(error)
        return unavailable

    try:
        ensure_schema(connection)
        phishing_rows = _safe_rows(
            connection,
            """
            SELECT id, url AS target, risk_score, indicators,
                   created_at
            FROM phishing_analysis
            ORDER BY id DESC
            LIMIT 10
            """,
            module=PHISHING_MODULE,
        )
        other_rows = _safe_rows(
            connection,
            """
            SELECT id, module, target, risk_level, risk_score,
                   finding, recommendation, created_at
            FROM security_analyses
            WHERE module <> %s
            ORDER BY id DESC
            LIMIT 10
            """,
            params=(PHISHING_MODULE,),
        )
        counts = _combined_counts(connection)
        recent = _merge_recent(phishing_rows, other_rows)

        return {
            "total": counts["total"],
            "high_risk": counts["high_risk"],
            "medium_risk": counts["medium_risk"],
            "low_risk": counts["low_risk"],
            "average_risk": counts["average_risk"],
            "recent_analyses": recent,
            "database": "online",
            "message": (
                "No analyses have been stored yet."
                if counts["total"] == 0
                else ""
            ),
        }

    except Exception as error:
        _log_db_problem(error)
        return empty_dashboard(
            "Analysis history could not be read. "
            "Check the MySQL configuration."
        )

    finally:
        connection.close()


def _combined_counts(connection) -> dict:
    count_sql = """
        COUNT(*) AS total,
        SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) AS high_risk,
        SUM(
            CASE
                WHEN risk_score >= 40 AND risk_score < 70 THEN 1
                ELSE 0
            END
        ) AS medium_risk,
        SUM(CASE WHEN risk_score < 40 THEN 1 ELSE 0 END) AS low_risk,
        SUM(CASE WHEN risk_score IS NULL THEN 0 ELSE risk_score END)
            AS score_total,
        SUM(CASE WHEN risk_score IS NULL THEN 0 ELSE 1 END) AS scored
    """
    phishing = _count_table(
        connection,
        f"SELECT {count_sql} FROM phishing_analysis",
    )
    other = _count_table(
        connection,
        f"""
        SELECT {count_sql}
        FROM security_analyses
        WHERE module <> %s
        """,
        params=(PHISHING_MODULE,),
    )

    total = phishing["total"] + other["total"]
    score_total = phishing["score_total"] + other["score_total"]
    scored = phishing["scored"] + other["scored"]

    average = None
    if scored:
        average = round(score_total / scored)

    return {
        "total": total,
        "high_risk": phishing["high_risk"] + other["high_risk"],
        "medium_risk": phishing["medium_risk"] + other["medium_risk"],
        "low_risk": phishing["low_risk"] + other["low_risk"],
        "average_risk": average,
    }


def _count_table(connection, query: str, params=()) -> dict:
    empty = {
        "total": 0,
        "high_risk": 0,
        "medium_risk": 0,
        "low_risk": 0,
        "score_total": 0,
        "scored": 0,
    }
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(query, params)
        row = cursor.fetchone() or {}
    except Exception as error:
        _log_db_problem(error)
        return empty
    finally:
        cursor.close()

    def as_int(name):
        value = row.get(name)
        return int(value or 0)

    return {
        "total": as_int("total"),
        "high_risk": as_int("high_risk"),
        "medium_risk": as_int("medium_risk"),
        "low_risk": as_int("low_risk"),
        "score_total": as_int("score_total"),
        "scored": as_int("scored"),
    }


def _safe_rows(connection, query: str, module=None, params=()):
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(query, params)
        rows = cursor.fetchall()
    except Exception:
        cursor.close()
        fallback = _without_timestamp(query)
        if fallback == query:
            return []
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(fallback, params)
            rows = cursor.fetchall()
        except Exception as error:
            _log_db_problem(error)
            return []
        finally:
            cursor.close()
    else:
        cursor.close()

    normalized = []

    for row in rows:
        created = row.get("created_at")
        if created is not None and hasattr(created, "isoformat"):
            created = created.isoformat()

        indicators = row.get("indicators") or ""
        finding = row.get("finding") or indicators

        normalized.append({
            "id": row.get("id"),
            "module": row.get("module") or module or "Analysis",
            "target": row.get("target") or "",
            "url": row.get("target") or "",
            "risk_score": row.get("risk_score"),
            "risk_level": row.get("risk_level"),
            "finding": finding,
            "recommendation": row.get("recommendation") or "",
            "created_at": created,
        })

    return normalized


def _without_timestamp(query: str) -> str:
    return re.sub(r",\s*created_at", "", query)


def _merge_recent(phishing_rows, other_rows):
    combined = list(phishing_rows) + list(other_rows)

    def sort_key(item):
        return (
            item.get("created_at") or "",
            item.get("id") or 0,
        )

    combined.sort(key=sort_key, reverse=True)
    return combined[:10]
