import sqlite3
from pathlib import Path


# ---------------------------------------------------------
# DATABASE LOCATION
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "agentshield.db"


# ---------------------------------------------------------
# CREATE FILE REPUTATION TABLE
# ---------------------------------------------------------

def init_reputation_database():
    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS file_reputation (
            sha256 TEXT PRIMARY KEY,
            filename TEXT NOT NULL,

            first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            times_seen INTEGER NOT NULL DEFAULT 1,

            last_status TEXT NOT NULL,
            last_risk_score INTEGER NOT NULL,
            last_severity TEXT NOT NULL,
            last_action TEXT NOT NULL,

            highest_risk_score INTEGER NOT NULL,
            highest_action TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# LOOK UP FILE BY SHA-256
# ---------------------------------------------------------

def get_file_reputation(sha256):
    connection = sqlite3.connect(DB_PATH)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM file_reputation
        WHERE sha256 = ?
        """,
        (sha256,),
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return None

    return dict(row)


# ---------------------------------------------------------
# SAVE / UPDATE FILE REPUTATION
# ---------------------------------------------------------

def save_file_reputation(
    sha256,
    filename,
    status,
    risk_score,
    severity,
    action,
):
    existing = get_file_reputation(sha256)

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    if existing is None:
        cursor.execute(
            """
            INSERT INTO file_reputation (
                sha256,
                filename,
                last_status,
                last_risk_score,
                last_severity,
                last_action,
                highest_risk_score,
                highest_action
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sha256,
                filename,
                status,
                risk_score,
                severity,
                action,
                risk_score,
                action,
            ),
        )

    else:
        highest_risk_score = max(
            existing["highest_risk_score"],
            risk_score,
        )

        if risk_score >= existing["highest_risk_score"]:
            highest_action = action
        else:
            highest_action = existing["highest_action"]

        cursor.execute(
            """
            UPDATE file_reputation
            SET
                filename = ?,
                last_seen = CURRENT_TIMESTAMP,
                times_seen = times_seen + 1,
                last_status = ?,
                last_risk_score = ?,
                last_severity = ?,
                last_action = ?,
                highest_risk_score = ?,
                highest_action = ?
            WHERE sha256 = ?
            """,
            (
                filename,
                status,
                risk_score,
                severity,
                action,
                highest_risk_score,
                highest_action,
                sha256,
            ),
        )

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# DATABASE STATS
# ---------------------------------------------------------

def get_reputation_stats():
    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM file_reputation
        """
    )

    total_known_files = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM file_reputation
        WHERE highest_action = 'BLOCK'
        """
    )

    blocked_files = cursor.fetchone()[0]

    connection.close()

    return {
        "total_known_files": total_known_files,
        "blocked_files": blocked_files,
    }


# ---------------------------------------------------------
# INITIALIZE DATABASE
# ---------------------------------------------------------

init_reputation_database()