import json
import sqlite3
from datetime import datetime


DATABASE_NAME = "agentshield.db"


# =========================================
# CREATE / MIGRATE DATABASE
# =========================================

def create_database():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            status TEXT NOT NULL,
            detected_pattern TEXT,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at TEXT,
            threat_details TEXT,
            scan_type TEXT DEFAULT 'prompt'
        )
        """
    )


    # =====================================
    # CHECK EXISTING COLUMNS
    # =====================================

    cursor.execute(
        "PRAGMA table_info(scans)"
    )


    columns = cursor.fetchall()


    column_names = [
        column[1]
        for column
        in columns
    ]


    # =====================================
    # MIGRATE created_at
    # =====================================

    if (
        "created_at"
        not in column_names
    ):

        cursor.execute(
            """
            ALTER TABLE scans
            ADD COLUMN created_at TEXT
            """
        )


    # =====================================
    # MIGRATE threat_details
    # =====================================

    if (
        "threat_details"
        not in column_names
    ):

        cursor.execute(
            """
            ALTER TABLE scans
            ADD COLUMN threat_details TEXT
            """
        )


    # =====================================
    # MIGRATE scan_type
    # =====================================

    if (
        "scan_type"
        not in column_names
    ):

        cursor.execute(
            """
            ALTER TABLE scans
            ADD COLUMN scan_type TEXT
            DEFAULT 'prompt'
            """
        )


    # =====================================
    # FIX OLD TIMESTAMPS
    # =====================================

    migration_time = (
        datetime.now()
        .isoformat(
            timespec="seconds"
        )
    )


    cursor.execute(
        """
        UPDATE scans
        SET created_at = ?
        WHERE created_at IS NULL
           OR created_at = ''
        """,
        (
            migration_time,
        )
    )


    # =====================================
    # MARK OLD SCANS AS PROMPT SCANS
    # =====================================

    cursor.execute(
        """
        UPDATE scans
        SET scan_type = 'prompt'
        WHERE scan_type IS NULL
           OR scan_type = ''
        """
    )


    # =====================================
    # POLICY STATE TABLE
    # =====================================

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_states (
            policy_id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL
        )
        """
    )


    connection.commit()

    connection.close()


# =========================================
# SAVE SECURITY SCAN
# =========================================

def save_scan(
    prompt,
    status,
    detected_pattern,
    risk_score,
    severity,
    action,
    threat_details=None,
    scan_type="prompt",
):

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()


    created_at = (
        datetime.now()
        .isoformat(
            timespec="seconds"
        )
    )


    threat_details_json = json.dumps(
        threat_details or []
    )


    cursor.execute(
        """
        INSERT INTO scans (
            prompt,
            status,
            detected_pattern,
            risk_score,
            severity,
            action,
            created_at,
            threat_details,
            scan_type
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            prompt,
            status,
            detected_pattern,
            risk_score,
            severity,
            action,
            created_at,
            threat_details_json,
            scan_type,
        )
    )


    connection.commit()

    connection.close()


# =========================================
# GET ALL SCANS
# =========================================

def get_all_scans():

    connection = sqlite3.connect(
        DATABASE_NAME
    )


    connection.row_factory = (
        sqlite3.Row
    )


    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            id,
            prompt,
            status,
            detected_pattern,
            risk_score,
            severity,
            action,
            created_at,
            threat_details,
            scan_type
        FROM scans
        ORDER BY id DESC
        """
    )


    rows = cursor.fetchall()


    scans = []


    for row in rows:

        scan = dict(
            row
        )


        saved_details = (
            scan.get(
                "threat_details"
            )
        )


        if saved_details:

            try:

                scan[
                    "threat_details"
                ] = json.loads(
                    saved_details
                )

            except json.JSONDecodeError:

                scan[
                    "threat_details"
                ] = []

        else:

            scan[
                "threat_details"
            ] = []


        if not scan.get(
            "scan_type"
        ):

            scan[
                "scan_type"
            ] = "prompt"


        scans.append(
            scan
        )


    connection.close()


    return scans


# =========================================
# DELETE ONE SCAN
# =========================================

def delete_scan(
    scan_id: int
):

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        DELETE FROM scans
        WHERE id = ?
        """,
        (
            scan_id,
        )
    )


    deleted_count = (
        cursor.rowcount
    )


    connection.commit()

    connection.close()


    return (
        deleted_count > 0
    )


# =========================================
# CLEAR ALL SCANS
# =========================================

def clear_all_scans():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        DELETE FROM scans
        """
    )


    deleted_count = (
        cursor.rowcount
    )


    cursor.execute(
        """
        DELETE FROM sqlite_sequence
        WHERE name = 'scans'
        """
    )


    connection.commit()

    connection.close()


    return deleted_count


# =========================================
# DASHBOARD STATS
# =========================================

def get_dashboard_stats():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()


    # =====================================
    # ALL SCANS
    # =====================================

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        """
    )


    total_scans = (
        cursor.fetchone()[0]
    )


    # =====================================
    # THREATS
    # =====================================

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE status = 'dangerous'
        """
    )


    threats_detected = (
        cursor.fetchone()[0]
    )


    # =====================================
    # BLOCKED
    # =====================================

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE action = 'BLOCK'
        """
    )


    blocked_requests = (
        cursor.fetchone()[0]
    )


    # =====================================
    # SAFE
    # =====================================

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE status = 'safe'
        """
    )


    safe_requests = (
        cursor.fetchone()[0]
    )


    # =====================================
    # PROMPT SCANS
    # =====================================

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE scan_type = 'prompt'
        """
    )


    prompt_scans = (
        cursor.fetchone()[0]
    )


    # =====================================
    # URL SCANS
    # =====================================

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE scan_type = 'url'
        """
    )


    url_scans = (
        cursor.fetchone()[0]
    )


    # =====================================
    # NETWORK SCANS
    # =====================================

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE scan_type = 'network'
        """
    )


    network_scans = (
        cursor.fetchone()[0]
    )


    # =====================================
    # FILE SCANS
    # =====================================

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE scan_type = 'file'
        """
    )


    file_scans = (
        cursor.fetchone()[0]
    )


    connection.close()


    return {
        "total_scans":
            total_scans,

        "threats_detected":
            threats_detected,

        "blocked_requests":
            blocked_requests,

        "safe_requests":
            safe_requests,

        "prompt_scans":
            prompt_scans,

        "url_scans":
            url_scans,

        "network_scans":
            network_scans,

        "file_scans":
            file_scans,
    }


# =========================================
# INITIALIZE POLICY STATES
# =========================================

def initialize_policy_states(
    policies
):

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()


    for (
        policy_id,
        enabled,
    ) in policies:

        cursor.execute(
            """
            INSERT OR IGNORE INTO policy_states (
                policy_id,
                enabled
            )
            VALUES (?, ?)
            """,
            (
                policy_id,
                1 if enabled else 0,
            )
        )


    connection.commit()

    connection.close()


# =========================================
# GET POLICY STATES
# =========================================

def get_policy_states():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT
            policy_id,
            enabled
        FROM policy_states
        """
    )


    rows = cursor.fetchall()


    states = {

        policy_id:
            bool(enabled)

        for (
            policy_id,
            enabled,
        )
        in rows

    }


    connection.close()


    return states


# =========================================
# SAVE POLICY STATE
# =========================================

def save_policy_state(
    policy_id,
    enabled
):

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        INSERT INTO policy_states (
            policy_id,
            enabled
        )
        VALUES (?, ?)

        ON CONFLICT(policy_id)
        DO UPDATE SET
            enabled = excluded.enabled
        """,
        (
            policy_id,
            1 if enabled else 0,
        )
    )


    connection.commit()

    connection.close()