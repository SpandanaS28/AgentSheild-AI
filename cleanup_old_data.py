import shutil
import sqlite3


DATABASE_NAME = "agentshield.db"
BACKUP_NAME = "agentshield_backup.db"


# =========================================
# BACK UP DATABASE FIRST
# =========================================

shutil.copyfile(
    DATABASE_NAME,
    BACKUP_NAME
)

print("Backup created: agentshield_backup.db")


# =========================================
# CONNECT TO DATABASE
# =========================================

connection = sqlite3.connect(
    DATABASE_NAME
)

cursor = connection.cursor()


# =========================================
# FIX OLD THREAT NAME
# =========================================

cursor.execute(
    """
    UPDATE scans
    SET detected_pattern = 'Secret Extraction'
    WHERE detected_pattern = 'reveal password'
    """
)


updated_rows = cursor.rowcount


connection.commit()

connection.close()


# =========================================
# FINISHED
# =========================================

print(
    f"Cleanup complete. Updated {updated_rows} old scan(s)."
)