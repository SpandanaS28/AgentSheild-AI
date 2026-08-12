import file_scanner


# =========================================
# FAKE LOCAL REPUTATION DATABASE
#
# These tests do NOT modify your real
# agentshield.db database.
# =========================================

fake_reputation_store = {}


def fake_get_file_reputation(sha256):
    return fake_reputation_store.get(sha256)


def fake_save_file_reputation(
    sha256,
    filename,
    status,
    risk_score,
    severity,
    action,
):
    existing = fake_reputation_store.get(sha256)

    if existing is None:
        fake_reputation_store[sha256] = {
            "sha256": sha256,
            "filename": filename,
            "first_seen": "test-time",
            "last_seen": "test-time",
            "times_seen": 1,
            "last_status": status,
            "last_risk_score": risk_score,
            "last_severity": severity,
            "last_action": action,
            "highest_risk_score": risk_score,
            "highest_action": action,
        }

        return

    existing["times_seen"] += 1
    existing["last_status"] = status
    existing["last_risk_score"] = risk_score
    existing["last_severity"] = severity
    existing["last_action"] = action

    if risk_score >= existing["highest_risk_score"]:
        existing["highest_risk_score"] = risk_score
        existing["highest_action"] = action


# =========================================
# FAKE DEFENDER RESULTS
# =========================================

def fake_clean_defender(filename, content):
    return {
        "available": True,
        "checked": True,
        "engine": "Microsoft Defender Antivirus",
        "status": "clean",
        "threat_detected": False,
        "message": (
            "Microsoft Defender completed the scan "
            "and found no threats."
        ),
    }


def fake_detected_defender(filename, content):
    return {
        "available": True,
        "checked": True,
        "engine": "Microsoft Defender Antivirus",
        "status": "detected",
        "threat_detected": True,
        "message": (
            "Microsoft Defender reported "
            "a possible threat."
        ),
    }


# =========================================
# TEST 1
# DEFENDER CLEAN RESULT
# =========================================

def test_defender_clean_file(monkeypatch):
    fake_reputation_store.clear()

    monkeypatch.setattr(
        file_scanner,
        "get_file_reputation",
        fake_get_file_reputation,
    )

    monkeypatch.setattr(
        file_scanner,
        "save_file_reputation",
        fake_save_file_reputation,
    )

    monkeypatch.setattr(
        file_scanner,
        "scan_with_windows_defender",
        fake_clean_defender,
    )

    result = file_scanner.analyze_file(
        "safe_test.txt",
        b"AgentShield harmless test file",
    )

    assert result["status"] == "safe"
    assert result["risk_score"] == 10
    assert result["severity"] == "low"
    assert result["action"] == "ALLOW"

    assert result["antivirus_checked"] is True

    assert result["antivirus"]["engine"] == (
        "Microsoft Defender Antivirus"
    )

    assert result["antivirus"]["status"] == "clean"

    assert result["antivirus"]["threat_detected"] is False


# =========================================
# TEST 2
# DEFENDER DETECTION FORCES BLOCK
# =========================================

def test_defender_detection_blocks_file(monkeypatch):
    fake_reputation_store.clear()

    monkeypatch.setattr(
        file_scanner,
        "get_file_reputation",
        fake_get_file_reputation,
    )

    monkeypatch.setattr(
        file_scanner,
        "save_file_reputation",
        fake_save_file_reputation,
    )

    monkeypatch.setattr(
        file_scanner,
        "scan_with_windows_defender",
        fake_detected_defender,
    )

    result = file_scanner.analyze_file(
        "ordinary.txt",
        b"harmless fake test content",
    )

    assert result["status"] == "dangerous"
    assert result["risk_score"] == 100
    assert result["severity"] == "critical"
    assert result["action"] == "BLOCK"

    assert result["antivirus"]["checked"] is True
    assert result["antivirus"]["threat_detected"] is True

    categories = [
        threat["category"]
        for threat in result["threats"]
    ]

    assert "Microsoft Defender Detection" in categories


# =========================================
# TEST 3
# FIRST REPUTATION LOOKUP
# =========================================

def test_first_file_reputation_scan(monkeypatch):
    fake_reputation_store.clear()

    monkeypatch.setattr(
        file_scanner,
        "get_file_reputation",
        fake_get_file_reputation,
    )

    monkeypatch.setattr(
        file_scanner,
        "save_file_reputation",
        fake_save_file_reputation,
    )

    monkeypatch.setattr(
        file_scanner,
        "scan_with_windows_defender",
        fake_clean_defender,
    )

    result = file_scanner.analyze_file(
        "reputation_test.txt",
        b"unique reputation test content",
    )

    assert result["reputation_checked"] is True

    assert result["reputation_source"] == (
        "AgentShield Local Reputation"
    )

    assert result["reputation"]["known_before_scan"] is False

    assert result["reputation"]["times_seen"] == 1

    assert result["reputation"]["highest_risk_score"] == 10

    assert result["reputation"]["highest_action"] == "ALLOW"


# =========================================
# TEST 4
# SECOND REPUTATION LOOKUP
# =========================================

def test_repeated_file_is_recognized(monkeypatch):
    fake_reputation_store.clear()

    monkeypatch.setattr(
        file_scanner,
        "get_file_reputation",
        fake_get_file_reputation,
    )

    monkeypatch.setattr(
        file_scanner,
        "save_file_reputation",
        fake_save_file_reputation,
    )

    monkeypatch.setattr(
        file_scanner,
        "scan_with_windows_defender",
        fake_clean_defender,
    )

    content = b"same file content for reputation test"

    first_result = file_scanner.analyze_file(
        "same_file.txt",
        content,
    )

    second_result = file_scanner.analyze_file(
        "same_file.txt",
        content,
    )

    assert first_result["reputation"]["known_before_scan"] is False

    assert first_result["reputation"]["times_seen"] == 1

    assert second_result["reputation"]["known_before_scan"] is True

    assert second_result["reputation"]["times_seen"] == 2

    assert second_result["reputation"]["previous_risk_score"] == 10

    assert second_result["reputation"]["previous_severity"] == "low"

    assert second_result["reputation"]["previous_action"] == "ALLOW"