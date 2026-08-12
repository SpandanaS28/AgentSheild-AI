import os

import pytest


# ---------------------------------------------------------
# TEST ENVIRONMENT
#
# Use a dedicated test API key.
# This must happen BEFORE importing main.
# ---------------------------------------------------------

TEST_API_KEY = "agentshield-test-key"

os.environ["AGENTSHIELD_API_KEY"] = TEST_API_KEY


from fastapi.testclient import TestClient

import file_scanner
import main


# ---------------------------------------------------------
# TEST SETUP
# ---------------------------------------------------------

# Pytest may already have imported main from another file.
# Force the shared module to use the test key.
main.API_KEY = TEST_API_KEY


client = TestClient(
    main.app
)


AUTH_HEADERS = {
    "X-API-Key": TEST_API_KEY
}


# ---------------------------------------------------------
# Prevent these tests from adding incidents
# to the real SQLite incident history.
# ---------------------------------------------------------

def fake_save_scan(
    *args,
    **kwargs,
):
    return None


main.save_scan = fake_save_scan


# ---------------------------------------------------------
# FAKE FILE REPUTATION DATABASE
# ---------------------------------------------------------

fake_reputation_store = {}


def fake_get_file_reputation(
    sha256,
):

    return (
        fake_reputation_store
        .get(
            sha256
        )
    )


def fake_save_file_reputation(
    sha256,
    filename,
    status,
    risk_score,
    severity,
    action,
):

    existing = (
        fake_reputation_store
        .get(
            sha256
        )
    )


    if existing is None:

        fake_reputation_store[
            sha256
        ] = {
            "sha256":
                sha256,

            "filename":
                filename,

            "first_seen":
                "test-time",

            "last_seen":
                "test-time",

            "times_seen":
                1,

            "last_status":
                status,

            "last_risk_score":
                risk_score,

            "last_severity":
                severity,

            "last_action":
                action,

            "highest_risk_score":
                risk_score,

            "highest_action":
                action,
        }

        return


    existing[
        "times_seen"
    ] += 1


    existing[
        "last_status"
    ] = status


    existing[
        "last_risk_score"
    ] = risk_score


    existing[
        "last_severity"
    ] = severity


    existing[
        "last_action"
    ] = action


    if (
        risk_score
        >=
        existing[
            "highest_risk_score"
        ]
    ):

        existing[
            "highest_risk_score"
        ] = risk_score

        existing[
            "highest_action"
        ] = action


# ---------------------------------------------------------
# FAKE DEFENDER
# ---------------------------------------------------------

def fake_clean_defender(
    filename,
    content,
):

    return {
        "available":
            True,

        "checked":
            True,

        "engine":
            "Microsoft Defender Antivirus",

        "status":
            "clean",

        "threat_detected":
            False,

        "message":
            (
                "Microsoft Defender completed "
                "the scan and found no threats."
            ),
    }


# ---------------------------------------------------------
# AUTOMATIC FILE-SCANNER ISOLATION
# ---------------------------------------------------------

@pytest.fixture(
    autouse=True
)
def isolate_file_security(
    monkeypatch,
):

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


# ---------------------------------------------------------
# TEST 1
# SAFE URL
# ---------------------------------------------------------

def test_safe_url():

    response = client.post(
        "/scan-url",
        headers=AUTH_HEADERS,
        json={
            "url":
                "https://example.com"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "safe"

    assert data["risk_score"] == 10

    assert data["severity"] == "low"

    assert data["action"] == "ALLOW"

    assert data["threats"] == []


# ---------------------------------------------------------
# TEST 2
# SUSPICIOUS URL
# ---------------------------------------------------------

def test_suspicious_url():

    response = client.post(
        "/scan-url",
        headers=AUTH_HEADERS,
        json={
            "url":
                "https://example.com/login"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "dangerous"

    assert data["risk_score"] == 35

    assert data["severity"] == "medium"

    assert data["action"] == "MONITOR"


    categories = [
        threat["category"]
        for threat
        in data["threats"]
    ]


    assert (
        "Suspicious URL Keywords"
        in categories
    )


# ---------------------------------------------------------
# TEST 3
# SAFE PUBLIC IP
# ---------------------------------------------------------

def test_safe_public_ip():

    response = client.post(
        "/scan-network",
        headers=AUTH_HEADERS,
        json={
            "indicator":
                "8.8.8.8"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "safe"

    assert data["risk_score"] == 10

    assert data["severity"] == "low"

    assert data["action"] == "ALLOW"

    assert data["threats"] == []


# ---------------------------------------------------------
# TEST 4
# LOOPBACK IP
# ---------------------------------------------------------

def test_loopback_ip_is_blocked():

    response = client.post(
        "/scan-network",
        headers=AUTH_HEADERS,
        json={
            "indicator":
                "127.0.0.1"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "dangerous"

    assert data["risk_score"] == 85

    assert data["severity"] == "critical"

    assert data["action"] == "BLOCK"


    categories = [
        threat["category"]
        for threat
        in data["threats"]
    ]


    assert (
        "Loopback Address"
        in categories
    )


# ---------------------------------------------------------
# TEST 5
# SAFE TEXT FILE
# ---------------------------------------------------------

def test_safe_text_file():

    response = client.post(
        "/scan-file",
        headers=AUTH_HEADERS,
        files={
            "file": (
                "safe_test.txt",
                (
                    b"This is a harmless "
                    b"AgentShield test file."
                ),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()


    assert (
        data["filename"]
        ==
        "safe_test.txt"
    )


    assert data["status"] == "safe"

    assert data["risk_score"] == 10

    assert data["severity"] == "low"

    assert data["action"] == "ALLOW"

    assert data["threats"] == []


    assert (
        "hashes"
        in data
    )


    assert (
        "md5"
        in data["hashes"]
    )


    assert (
        "sha1"
        in data["hashes"]
    )


    assert (
        "sha256"
        in data["hashes"]
    )


    assert (
        data["antivirus"][
            "checked"
        ]
        is True
    )


    assert (
        data["antivirus"][
            "threat_detected"
        ]
        is False
    )


# ---------------------------------------------------------
# TEST 6
# FAKE DANGEROUS-LOOKING FILE
#
# This is NOT malware.
# It is harmless text with a suspicious filename.
# ---------------------------------------------------------

def test_fake_double_extension_file_is_blocked():

    response = client.post(
        "/scan-file",
        headers=AUTH_HEADERS,
        files={
            "file": (
                "photo.jpg.exe",
                b"hello",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()


    assert (
        data["filename"]
        ==
        "photo.jpg.exe"
    )


    assert (
        data["status"]
        ==
        "dangerous"
    )


    assert (
        data["risk_score"]
        >=
        90
    )


    assert (
        data["severity"]
        ==
        "critical"
    )


    assert (
        data["action"]
        ==
        "BLOCK"
    )


    categories = [
        threat["category"]
        for threat
        in data["threats"]
    ]


    assert (
        "Double Extension"
        in categories
    )


    assert (
        "Executable File"
        in categories
    )