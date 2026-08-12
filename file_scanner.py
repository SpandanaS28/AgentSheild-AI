import hashlib
import math
import os
import re

from reputation_database import (
    get_file_reputation,
    save_file_reputation,
)

from windows_defender import (
    scan_with_windows_defender,
)


# =========================================
# FILE EXTENSION GROUPS
# =========================================

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".msi",
    ".scr",
    ".com",
    ".sys",
}

SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".sh",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".tar",
    ".gz",
}

MACRO_OFFICE_EXTENSIONS = {
    ".docm",
    ".xlsm",
    ".pptm",
}

PACKAGE_EXTENSIONS = {
    ".jar",
    ".apk",
}


# =========================================
# SUSPICIOUS SCRIPT PATTERNS
# =========================================

SUSPICIOUS_TEXT_PATTERNS = [
    {
        "category": "Encoded PowerShell",
        "score": 85,
        "pattern": r"(?i)powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand)\b",
        "explanation": (
            "The file appears to contain an encoded PowerShell command. "
            "Encoded commands are sometimes used to hide script behavior."
        ),
    },
    {
        "category": "PowerShell Expression Execution",
        "score": 75,
        "pattern": r"(?i)\binvoke-expression\b|\biex\b",
        "explanation": (
            "The script contains PowerShell expression execution syntax, "
            "which can dynamically execute constructed commands."
        ),
    },
    {
        "category": "Base64 Decoding",
        "score": 55,
        "pattern": r"(?i)frombase64string",
        "explanation": (
            "The file contains Base64 decoding behavior. "
            "This can be legitimate, but it is also commonly used "
            "to obscure payloads."
        ),
    },
    {
        "category": "Command Shell Execution",
        "score": 65,
        "pattern": r"(?i)\bcmd(?:\.exe)?\s*/c\b",
        "explanation": (
            "The file contains command-shell execution syntax."
        ),
    },
    {
        "category": "Download And Execute Pattern",
        "score": 80,
        "pattern": r"(?i)\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sh|bash)\b",
        "explanation": (
            "The script appears to download content and immediately "
            "pipe it into a shell for execution."
        ),
    },
]


# =========================================
# SEVERITY
# =========================================

def get_file_severity(score: int):

    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 30:
        return "medium"

    return "low"


# =========================================
# ACTION
# =========================================

def get_file_action(severity: str):

    if severity == "critical":
        return "BLOCK"

    if severity == "high":
        return "REVIEW"

    if severity == "medium":
        return "MONITOR"

    return "ALLOW"


# =========================================
# ADD FINDING
# =========================================

def add_file_finding(
    findings: list,
    category: str,
    score: int,
    matched_text: str,
    explanation: str,
):

    findings.append(
        {
            "category": category,
            "score": score,
            "matched_text": matched_text,
            "explanation": explanation,
        }
    )


# =========================================
# FILE HASHES
# =========================================

def calculate_hashes(content: bytes):

    return {
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


# =========================================
# ENTROPY
# =========================================

def calculate_entropy(content: bytes):

    if not content:
        return 0.0

    frequencies = [0] * 256

    for byte in content:
        frequencies[byte] += 1

    entropy = 0.0

    total = len(content)

    for count in frequencies:

        if count == 0:
            continue

        probability = count / total

        entropy -= probability * math.log2(
            probability
        )

    return round(
        entropy,
        3,
    )


# =========================================
# DETECT FILE TYPE FROM MAGIC BYTES
# =========================================

def detect_magic_type(content: bytes):

    if content.startswith(
        b"MZ"
    ):
        return "Windows Executable"

    if content.startswith(
        b"\x7fELF"
    ):
        return "ELF Executable"

    if content.startswith(
        b"%PDF"
    ):
        return "PDF Document"

    if content.startswith(
        b"PK\x03\x04"
    ):
        return "ZIP / Office Archive"

    if content.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):
        return "PNG Image"

    if content.startswith(
        b"\xff\xd8\xff"
    ):
        return "JPEG Image"

    if content.startswith(
        b"GIF87a"
    ) or content.startswith(
        b"GIF89a"
    ):
        return "GIF Image"

    if content.startswith(
        b"Rar!\x1a\x07"
    ):
        return "RAR Archive"

    if content.startswith(
        b"7z\xbc\xaf\x27\x1c"
    ):
        return "7-Zip Archive"

    if content.startswith(
        b"#!"
    ):
        return "Script"

    return "Unknown / Generic"


# =========================================
# EXPECTED EXTENSIONS BY MAGIC TYPE
# =========================================

EXPECTED_EXTENSIONS = {
    "Windows Executable": {
        ".exe",
        ".dll",
        ".scr",
        ".com",
        ".sys",
    },

    "ELF Executable": {
        "",
        ".bin",
        ".elf",
        ".so",
    },

    "PDF Document": {
        ".pdf",
    },

    "ZIP / Office Archive": {
        ".zip",
        ".docx",
        ".xlsx",
        ".pptx",
        ".docm",
        ".xlsm",
        ".pptm",
        ".jar",
        ".apk",
    },

    "PNG Image": {
        ".png",
    },

    "JPEG Image": {
        ".jpg",
        ".jpeg",
    },

    "GIF Image": {
        ".gif",
    },

    "RAR Archive": {
        ".rar",
    },

    "7-Zip Archive": {
        ".7z",
    },
}


# =========================================
# SAFE TEXT EXTRACTION
# =========================================

def extract_text_sample(
    content: bytes,
):

    sample = content[
        :200_000
    ]

    try:

        return sample.decode(
            "utf-8",
            errors="ignore",
        )

    except Exception:

        return ""


# =========================================
# ADD REPUTATION + ANTIVIRUS METADATA
# =========================================

def attach_security_metadata(
    result: dict,
    previous_reputation,
    defender_result: dict,
):

    sha256 = result[
        "hashes"
    ][
        "sha256"
    ]

    # =====================================
    # WINDOWS DEFENDER RESULT
    # =====================================

    result["antivirus"] = {
        "available":
            defender_result.get(
                "available",
                False,
            ),

        "checked":
            defender_result.get(
                "checked",
                False,
            ),

        "engine":
            defender_result.get(
                "engine",
                "Microsoft Defender Antivirus",
            ),

        "status":
            defender_result.get(
                "status",
                "unknown",
            ),

        "threat_detected":
            defender_result.get(
                "threat_detected",
                False,
            ),

        "message":
            defender_result.get(
                "message",
                "Antivirus result unavailable.",
            ),
    }


    result["antivirus_checked"] = (
        defender_result.get(
            "checked",
            False,
        )
    )


    # =====================================
    # LOCAL REPUTATION DATABASE
    # =====================================

    try:

        save_file_reputation(
            sha256=sha256,
            filename=result[
                "filename"
            ],
            status=result[
                "status"
            ],
            risk_score=result[
                "risk_score"
            ],
            severity=result[
                "severity"
            ],
            action=result[
                "action"
            ],
        )


        current_reputation = (
            get_file_reputation(
                sha256
            )
        )


        known_before_scan = (
            previous_reputation
            is not None
        )


        result[
            "reputation_checked"
        ] = True


        result[
            "reputation_source"
        ] = (
            "AgentShield Local Reputation"
        )


        result[
            "external_reputation_checked"
        ] = False


        result[
            "reputation"
        ] = {
            "known_before_scan":
                known_before_scan,

            "times_seen":
                (
                    current_reputation[
                        "times_seen"
                    ]
                    if current_reputation
                    else 1
                ),

            "first_seen":
                (
                    current_reputation[
                        "first_seen"
                    ]
                    if current_reputation
                    else None
                ),

            "last_seen":
                (
                    current_reputation[
                        "last_seen"
                    ]
                    if current_reputation
                    else None
                ),

            "previous_status":
                (
                    previous_reputation[
                        "last_status"
                    ]
                    if previous_reputation
                    else None
                ),

            "previous_risk_score":
                (
                    previous_reputation[
                        "last_risk_score"
                    ]
                    if previous_reputation
                    else None
                ),

            "previous_severity":
                (
                    previous_reputation[
                        "last_severity"
                    ]
                    if previous_reputation
                    else None
                ),

            "previous_action":
                (
                    previous_reputation[
                        "last_action"
                    ]
                    if previous_reputation
                    else None
                ),

            "highest_risk_score":
                (
                    current_reputation[
                        "highest_risk_score"
                    ]
                    if current_reputation
                    else result[
                        "risk_score"
                    ]
                ),

            "highest_action":
                (
                    current_reputation[
                        "highest_action"
                    ]
                    if current_reputation
                    else result[
                        "action"
                    ]
                ),
        }


        if known_before_scan:

            result[
                "reputation_message"
            ] = (
                "This SHA-256 hash has been seen "
                "previously by AgentShield."
            )

        else:

            result[
                "reputation_message"
            ] = (
                "No previous AgentShield reputation "
                "record was found. This file has now "
                "been added to the local reputation "
                "database."
            )


    except Exception:

        result[
            "reputation_checked"
        ] = False

        result[
            "reputation_source"
        ] = (
            "AgentShield Local Reputation"
        )

        result[
            "external_reputation_checked"
        ] = False

        result[
            "reputation"
        ] = None

        result[
            "reputation_message"
        ] = (
            "The local reputation database "
            "could not be checked."
        )


    # =====================================
    # FINAL NOTE
    # =====================================

    if result[
        "antivirus_checked"
    ]:

        result[
            "note"
        ] = (
            "AgentShield performed local static "
            "analysis, checked its SHA-256 local "
            "reputation database and scanned the "
            "file with Microsoft Defender Antivirus. "
            "No external malware reputation service "
            "was queried."
        )

    else:

        result[
            "note"
        ] = (
            "AgentShield performed local static "
            "analysis and checked its SHA-256 local "
            "reputation database. Microsoft Defender "
            "could not complete the antivirus check. "
            "No external malware reputation service "
            "was queried."
        )


    return result


# =========================================
# FILE ANALYZER
# =========================================

def analyze_file(
    filename: str,
    content: bytes,
):

    if not filename:

        filename = (
            "unnamed-file"
        )


    safe_filename = (
        os.path.basename(
            filename
        )
    )


    file_size = len(
        content
    )


    extension = (
        os.path.splitext(
            safe_filename
        )[1]
        .lower()
    )


    # =====================================
    # HASHES
    # =====================================

    hashes = calculate_hashes(
        content
    )


    # =====================================
    # PREVIOUS LOCAL REPUTATION
    # =====================================

    previous_reputation = None

    try:

        previous_reputation = (
            get_file_reputation(
                hashes[
                    "sha256"
                ]
            )
        )

    except Exception:

        previous_reputation = None


    # =====================================
    # MICROSOFT DEFENDER
    #
    # The uploaded file is NEVER executed.
    # Defender only scans the file bytes.
    # =====================================

    defender_result = (
        scan_with_windows_defender(
            safe_filename,
            content,
        )
    )


    entropy = calculate_entropy(
        content
    )


    magic_type = detect_magic_type(
        content
    )


    findings = []


    # =====================================
    # DEFENDER DETECTION
    # =====================================

    if defender_result.get(
        "threat_detected",
        False,
    ):

        add_file_finding(
            findings,
            "Microsoft Defender Detection",
            100,
            "Microsoft Defender Antivirus",
            (
                "Microsoft Defender Antivirus "
                "reported a possible threat in "
                "the uploaded file."
            ),
        )


    # =====================================
    # EMPTY FILE
    # =====================================

    if file_size == 0:

        add_file_finding(
            findings,
            "Empty File",
            20,
            safe_filename,
            (
                "The uploaded file contains "
                "no data."
            ),
        )


    # =====================================
    # DOUBLE EXTENSION
    # =====================================

    lower_name = (
        safe_filename.lower()
    )


    dangerous_extension_pattern = (
        r"\.(?:pdf|doc|docx|jpg|jpeg|png|txt|xlsx|pptx)"
        r"\.(?:exe|scr|bat|cmd|ps1|vbs|js|hta)$"
    )


    if re.search(
        dangerous_extension_pattern,
        lower_name,
    ):

        add_file_finding(
            findings,
            "Double Extension",
            90,
            safe_filename,
            (
                "The filename uses a deceptive "
                "double extension, which can make "
                "an executable or script appear "
                "to be a document or image."
            ),
        )


    # =====================================
    # EXECUTABLE EXTENSION
    # =====================================

    if (
        extension
        in EXECUTABLE_EXTENSIONS
    ):

        add_file_finding(
            findings,
            "Executable File",
            80,
            extension,
            (
                "The uploaded file uses an "
                "executable extension that can "
                "run native code on a system."
            ),
        )


    # =====================================
    # SCRIPT EXTENSION
    # =====================================

    elif (
        extension
        in SCRIPT_EXTENSIONS
    ):

        add_file_finding(
            findings,
            "Script File",
            65,
            extension,
            (
                "The uploaded file is a script "
                "that may execute commands on "
                "a system."
            ),
        )


    # =====================================
    # MACRO-ENABLED OFFICE FILE
    # =====================================

    if (
        extension
        in MACRO_OFFICE_EXTENSIONS
    ):

        add_file_finding(
            findings,
            "Macro-Enabled Office File",
            65,
            extension,
            (
                "The uploaded Office document "
                "format supports embedded macros. "
                "Macros can be legitimate but are "
                "also commonly used in malicious "
                "documents."
            ),
        )


    # =====================================
    # PACKAGE FILE
    # =====================================

    if (
        extension
        in PACKAGE_EXTENSIONS
    ):

        add_file_finding(
            findings,
            "Executable Package",
            60,
            extension,
            (
                "The uploaded file is an executable "
                "application package or Java archive."
            ),
        )


    # =====================================
    # ARCHIVE FILE
    # =====================================

    if (
        extension
        in ARCHIVE_EXTENSIONS
    ):

        add_file_finding(
            findings,
            "Archive File",
            35,
            extension,
            (
                "The uploaded file is an archive. "
                "Archives can contain additional "
                "files that require separate "
                "inspection."
            ),
        )


    # =====================================
    # MAGIC BYTE EXECUTABLE
    # =====================================

    if (
        magic_type
        ==
        "Windows Executable"
        and
        extension
        not in EXECUTABLE_EXTENSIONS
    ):

        add_file_finding(
            findings,
            "Hidden Executable",
            95,
            magic_type,
            (
                "The file contents identify it "
                "as a Windows executable, but the "
                "filename does not use a normal "
                "executable extension."
            ),
        )


    if (
        magic_type
        ==
        "ELF Executable"
    ):

        add_file_finding(
            findings,
            "ELF Executable",
            75,
            magic_type,
            (
                "The file contains an ELF "
                "executable header used by Linux "
                "and Unix binaries."
            ),
        )


    # =====================================
    # EXTENSION / CONTENT MISMATCH
    # =====================================

    expected_extensions = (
        EXPECTED_EXTENSIONS.get(
            magic_type
        )
    )


    if (
        expected_extensions
        and
        extension
        not in expected_extensions
    ):

        add_file_finding(
            findings,
            "File Type Mismatch",
            60,
            (
                f"{extension or '[no extension]'} "
                f"vs {magic_type}"
            ),
            (
                "The filename extension does not "
                "match the file type identified "
                "from its header bytes."
            ),
        )


    # =====================================
    # HIGH ENTROPY
    # =====================================

    if (
        file_size >= 512
        and
        entropy >= 7.2
    ):

        add_file_finding(
            findings,
            "High File Entropy",
            45,
            f"Entropy {entropy}",
            (
                "The file has unusually high byte "
                "entropy. This can occur in "
                "compressed, encrypted or packed "
                "files and is not proof of malware "
                "by itself."
            ),
        )


    # =====================================
    # SCRIPT CONTENT ANALYSIS
    # =====================================

    should_scan_text = (
        extension
        in SCRIPT_EXTENSIONS
        or
        magic_type
        ==
        "Script"
    )


    if should_scan_text:

        text_sample = (
            extract_text_sample(
                content
            )
        )


        for rule in (
            SUSPICIOUS_TEXT_PATTERNS
        ):

            match = re.search(
                rule[
                    "pattern"
                ],
                text_sample,
            )


            if match:

                add_file_finding(
                    findings,
                    rule[
                        "category"
                    ],
                    rule[
                        "score"
                    ],
                    match.group(0)[
                        :120
                    ],
                    rule[
                        "explanation"
                    ],
                )


    # =====================================
    # SAFE FILE
    # =====================================

    if not findings:

        result = {
            "filename":
                safe_filename,

            "file_size":
                file_size,

            "extension":
                extension or None,

            "detected_file_type":
                magic_type,

            "entropy":
                entropy,

            "hashes":
                hashes,

            "status":
                "safe",

            "message":
                (
                    "No suspicious local file "
                    "indicators were detected."
                ),

            "risk_score":
                10,

            "severity":
                "low",

            "action":
                "ALLOW",

            "threats":
                [],

            "analysis_type":
                (
                    "local_static_analysis_"
                    "plus_antivirus"
                ),
        }


        return attach_security_metadata(
            result,
            previous_reputation,
            defender_result,
        )


    # =====================================
    # CALCULATE FINAL RISK
    # =====================================

    highest_score = max(
        finding[
            "score"
        ]
        for finding
        in findings
    )


    extra_risk = (
        (
            len(
                findings
            )
            -
            1
        )
        *
        5
    )


    risk_score = min(
        100,
        highest_score
        +
        extra_risk,
    )


    severity = (
        get_file_severity(
            risk_score
        )
    )


    action = (
        get_file_action(
            severity
        )
    )


    status = (
        "safe"
        if action == "ALLOW"
        else "dangerous"
    )


    result = {
        "filename":
            safe_filename,

        "file_size":
            file_size,

        "extension":
            extension or None,

        "detected_file_type":
            magic_type,

        "entropy":
            entropy,

        "hashes":
            hashes,

        "status":
            status,

        "message":
            (
                "Suspicious file indicators "
                "were detected."
            ),

        "risk_score":
            risk_score,

        "severity":
            severity,

        "action":
            action,

        "threats":
            findings,

        "analysis_type":
            (
                "local_static_analysis_"
                "plus_antivirus"
            ),
    }


    return attach_security_metadata(
        result,
        previous_reputation,
        defender_result,
    )