import ipaddress
import os
import re
import secrets
import time

from collections import (
    defaultdict,
    deque,
)

from pathlib import Path

from urllib.parse import (
    parse_qsl,
    unquote,
    urlencode,
    urlparse,
    urlunparse,
)

from dotenv import load_dotenv

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    Security,
    UploadFile,
)

from fastapi.middleware.cors import (
    CORSMiddleware,
)

from fastapi.security import (
    APIKeyHeader,
)

from pydantic import BaseModel


from database import (
    create_database,
    save_scan,
    get_all_scans,
    get_dashboard_stats,
    initialize_policy_states,
    get_policy_states,
    save_policy_state,
    delete_scan,
    clear_all_scans,
)

from network_scanner import (
    analyze_network_indicator,
)

from file_scanner import (
    analyze_file,
)


# =========================================
# ENVIRONMENT CONFIGURATION
# =========================================

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(
    BASE_DIR / ".env"
)


# =========================================
# APP
# =========================================

app = FastAPI(
    title="AgentShield AI"
)


# =========================================
# DATABASE
# =========================================

create_database()


# =========================================
# CORS
# =========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================
# API SECURITY
# =========================================

API_KEY = os.getenv(
    "AGENTSHIELD_API_KEY"
)


if not API_KEY:

    raise RuntimeError(
        "AGENTSHIELD_API_KEY is not configured. "
        "Create a .env file or set the environment variable."
    )


api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def verify_api_key(
    supplied_api_key: str | None =
        Security(api_key_header)
):

    if supplied_api_key is None:

        raise HTTPException(
            status_code=401,
            detail="Missing API key",
        )


    if not secrets.compare_digest(
        supplied_api_key,
        API_KEY,
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
        )


    return True


# =========================================
# RATE LIMIT
# =========================================

SCAN_RATE_LIMIT = 20

SCAN_RATE_WINDOW_SECONDS = 60


scan_request_history = defaultdict(
    deque
)


def check_scan_rate_limit(
    request: Request
):

    if request.client:

        client_ip = (
            request.client.host
        )

    else:

        client_ip = "unknown"


    now = time.monotonic()


    request_times = (
        scan_request_history[
            client_ip
        ]
    )


    while (
        request_times
        and
        now - request_times[0]
        >= SCAN_RATE_WINDOW_SECONDS
    ):

        request_times.popleft()


    if (
        len(request_times)
        >= SCAN_RATE_LIMIT
    ):

        oldest_request = (
            request_times[0]
        )


        seconds_until_reset = max(
            1,
            int(
                SCAN_RATE_WINDOW_SECONDS
                -
                (
                    now -
                    oldest_request
                )
            )
            +
            1
        )


        raise HTTPException(
            status_code=429,

            detail=(
                "Scan rate limit exceeded. "
                f"Try again in approximately "
                f"{seconds_until_reset} seconds."
            ),

            headers={
                "Retry-After":
                    str(
                        seconds_until_reset
                    )
            },
        )


    request_times.append(
        now
    )


# =========================================
# FILE SCANNER CONFIG
# =========================================

MAX_FILE_SIZE_BYTES = (
    10
    *
    1024
    *
    1024
)


# =========================================
# REQUEST MODELS
# =========================================

class PromptRequest(BaseModel):
    prompt: str


class URLRequest(BaseModel):
    url: str


class NetworkRequest(BaseModel):
    indicator: str


class PolicyUpdateRequest(BaseModel):
    enabled: bool


# =========================================
# HOME
# =========================================

@app.get("/")
def home():

    return {
        "message":
            "AgentShield AI backend is running",

        "security":
            "API key protection enabled",

        "scan_rate_limit":
            f"{SCAN_RATE_LIMIT} requests per minute",

        "max_file_size":
            "10 MB",

        "capabilities": [
            "AI Prompt Security",
            "Sensitive Data Protection",
            "URL Security Scanner",
            "IP / Domain Security Scanner",
            "File Security Scanner",
            "Unified Security Incident History",
        ],
    }


# =========================================
# SENSITIVE DATA RULES
# =========================================

SENSITIVE_DATA_RULES = [

    {
        "type":
            "Password",

        "pattern":
            r"(?i)\b(?P<prefix>(?:password|passwd|pwd)\s*[:=]\s*)(?P<secret>[^\s,;]+)",
    },

    {
        "type":
            "API Key",

        "pattern":
            r"(?i)\b(?P<prefix>(?:api[_ -]?key|secret[_ -]?key)\s*[:=]\s*)(?P<secret>[A-Za-z0-9_\-./+=]{8,})",
    },

    {
        "type":
            "Client Secret",

        "pattern":
            r"(?i)\b(?P<prefix>client[_ -]?secret\s*[:=]\s*)(?P<secret>[A-Za-z0-9_\-./+=]{8,})",
    },

    {
        "type":
            "Bearer Token",

        "pattern":
            r"(?i)\b(?P<prefix>bearer\s+)(?P<secret>[A-Za-z0-9._~+/=-]{8,})",
    },

    {
        "type":
            "JWT Token",

        "pattern":
            r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
    },

    {
        "type":
            "Secret Token",

        "pattern":
            r"\bsk-[A-Za-z0-9_-]{16,}\b",
    },

    {
        "type":
            "AWS Access Key",

        "pattern":
            r"\bAKIA[0-9A-Z]{16}\b",
    },

]


# =========================================
# REDACT SENSITIVE DATA
# =========================================

def redact_sensitive_data(
    text: str
):

    redacted_text = text

    detected_types = set()


    for rule in SENSITIVE_DATA_RULES:

        def replace_secret(
            match
        ):

            detected_types.add(
                rule["type"]
            )


            prefix = (
                match
                .groupdict()
                .get("prefix")
            )


            if prefix:

                return (
                    prefix
                    +
                    "[REDACTED]"
                )


            return "[REDACTED]"


        redacted_text = re.sub(
            rule["pattern"],
            replace_secret,
            redacted_text,
        )


    return (
        redacted_text,
        sorted(
            detected_types
        ),
    )


# =========================================
# PROMPT SECURITY POLICIES
# =========================================

THREAT_RULES = [

    {
        "id": 1,
        "category": "Prompt Injection",
        "description":
            "The prompt tries to override, ignore or bypass existing AI instructions.",
        "score": 85,
        "enabled": True,
        "patterns": [
            r"ignore previous instructions",
            r"ignore all previous instructions",
            r"disregard previous instructions",
            r"forget previous instructions",
            r"override previous instructions",
            r"bypass instructions",
            r"ignore your rules",
            r"break your rules",
            r"jailbreak",
            r"developer mode",
        ],
    },

    {
        "id": 2,
        "category": "System Prompt Extraction",
        "description":
            "The prompt tries to reveal hidden system prompts or protected internal AI instructions.",
        "score": 95,
        "enabled": True,
        "patterns": [
            r"reveal (your )?system prompt",
            r"show (your )?system prompt",
            r"display (your )?system prompt",
            r"print (your )?system prompt",
            r"show hidden instructions",
            r"reveal hidden instructions",
            r"what are your system instructions",
            r"show your internal instructions",
            r"reveal your instructions",
        ],
    },

    {
        "id": 3,
        "category": "Secret Extraction",
        "description":
            "The prompt tries to obtain passwords, API keys, access tokens or other credentials.",
        "score": 95,
        "enabled": True,
        "patterns": [
            r"show password",
            r"show (your )?password",
            r"reveal password",
            r"reveal (your )?password",
            r"give me the password",
            r"show api key",
            r"show (your )?api key",
            r"reveal api key",
            r"reveal (your )?api key",
            r"give me the api key",
            r"show secret key",
            r"reveal secret key",
            r"show access token",
            r"reveal access token",
            r"show credentials",
            r"reveal credentials",
            r"steal credentials",
        ],
    },

    {
        "id": 4,
        "category": "Privilege Escalation",
        "description":
            "The prompt tries to gain administrator or root privileges or bypass authentication.",
        "score": 80,
        "enabled": True,
        "patterns": [
            r"give me admin access",
            r"grant admin access",
            r"give root access",
            r"grant root access",
            r"elevate privileges",
            r"bypass authentication",
            r"disable authentication",
            r"disable security",
            r"bypass security controls",
        ],
    },

    {
        "id": 5,
        "category": "Destructive Action",
        "description":
            "The prompt contains instructions that could delete files, destroy databases or erase data.",
        "score": 90,
        "enabled": True,
        "patterns": [
            r"rm\s+-rf",
            r"delete all files",
            r"delete the database",
            r"drop database",
            r"drop table",
            r"wipe all data",
            r"erase all data",
            r"format disk",
            r"destroy database",
        ],
    },

    {
        "id": 6,
        "category": "Security Evasion",
        "description":
            "The prompt tries to avoid monitoring, bypass security controls or evade detection.",
        "score": 75,
        "enabled": True,
        "patterns": [
            r"bypass detection",
            r"avoid detection",
            r"evade detection",
            r"hide from security",
            r"disable monitoring",
            r"bypass firewall",
            r"avoid security checks",
        ],
    },

    {
        "id": 7,
        "category": "Sensitive Data Exposure",
        "description":
            "The prompt contains sensitive credentials such as passwords, API keys or access tokens.",
        "score": 70,
        "enabled": True,
        "patterns": [
            rule["pattern"]
            for rule
            in SENSITIVE_DATA_RULES
        ],
    },

]


# =========================================
# INITIALIZE POLICY STATES
# =========================================

default_policy_states = [

    (
        rule["id"],
        rule["enabled"],
    )

    for rule
    in THREAT_RULES

]


initialize_policy_states(
    default_policy_states
)


saved_policy_states = (
    get_policy_states()
)


for rule in THREAT_RULES:

    if (
        rule["id"]
        in saved_policy_states
    ):

        rule["enabled"] = (
            saved_policy_states[
                rule["id"]
            ]
        )


# =========================================
# SEVERITY
# =========================================

def get_severity(
    score: int
):

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

def get_action(
    severity: str
):

    if severity == "critical":
        return "BLOCK"

    if severity == "high":
        return "REVIEW"

    if severity == "medium":
        return "MONITOR"

    return "ALLOW"


# =========================================
# GET DLP POLICY
# =========================================

def get_sensitive_data_policy():

    for rule in THREAT_RULES:

        if (
            rule["category"]
            ==
            "Sensitive Data Exposure"
        ):

            return rule


    return None


# =========================================
# BUILD DETECTED CATEGORY STRING
# =========================================

def build_detected_pattern(
    result: dict
):

    existing_pattern = (
        result.get(
            "detected_pattern"
        )
    )


    if existing_pattern:

        return existing_pattern


    threats = (
        result.get(
            "threats"
        )
        or []
    )


    categories = []


    for threat in threats:

        category = (
            threat.get(
                "category"
            )
        )


        if (
            category
            and
            category not in categories
        ):

            categories.append(
                category
            )


    if not categories:

        return None


    return ", ".join(
        categories
    )


# =========================================
# SAVE NON-PROMPT SCAN
# =========================================

def save_unified_scan(
    scan_type: str,
    subject: str,
    result: dict,
):

    detected_pattern = (
        build_detected_pattern(
            result
        )
    )


    save_scan(
        prompt=
            subject,

        status=
            result.get(
                "status",
                "safe",
            ),

        detected_pattern=
            detected_pattern,

        risk_score=
            result.get(
                "risk_score",
                10,
            ),

        severity=
            result.get(
                "severity",
                "low",
            ),

        action=
            result.get(
                "action",
                "ALLOW",
            ),

        threat_details=
            result.get(
                "threats",
                [],
            ),

        scan_type=
            scan_type,
    )


# =========================================
# PROMPT SCANNER
# =========================================

@app.post(
    "/scan",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def scan_prompt(
    data: PromptRequest,
    request: Request,
):

    check_scan_rate_limit(
        request
    )


    original_prompt = (
        data.prompt
    )


    (
        safe_prompt_for_storage,
        sensitive_data_types,
    ) = redact_sensitive_data(
        original_prompt
    )


    redaction_applied = (
        len(
            sensitive_data_types
        ) > 0
    )


    prompt = (
        original_prompt.lower()
    )


    prompt = re.sub(
        r"\s+",
        " ",
        prompt,
    ).strip()


    detected_threats = []


    for rule in THREAT_RULES:

        if (
            rule["category"]
            ==
            "Sensitive Data Exposure"
        ):

            continue


        if not rule["enabled"]:

            continue


        for pattern in rule["patterns"]:

            match = re.search(
                pattern,
                prompt,
            )


            if match:

                detected_threats.append(
                    {
                        "category":
                            rule["category"],

                        "score":
                            rule["score"],

                        "matched_text":
                            match.group(0),

                        "explanation":
                            rule["description"],
                    }
                )

                break


    sensitive_policy = (
        get_sensitive_data_policy()
    )


    if (
        sensitive_data_types
        and
        sensitive_policy
        and
        sensitive_policy["enabled"]
    ):

        safe_sensitive_description = (
            ", ".join(
                sensitive_data_types
            )
            +
            " (values redacted)"
        )


        detected_threats.append(
            {
                "category":
                    sensitive_policy[
                        "category"
                    ],

                "score":
                    sensitive_policy[
                        "score"
                    ],

                "matched_text":
                    safe_sensitive_description,

                "explanation":
                    (
                        "Sensitive credentials were detected in the prompt. "
                        "Their values were redacted before the incident was stored."
                    ),
            }
        )


    if detected_threats:

        highest_score = max(
            threat["score"]
            for threat
            in detected_threats
        )


        extra_risk = (
            (
                len(
                    detected_threats
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


        severity = get_severity(
            risk_score
        )


        action = get_action(
            severity
        )


        detected_categories = (
            ", ".join(
                threat["category"]
                for threat
                in detected_threats
            )
        )


        save_scan(
            prompt=
                safe_prompt_for_storage,

            status=
                "dangerous",

            detected_pattern=
                detected_categories,

            risk_score=
                risk_score,

            severity=
                severity,

            action=
                action,

            threat_details=
                detected_threats,

            scan_type=
                "prompt",
        )


        if redaction_applied:

            message = (
                "Security threats were detected. "
                "Sensitive data was redacted before storage."
            )

        else:

            message = (
                "Security threats were detected in this prompt."
            )


        return {
            "status":
                "dangerous",

            "message":
                message,

            "detected_pattern":
                detected_categories,

            "risk_score":
                risk_score,

            "severity":
                severity,

            "action":
                action,

            "threats":
                detected_threats,

            "sensitive_data_detected":
                sensitive_data_types,

            "redaction_applied":
                redaction_applied,
        }


    risk_score = 10

    severity = "low"

    action = "ALLOW"


    save_scan(
        prompt=
            safe_prompt_for_storage,

        status=
            "safe",

        detected_pattern=
            None,

        risk_score=
            risk_score,

        severity=
            severity,

        action=
            action,

        threat_details=
            [],

        scan_type=
            "prompt",
    )


    if redaction_applied:

        safe_message = (
            "No enabled security policy blocked this request. "
            "Sensitive data was redacted before storage."
        )

    else:

        safe_message = (
            "No dangerous security pattern was detected."
        )


    return {
        "status":
            "safe",

        "message":
            safe_message,

        "detected_pattern":
            None,

        "risk_score":
            risk_score,

        "severity":
            severity,

        "action":
            action,

        "threats":
            [],

        "sensitive_data_detected":
            sensitive_data_types,

        "redaction_applied":
            redaction_applied,
    }


# =========================================
# URL CONFIGURATION
# =========================================

URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}


URL_EXECUTABLE_EXTENSIONS = (
    ".exe",
    ".msi",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".jar",
    ".apk",
)


URL_ARCHIVE_EXTENSIONS = (
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".tar",
    ".gz",
)


URL_SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "update",
    "confirm",
    "reset",
    "wallet",
    "invoice",
    "payment",
    "banking",
}


SENSITIVE_URL_QUERY_KEYS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "access_token",
    "auth_token",
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "client_secret",
    "key",
}


# =========================================
# NORMALIZE URL
# =========================================

def normalize_url(
    raw_url: str
):

    cleaned_url = (
        raw_url.strip()
    )


    if not cleaned_url:

        raise HTTPException(
            status_code=400,
            detail="Please provide a URL.",
        )


    if len(
        cleaned_url
    ) > 4096:

        raise HTTPException(
            status_code=400,
            detail="URL is too long to analyze.",
        )


    if not re.match(
        r"^[A-Za-z][A-Za-z0-9+.-]*://",
        cleaned_url,
    ):

        cleaned_url = (
            "https://"
            +
            cleaned_url
        )


    return cleaned_url


# =========================================
# SANITIZE URL
# =========================================

def sanitize_url_for_display(
    url: str
):

    try:

        parsed = urlparse(
            url
        )


        hostname = (
            parsed.hostname
            or ""
        )


        display_host = (
            hostname
        )


        if (
            ":" in display_host
            and
            not display_host.startswith(
                "["
            )
        ):

            display_host = (
                f"[{display_host}]"
            )


        try:

            port = parsed.port

        except ValueError:

            port = None


        if port is not None:

            display_host = (
                f"{display_host}:{port}"
            )


        if (
            parsed.username
            or
            parsed.password
        ):

            display_host = (
                "[REDACTED]@"
                +
                display_host
            )


        safe_query_pairs = []


        for (
            key,
            value,
        ) in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        ):

            normalized_key = (
                key
                .lower()
                .replace(
                    "-",
                    "_",
                )
            )


            if (
                normalized_key
                in SENSITIVE_URL_QUERY_KEYS
            ):

                safe_query_pairs.append(
                    (
                        key,
                        "[REDACTED]",
                    )
                )

            else:

                safe_query_pairs.append(
                    (
                        key,
                        value,
                    )
                )


        safe_query = urlencode(
            safe_query_pairs,
            doseq=True,
        )


        safe_url = urlunparse(
            (
                parsed.scheme,
                display_host,
                parsed.path,
                parsed.params,
                safe_query,
                "",
            )
        )


        (
            safe_url,
            _,
        ) = redact_sensitive_data(
            safe_url
        )


        return safe_url


    except Exception:

        return "[URL REDACTED]"


# =========================================
# URL FINDING
# =========================================

def add_url_finding(
    findings,
    category,
    score,
    matched_text,
    explanation,
):

    findings.append(
        {
            "category":
                category,

            "score":
                score,

            "matched_text":
                matched_text,

            "explanation":
                explanation,
        }
    )


# =========================================
# URL ANALYZER
# =========================================

def analyze_url(
    raw_url: str
):

    normalized_url = (
        normalize_url(
            raw_url
        )
    )


    parsed = urlparse(
        normalized_url
    )


    scheme = (
        parsed.scheme.lower()
    )


    findings = []


    if scheme not in {
        "http",
        "https",
    }:

        add_url_finding(
            findings,
            "Unsafe URL Scheme",
            90,
            scheme,
            (
                "The value uses a non-HTTP web scheme. "
                "AgentShield only considers HTTP and HTTPS normal web URLs."
            ),
        )


        risk_score = 90

        severity = get_severity(
            risk_score
        )

        action = get_action(
            severity
        )


        return {
            "status":
                "dangerous",

            "message":
                "A dangerous or unsupported URL scheme was detected.",

            "url":
                sanitize_url_for_display(
                    normalized_url
                ),

            "hostname":
                parsed.hostname,

            "detected_pattern":
                "Unsafe URL Scheme",

            "risk_score":
                risk_score,

            "severity":
                severity,

            "action":
                action,

            "threats":
                findings,

            "analysis_type":
                "local_heuristic",

            "reputation_checked":
                False,

            "note":
                (
                    "No external malware or reputation database "
                    "was queried for this result."
                ),
        }


    hostname = (
        parsed.hostname
    )


    if not hostname:

        raise HTTPException(
            status_code=400,
            detail="The URL does not contain a valid hostname.",
        )


    hostname = (
        hostname.lower()
    )


    if " " in hostname:

        raise HTTPException(
            status_code=400,
            detail="The URL hostname is invalid.",
        )


    safe_url = (
        sanitize_url_for_display(
            normalized_url
        )
    )


    decoded_url = (
        unquote(
            normalized_url
        )
        .lower()
    )


    decoded_path = (
        unquote(
            parsed.path
        )
        .lower()
    )


    if (
        parsed.username
        or
        parsed.password
    ):

        add_url_finding(
            findings,
            "Embedded Credentials",
            85,
            "credentials@hostname (redacted)",
            (
                "The URL contains embedded username or password information."
            ),
        )


    if hostname in {
        "localhost",
        "localhost.localdomain",
    }:

        add_url_finding(
            findings,
            "Local Network Target",
            80,
            hostname,
            (
                "The URL targets the local machine. "
                "Local addresses can be important in SSRF and internal-service attacks."
            ),
        )


    try:

        ip_value = (
            ipaddress.ip_address(
                hostname
            )
        )


        if (
            ip_value.is_private
            or
            ip_value.is_loopback
            or
            ip_value.is_link_local
            or
            ip_value.is_reserved
        ):

            add_url_finding(
                findings,
                "Private IP Target",
                80,
                hostname,
                (
                    "The URL points directly to a private, loopback, "
                    "link-local or reserved IP address."
                ),
            )

        else:

            add_url_finding(
                findings,
                "Raw IP Address",
                50,
                hostname,
                (
                    "The URL uses a raw IP address instead of a normal domain name."
                ),
            )


        hostname_is_ip = True


    except ValueError:

        hostname_is_ip = False


    if (
        "xn--"
        in hostname
    ):

        add_url_finding(
            findings,
            "Punycode Domain",
            50,
            hostname,
            (
                "The hostname contains Punycode. "
                "Internationalized domains can be legitimate but may also be used for look-alike phishing domains."
            ),
        )


    if (
        hostname
        in URL_SHORTENER_DOMAINS
    ):

        add_url_finding(
            findings,
            "URL Shortener",
            40,
            hostname,
            (
                "The link uses a URL-shortening service, which hides the final destination."
            ),
        )


    if not hostname_is_ip:

        hostname_parts = [
            part
            for part
            in hostname.split(".")
            if part
        ]


        if (
            len(
                hostname_parts
            )
            >= 5
        ):

            add_url_finding(
                findings,
                "Excessive Subdomains",
                35,
                f"{len(hostname_parts)} hostname sections",
                (
                    "The hostname contains an unusually large number of sections."
                ),
            )


    matched_keywords = sorted(
        {
            keyword
            for keyword
            in URL_SUSPICIOUS_KEYWORDS
            if keyword
            in decoded_url
        }
    )


    if matched_keywords:

        add_url_finding(
            findings,
            "Suspicious URL Keywords",
            35,
            ", ".join(
                matched_keywords[:6]
            ),
            (
                "The URL contains words commonly seen in login, verification, "
                "credential-reset or payment-themed links. "
                "This is a heuristic indicator and does not prove the site is malicious."
            ),
        )


    if decoded_path.endswith(
        URL_EXECUTABLE_EXTENSIONS
    ):

        extension = (
            "."
            +
            decoded_path
            .rsplit(
                ".",
                1
            )[-1]
        )


        add_url_finding(
            findings,
            "Executable Download",
            80,
            extension,
            (
                "The URL appears to directly reference an executable or script file."
            ),
        )


    elif decoded_path.endswith(
        URL_ARCHIVE_EXTENSIONS
    ):

        extension = (
            "."
            +
            decoded_path
            .rsplit(
                ".",
                1
            )[-1]
        )


        add_url_finding(
            findings,
            "Archive Download",
            45,
            extension,
            (
                "The URL directly references an archive file."
            ),
        )


    if (
        len(
            normalized_url
        )
        >= 180
    ):

        add_url_finding(
            findings,
            "Unusually Long URL",
            35,
            f"{len(normalized_url)} characters",
            (
                "The URL is unusually long and may hide suspicious parameters."
            ),
        )


    encoded_sequence_count = len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            normalized_url,
        )
    )


    if (
        encoded_sequence_count
        >= 4
    ):

        add_url_finding(
            findings,
            "Heavy URL Encoding",
            45,
            f"{encoded_sequence_count} encoded sequences",
            (
                "The URL contains a high amount of percent-encoded content."
            ),
        )


    try:

        port = (
            parsed.port
        )


        if (
            port is not None
            and
            port not in {
                80,
                443,
            }
        ):

            add_url_finding(
                findings,
                "Non-Standard Web Port",
                40,
                str(port),
                (
                    "The URL uses a web port other than standard HTTP or HTTPS."
                ),
            )


    except ValueError:

        add_url_finding(
            findings,
            "Invalid Port",
            70,
            "invalid port value",
            (
                "The URL contains an invalid network port value."
            ),
        )


    if scheme == "http":

        add_url_finding(
            findings,
            "Insecure HTTP",
            20,
            "http",
            (
                "The URL uses HTTP instead of HTTPS."
            ),
        )


    if not findings:

        return {
            "status":
                "safe",

            "message":
                "No suspicious URL structure was detected by the local AgentShield rules.",

            "url":
                safe_url,

            "hostname":
                hostname,

            "detected_pattern":
                None,

            "risk_score":
                10,

            "severity":
                "low",

            "action":
                "ALLOW",

            "threats":
                [],

            "analysis_type":
                "local_heuristic",

            "reputation_checked":
                False,

            "note":
                (
                    "This result checks URL structure only. "
                    "No external malware or reputation database was queried."
                ),
        }


    highest_score = max(
        finding["score"]
        for finding
        in findings
    )


    extra_risk = (
        (
            len(findings)
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


    severity = get_severity(
        risk_score
    )


    action = get_action(
        severity
    )


    status = (
        "safe"
        if action == "ALLOW"
        else "dangerous"
    )


    detected_categories = (
        ", ".join(
            finding["category"]
            for finding
            in findings
        )
    )


    if status == "dangerous":

        message = (
            "Suspicious URL indicators were detected."
        )

    else:

        message = (
            "Only low-risk URL indicators were detected."
        )


    return {
        "status":
            status,

        "message":
            message,

        "url":
            safe_url,

        "hostname":
            hostname,

        "detected_pattern":
            detected_categories,

        "risk_score":
            risk_score,

        "severity":
            severity,

        "action":
            action,

        "threats":
            findings,

        "analysis_type":
            "local_heuristic",

        "reputation_checked":
            False,

        "note":
            (
                "This result checks URL structure only. "
                "No external malware or reputation database was queried."
            ),
    }


# =========================================
# URL SCANNER ENDPOINT
# =========================================

@app.post(
    "/scan-url",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def scan_url(
    data: URLRequest,
    request: Request,
):

    check_scan_rate_limit(
        request
    )


    result = analyze_url(
        data.url
    )


    # Important:
    # store only the sanitized URL returned
    # by analyze_url, not the original URL.

    save_unified_scan(
        scan_type=
            "url",

        subject=
            result["url"],

        result=
            result,
    )


    return result


# =========================================
# IP / DOMAIN SCANNER
# =========================================

@app.post(
    "/scan-network",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def scan_network(
    data: NetworkRequest,
    request: Request,
):

    check_scan_rate_limit(
        request
    )


    try:

        result = (
            analyze_network_indicator(
                data.indicator
            )
        )


        save_unified_scan(
            scan_type=
                "network",

            subject=
                result["indicator"],

            result=
                result,
        )


        return result


    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(
                error
            ),
        )


# =========================================
# FILE SCANNER
# =========================================

@app.post(
    "/scan-file",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
async def scan_file(
    request: Request,

    file: UploadFile =
        File(...),
):

    check_scan_rate_limit(
        request
    )


    filename = (
        file.filename
        or
        "unnamed-file"
    )


    content = await file.read(
        MAX_FILE_SIZE_BYTES
        +
        1
    )


    await file.close()


    if (
        len(content)
        >
        MAX_FILE_SIZE_BYTES
    ):

        raise HTTPException(
            status_code=413,
            detail=(
                "File is too large. "
                "AgentShield currently accepts files up to 10 MB."
            ),
        )


    try:

        result = analyze_file(
            filename=
                filename,

            content=
                content,
        )


        result[
            "max_file_size"
        ] = "10 MB"


        # Only the filename and analysis
        # results are stored.
        # The uploaded file contents are
        # NOT saved into SQLite.

        save_unified_scan(
            scan_type=
                "file",

            subject=
                result["filename"],

            result=
                result,
        )


        return result


    except HTTPException:

        raise


    except Exception:

        raise HTTPException(
            status_code=500,
            detail="AgentShield could not analyze this file.",
        )


# =========================================
# GET ALL INCIDENTS
# =========================================

@app.get(
    "/scans",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def view_scans():

    scans = (
        get_all_scans()
    )


    return {
        "total":
            len(scans),

        "scans":
            scans,
    }


# =========================================
# DELETE INCIDENT
# =========================================

@app.delete(
    "/scans/{scan_id}",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def delete_incident(
    scan_id: int
):

    deleted = delete_scan(
        scan_id
    )


    if not deleted:

        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )


    return {
        "message":
            "Incident deleted successfully.",

        "deleted_id":
            scan_id,
    }


# =========================================
# CLEAR HISTORY
# =========================================

@app.delete(
    "/scans",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def clear_incident_history():

    deleted_count = (
        clear_all_scans()
    )


    return {
        "message":
            "Incident history cleared successfully.",

        "deleted_count":
            deleted_count,
    }


# =========================================
# DASHBOARD STATS
# =========================================

@app.get(
    "/stats",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def dashboard_stats():

    return (
        get_dashboard_stats()
    )


# =========================================
# GET POLICIES
# =========================================

@app.get(
    "/policies",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def get_policies():

    policies = []


    for rule in THREAT_RULES:

        policies.append(
            {
                "id":
                    rule["id"],

                "category":
                    rule["category"],

                "description":
                    rule["description"],

                "risk_score":
                    rule["score"],

                "severity":
                    get_severity(
                        rule["score"]
                    ),

                "enabled":
                    rule["enabled"],

                "patterns_count":
                    len(
                        rule["patterns"]
                    ),
            }
        )


    enabled_count = sum(
        1
        for policy
        in policies
        if policy["enabled"]
    )


    return {
        "total":
            len(policies),

        "enabled":
            enabled_count,

        "policies":
            policies,
    }


# =========================================
# UPDATE POLICY
# =========================================

@app.patch(
    "/policies/{policy_id}",
    dependencies=[
        Depends(
            verify_api_key
        )
    ],
)
def update_policy(
    policy_id: int,
    data: PolicyUpdateRequest,
):

    for rule in THREAT_RULES:

        if (
            rule["id"]
            ==
            policy_id
        ):

            rule["enabled"] = (
                data.enabled
            )


            save_policy_state(
                policy_id=
                    policy_id,

                enabled=
                    data.enabled,
            )


            return {
                "message":
                    "Policy updated successfully.",

                "policy": {
                    "id":
                        rule["id"],

                    "category":
                        rule["category"],

                    "enabled":
                        rule["enabled"],

                    "risk_score":
                        rule["score"],

                    "severity":
                        get_severity(
                            rule["score"]
                        ),
                },
            }


    raise HTTPException(
        status_code=404,
        detail="Policy not found",
    )