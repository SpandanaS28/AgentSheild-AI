import ipaddress
import re


# =========================================
# SUSPICIOUS DOMAIN WORDS
# =========================================

SUSPICIOUS_DOMAIN_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "confirm",
    "reset",
    "password",
    "wallet",
    "payment",
    "banking",
    "invoice",
    "support",
}


# =========================================
# SEVERITY
# =========================================

def get_network_severity(
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

def get_network_action(
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
# ADD FINDING
# =========================================

def add_finding(
    findings: list,
    category: str,
    score: int,
    matched_text: str,
    explanation: str,
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
# CLEAN INPUT
# =========================================

def clean_indicator(
    value: str
):

    cleaned = (
        value
        .strip()
        .lower()
    )


    # Remove common URL prefixes if the
    # user pastes a full website address.

    cleaned = re.sub(
        r"^https?://",
        "",
        cleaned,
    )


    # Remove path/query after hostname.

    cleaned = cleaned.split(
        "/"
    )[0]


    cleaned = cleaned.split(
        "?"
    )[0]


    cleaned = cleaned.split(
        "#"
    )[0]


    # Remove trailing dot.

    cleaned = cleaned.rstrip(
        "."
    )


    return cleaned


# =========================================
# DOMAIN VALIDATION
# =========================================

def is_valid_domain(
    domain: str
):

    if (
        not domain
        or
        len(domain) > 253
    ):

        return False


    labels = domain.split(
        "."
    )


    if (
        len(labels) < 2
    ):

        return False


    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
        re.IGNORECASE,
    )


    for label in labels:

        if (
            not label_pattern.match(
                label
            )
        ):

            return False


    return True


# =========================================
# IP ANALYSIS
# =========================================

def analyze_ip(
    ip_text: str
):

    ip_value = ipaddress.ip_address(
        ip_text
    )


    findings = []


    # =====================================
    # LOOPBACK
    # =====================================

    if ip_value.is_loopback:

        add_finding(
            findings,
            "Loopback Address",
            85,
            ip_text,
            (
                "The IP points back to the local machine. "
                "Loopback targets are important when checking "
                "for SSRF and internal-service access."
            ),
        )


    # =====================================
    # PRIVATE
    # =====================================

    elif ip_value.is_private:

        add_finding(
            findings,
            "Private Network Address",
            70,
            ip_text,
            (
                "The IP belongs to a private network range "
                "and is not normally reachable directly "
                "from the public Internet."
            ),
        )


    # =====================================
    # LINK LOCAL
    # =====================================

    if ip_value.is_link_local:

        add_finding(
            findings,
            "Link-Local Address",
            75,
            ip_text,
            (
                "The IP is restricted to the local network "
                "segment and may reference internal services."
            ),
        )


    # =====================================
    # RESERVED
    # =====================================

    if ip_value.is_reserved:

        add_finding(
            findings,
            "Reserved IP Address",
            60,
            ip_text,
            (
                "The IP belongs to a reserved address range "
                "rather than an ordinary public Internet host."
            ),
        )


    # =====================================
    # MULTICAST
    # =====================================

    if ip_value.is_multicast:

        add_finding(
            findings,
            "Multicast Address",
            50,
            ip_text,
            (
                "The IP is a multicast address and does not "
                "represent a normal single public host."
            ),
        )


    # =====================================
    # UNSPECIFIED
    # =====================================

    if ip_value.is_unspecified:

        add_finding(
            findings,
            "Unspecified Address",
            80,
            ip_text,
            (
                "The IP represents an unspecified address "
                "and should not normally be used as a remote host."
            ),
        )


    # =====================================
    # PUBLIC IP
    # =====================================

    if not findings:

        return {
            "indicator":
                ip_text,

            "indicator_type":
                "ip",

            "ip_version":
                ip_value.version,

            "status":
                "safe",

            "message":
                (
                    "The IP has a normal public address structure. "
                    "No local structural risk indicator was detected."
                ),

            "risk_score":
                10,

            "severity":
                "low",

            "action":
                "ALLOW",

            "threats":
                [],

            "reputation_checked":
                False,

            "analysis_type":
                "local_heuristic",

            "note":
                (
                    "AgentShield has not checked an external "
                    "IP reputation database for this result."
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


    severity = (
        get_network_severity(
            risk_score
        )
    )


    action = (
        get_network_action(
            severity
        )
    )


    return {
        "indicator":
            ip_text,

        "indicator_type":
            "ip",

        "ip_version":
            ip_value.version,

        "status":
            (
                "safe"
                if action == "ALLOW"
                else "dangerous"
            ),

        "message":
            (
                "Network security indicators "
                "were detected for this IP."
            ),

        "risk_score":
            risk_score,

        "severity":
            severity,

        "action":
            action,

        "threats":
            findings,

        "reputation_checked":
            False,

        "analysis_type":
            "local_heuristic",

        "note":
            (
                "AgentShield has not checked an external "
                "IP reputation database for this result."
            ),
    }


# =========================================
# DOMAIN ANALYSIS
# =========================================

def analyze_domain(
    domain: str
):

    findings = []


    # =====================================
    # PUNYCODE
    # =====================================

    if (
        "xn--"
        in domain
    ):

        add_finding(
            findings,
            "Punycode Domain",
            50,
            domain,
            (
                "The domain uses Punycode. "
                "Internationalized domains can be legitimate, "
                "but attackers may use look-alike characters "
                "for phishing."
            ),
        )


    labels = domain.split(
        "."
    )


    # =====================================
    # EXCESSIVE SUBDOMAINS
    # =====================================

    if (
        len(labels) >= 5
    ):

        add_finding(
            findings,
            "Excessive Subdomains",
            35,
            f"{len(labels)} domain sections",
            (
                "The hostname contains many domain sections. "
                "Long subdomain chains can make phishing "
                "domains harder to visually inspect."
            ),
        )


    # =====================================
    # VERY LONG DOMAIN
    # =====================================

    if (
        len(domain) >= 80
    ):

        add_finding(
            findings,
            "Unusually Long Domain",
            40,
            f"{len(domain)} characters",
            (
                "The domain name is unusually long and may "
                "be designed to make the destination harder "
                "to understand."
            ),
        )


    # =====================================
    # LONG LABEL
    # =====================================

    longest_label = max(
        len(label)
        for label
        in labels
    )


    if (
        longest_label >= 40
    ):

        add_finding(
            findings,
            "Unusually Long Domain Label",
            35,
            f"{longest_label} characters",
            (
                "One section of the hostname is unusually long."
            ),
        )


    # =====================================
    # MANY HYPHENS
    # =====================================

    hyphen_count = (
        domain.count(
            "-"
        )
    )


    if (
        hyphen_count >= 4
    ):

        add_finding(
            findings,
            "Heavy Hyphen Usage",
            30,
            f"{hyphen_count} hyphens",
            (
                "The hostname contains many hyphens. "
                "This can appear in automatically generated "
                "or phishing-style domains."
            ),
        )


    # =====================================
    # NUMERIC HEAVY DOMAIN
    # =====================================

    letters_and_numbers = [
        character

        for character
        in domain

        if character.isalnum()
    ]


    numeric_characters = [
        character

        for character
        in letters_and_numbers

        if character.isdigit()
    ]


    if (
        letters_and_numbers
        and
        (
            len(
                numeric_characters
            )
            /
            len(
                letters_and_numbers
            )
        )
        >= 0.45
    ):

        add_finding(
            findings,
            "Numeric-Heavy Domain",
            30,
            domain,
            (
                "A large portion of the hostname is numeric. "
                "This is not necessarily malicious but can "
                "be a useful heuristic indicator."
            ),
        )


    # =====================================
    # SUSPICIOUS KEYWORDS
    # =====================================

    matched_keywords = sorted(
        {
            keyword

            for keyword
            in SUSPICIOUS_DOMAIN_KEYWORDS

            if keyword
            in domain
        }
    )


    if matched_keywords:

        add_finding(
            findings,
            "Suspicious Domain Keywords",
            35,
            ", ".join(
                matched_keywords[
                    :6
                ]
            ),
            (
                "The hostname contains terms commonly seen "
                "in login, account verification, support "
                "or payment-themed phishing campaigns. "
                "This alone does not prove the domain is malicious."
            ),
        )


    # =====================================
    # SAFE DOMAIN
    # =====================================

    if not findings:

        return {
            "indicator":
                domain,

            "indicator_type":
                "domain",

            "status":
                "safe",

            "message":
                (
                    "No suspicious domain structure "
                    "was detected by AgentShield."
                ),

            "risk_score":
                10,

            "severity":
                "low",

            "action":
                "ALLOW",

            "threats":
                [],

            "reputation_checked":
                False,

            "analysis_type":
                "local_heuristic",

            "note":
                (
                    "This result checks domain structure only. "
                    "No external reputation service was queried."
                ),
        }


    # =====================================
    # DOMAIN RISK
    # =====================================

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


    severity = (
        get_network_severity(
            risk_score
        )
    )


    action = (
        get_network_action(
            severity
        )
    )


    return {
        "indicator":
            domain,

        "indicator_type":
            "domain",

        "status":
            (
                "safe"
                if action == "ALLOW"
                else "dangerous"
            ),

        "message":
            (
                "Suspicious domain indicators were detected."
            ),

        "risk_score":
            risk_score,

        "severity":
            severity,

        "action":
            action,

        "threats":
            findings,

        "reputation_checked":
            False,

        "analysis_type":
            "local_heuristic",

        "note":
            (
                "This result checks domain structure only. "
                "No external reputation service was queried."
            ),
    }


# =========================================
# MAIN IP / DOMAIN SCANNER
# =========================================

def analyze_network_indicator(
    value: str
):

    indicator = (
        clean_indicator(
            value
        )
    )


    if not indicator:

        raise ValueError(
            "Please provide an IP address or domain."
        )


    # =====================================
    # TRY IP FIRST
    # =====================================

    try:

        ipaddress.ip_address(
            indicator
        )


        return analyze_ip(
            indicator
        )


    except ValueError:

        pass


    # =====================================
    # DOMAIN
    # =====================================

    if not is_valid_domain(
        indicator
    ):

        raise ValueError(
            "Please provide a valid IP address or domain."
        )


    return analyze_domain(
        indicator
    )