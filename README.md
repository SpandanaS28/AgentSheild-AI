# 🛡️ AgentShield AI

**AgentShield AI** is an AI security gateway and threat-analysis platform designed to inspect AI prompts, URLs, IP addresses, domains, and files before they reach sensitive systems.

It combines **AI prompt security**, **DLP-style sensitive data detection**, **security policy enforcement**, **risk scoring**, **incident management**, **local malware reputation**, and **Microsoft Defender Antivirus integration** in one security dashboard.

> AgentShield AI is a portfolio cybersecurity project built with **FastAPI, React, TypeScript, SQLite, and Microsoft Defender**.

---

## 🚀 Key Features

### 🤖 AI Prompt Security

AgentShield analyzes AI prompts before they reach an AI application.

It currently detects security categories including:

- Prompt Injection
- System Prompt Extraction
- Secret Extraction
- Privilege Escalation
- Destructive Actions
- Security Evasion
- Sensitive Data Exposure

Each prompt receives:

- Risk Score
- Severity
- Security Status
- Enforcement Action

Possible actions:

```text
ALLOW
MONITOR
REVIEW
BLOCK
```

---

## 🔐 Sensitive Data Protection / DLP

AgentShield detects sensitive information in prompts, including:

- Passwords
- API Keys
- Secret Keys
- Client Secrets
- Bearer Tokens
- JWT Tokens
- OpenAI-style `sk-...` keys
- AWS Access Keys

Sensitive values are redacted before security incidents are stored in the database.

---

## 🌐 URL Security Scanner

The URL scanner performs local structural and heuristic analysis.

It can detect indicators such as:

- Embedded credentials
- Raw IP addresses
- Private or local network targets
- Punycode domains
- URL shorteners
- Excessive subdomains
- Suspicious keywords
- Executable downloads
- Archive downloads
- Unusual ports
- Heavy percent encoding
- Insecure HTTP
- Unusually long URLs

> URL scanning currently uses AgentShield's local heuristics and does not claim external global reputation intelligence.

---

## 🌍 IP / Domain Scanner

AgentShield can inspect IP addresses and domain names for suspicious structural characteristics.

Examples include:

- Loopback addresses
- Private IP ranges
- Reserved addresses
- Suspicious domain structures
- Punycode
- Excessive subdomains
- Security-sensitive keywords

The scanner assigns the same standardized:

```text
Risk → Severity → Action
```

decision used throughout AgentShield.

---

## 📁 File Security Scanner

AgentShield includes multi-layer file analysis without executing uploaded files.

### Static Analysis

The file scanner checks:

- File extensions
- Double extensions
- Hidden executable patterns
- Executable packages
- Archive files
- Macro-enabled Office files
- ELF executables
- Magic-byte file types
- File type mismatches
- File entropy
- Suspicious script patterns
- Encoded PowerShell
- `Invoke-Expression`
- Base64 decoding indicators
- Shell execution indicators
- `curl` / `wget` pipe-to-shell patterns

### Cryptographic Hashing

AgentShield calculates:

- MD5
- SHA-1
- SHA-256

SHA-256 is also used by the local file reputation system.

---

## 🦠 Microsoft Defender Antivirus Integration

On supported Windows systems, AgentShield integrates with:

**Microsoft Defender Antivirus**

Uploaded files are temporarily scanned using Defender's command-line scanner.

AgentShield does **not execute uploaded files**.

The interface reports:

- Antivirus availability
- Scan completion
- Antivirus engine
- Threat detection status
- Defender scan result

> Microsoft Defender integration requires a Windows host with Microsoft Defender available. On unsupported deployment environments, antivirus scanning may be reported as unavailable.

---

## 🧠 AgentShield Local Reputation Database

AgentShield maintains its own SHA-256-based file reputation database.

For previously scanned files, it tracks information such as:

- Previously seen status
- Number of times seen
- First seen
- Last seen
- Previous risk score
- Previous severity
- Previous action
- Highest historical risk
- Highest historical action

This is an **AgentShield-local reputation database**, not a global threat-intelligence service.

---

## 🚨 Unified Incident Management

All scanner activity can be stored in one SQLite incident history.

Supported incident types:

- 🟣 Prompt
- 🔵 URL
- 🟠 Network
- 🟢 File

The incident dashboard includes:

- Search
- Scan-type filtering
- Status filtering
- Severity filtering
- Action filtering
- Date filtering
- Risk sorting
- Pagination
- Incident details
- Individual incident deletion
- Clear history
- CSV export

---

## 📋 Security Policy Management

AgentShield contains configurable security policies.

Policies can be enabled or disabled directly from the dashboard.

The prompt security engine respects the current policy configuration when making detection and enforcement decisions.

---

## 📊 Security Analytics

The analytics dashboard displays security information such as:

- Total scans
- Threats detected
- Blocked requests
- Safe requests
- Threat rate
- Safe rate
- Block rate
- Average risk
- Highest risk
- Scanner activity
- Threat-category distribution

---

## 🔑 API Security

Backend endpoints are protected with an API key using the:

```http
X-API-Key
```

header.

AgentShield also includes basic scanner rate limiting.

Current local default rate:

```text
20 scanner requests per 60 seconds per client IP
```

Secrets are loaded from environment variables instead of being hardcoded into the backend source code.

---

## 🏗️ Architecture

```text
                     ┌─────────────────────────┐
                     │      React Frontend     │
                     │      TypeScript/Vite    │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │      FastAPI Backend    │
                     │     API Key Security    │
                     │      Rate Limiting      │
                     └────────────┬────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
      ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
      │ Prompt Engine │   │ URL / Network │   │  File Scanner │
      │ + DLP Rules   │   │    Scanner    │   │ Static + AV   │
      └───────┬───────┘   └───────┬───────┘   └───────┬───────┘
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │ Risk / Severity / Action│
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │     SQLite Database     │
                     │ Incidents + Policies +  │
                     │   Local Reputation      │
                     └─────────────────────────┘
```

---

## 🆚 AgentShield AI vs VirusTotal

AgentShield and VirusTotal overlap in some security areas, but they solve different core problems.

### VirusTotal focuses on

- Global malware reputation
- Multi-engine antivirus scanning
- File intelligence
- URL intelligence
- Domain intelligence
- IP intelligence
- Malware sandbox behavior
- Large-scale threat intelligence

### AgentShield adds

- AI Prompt Injection Detection
- System Prompt Extraction Detection
- Secret Extraction Detection
- Sensitive Data / DLP Detection
- Privilege Escalation Detection
- Destructive Action Detection
- Security Evasion Detection
- AI Security Policy Enforcement
- Risk-based AI decisions
- `ALLOW / MONITOR / REVIEW / BLOCK`
- Unified AI + URL + network + file incident management

AgentShield is therefore **not intended to be a VirusTotal replacement**.

Its main goal is to provide an **AI security gateway combined with local cybersecurity analysis**.

---

## 🛠️ Technology Stack

### Backend

- Python
- FastAPI
- Uvicorn
- SQLite
- python-dotenv
- python-multipart

### Frontend

- React
- TypeScript
- Vite
- CSS

### Security

- Regex / rule-based prompt detection
- Sensitive-data detection
- SHA-256 reputation tracking
- Static file analysis
- Microsoft Defender Antivirus
- API-key authentication
- Rate limiting

### Testing

- Pytest
- FastAPI TestClient
- Mocked antivirus/reputation security tests

---

## 📂 Project Structure

```text
AgentShield-AI/
│
├── main.py
├── database.py
├── file_scanner.py
├── network_scanner.py
├── reputation_database.py
├── windows_defender.py
├── cleanup_old_data.py
├── requirements.txt
├── .env.example
├── .gitignore
│
├── tests/
│   ├── test_agentshield.py
│   ├── test_scanners.py
│   ├── test_security_features.py
│   └── test_file_security_layers.py
│
└── frontend/
    ├── src/
    │   ├── App.tsx
    │   ├── App.css
    │   ├── index.css
    │   ├── main.tsx
    │   └── assets/
    │
    ├── public/
    ├── package.json
    ├── vite.config.ts
    └── .env.example
```

---

## ⚙️ Local Installation

### 1. Clone the repository

```bash
git clone https://github.com/SpandanaS28/AgentShield-AI.git
cd AgentShield-AI
```

---

### 2. Create a Python virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

---

### 3. Install backend dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Create the backend environment file

Create:

```text
.env
```

Example:

```env
AGENTSHIELD_API_KEY=replace-with-a-strong-random-api-key
```

You can generate a random key with Python:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Never commit your real `.env` file.

---

### 5. Start the backend

```bash
uvicorn main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger API documentation:

```text
http://127.0.0.1:8000/docs
```

---

## 💻 Frontend Setup

Open another terminal:

```bash
cd frontend
npm install
```

Create:

```text
frontend/.env.local
```

Example:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_AGENTSHIELD_API_KEY=your-local-development-key
```

Then start the frontend:

```bash
npm run dev
```

Frontend:

```text
http://localhost:5173
```

---

## ⚠️ Important Frontend API-Key Note

Environment variables beginning with:

```text
VITE_
```

are bundled into frontend browser code.

Therefore:

```text
VITE_AGENTSHIELD_API_KEY
```

must **not** be treated as a secure production secret.

The current configuration is suitable for local development and portfolio demonstration.

A production deployment should use proper user authentication, sessions, a backend-for-frontend architecture, or another server-side authorization mechanism.

---

## 🧪 Running Tests

Activate the Python virtual environment and run:

```bash
python -m pytest -q
```

Current tested result:

```text
19 passed
```

The security test suite includes:

- Prompt security tests
- API authentication tests
- Rate-limit tests
- URL scanner tests
- Network scanner tests
- File scanner tests
- DLP tests
- Policy tests
- Local reputation tests
- Mock Microsoft Defender clean/detection tests

---

## 🏭 Production Build

To verify the React production build:

```bash
cd frontend
npm run build
```

The resulting frontend production files are generated in:

```text
frontend/dist/
```

The `dist` directory is intentionally ignored by Git.

---

## 🔒 Security Design Principles

AgentShield follows several important security principles:

- Uploaded files are never intentionally executed by AgentShield.
- Sensitive prompt values are redacted before storage.
- Real `.env` files are excluded from Git.
- SQLite databases are excluded from Git.
- Frontend dependencies are excluded from Git.
- Antivirus integration uses Microsoft Defender on supported Windows systems.
- External reputation intelligence is not falsely claimed.
- Local reputation is clearly labeled as local.
- File scanning has a maximum upload size.
- Security endpoints use API-key protection.
- Scanner requests are rate limited.

---

## 🚧 Current Limitations

AgentShield is currently a portfolio/security research project.

Current limitations include:

- Prompt detection is primarily rule/regex based rather than a trained ML security classifier.
- URL and IP/domain scanning use local heuristics rather than global reputation feeds.
- Local file reputation contains only files previously analyzed by the AgentShield installation.
- Microsoft Defender provides one local antivirus engine rather than multi-engine scanning.
- Defender integration requires a compatible Windows environment.
- AgentShield does not currently execute malware in a sandbox.
- SQLite may require a persistent volume or database migration for production cloud deployment.

---

## 🔮 Future Improvements

Possible future versions may include:

- ML/LLM-assisted prompt attack classification
- Advanced semantic prompt-injection detection
- User accounts and role-based access control
- PostgreSQL support
- Persistent cloud storage
- Threat-intelligence feeds
- Safe external malware-reputation integration
- SIEM integration
- Webhook alerts
- Email/security notifications
- IOC enrichment
- Security event correlation
- Containerized deployment
- Dedicated isolated malware sandbox infrastructure
- CI/CD security testing
- Improved production authentication

---

## 🎯 Project Goal

The goal of AgentShield AI is to explore how conventional cybersecurity controls can be extended into modern generative-AI applications.

Instead of protecting only files and network indicators, AgentShield also treats **AI prompts, secrets, security policies, and model interactions as security-sensitive objects**.

The project demonstrates how an AI-facing security gateway can combine:

```text
Prompt Security
       +
Data Loss Prevention
       +
Policy Enforcement
       +
Risk Scoring
       +
File Security
       +
Network Analysis
       +
Incident Management
```

into one security platform.

---

## 👩‍💻 Author

**Spandana S**

GitHub: **SpandanaS28**

---

## ⚠️ Disclaimer

AgentShield AI is intended for educational, portfolio, defensive-security, and research purposes.

It should not be considered a replacement for enterprise antivirus, EDR, SIEM, sandboxing, professional threat-intelligence services, or other production security controls.
