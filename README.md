# DECOCT  
## Digital Evidence Chain-of-Custody Tool

DECOCT is a Blue Team forensic utility designed to preserve the **integrity, traceability, and accountability** of digital evidence through structured chain-of-custody management.

It enables investigators and security teams to securely register, verify, and audit both **local and remote (SSH-based) evidence**, while enforcing **Role-Based Access Control (RBAC)** and forensic-aligned security controls.

>  Currently supported on Linux systems (Kali, Ubuntu, Parrot OS, etc.)  
>  Windows `.exe` version is in active development and will be released soon.

---

##  Project Objectives

- Ensure digital evidence integrity using cryptographic hashing  
- Maintain defensible chain-of-custody records  
- Enforce least-privilege access control  
- Provide structured forensic audit logging  
- Support remote evidence verification securely via SSH  

---

# 🔹 Core Capabilities

## 1. Evidence Registration & Verification

### Local Evidence
- Single or multiple file registration
- Recursive directory expansion
- SHA-based hash generation
- Automatic Evidence ID assignment
- Custodian and purpose tracking
- Timestamped records

### Remote Evidence (SSH)
- Secure remote hashing via SSH
- Recursive remote directory handling
- Strict IPv4 validation
- No credential storage
- Hash comparison against stored integrity value

---

## 2. Chain-of-Custody Enforcement

DECOCT maintains structured forensic records including:

- Unique Evidence IDs
- Collection timestamps
- Assigned custodian
- Purpose of collection
- Full activity audit trail

All actions are recorded in `audit.log`, including:

- Evidence registration
- Verification attempts
- Deletion events
- Password resets
- Temporary admin elevation
- Tool reset operations

---

## 3. Role-Based Access Control (RBAC)

- Organization setup during first launch
- Primary Admin account (non-deletable)
- Maximum of 5 user accounts
- Role-based permission enforcement

### Admin-Only Actions
- Delete evidence
- Reset tool
- Add user accounts
- Remove user accounts
- View all accounts

---

## 4. Temporary Administrative Elevation

Standard users may request temporary administrative privileges:

- Requires admin authentication
- Clearly marked elevated session
- Fully logged privilege escalation and revocation
- Automatic rollback to original privileges

This ensures operational flexibility without compromising accountability.

---

## 5. Security Controls

### Password Policy Enforcement
Passwords must contain:
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character

### Account Security
- Salted SHA-256 password hashing
- Secure credential storage (`accounts.sec`)
- Enforced file permissions (`chmod 600`)
- Admin re-authentication for sensitive actions

### Network & Input Validation
The system rejects:
- Invalid IPv4 addresses
- `0.0.0.0`
- `255.255.255.255`
- Loopback ranges (127.x.x.x)
- Link-local ranges (169.254.x.x)

Additional safeguards:
- Empty field prevention
- Controlled exit handling (Ctrl+C confirmation)
- Strict input validation

---

# 🛡 Compliance Alignment

DECOCT is designed in alignment with:

- ISO/IEC 27037 — Digital evidence identification, collection, and preservation
- NIST SP 800-86 — Forensic techniques integration into incident response
- ISO/IEC 27001 — Information Security Management Systems (ISMS)

These alignments support forensic defensibility and audit readiness.

---

# ⚙ Installation

## Requirements
- Linux operating system
- Python 3.6+
- Internet access (first-time dependency installation only)

## Automatic Environment Bootstrap

On startup, DECOCT automatically:

- Verifies Python version
- Ensures pip availability
- Installs required dependencies if missing:
  - `paramiko`
  - `ipaddress`

---

# 🚀 Running DECOCT

```bash
cd ~/path/to/DECOCT_Folder
python3 decoct.py
```

On first launch:
- Organization configuration setup
- Primary Admin account creation

---

# 📂 Runtime Files

| File              | Purpose |
|-------------------|----------|
| `evidence.json`   | Stores registered evidence records |
| `audit.log`       | Logs all system actions |
| `accounts.sec`    | Secure user credential storage |
| `org_config.json` | Organization configuration |

> These files persist independently to maintain forensic integrity across sessions.

---

# Evidence Workflow

```
Login → RBAC Enforcement → Evidence Registration (Local/Remote)
        ↓
   SHA Hash Generation
        ↓
Chain-of-Custody Record Created
        ↓
Audit Logging & Verification
```

---

# Forensic Design Principles

DECOCT enforces:

- Integrity (cryptographic hash validation)
- Traceability (comprehensive logging)
- Accountability (role enforcement)
- Non-repudiation (timestamped audit trail)
- Least-Privilege Access Model

---

# 🗺 Roadmap

- Windows standalone `.exe` release (in progress)
- Database-backed storage option
- Digital signature integration
- SIEM integration capability
- Expanded enterprise scalability

---

# 📜 License

Developed by **PYD**  
Version 1.0  
Educational, Blue Team training, and research use.

---

# 📌 Disclaimer

This tool is intended for lawful forensic investigation, cybersecurity training, and research environments only. Users are responsible for ensuring compliance with local laws and organizational policies.
