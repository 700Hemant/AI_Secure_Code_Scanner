# 🛡️ AI Secure Code Scanner

> Find security vulnerabilities before attackers do.

AI Secure Code Scanner is a web-based source-code security analysis platform designed to identify common security vulnerabilities in source files and ZIP-based software projects.

The platform combines rule-based static analysis, AI-assisted security explanations, deterministic local fallback explanations, security scoring, severity classification, detection confidence, remediation guidance, scan history, dashboard analytics, and PDF security reporting.

---

# 1. Project Overview

AI Secure Code Scanner is a practical cybersecurity application that automatically analyzes source code and identifies potentially insecure coding patterns.

The application allows users to:

- Upload ZIP projects
- Upload supported source-code files
- Run automated security scans
- View security vulnerabilities
- View severity and confidence
- Inspect evidence and code context
- View recommended fixes
- Get English and Hindi remediation guidance
- Request AI security explanations
- View previous scan history
- Generate PDF security reports

The system is designed as an AI-assisted static security analysis platform for developers, students, security learners, and software teams.

---

# 2. Main Objectives

The main objectives of the project are:

- Detect common security vulnerabilities in source code
- Analyze ZIP-based software projects
- Provide severity classification
- Provide detection confidence
- Explain security issues in understandable language
- Provide practical remediation steps
- Provide English and Hindi security guidance
- Maintain scan history
- Generate professional PDF reports
- Provide dashboard-based security statistics
- Reduce false positives for common local-development configurations
- Provide AI-assisted security explanations with local fallback support

---

# 3. Technology Stack

## Frontend

- React
- Vite
- JavaScript
- JSX
- CSS

## Backend

- Python
- FastAPI
- Uvicorn
- SQLite
- ReportLab

## Security Analysis

- Custom Python static-analysis engine
- Pattern matching rules
- CWE references
- Severity classification
- Confidence scoring
- Evidence extraction
- Code-context extraction
- Remediation suggestions

## AI Explanation Layer

- OpenAI
- Google Gemini
- Mistral
- Local deterministic fallback

External AI providers are optional for the core security scanner because the backend contains a local fallback explanation system.

---

# 4. Key Features

## 🔍 Project Scanning

The user can upload:

- ZIP projects
- Supported source-code files

The backend extracts and analyzes the submitted code.

## 🛡️ Vulnerability Detection

The scanner contains detection rules for:

- Cross-Site Scripting (XSS)
- Code Injection
- Dynamic Code Execution
- Command Injection
- Hard-coded Secrets
- Weak Cryptography
- Security Misconfiguration
- Insecure HTTP Connections
- Insecure CORS
- CSRF-related heuristics
- Path Traversal
- SSRF-related patterns
- Insecure Deserialization
- Weak Randomness
- JWT/security configuration issues
- Other insecure coding patterns supported by the scanner

## 📊 Security Dashboard

The dashboard provides:

- Security Score
- Severity Distribution
- Risk Categories
- Detection Confidence
- Detailed Findings
- Scan History

## 🌐 Bilingual Remediation

Security fixes are displayed in:

- English
- Hindi

## 🤖 AI Security Explanation

The application can generate explanations for individual findings.

## 📚 Scan History

Previous scans are stored in SQLite.

## 📑 PDF Security Report

The application can generate downloadable PDF security reports.

---

# 5. System Architecture

The project follows a modular architecture:

```text
                         ┌─────────────────────┐
                         │        USER         │
                         │                     │
                         │ Upload ZIP / Code   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   REACT FRONTEND    │
                         │                     │
                         │ • File Upload       │
                         │ • Dashboard         │
                         │ • Security Score    │
                         │ • Findings          │
                         │ • History           │
                         │ • PDF Report        │
                         └──────────┬──────────┘
                                    │
                                REST API
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   FASTAPI BACKEND   │
                         │                     │
                         │ • API Endpoints     │
                         │ • File Processing   │
                         │ • Scan Management   │
                         │ • AI Explanation   │
                         │ • PDF Generation   │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
           ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
           │   SECURITY   │ │  AI ENGINE   │ │   SQLITE     │
           │   SCANNER    │ │              │ │   DATABASE   │
           │              │ │ OpenAI       │ │              │
           │ Static       │ │ Gemini       │ │ Scan History │
           │ Analysis     │ │ Mistral      │ │ Records      │
           │ Rules        │ │ Local        │ │              │
           └──────┬───────┘ │ Fallback     │ └──────────────┘
                  │          └──────────────┘
                  ▼
           ┌──────────────────────┐
           │ Security Findings    │
           │                      │
           │ • Severity           │
           │ • Confidence         │
           │ • CWE                │
           │ • Evidence           │
           │ • Recommended Fix    │
           └──────────┬───────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │ Dashboard / PDF      │
           │ Security Report      │
           └──────────────────────┘