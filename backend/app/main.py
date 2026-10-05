from pathlib import Path
import json
import os
import sqlite3
import tempfile
import zipfile
import urllib.request
import urllib.error
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from io import BytesIO
from xml.sax.saxutils import escape

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.scanner import scan_project


# =========================================================
# BASE / ENVIRONMENT
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)


# =========================================================
# AI CONFIGURATION
# =========================================================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5-mini").strip()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip()

MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY", "").strip()

MISTRAL_MODEL = os.getenv("MISTRAL_MODEL", "mistral-small-latest").strip()


# =========================================================
# DATABASE
# =========================================================

DB_FILE = BASE_DIR / "scanner.db"


def get_connection():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            score INTEGER DEFAULT 100,
            critical INTEGER DEFAULT 0,
            high INTEGER DEFAULT 0,
            medium INTEGER DEFAULT 0,
            low INTEGER DEFAULT 0,
            findings TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    connection.commit()
    connection.close()


init_database()


# =========================================================
# FASTAPI
# =========================================================

app = FastAPI(
    title="AI Secure Code Scanner API",
    version="5.1.0",
    description="AI-powered source code security analysis platform",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# HELPERS
# =========================================================

def normalize_count(counts, key):
    if not counts:
        return 0

    return int(
        counts.get(key)
        or counts.get(key.lower())
        or 0
    )


def get_scan_counts(result):
    counts = result.get("counts", {})

    return {
        "critical": normalize_count(counts, "CRITICAL"),
        "high": normalize_count(counts, "HIGH"),
        "medium": normalize_count(counts, "MEDIUM"),
        "low": normalize_count(counts, "LOW"),
    }


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(filename, result):
    counts = get_scan_counts(result)

    score = int(result.get("score", 100))

    findings = result.get("findings", [])

    findings_json = json.dumps(
        findings,
        ensure_ascii=False
    )

    connection = get_connection()

    existing = connection.execute(
        """
        SELECT id
        FROM scans
        WHERE filename = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (filename,)
    ).fetchone()

    if existing:
        connection.execute(
            """
            UPDATE scans
            SET
                score = ?,
                critical = ?,
                high = ?,
                medium = ?,
                low = ?,
                findings = ?,
                created_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                score,
                counts["critical"],
                counts["high"],
                counts["medium"],
                counts["low"],
                findings_json,
                existing["id"],
            ),
        )
    else:
        connection.execute(
            """
            INSERT INTO scans (
                filename,
                score,
                critical,
                high,
                medium,
                low,
                findings
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename,
                score,
                counts["critical"],
                counts["high"],
                counts["medium"],
                counts["low"],
                findings_json,
            ),
        )

    # Keep history unique by filename. If older duplicate rows exist,
    # retain the row just updated/inserted and remove older copies.
    connection.execute(
        """
        DELETE FROM scans
        WHERE filename = ?
          AND id != (
              SELECT MAX(id) FROM scans WHERE filename = ?
          )
        """,
        (filename, filename),
    )

    connection.commit()
    connection.close()


def cleanup_duplicate_history():
    """Remove older duplicate history rows, keeping the newest scan per filename."""
    connection = get_connection()
    connection.execute(
        """
        DELETE FROM scans
        WHERE id NOT IN (
            SELECT MAX(id)
            FROM scans
            GROUP BY filename
        )
        """
    )
    connection.commit()
    connection.close()


cleanup_duplicate_history()


# =========================================================
# UTC -> IST
# =========================================================

def convert_to_ist(value):
    if not value:
        return value

    try:
        dt = datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S"
        )

        dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(ZoneInfo("Asia/Kolkata"))

        return dt.isoformat()

    except Exception:
        return value


# =========================================================
# GET HISTORY
# =========================================================

def get_history():
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            filename,
            score,
            critical,
            high,
            medium,
            low,
            created_at
        FROM scans
        ORDER BY id DESC
        LIMIT 50
        """
    ).fetchall()

    connection.close()

    history = []

    for row in rows:
        item = dict(row)
        item["created_at"] = convert_to_ist(
            item.get("created_at")
        )
        history.append(item)

    return history


# =========================================================
# SAFE ZIP EXTRACTION
# =========================================================

def safe_extract_zip(zip_path, destination):
    destination = Path(destination).resolve()

    with zipfile.ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            member_path = (
                destination / member.filename
            ).resolve()

            if not str(member_path).startswith(
                str(destination)
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Unsafe ZIP file detected."
                )

        archive.extractall(destination)


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    return {
        "name": "AI Secure Code Scanner API",
        "status": "running",
        "version": "5.1.0",
        "docs": "/docs",
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "providers": {
            "openai": bool(OPENAI_API_KEY),
            "gemini": bool(GEMINI_API_KEY),
            "mistral": bool(MISTRAL_API_KEY),
        },
        "models": {
            "openai": OPENAI_MODEL,
            "gemini": GEMINI_MODEL,
            "mistral": MISTRAL_MODEL,
        },
    }


# =========================================================
# HISTORY
# =========================================================

@app.get("/api/history")
def history():
    return get_history()


# =========================================================
# SCAN DETAILS
# =========================================================

@app.get("/api/history/{scan_id}")
def scan_details(scan_id: int):
    connection = get_connection()

    row = connection.execute(
        """
        SELECT
            id,
            filename,
            score,
            critical,
            high,
            medium,
            low,
            findings,
            created_at
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    ).fetchone()

    connection.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Scan not found."
        )

    item = dict(row)

    try:
        item["findings"] = json.loads(
            item.get("findings") or "[]"
        )
    except Exception:
        item["findings"] = []

    item["created_at"] = convert_to_ist(
        item.get("created_at")
    )

    return item


# =========================================================
# SCAN PROJECT
# =========================================================

@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected."
        )

    filename = Path(file.filename).name

    allowed_extensions = {
        ".zip", ".py", ".js", ".jsx", ".ts", ".tsx",
        ".java", ".php", ".go", ".cs", ".cpp", ".c",
        ".html", ".css", ".sql", ".json", ".rb",
    }

    extension = Path(filename).suffix.lower()

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. "
                "Upload a ZIP or supported source file."
            ),
        )

    file_bytes = await file.read()

    if not file_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty."
        )

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / filename
            temp_path.write_bytes(file_bytes)

            project_dir = Path(temp_dir) / "project"
            project_dir.mkdir(parents=True, exist_ok=True)

            if extension == ".zip":
                safe_extract_zip(temp_path, project_dir)
                scan_root = project_dir
            else:
                scan_root = project_dir
                destination = scan_root / filename
                destination.write_bytes(file_bytes)

            result = scan_project(scan_root)
            result["filename"] = filename

            save_scan(filename, result)

            return result

    except HTTPException:
        raise

    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=400,
            detail="Invalid or corrupted ZIP file."
        )

    except Exception as error:
        print("Scan error:", repr(error))

        raise HTTPException(
            status_code=500,
            detail=f"Security scan failed: {str(error)}",
        )


# =========================================================
# PDF REPORT
# =========================================================

@app.post("/api/report/pdf")
async def generate_pdf_report(payload: dict):
    """Generate a PDF report from the current scan result."""

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import (
            getSampleStyleSheet,
            ParagraphStyle,
        )
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            KeepTogether,
        )
    except ImportError as error:
        raise HTTPException(
            status_code=500,
            detail="PDF support is not installed. Run: pip install reportlab",
        ) from error

    filename = str(
        payload.get("filename") or "Security Scan"
    )

    score = int(
        payload.get("score") or 0
    )

    counts = payload.get("counts") or {}
    findings = payload.get("findings") or []

    files_scanned = int(
        payload.get("files_scanned") or 0
    )

    lines_scanned = int(
        payload.get("lines_scanned") or 0
    )

    summary = str(
        payload.get("summary")
        or f"Detected {len(findings)} security finding(s)."
    )

    def txt(value):
        return escape(
            str(value if value is not None else "—")
        ).replace("\n", "<br/>")

    def count_value(name):
        return counts.get(
            name,
            counts.get(name.upper(), 0)
        ) or 0

    buffer = BytesIO()

    safe_title = (
        filename.replace("/", "_")
        .replace("\\", "_")
    )

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Security Report - {safe_title}",
        author="AI Secure Code Scanner",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=27,
        alignment=TA_CENTER,
        spaceAfter=8,
    )

    sub_style = ParagraphStyle(
        "ReportSub",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#666666"),
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
    )

    story = [
        Paragraph(
            "AI Secure Code Scanner",
            title_style
        ),
        Paragraph(
            "Automated Security Analysis Report",
            sub_style
        ),
        Paragraph(
            f"<b>Scanned file:</b> {txt(filename)}",
            body_style
        ),
        Paragraph(
            f"<b>Security score:</b> {score}/100",
            body_style
        ),
        Spacer(1, 8),
    ]

    summary_data = [
        [
            "Critical",
            "High",
            "Medium",
            "Low",
            "Files",
            "Lines",
            "Total",
        ],
        [
            str(count_value("critical")),
            str(count_value("high")),
            str(count_value("medium")),
            str(count_value("low")),
            str(files_scanned),
            str(lines_scanned),
            str(len(findings)),
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[24 * mm] * 7,
        repeatRows=1,
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1f2937"),
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white,
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER",
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold",
            ),
            (
                "FONTNAME",
                (0, 1),
                (-1, 1),
                "Helvetica-Bold",
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#d1d5db"),
            ),
            (
                "BACKGROUND",
                (0, 1),
                (-1, 1),
                colors.HexColor("#f3f4f6"),
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
        ])
    )

    story += [
        summary_table,
        Spacer(1, 12),
        Paragraph("Summary", heading_style),
        Paragraph(txt(summary), body_style),
        Paragraph("Security Findings", heading_style),
    ]

    if not findings:
        story.append(
            Paragraph(
                "No supported security findings were detected.",
                body_style,
            )
        )
    else:
        for index, finding in enumerate(findings, 1):
            severity = str(
                finding.get("severity") or "LOW"
            ).upper()

            title = finding.get(
                "title"
            ) or "Security Finding"

            category = finding.get(
                "category"
            ) or "—"

            cwe = finding.get(
                "cwe"
            ) or "—"

            file_name = finding.get(
                "file"
            ) or "—"

            line = finding.get(
                "line"
            ) or "—"

            confidence = finding.get(
                "confidence"
            ) or "—"

            evidence = finding.get(
                "evidence"
            ) or "—"

            context = finding.get(
                "context"
            ) or "—"

            fix = finding.get(
                "fix"
            ) or (
                "Review and remediate the affected "
                "code before deployment."
            )

            description = finding.get(
                "description"
            ) or "—"

            header = Table(
                [[
                    Paragraph(
                        f"<b>#{index} {txt(title)}</b>",
                        body_style,
                    ),
                    Paragraph(
                        f"<b>{txt(severity)}</b>",
                        body_style,
                    ),
                ]],
                colWidths=[145 * mm, 25 * mm],
            )

            header.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        colors.HexColor("#eef2ff"),
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        colors.HexColor("#c7d2fe"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                ])
            )

            detail = [
                [
                    Paragraph("Category", small_style),
                    Paragraph(txt(category), small_style),
                    Paragraph("CWE", small_style),
                    Paragraph(txt(cwe), small_style),
                ],
                [
                    Paragraph("File", small_style),
                    Paragraph(txt(file_name), small_style),
                    Paragraph("Line", small_style),
                    Paragraph(txt(line), small_style),
                ],
                [
                    Paragraph("Confidence", small_style),
                    Paragraph(txt(confidence), small_style),
                    Paragraph("", small_style),
                    Paragraph("", small_style),
                ],
            ]

            detail_table = Table(
                detail,
                colWidths=[25 * mm, 75 * mm, 20 * mm, 50 * mm],
            )

            detail_table.setStyle(
                TableStyle([
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#e5e7eb"),
                    ),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.HexColor("#f9fafb"),
                    ),
                    (
                        "BACKGROUND",
                        (2, 0),
                        (2, -1),
                        colors.HexColor("#f9fafb"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ])
            )

            story.append(
                KeepTogether([
                    header,
                    Spacer(1, 4),
                    detail_table,
                    Spacer(1, 5),
                    Paragraph(
                        f"<b>Problem:</b> {txt(description)}",
                        body_style,
                    ),
                    Paragraph(
                        f"<b>Evidence:</b> {txt(evidence)}",
                        small_style,
                    ),
                    Paragraph(
                        f"<b>Code context:</b> {txt(context)}",
                        small_style,
                    ),
                    Paragraph(
                        f"<b>Recommended fix:</b> {txt(fix)}",
                        body_style,
                    ),
                    Spacer(1, 10),
                ])
            )

    story += [
        Spacer(1, 8),
        Paragraph(
            "Generated by AI Secure Code Scanner",
            sub_style,
        ),
    ]

    document.build(story)
    buffer.seek(0)

    safe_name = (
        Path(filename).stem
        .replace(" ", "_")
        or "security_scan"
    )

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="'
                f'{safe_name}_security_report.pdf"'
            )
        },
    )


# =========================================================
# AI PROMPT
# =========================================================

def build_ai_prompt(findings, score):
    findings_text = json.dumps(
        findings,
        indent=2,
        ensure_ascii=False
    )

    return f"""
You are a cybersecurity code-review assistant.

Analyze the following security scan findings.

Security Score:
{score}/100

Findings:
{findings_text}

For each finding explain:

1. What the vulnerability is.
2. Why it is dangerous.
3. How an attacker could potentially abuse it.
4. How the developer should fix it.
5. Give a short secure-code example when useful.

Keep the explanation practical and understandable for a
college-level cybersecurity project.

Do not invent vulnerabilities that are not present in the
provided findings.

Return a clear structured security explanation.
""".strip()


# =========================================================
# OPENAI
# =========================================================

def call_openai(prompt):
    if not OPENAI_API_KEY:
        raise RuntimeError(
            "OPENAI_API_KEY is not configured."
        )

    url = "https://api.openai.com/v1/chat/completions"

    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert cybersecurity "
                    "code analysis assistant."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.2,
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=60
        ) as response:
            body = response.read().decode("utf-8")
            data = json.loads(body)

            return (
                data
                .get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )

    except urllib.error.HTTPError as error:
        body = error.read().decode(
            "utf-8",
            errors="ignore"
        )

        raise RuntimeError(
            f"OpenAI HTTP {error.code}: {body}"
        )

    except Exception as error:
        raise RuntimeError(
            f"OpenAI error: {error}"
        )


# =========================================================
# GEMINI
# =========================================================

def call_gemini(prompt):
    if not GEMINI_API_KEY:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured."
        )

    url = (
        "https://generativelanguage.googleapis.com/"
        f"v1beta/models/{GEMINI_MODEL}:generateContent"
        f"?key={GEMINI_API_KEY}"
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ]
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=60
        ) as response:
            body = response.read().decode("utf-8")
            data = json.loads(body)

            candidates = data.get("candidates", [])

            if not candidates:
                return ""

            content = candidates[0].get(
                "content",
                {}
            )

            parts = content.get(
                "parts",
                []
            )

            text_parts = []

            for part in parts:
                text = part.get("text", "")

                if text:
                    text_parts.append(text)

            return "\n".join(text_parts).strip()

    except urllib.error.HTTPError as error:
        body = error.read().decode(
            "utf-8",
            errors="ignore"
        )

        raise RuntimeError(
            f"Gemini HTTP {error.code}: {body}"
        )

    except Exception as error:
        raise RuntimeError(
            f"Gemini error: {error}"
        )


# =========================================================
# MISTRAL
# =========================================================

def call_mistral(prompt):
    if not MISTRAL_API_KEY:
        raise RuntimeError(
            "MISTRAL_API_KEY is not configured."
        )

    url = "https://api.mistral.ai/v1/chat/completions"

    payload = {
        "model": MISTRAL_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert cybersecurity "
                    "code analysis assistant."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.2,
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MISTRAL_API_KEY}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=60
        ) as response:
            body = response.read().decode("utf-8")
            data = json.loads(body)

            return (
                data
                .get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )

    except urllib.error.HTTPError as error:
        body = error.read().decode(
            "utf-8",
            errors="ignore"
        )

        raise RuntimeError(
            f"Mistral HTTP {error.code}: {body}"
        )

    except Exception as error:
        raise RuntimeError(
            f"Mistral error: {error}"
        )


# =========================================================
# LOCAL AI EXPLANATION FALLBACK
# =========================================================

def _finding_text(finding, *keys):
    """Return the first non-empty string value from a finding."""
    for key in keys:
        value = finding.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def local_explanation_for_finding(finding):
    """
    Generate a deterministic cybersecurity explanation without any
    external AI/API call. This is used whenever OpenAI, Gemini and
    Mistral are unavailable or return an empty response.
    """

    title = _finding_text(finding, "title", "name", "rule", "message")
    category = _finding_text(finding, "category")
    cwe = _finding_text(finding, "cwe")
    severity = _finding_text(finding, "severity") or "UNKNOWN"
    file_name = _finding_text(finding, "file", "filename", "path")
    line = _finding_text(finding, "line", "line_number")
    code = _finding_text(
        finding,
        "code",
        "evidence",
        "matched_code",
        "snippet",
        "context",
    )
    existing_fix = _finding_text(
        finding,
        "recommendation",
        "recommended_fix",
        "fix",
    )

    haystack = " ".join(
        [title, category, cwe, code]
    ).lower()

    rules = [
        (
            ("xss", "cross-site scripting", "innerhtml", "inner html",
             "document.write", "dangerouslysetinnerhtml"),
            (
                "Cross-Site Scripting (XSS) occurs when untrusted input is "
                "inserted into HTML or a DOM sink without adequate output "
                "encoding or sanitization. An attacker may be able to inject "
                "JavaScript or malicious HTML into a victim's browser.",
                "Avoid assigning untrusted data to innerHTML or similar HTML "
                "sinks. Prefer textContent/createElement for plain text. If "
                "HTML is genuinely required, sanitize the untrusted HTML with "
                "a trusted sanitizer such as DOMPurify.",
            ),
        ),
        (
            ("sql injection", "sqli", "sql query", "cwe-89", "cwe 89"),
            (
                "SQL Injection can occur when untrusted input is combined "
                "directly with a SQL statement. An attacker may alter the "
                "query logic, read unauthorized data, modify records, or "
                "perform other database operations.",
                "Use parameterized queries/prepared statements and pass user "
                "input as parameters instead of concatenating it into SQL. "
                "Also validate input and apply least-privilege database access.",
            ),
        ),
        (
            ("command injection", "shell execution", "os.system", "shell=true",
             "subprocess", "cwe-78"),
            (
                "Command Injection is possible when attacker-controlled data "
                "can influence an operating-system command. A successful "
                "attack may execute unintended commands with the application's "
                "permissions.",
                "Avoid shell command construction from untrusted input. Prefer "
                "safe process APIs with an argument list and shell=False, use "
                "allowlists for permitted values, and validate arguments before "
                "execution.",
            ),
        ),
        (
            ("dynamic code execution", "eval(", "exec(", "cwe-95", "code injection"),
            (
                "Dynamic code execution evaluates data as program code. If an "
                "attacker can control the evaluated expression, they may execute "
                "arbitrary code in the application's security context.",
                "Avoid eval/exec and replace them with a safe parser or explicit "
                "operations. If the input represents data, parse it as data "
                "rather than executable code, and use a strict allowlist of "
                "supported operations.",
            ),
        ),
        (
            ("hard-coded secret", "hardcoded secret", "hard-coded password",
             "api_key", "api key", "password", "secret", "cwe-798"),
            (
                "A hard-coded secret stores a credential, API key, password, "
                "or token directly in source code. Anyone who obtains the code "
                "may be able to recover and reuse the credential.",
                "Move secrets to environment variables or a dedicated secret "
                "manager, never commit real credentials to source control, and "
                "rotate any credential that has already been exposed.",
            ),
        ),
        (
            ("weak cryptographic", "md5", "sha1", "weak crypto", "cwe-327", "cwe 328"),
            (
                "A weak or obsolete cryptographic primitive may not provide the "
                "security properties expected by the application. For passwords, "
                "fast hashes such as MD5 are especially unsuitable because they "
                "are designed to be computed quickly.",
                "For password storage, use a password-hashing algorithm such as "
                "Argon2id, bcrypt, or scrypt with appropriate parameters. For "
                "integrity-only use cases, choose a modern cryptographic hash such "
                "as SHA-256 or SHA-3 where appropriate.",
            ),
        ),
        (
            ("debug mode", "debug=true", "debug mode enabled", "cwe-489"),
            (
                "Debug mode can expose detailed error messages, stack traces, "
                "debug interfaces, or other development information that should "
                "not be available in production.",
                "Disable debug mode in production and use a production-grade "
                "application server/configuration. Keep detailed diagnostics in "
                "protected server-side logs instead of exposing them to users.",
            ),
        ),
        (
            ("tls verification", "certificate verification", "verify=false",
             "ssl verify", "cwe-295"),
            (
                "Disabling TLS/certificate verification can allow a man-in-the-"
                "middle attacker to intercept or modify network traffic without "
                "the application detecting the invalid certificate.",
                "Keep TLS certificate verification enabled and use a trusted "
                "certificate chain. Do not disable verification merely to bypass "
                "certificate errors in production.",
            ),
        ),
        (
            ("insecure deserialization", "pickle", "deserializ", "cwe-502"),
            (
                "Insecure deserialization can turn attacker-controlled serialized "
                "data into objects or operations with dangerous side effects. "
                "Depending on the technology, this can lead to code execution or "
                "other security-impacting behavior.",
                "Do not deserialize untrusted data with unsafe object deserializers. "
                "Prefer a simple data format such as JSON and validate the resulting "
                "data against an expected schema.",
            ),
        ),
        (
            ("ssrf", "server-side request forgery", "cwe-918"),
            (
                "Server-Side Request Forgery (SSRF) can let an attacker influence "
                "server-side requests and potentially reach internal services or "
                "metadata endpoints that are not intended to be public.",
                "Use an allowlist of permitted destinations, validate and normalize "
                "URLs, restrict private/internal network ranges, and avoid letting "
                "users directly control server-side request destinations.",
            ),
        ),
        (
            ("path traversal", "directory traversal", "../", "cwe-22"),
            (
                "Path Traversal occurs when untrusted path components can escape the "
                "intended directory. An attacker may access files outside the "
                "application's allowed storage area.",
                "Resolve paths against a fixed base directory, verify the resolved "
                "path remains inside that directory, and use an allowlist for file "
                "names where possible.",
            ),
        ),
        (
            ("cors", "insecure cors", "allow_origins", "cwe-942"),
            (
                "An overly permissive CORS configuration can allow untrusted web "
                "origins to make browser requests to an API in contexts where the "
                "application expects only trusted origins.",
                "Configure an explicit allowlist of trusted origins. Avoid wildcard "
                "origins when credentials or sensitive authenticated operations are "
                "involved, and review allowed methods and headers.",
            ),
        ),
        (
            ("csrf", "cross-site request forgery", "cwe-352"),
            (
                "Cross-Site Request Forgery can cause a user's browser to submit an "
                "unintended state-changing request while the user is authenticated.",
                "Use framework-supported CSRF protection for state-changing requests, "
                "validate the Origin/Referer where appropriate, and use secure cookie "
                "settings such as SameSite according to the application's requirements.",
            ),
        ),
        (
            ("insecure http", "http://", "cleartext", "cwe-319"),
            (
                "Sending sensitive information over unencrypted HTTP can expose data "
                "to network interception or modification.",
                "Use HTTPS/TLS for sensitive traffic and update API endpoints, redirects, "
                "and configuration so production requests do not fall back to HTTP.",
            ),
        ),
        (
            ("weak randomness", "random.random", "predictable random", "cwe-330"),
            (
                "A predictable random-number source may be unsuitable for security-"
                "sensitive values such as tokens, reset links, session identifiers, "
                "or cryptographic material.",
                "Use a cryptographically secure random generator such as Python's "
                "secrets module or the security API provided by the platform.",
            ),
        ),
        (
            ("jwt none", "alg=none", "jwt algorithm none", "cwe-327"),
            (
                "Accepting an unsigned JWT algorithm can allow a forged token to be "
                "treated as authentic if the application does not enforce an approved "
                "signature algorithm.",
                "Allowlist the expected JWT signing algorithm, require signature "
                "verification, and reject tokens using unsupported or unsigned algorithms.",
            ),
        ),
    ]

    explanation = None
    fix = existing_fix

    for keywords, pair in rules:
        if any(keyword in haystack for keyword in keywords):
            explanation, rule_fix = pair
            if not fix:
                fix = rule_fix
            break

    if not explanation:
        explanation = (
            "The scanner detected a security condition that should be reviewed "
            "because the reported code pattern may create risk when combined with "
            "attacker-controlled input or an unsafe application configuration. "
            "The exact impact depends on how the surrounding code is used."
        )

    if not fix:
        fix = (
            "Review the reported code path, validate untrusted input, use the "
            "safest API available for the operation, and apply the principle of "
            "least privilege. Confirm the fix with a follow-up security scan."
        )

    location = file_name
    if line:
        location = f"{location}:{line}" if location else f"line {line}"

    parts = [
        "LOCAL SECURITY EXPLANATION",
        "",
        f"Severity: {severity}",
    ]

    if title:
        parts.append(f"Finding: {title}")

    if category:
        parts.append(f"Category: {category}")

    if cwe:
        parts.append(f"CWE: {cwe}")

    if location:
        parts.append(f"Location: {location}")

    parts.extend([
        "",
        "What it means:",
        explanation,
        "",
        "Why it matters:",
        "If attacker-controlled data can reach this code path, the vulnerability "
        "may be exploitable and could affect confidentiality, integrity, or availability "
        "depending on the application context.",
        "",
        "Recommended fix:",
        fix,
        "",
        "Hindi explanation:",
        _local_hindi_explanation(title, haystack, fix),
    ])

    if code:
        parts.extend([
            "",
            "Detected code/evidence:",
            code,
        ])

    return "\n".join(parts).strip()


def _local_hindi_explanation(title, haystack, fix):
    """Short Hindi fallback text for the UI when external AI is unavailable."""

    if any(x in haystack for x in (
        "xss", "cross-site scripting", "innerhtml", "document.write",
        "dangerouslysetinnerhtml"
    )):
        return (
            "यह XSS समस्या है। अगर user का untrusted input सीधे HTML/DOM में डाला जाता है, "
            "तो attacker malicious JavaScript चला सकता है। Plain text के लिए textContent का "
            "उपयोग करें; HTML जरूरी हो तो DOMPurify जैसे trusted sanitizer का उपयोग करें।"
        )

    if any(x in haystack for x in (
        "command injection", "shell execution", "os.system", "shell=true", "cwe-78"
    )):
        return (
            "यह Command Injection का risk है। User input को सीधे shell command में न जोड़ें। "
            "Safe argument-list API, shell=False और strict input validation/allowlist का उपयोग करें।"
        )

    if any(x in haystack for x in (
        "dynamic code execution", "eval(", "exec(", "cwe-95", "code injection"
    )):
        return (
            "यह Dynamic Code Execution का risk है। eval/exec से user input को code की तरह "
            "execute न करें। Safe parser या fixed operations/allowlist का उपयोग करें।"
        )

    if any(x in haystack for x in (
        "hard-coded secret", "hardcoded secret", "api_key", "api key",
        "password", "secret", "cwe-798"
    )):
        return (
            "Code में API key, password या secret hard-code नहीं करना चाहिए। इन्हें environment "
            "variables या secret manager में रखें और अगर credential expose हो चुका है तो उसे rotate करें।"
        )

    if any(x in haystack for x in (
        "weak cryptographic", "md5", "sha1", "weak crypto", "cwe-327", "cwe-328"
    )):
        return (
            "Weak cryptography सुरक्षा कम कर सकती है। Password के लिए Argon2id/bcrypt/scrypt "
            "जैसे password-hashing algorithms और दूसरे use cases में appropriate modern hash का उपयोग करें।"
        )

    if any(x in haystack for x in (
        "debug mode", "debug=true", "debug mode enabled", "cwe-489"
    )):
        return (
            "Production में debug mode बंद रखें। Debug information, stack traces और development "
            "interfaces को public users से expose नहीं करना चाहिए।"
        )

    return (
        "Scanner ने एक security condition detect की है। Report में दिए code path को review करें, "
        "untrusted input validate करें और recommended fix लागू करके दोबारा scan करें।"
    )


# =========================================================
# AI EXPLANATION
# =========================================================

@app.post("/api/ai-explain")
async def ai_explain(payload: dict):
    findings = payload.get("findings", [])
    score = payload.get("score", 100)

    if not findings:
        return {
            "explanation":
                "No security findings were provided."
        }

    prompt = build_ai_prompt(
        findings,
        score
    )

    errors = []

    # -----------------------------------------------------
    # OPENAI
    # -----------------------------------------------------

    if OPENAI_API_KEY:
        try:
            explanation = call_openai(prompt)

            if explanation:
                return {
                    "provider": "openai",
                    "explanation": explanation,
                }

        except Exception as error:
            print("OpenAI failed:", error)
            errors.append(f"OpenAI: {error}")

    # -----------------------------------------------------
    # GEMINI
    # -----------------------------------------------------

    if GEMINI_API_KEY:
        try:
            explanation = call_gemini(prompt)

            if explanation:
                return {
                    "provider": "gemini",
                    "explanation": explanation,
                }

        except Exception as error:
            print("Gemini failed:", error)
            errors.append(f"Gemini: {error}")

    # -----------------------------------------------------
    # MISTRAL
    # -----------------------------------------------------

    if MISTRAL_API_KEY:
        try:
            explanation = call_mistral(prompt)

            if explanation:
                return {
                    "provider": "mistral",
                    "explanation": explanation,
                }

        except Exception as error:
            print("Mistral failed:", error)
            errors.append(f"Mistral: {error}")

    # -----------------------------------------------------
    # LOCAL FALLBACK
    # -----------------------------------------------------
    # If all external AI providers fail, do not leave the UI with
    # "AI Explanation is currently unavailable". Generate a useful
    # deterministic explanation from the scanner finding itself.

    local_sections = []

    for finding in findings:
        try:
            local_sections.append(
                local_explanation_for_finding(finding)
            )
        except Exception as error:
            print("Local explanation failed:", error)

    if local_sections:
        return {
            "provider": "local-fallback",
            "explanation": (
                "External AI providers were unavailable, so the scanner "
                "generated this explanation locally from the detected "
                "security findings. No API balance is required.\n\n"
                + "\n\n".join(local_sections)
            ),
            "errors": errors,
        }

    return {
        "provider": "local-fallback",
        "explanation": (
            "The external AI providers were unavailable and no local "
            "explanation could be generated for the supplied findings."
        ),
        "errors": errors,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
