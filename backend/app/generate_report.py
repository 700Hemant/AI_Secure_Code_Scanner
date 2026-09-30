from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.units import mm
from pathlib import Path


# ============================================================
# CONFIG
# ============================================================

OUTPUT_FILE = "security_report.pdf"


# ============================================================
# SAMPLE SCAN RESULT
# ============================================================

scan_result = {
    "score": 5,
    "files_scanned": 5,
    "lines_scanned": 134,

    "counts": {
        "CRITICAL": 1,
        "HIGH": 5,
        "MEDIUM": 2,
        "LOW": 2,
    },

    "findings": [
        {
            "title": "Potential Cross-Site Scripting (XSS)",
            "severity": "LOW",
            "cwe": "CWE-79",
            "file": "vulnerable.html",
            "line": 17,
            "category": "Cross-Site Scripting",
            "confidence": "Low",
            "description": (
                "An HTML/DOM sink was detected and may receive "
                "untrusted input."
            ),
            "evidence": (
                'document.getElementById("output").innerHTML ='
            ),
            "fix": (
                "Prefer textContent/createElement for untrusted data. "
                "If HTML is required, sanitize it with DOMPurify."
            ),
        },

        {
            "title": "Potential Hard-Coded Secret",
            "severity": "HIGH",
            "cwe": "CWE-798",
            "file": "vulnerable_app.py",
            "line": 12,
            "category": "Secrets Management",
            "confidence": "Medium",
            "description": (
                "A credential-like value appears to be hard-coded."
            ),
            "evidence": (
                'API_KEY = "sk-test-1234567890abcdef"'
            ),
            "fix": (
                "Move secrets to environment variables or a secure "
                "secrets manager and rotate exposed credentials."
            ),
        },

        {
            "title": "Dynamic Code Execution",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "file": "vulnerable_app.py",
            "line": 44,
            "category": "Code Injection",
            "confidence": "High",
            "description": (
                "Dynamic code execution can execute "
                "attacker-controlled code."
            ),
            "evidence": "return eval(expression)",
            "fix": (
                "Avoid eval/exec. Use explicit parsing and "
                "safe APIs instead."
            ),
        },

        {
            "title": "Shell Execution Enabled",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "file": "vulnerable_app.py",
            "line": 36,
            "category": "Command Injection",
            "confidence": "High",
            "description": (
                "shell=True increases the risk of command injection."
            ),
            "evidence": "shell=True,",
            "fix": (
                "Avoid shell=True. Pass commands as an argument "
                "list and validate arguments."
            ),
        },

        {
            "title": "Weak Cryptographic Algorithm",
            "severity": "MEDIUM",
            "cwe": "CWE-327",
            "file": "vulnerable_app.py",
            "line": 49,
            "category": "Cryptography",
            "confidence": "High",
            "description": (
                "MD5/SHA-1 should not be used for "
                "security-sensitive hashing."
            ),
            "evidence": (
                "hashlib.md5(password.encode()).hexdigest()"
            ),
            "fix": (
                "Use SHA-256/SHA-3 for integrity use cases. "
                "For passwords use Argon2, bcrypt or scrypt."
            ),
        },

        {
            "title": "Potential Command Injection",
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "file": "vulnerable_server.py",
            "line": 15,
            "category": "Command Injection",
            "confidence": "High",
            "description": (
                "User-controlled data reaches an operating-system "
                "command execution sink."
            ),
            "evidence": 'os.system("echo " + host)',
            "fix": (
                "Avoid shell execution. Use fixed commands with "
                "validated arguments."
            ),
        },

        {
            "title": "Debug Mode Enabled",
            "severity": "MEDIUM",
            "cwe": "CWE-489",
            "file": "vulnerable_server.py",
            "line": 22,
            "category": "Security Misconfiguration",
            "confidence": "High",
            "description": (
                "Debug mode may expose sensitive information."
            ),
            "evidence": (
                'app.run(host="127.0.0.1", port=5000, debug=True)'
            ),
            "fix": "Disable debug mode in production.",
        },

        {
            "title": "Dynamic Code Execution",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "file": "vulnerable_web.js",
            "line": 15,
            "category": "Code Injection",
            "confidence": "High",
            "description": (
                "Dynamic code execution can execute "
                "attacker-controlled JavaScript."
            ),
            "evidence": "const result = eval(expression);",
            "fix": (
                "Remove eval() and use explicit parsing or "
                "safe application logic."
            ),
        },

        {
            "title": "Potential Cross-Site Scripting (XSS)",
            "severity": "LOW",
            "cwe": "CWE-79",
            "file": "vulnerable_web.js",
            "line": 7,
            "category": "Cross-Site Scripting",
            "confidence": "Low",
            "description": (
                "User-controlled data appears to reach innerHTML."
            ),
            "evidence": (
                'document.getElementById("welcome").innerHTML ='
            ),
            "fix": (
                "Use textContent instead of innerHTML for "
                "untrusted text."
            ),
        },

        {
            "title": "Potential Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "cwe": "CWE-79",
            "file": "vulnerable_web.js",
            "line": 11,
            "category": "Cross-Site Scripting",
            "confidence": "High",
            "description": (
                "User-controlled data reaches an HTML sink."
            ),
            "evidence": (
                'document.querySelector("#message").innerHTML = message;'
            ),
            "fix": (
                "Use textContent or sanitize HTML with a trusted "
                "sanitizer such as DOMPurify."
            ),
        },
    ],
}


# ============================================================
# STYLES
# ============================================================

styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    "ReportTitle",
    parent=styles["Title"],
    fontSize=22,
    leading=26,
    alignment=TA_CENTER,
    spaceAfter=8,
)

subtitle_style = ParagraphStyle(
    "Subtitle",
    parent=styles["Heading2"],
    fontSize=14,
    leading=18,
    alignment=TA_CENTER,
    spaceAfter=20,
)

heading_style = ParagraphStyle(
    "SectionHeading",
    parent=styles["Heading1"],
    fontSize=14,
    leading=18,
    spaceBefore=12,
    spaceAfter=8,
)

body_style = ParagraphStyle(
    "Body",
    parent=styles["BodyText"],
    fontSize=9,
    leading=13,
)

small_style = ParagraphStyle(
    "Small",
    parent=styles["BodyText"],
    fontSize=7.5,
    leading=10,
)


# ============================================================
# PDF
# ============================================================

doc = SimpleDocTemplate(
    OUTPUT_FILE,
    pagesize=A4,
    rightMargin=15 * mm,
    leftMargin=15 * mm,
    topMargin=15 * mm,
    bottomMargin=15 * mm,
)

story = []


# ============================================================
# HEADER
# ============================================================

story.append(
    Paragraph(
        "AI Secure Code Scanner",
        title_style,
    )
)

story.append(
    Paragraph(
        "Security Scan Report",
        subtitle_style,
    )
)

story.append(
    Paragraph(
        "<b>Project:</b> test-vulnerable-project.zip",
        body_style,
    )
)

story.append(Spacer(1, 10))


# ============================================================
# SUMMARY
# ============================================================

story.append(
    Paragraph(
        "Security Summary",
        heading_style,
    )
)

counts = scan_result["counts"]

summary_data = [
    ["Metric", "Result"],
    ["Security Score", f'{scan_result["score"]} / 100'],
    [
        "Total Findings",
        str(len(scan_result["findings"])),
    ],
    ["Critical", str(counts["CRITICAL"])],
    ["High", str(counts["HIGH"])],
    ["Medium", str(counts["MEDIUM"])],
    ["Low", str(counts["LOW"])],
    [
        "Files Scanned",
        str(scan_result["files_scanned"]),
    ],
    [
        "Lines Scanned",
        str(scan_result["lines_scanned"]),
    ],
]

summary_table = Table(
    summary_data,
    colWidths=[
        75 * mm,
        55 * mm,
    ],
)

summary_table.setStyle(
    TableStyle(
        [
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
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold",
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey,
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#f3f4f6"),
                ],
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6,
            ),
        ]
    )
)

story.append(summary_table)
story.append(Spacer(1, 12))


# ============================================================
# FINDINGS
# ============================================================

story.append(
    Paragraph(
        "Security Findings",
        heading_style,
    )
)

finding_rows = [
    [
        "#",
        "Finding",
        "Severity",
        "CWE",
        "Location",
    ]
]

for index, item in enumerate(
    scan_result["findings"],
    1,
):
    finding_rows.append(
        [
            str(index),
            item["title"],
            item["severity"],
            item["cwe"],
            f'{item["file"]}:{item["line"]}',
        ]
    )


finding_table = Table(
    finding_rows,
    colWidths=[
        8 * mm,
        68 * mm,
        24 * mm,
        20 * mm,
        43 * mm,
    ],
    repeatRows=1,
)

finding_table.setStyle(
    TableStyle(
        [
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#111827"),
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white,
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold",
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                7.5,
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.35,
                colors.grey,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#f8fafc"),
                ],
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                4,
            ),
        ]
    )
)

story.append(finding_table)


# ============================================================
# DETAILED FINDINGS
# ============================================================

story.append(
    Paragraph(
        "Finding Details",
        heading_style,
    )
)

for index, item in enumerate(
    scan_result["findings"],
    1,
):

    story.append(
        Paragraph(
            f'{index}. {item["title"]}',
            ParagraphStyle(
                f"Finding{index}",
                parent=styles["Heading2"],
                fontSize=11,
                leading=14,
                spaceBefore=10,
                spaceAfter=5,
            ),
        )
    )

    details = [
        ["Severity", item["severity"]],
        ["CWE", item["cwe"]],
        ["Category", item["category"]],
        ["Confidence", item["confidence"]],
        [
            "Location",
            f'{item["file"]}:{item["line"]}',
        ],
        [
            "Description",
            item["description"],
        ],
        [
            "Evidence",
            item["evidence"],
        ],
        [
            "Recommended Fix",
            item["fix"],
        ],
    ]

    detail_table = Table(
        details,
        colWidths=[
            35 * mm,
            125 * mm,
        ],
    )

    detail_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#e5e7eb"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    story.append(detail_table)
    story.append(Spacer(1, 8))


# ============================================================
# FOOTER / DISCLAIMER
# ============================================================

story.append(
    Spacer(1, 10)
)

story.append(
    Paragraph(
        "<b>Note:</b> This report represents static-analysis "
        "results from the current scanner ruleset. Findings "
        "should be manually validated before being treated as "
        "confirmed vulnerabilities.",
        small_style,
    )
)


# ============================================================
# BUILD
# ============================================================

doc.build(story)

print(
    f"Security report created successfully: "
    f"{OUTPUT_FILE}"
)