import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API_BASE = " http://127.0.0.1:8000";

/* =========================================================
   HELPERS
========================================================= */

function getCount(counts, severity) {
  if (!counts) return 0;

  return (
    counts[severity] ??
    counts[severity.toLowerCase()] ??
    0
  );
}

function getSeverityClass(severity) {
  return String(severity || "LOW").toLowerCase();
}

function getScoreMessage(score) {
  if (score >= 90) return "Excellent security posture";
  if (score >= 75) return "Good security posture";
  if (score >= 60) return "Moderate security risk";
  if (score >= 40) return "High security risk";
  return "Critical security risk";
}

function getSuggestion(finding) {
  const category = String(
    finding?.category || ""
  ).toLowerCase();

  const title = String(
    finding?.title || ""
  ).toLowerCase();

  if (
    category.includes("cross-site") ||
    title.includes("xss")
  ) {
    return "Avoid innerHTML for untrusted data. Prefer textContent or sanitize HTML with a trusted sanitizer such as DOMPurify.";
  }

  if (
    category.includes("sql") ||
    title.includes("sql")
  ) {
    return "Use parameterized queries or prepared statements instead of building SQL statements through string concatenation.";
  }

  if (
    category.includes("secret") ||
    title.includes("secret")
  ) {
    return "Move API keys, passwords and tokens to environment variables or a secure secrets manager.";
  }

  if (
    category.includes("code injection") ||
    title.includes("dynamic code")
  ) {
    return "Avoid eval() and exec(). Use safe parsing and explicit program logic instead.";
  }

  if (
    category.includes("crypt") ||
    title.includes("crypt")
  ) {
    return "Replace weak cryptographic algorithms such as MD5 or SHA-1 with modern secure alternatives.";
  }

  if (
    category.includes("transport") ||
    title.includes("tls") ||
    title.includes("certificate")
  ) {
    return "Keep TLS certificate verification enabled and avoid verify=False or equivalent insecure settings.";
  }

  if (
    category.includes("command") ||
    title.includes("command injection")
  ) {
    return "Avoid executing user-controlled commands. Use fixed command arguments and validate all external input.";
  }

  return (
    finding?.fix ||
    "Review this finding and validate the affected code before deployment."
  );
}

function getBilingualFix(finding) {
  const category = String(finding?.category || "").toLowerCase();
  const title = String(finding?.title || "").toLowerCase();

  if (category.includes("cross-site") || title.includes("xss")) {
    return `Prefer textContent/createElement for untrusted data. If HTML is required, sanitize untrusted content with a trusted sanitizer such as DOMPurify.

हिंदी: Untrusted data के लिए textContent/createElement का उपयोग करें। अगर HTML जरूरी हो, तो DOMPurify जैसे trusted sanitizer से untrusted content को sanitize करें।`;
  }
  if (category.includes("secret") || title.includes("secret")) {
    return `Move API keys, passwords and tokens to environment variables or a secure secrets manager, and rotate exposed credentials.

हिंदी: API keys, passwords और tokens को environment variables या secure secrets manager में रखें और जो credentials expose हो चुके हैं उन्हें बदल दें।`;
  }
  if (category.includes("sql") || title.includes("sql")) {
    return `Use parameterized queries or prepared statements instead of string concatenation.

हिंदी: String concatenation की जगह parameterized queries या prepared statements का उपयोग करें।`;
  }
  if (category.includes("code injection") || title.includes("dynamic code") || title.includes("eval")) {
    return `Avoid eval() and exec(). Use safe parsing and explicit program logic instead.

हिंदी: eval() और exec() से बचें। इसकी जगह safe parsing और explicit program logic का उपयोग करें।`;
  }
  if (category.includes("command") || title.includes("command injection") || title.includes("shell execution")) {
    return `Avoid shell execution where possible. Use fixed command arguments and validate all external input.

हिंदी: जहाँ संभव हो shell execution से बचें। Fixed command arguments का उपयोग करें और सभी external input को validate करें।`;
  }
  if (category.includes("crypt") || title.includes("crypt")) {
    return `Replace weak cryptographic algorithms with modern secure alternatives. For passwords, use Argon2, bcrypt or scrypt.

हिंदी: कमजोर cryptographic algorithms को modern secure alternatives से बदलें। Passwords के लिए Argon2, bcrypt या scrypt का उपयोग करें।`;
  }
  if (category.includes("transport") || title.includes("tls") || title.includes("certificate")) {
    return `Keep TLS certificate verification enabled and use trusted certificates.

हिंदी: TLS certificate verification को enabled रखें और trusted certificates का उपयोग करें।`;
  }
  if (title.includes("debug") || category.includes("misconfiguration")) {
    return `Disable debug mode in production and keep development diagnostics restricted to development environments.

हिंदी: Production में debug mode बंद रखें और development diagnostics को केवल development environment तक सीमित रखें।`;
  }

  const fix = finding?.fix || getSuggestion(finding);
  return `${fix}\n\nहिंदी: इस security issue को ठीक करें और deployment से पहले affected code को सुरक्षित तरीके से review करें।`;
}

function getOfflineAIExplanation(finding) {
  const category = String(finding?.category || "").toLowerCase();
  const title = String(finding?.title || "").toLowerCase();
  const severity = String(finding?.severity || "LOW").toUpperCase();
  const evidence = finding?.evidence || "the detected code pattern";
  const fix = finding?.fix || getSuggestion(finding);

  let explanation = "This finding indicates a security risk that should be reviewed before the code is deployed.";
  let risk = "An attacker may be able to abuse the affected code path depending on how the input is controlled.";
  let secureApproach = "Validate untrusted input, use safe APIs, and follow the recommended remediation before deployment.";

  if (category.includes("cross-site") || title.includes("xss")) {
    explanation = "The application writes data into an HTML sink such as innerHTML. If that value can contain attacker-controlled input, the browser may interpret the input as HTML or JavaScript instead of plain text.";
    risk = "An attacker could inject malicious content into a user's browser, potentially stealing session data, changing page content, or performing actions as the victim.";
    secureApproach = "For plain text, use textContent or equivalent safe DOM APIs. If HTML is genuinely required, sanitize untrusted HTML with a well-maintained sanitizer such as DOMPurify and avoid inserting raw user input.";
  } else if (category.includes("secret") || title.includes("secret")) {
    explanation = "A password, API key, token, or secret-like value is present directly in source code or as an unsafe default. Source code can be copied, logged, backed up, or exposed through repositories and build artifacts.";
    risk = "Anyone who obtains the value may be able to access the associated service or account. Committed secrets should be considered exposed and rotated.";
    secureApproach = "Move secrets to environment variables or a dedicated secrets manager, keep them out of source control, and rotate any credential that has already been committed.";
  } else if (category.includes("code injection") || title.includes("dynamic code") || title.includes("eval")) {
    explanation = "The application dynamically executes a string as code. This can turn untrusted input into executable program logic.";
    risk = "If an attacker can influence the evaluated string, they may execute arbitrary application code with the privileges of the process or browser context.";
    secureApproach = "Remove eval() or equivalent dynamic execution. Parse input as data and use explicit allow-listed operations or safe language/runtime APIs instead.";
  } else if (category.includes("command") || title.includes("command")) {
    explanation = "The application constructs or executes an operating-system command in a way that may allow external input to influence the command.";
    risk = "Command injection can allow an attacker to execute unintended operating-system commands with the permissions of the application process.";
    secureApproach = "Avoid shell execution where possible. Use direct process APIs with an argument array, allow-list valid values, and never concatenate untrusted input into a shell command.";
  } else if (category.includes("crypt") || title.includes("crypt")) {
    explanation = "The code uses a cryptographic algorithm that is considered weak for the detected purpose.";
    risk = "Weak cryptography can make hashes or protected values easier to attack, especially when used for passwords or security-sensitive data.";
    secureApproach = "Use modern algorithms appropriate for the purpose. For password storage, use a password-hashing scheme such as Argon2, bcrypt, or scrypt rather than a fast general-purpose hash.";
  } else if (category.includes("sql") || title.includes("sql")) {
    explanation = "The SQL statement appears to be constructed dynamically rather than using a parameterized query.";
    risk = "If attacker-controlled input reaches the query, an attacker may alter the SQL statement and access or modify data outside the intended operation.";
    secureApproach = "Use parameterized queries or prepared statements and pass user-controlled values as parameters rather than concatenating them into SQL.";
  } else if (category.includes("transport") || title.includes("tls") || title.includes("certificate")) {
    explanation = "TLS or certificate verification has been disabled or weakened, so the application may accept an untrusted connection.";
    risk = "An attacker positioned between the client and server may be able to intercept or modify traffic without the application detecting the invalid certificate.";
    secureApproach = "Keep certificate verification enabled and use trusted certificates. Do not disable TLS verification in production.";
  } else if (title.includes("debug") || category.includes("misconfiguration")) {
    explanation = "A debug or development-oriented security setting is enabled in application code.";
    risk = "Debug features can expose stack traces, configuration details, internal paths, or other information that helps an attacker understand the application.";
    secureApproach = "Disable debug mode in production and keep development diagnostics restricted to controlled development environments.";
  }

  return [
    "AI fallback explanation (built-in security analysis)",
    "",
    `Severity: ${severity}`,
    `What it means: ${explanation}`,
    `Why it matters: ${risk}`,
    `Detected evidence: ${evidence}`,
    `Recommended fix: ${fix}`,
    `Secure approach: ${secureApproach}`,
    "",
    "Note: The external AI provider was unavailable or its free-tier quota was exhausted, so this explanation was generated locally from the scanner's finding type and evidence."
  ].join("\n");
}

function getFindingKey(finding) {
  return [
    finding?.file || "unknown-file",
    finding?.line ?? "unknown-line",
    finding?.cwe || "no-cwe",
    finding?.title || "security-finding",
  ].join("::");
}

function formatAIResult(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;

  if (typeof value === "object") {
    return (
      value.explanation ||
      value.message ||
      value.analysis ||
      JSON.stringify(value, null, 2)
    );
  }

  return String(value);
}

function formatHistoryDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("en-GB", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
}

/* =========================================================
   STAT CARD
========================================================= */

function StatCard({ title, value, icon }) {
  return (
    <div className="stat-card">
      <div className="stat-card-top">
        <span className="stat-icon">{icon}</span>
        <span className="stat-title">{title}</span>
      </div>

      <div className="stat-value">
        {value}
      </div>
    </div>
  );
}

/* =========================================================
   SCORE CARD
========================================================= */

function ScoreCard({ score }) {
  const safeScore = Math.max(
    0,
    Math.min(100, Number(score) || 0)
  );

  return (
    <div className="score-card">
      <div className="score-header">
        <div>
          <div className="section-label">
            SECURITY SCORE
          </div>

          <div className="score-number">
            {safeScore}/100
          </div>

          <div className="score-message">
            {getScoreMessage(safeScore)}
          </div>
        </div>

        <div className="score-ring">
          <svg
            width="120"
            height="120"
            viewBox="0 0 120 120"
          >
            <circle
              cx="60"
              cy="60"
              r="50"
              fill="none"
              stroke="rgba(255,255,255,0.08)"
              strokeWidth="10"
            />

            <circle
              cx="60"
              cy="60"
              r="50"
              fill="none"
              stroke="currentColor"
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={`${safeScore * 3.14} 314`}
              transform="rotate(-90 60 60)"
            />
          </svg>

          <div className="score-ring-text">
            {safeScore}
          </div>
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   SEVERITY CHART
========================================================= */

function SeverityChart({ result }) {
  const data = [
    {
      name: "Critical",
      value: getCount(result?.counts, "CRITICAL"),
    },
    {
      name: "High",
      value: getCount(result?.counts, "HIGH"),
    },
    {
      name: "Medium",
      value: getCount(result?.counts, "MEDIUM"),
    },
    {
      name: "Low",
      value: getCount(result?.counts, "LOW"),
    },
  ];

  const maxValue = Math.max(
    1,
    ...data.map((item) => item.value)
  );

  return (
    <div className="chart-card">
      <div className="card-title">
        Findings by Severity
      </div>

      <div className="chart-subtitle">
        Distribution of detected security findings.
      </div>

      <div className="severity-chart">
        {data.map((item) => {
          const height =
            item.value === 0
              ? 4
              : Math.max(
                  12,
                  (item.value / maxValue) * 150
                );

          return (
            <div
              className="severity-column"
              key={item.name}
            >
              <div className="severity-count">
                {item.value}
              </div>

              <div className="severity-bar-container">
                <div
                  className={`severity-bar ${item.name.toLowerCase()}`}
                  style={{
                    height: `${height}px`,
                  }}
                />
              </div>

              <div className="severity-name">
                {item.name}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


/* =========================================================
   SECURITY OVERVIEW
========================================================= */

function SecurityOverview({ result }) {
  const categoryCounts = result?.category_counts || {};
  const confidenceCounts = result?.confidence_counts || {};

  const categories = Object.entries(categoryCounts)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, 6);

  const confidenceRows = [
    ["High", Number(confidenceCounts.High || 0), "high"],
    ["Medium", Number(confidenceCounts.Medium || 0), "medium"],
    ["Low", Number(confidenceCounts.Low || 0), "low"],
  ];

  const totalConfidence = confidenceRows.reduce(
    (total, [, value]) => total + value,
    0
  );

  return (
    <div className="security-overview-grid">
      {/* RISK CATEGORIES */}
      <div className="overview-card risk-category-card">
        <div className="overview-card-header">
          <div>
            <div className="card-title">Risk Categories</div>
            <div className="chart-subtitle">
              Most frequently detected security categories.
            </div>
          </div>
          <div className="overview-header-badge">
            {categories.length} categories
          </div>
        </div>

        {categories.length ? (
          <div className="category-list">
            {categories.map(([name, value]) => {
              const percentage = Math.round(
                (Number(value) /
                  Math.max(1, Number(categories[0]?.[1] || 1))) *
                  100
              );

              return (
                <div className="category-row" key={name}>
                  <div className="category-row-top">
                    <span>{name}</span>
                    <strong>{value}</strong>
                  </div>
                  <div className="category-track">
                    <div
                      className="category-fill"
                      style={{ width: `${Math.max(8, percentage)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="overview-empty">
            No category data available.
          </div>
        )}
      </div>

      {/* DETECTION CONFIDENCE */}
      <div className="overview-card confidence-card">
        <div className="overview-card-header">
          <div>
            <div className="card-title">Detection Confidence</div>
            <div className="chart-subtitle">
              How certain the scanner rules are about each detection.
            </div>
          </div>
          <div className="overview-header-badge">
            {totalConfidence} analyzed
          </div>
        </div>

        <div className="confidence-info-note">
          Confidence is different from severity. A finding can be Medium
          severity but still have High detection confidence.
        </div>

        <div className="confidence-summary-grid">
          {confidenceRows.map(([name, value, level]) => {
            const percentage = totalConfidence
              ? Math.round((value / totalConfidence) * 100)
              : 0;

            return (
              <div className={`confidence-summary ${level}`} key={name}>
                <div className="confidence-summary-label">{name}</div>
                <div className="confidence-summary-value">{value}</div>
                <div className="confidence-summary-percent">
                  {percentage}% of findings
                </div>
              </div>
            );
          })}
        </div>

        <div className="confidence-list professional-confidence-list">
          {confidenceRows.map(([name, value, level]) => {
            const percentage = totalConfidence
              ? Math.round((value / totalConfidence) * 100)
              : 0;

            return (
              <div className="confidence-row" key={name}>
                <div className="confidence-row-top">
                  <span>{name} confidence</span>
                  <strong>
                    {value} <small>({percentage}%)</small>
                  </strong>
                </div>
                <div className="category-track">
                  <div
                    className={`category-fill confidence-fill ${level}`}
                    style={{ width: `${percentage}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   FINDING CARD
========================================================= */

function FindingCard({
  finding,
  index,
  findingKey,
  onExplain,
  aiLoading,
  aiResult,
}) {
  const severity =
    String(
      finding?.severity || "LOW"
    ).toUpperCase();

  return (
    <div className="finding-card">
      <div className="finding-header">
        <div className="finding-number">
          {index + 1}
        </div>

        <div className="finding-title-area">
          <h3>
            {finding?.title ||
              "Security Finding"}
          </h3>

          <div className="finding-meta">
            <span
              className={`severity-badge ${getSeverityClass(
                severity
              )}`}
            >
              {severity}
            </span>

            {finding?.cwe && (
              <span className="cwe-badge">
                {finding.cwe}
              </span>
            )}

            {finding?.confidence && (
              <span className="confidence-badge">
                Confidence: {finding.confidence}
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="finding-body">
        {finding?.description && (
          <p className="finding-description">
            {finding.description}
          </p>
        )}

        {finding?.file && (
          <div className="finding-row">
            <strong>File:</strong>

            <code>
              {finding.file}
            </code>
          </div>
        )}

        {finding?.line && (
          <div className="finding-row">
            <strong>Line:</strong>

            <span>
              {finding.line}
            </span>
          </div>
        )}

        {finding?.evidence && (
          <div className="evidence-box">
            <div className="evidence-title">
              Evidence
            </div>

            <pre>
              {finding.evidence}
            </pre>
          </div>
        )}

        {finding?.context && (
          <div className="context-box">
            <div className="evidence-title">
              Code Context
            </div>

            <pre>
              {finding.context}
            </pre>
          </div>
        )}

        <div className="finding-detail-grid">
          <div className="finding-detail-item">
            <span>Category</span>
            <strong>{finding?.category || "Security"}</strong>
          </div>

          <div className="finding-detail-item">
            <span>Location</span>
            <strong>
              {finding?.file || "—"}
              {finding?.line ? `:${finding.line}` : ""}
            </strong>
          </div>

          <div className="finding-detail-item">
            <span>CWE</span>
            <strong>{finding?.cwe || "Not mapped"}</strong>
          </div>

          <div className="finding-detail-item">
            <span>Confidence</span>
            <strong>{finding?.confidence || "Not specified"}</strong>
          </div>
        </div>

        <div className="recommendation-box">
          <div className="recommendation-title">
            Recommended Fix
          </div>

          <p style={{ whiteSpace: "pre-line" }}>
            {getBilingualFix(finding)}
          </p>
        </div>

        <div className="finding-actions">
          <button
            className="secondary-button"
            onClick={() =>
              onExplain(finding, findingKey)
            }
            disabled={aiLoading}
          >
            {aiLoading
              ? "Analyzing..."
              : "🤖 Explain with AI"}
          </button>
        </div>

        {aiResult && (
          <div className="ai-result">
            <div className="ai-result-title">
              🤖 AI Security Explanation
            </div>

            <div className="ai-result-content">
              {aiResult}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* =========================================================
   HISTORY TABLE
========================================================= */

function HistoryTable({
  history,
  onOpenDetails,
}) {
  if (!history?.length) {
    return (
      <div className="empty-history">
        No scan history available.
      </div>
    );
  }

  return (
    <div className="history-table-wrapper">
      <table className="history-table">
        <thead>
          <tr>
            <th>File</th>
            <th>Score</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Date</th>
          </tr>
        </thead>

        <tbody>
          {history.map((item) => (
            <tr
              key={item.id}
              className="history-row-clickable"
              onClick={() =>
                onOpenDetails(item.id)
              }
              title="Click to view scan details"
            >
              <td>
                <div className="history-file-cell">
                  <span className="history-file-icon">
                    📄
                  </span>

                  <span>
                    {item.filename}
                  </span>
                </div>
              </td>

              <td>
                <span className="history-score">
                  {item.score}/100
                </span>
              </td>

              <td>
                {item.critical ?? 0}
              </td>

              <td>
                {item.high ?? 0}
              </td>

              <td>
                {item.medium ?? 0}
              </td>

              <td>
                {item.low ?? 0}
              </td>

              <td>
                {formatHistoryDate(
                  item.created_at
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* =========================================================
   SCAN DETAILS MODAL
========================================================= */

function ScanDetailsModal({
  scan,
  loading,
  onClose,
}) {
  if (!scan && !loading) {
    return null;
  }

  if (loading) {
    return (
      <div className="details-overlay">
        <div className="details-modal details-loading-modal">
          <div className="details-loading-icon">
            🔄
          </div>

          <h3>
            Loading Scan Details
          </h3>

          <p>
            Please wait while the scan
            information is loaded.
          </p>
        </div>
      </div>
    );
  }

  const findings =
    Array.isArray(scan?.findings)
      ? scan.findings
      : [];

  return (
    <div
      className="details-overlay"
      onMouseDown={(event) => {
        if (
          event.target === event.currentTarget
        ) {
          onClose();
        }
      }}
    >
      <div className="details-modal">
        {/* HEADER */}

        <div className="details-modal-header">
          <div>
            <div className="section-label">
              SCAN DETAILS
            </div>

            <h2>
              {scan?.filename ||
                "Security Scan"}
            </h2>

            <p>
              Detailed information from
              this previous security scan.
            </p>
          </div>

          <button
            className="details-close-button"
            onClick={onClose}
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        {/* SUMMARY */}

        <div className="details-summary-grid">
          <div className="details-summary-card score">
            <span>
              Security Score
            </span>

            <strong>
              {scan?.score ?? 0}/100
            </strong>
          </div>

          <div className="details-summary-card critical">
            <span>Critical</span>

            <strong>
              {scan?.critical ?? 0}
            </strong>
          </div>

          <div className="details-summary-card high">
            <span>High</span>

            <strong>
              {scan?.high ?? 0}
            </strong>
          </div>

          <div className="details-summary-card medium">
            <span>Medium</span>

            <strong>
              {scan?.medium ?? 0}
            </strong>
          </div>

          <div className="details-summary-card low">
            <span>Low</span>

            <strong>
              {scan?.low ?? 0}
            </strong>
          </div>
        </div>

        {/* META */}

        <div className="details-meta-grid">
          <div className="details-meta-item">
            <span>Scan ID</span>

            <strong>
              #{scan?.id ?? "—"}
            </strong>
          </div>

          <div className="details-meta-item">
            <span>File</span>

            <strong>
              {scan?.filename || "—"}
            </strong>
          </div>

          <div className="details-meta-item">
            <span>Date & Time</span>

            <strong>
              {formatHistoryDate(
                scan?.created_at
              )}
            </strong>
          </div>

          <div className="details-meta-item">
            <span>Total Findings</span>

            <strong>
              {findings.length}
            </strong>
          </div>
        </div>

        {/* FINDINGS */}

        <div className="details-findings-section">
          <div className="details-section-title">
            Security Findings
          </div>

          <div className="details-section-subtitle">
            Findings stored from this scan.
          </div>

          {findings.length === 0 ? (
            <div className="details-no-findings">
              <div>
                ✅
              </div>

              <h3>
                No security findings
              </h3>

              <p>
                No supported security issues
                were stored for this scan.
              </p>
            </div>
          ) : (
            <div className="details-findings-list">
              {findings.map(
                (finding, index) => {
                  const severity =
                    String(
                      finding?.severity ||
                        "LOW"
                    ).toUpperCase();

                  return (
                    <div
                      className="details-finding-card"
                      key={`${finding?.file}-${finding?.line}-${index}`}
                    >
                      <div className="details-finding-header">
                        <div className="finding-number">
                          {index + 1}
                        </div>

                        <div>
                          <h3>
                            {finding?.title ||
                              "Security Finding"}
                          </h3>

                          <div className="finding-meta">
                            <span
                              className={`severity-badge ${getSeverityClass(
                                severity
                              )}`}
                            >
                              {severity}
                            </span>

                            {finding?.cwe && (
                              <span className="cwe-badge">
                                {finding.cwe}
                              </span>
                            )}

                            {finding?.confidence && (
                              <span className="confidence-badge">
                                Confidence:{" "}
                                {
                                  finding.confidence
                                }
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="details-finding-body">
                        {finding?.description && (
                          <p className="finding-description">
                            {
                              finding.description
                            }
                          </p>
                        )}

                        <div className="details-code-info">
                          {finding?.file && (
                            <div>
                              <span>
                                File
                              </span>

                              <code>
                                {finding.file}
                              </code>
                            </div>
                          )}

                          {finding?.line && (
                            <div>
                              <span>
                                Line
                              </span>

                              <strong>
                                {finding.line}
                              </strong>
                            </div>
                          )}

                          {finding?.category && (
                            <div>
                              <span>
                                Category
                              </span>

                              <strong>
                                {
                                  finding.category
                                }
                              </strong>
                            </div>
                          )}
                        </div>

                        {finding?.evidence && (
                          <div className="evidence-box">
                            <div className="evidence-title">
                              Evidence
                            </div>

                            <pre>
                              {
                                finding.evidence
                              }
                            </pre>
                          </div>
                        )}

                        {finding?.context && (
                          <div className="context-box">
                            <div className="evidence-title">
                              Code Context
                            </div>

                            <pre>
                              {
                                finding.context
                              }
                            </pre>
                          </div>
                        )}

                        <div className="recommendation-box">
                          <div className="recommendation-title">
                            Recommended Fix
                          </div>

                          <p style={{ whiteSpace: "pre-line" }}>
                            {getBilingualFix(finding)}
                          </p>
                        </div>
                      </div>
                    </div>
                  );
                }
              )}
            </div>
          )}
        </div>

        {/* FOOTER */}

        <div className="details-modal-footer">
          <button
            className="secondary-button details-close-footer"
            onClick={onClose}
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   MAIN APP
========================================================= */

function App() {
  const [selectedFile, setSelectedFile] =
    useState(null);

  const [result, setResult] =
    useState(null);

  const [history, setHistory] =
    useState([]);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  const [aiLoadingId, setAiLoadingId] =
    useState(null);

  const [aiResults, setAiResults] =
    useState({});

  const [dragActive, setDragActive] =
    useState(false);

  const [selectedScan, setSelectedScan] =
    useState(null);

  const [detailsLoading, setDetailsLoading] =
    useState(false);

  const [severityFilter, setSeverityFilter] = useState("ALL");

  /* =====================================================
     OPEN SCAN DETAILS
  ===================================================== */

  async function openScanDetails(scanId) {
    try {
      setDetailsLoading(true);
      setSelectedScan(null);

      const response =
        await fetch(
          `${API_BASE}/api/history/${scanId}`
        );

      if (!response.ok) {
        throw new Error(
          "Failed to load scan details."
        );
      }

      const data =
        await response.json();

      setSelectedScan(data);
    } catch (err) {
      console.error(
        "Scan details error:",
        err
      );

      alert(
        "Scan details load nahi ho paaye."
      );
    } finally {
      setDetailsLoading(false);
    }
  }

  /* =====================================================
     LOAD HISTORY
  ===================================================== */

  async function loadHistory() {
    try {
      const response =
        await fetch(
          `${API_BASE}/api/history`
        );

      if (!response.ok) {
        return;
      }

      const data =
        await response.json();

      setHistory(
        Array.isArray(data)
          ? data
          : Array.isArray(data?.history)
          ? data.history
          : []
      );
    } catch (err) {
      console.error(
        "History error:",
        err
      );
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  /* =====================================================
     FILE SELECT
  ===================================================== */

  function handleFileChange(event) {
    const file =
      event.target.files?.[0];

    if (!file) return;

    setSelectedFile(file);
    setError("");
    setResult(null);
    setAiResults({});
  }

  function handleDrop(event) {
    event.preventDefault();

    setDragActive(false);

    const file =
      event.dataTransfer.files?.[0];

    if (!file) return;

    setSelectedFile(file);
    setError("");
    setResult(null);
    setAiResults({});
  }

  function handleDragOver(event) {
    event.preventDefault();
    setDragActive(true);
  }

  function handleDragLeave(event) {
    event.preventDefault();
    setDragActive(false);
  }

  /* =====================================================
     SCAN
  ===================================================== */

  async function startScan() {
    if (!selectedFile) {
      setError(
        "Please select a ZIP or supported source file first."
      );
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setAiResults({});

    try {
      const formData =
        new FormData();

      formData.append(
        "file",
        selectedFile
      );

      const response =
        await fetch(
          `${API_BASE}/api/scan`,
          {
            method: "POST",
            body: formData,
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            "Scan failed."
        );
      }

      setResult(data);
      setSeverityFilter("ALL");

      await loadHistory();
    } catch (err) {
      console.error(err);

      setError(
        err?.message ||
          "Unable to connect to the scanner backend."
      );
    } finally {
      setLoading(false);
    }
  }

  /* =====================================================
     PDF REPORT
  ===================================================== */

  async function downloadPdfReport() {
    if (!result) return;

    try {
      setError("");

      const response = await fetch(`${API_BASE}/api/report/pdf`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(result),
      });

      if (!response.ok) {
        let message = "PDF report generate nahi ho paya.";
        try {
          const data = await response.json();
          message = data?.detail || message;
        } catch (_) {}
        throw new Error(message);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      const baseName = String(result.filename || "security_scan")
        .replace(/\\.[^/.]+$/, "")
        .replace(/[^a-zA-Z0-9_-]+/g, "_");

      link.href = url;
      link.download = `${baseName || "security_scan"}_security_report.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("PDF report error:", err);
      setError(err?.message || "PDF report generate nahi ho paya.");
    }
  }

  /* =====================================================
     AI EXPLANATION
  ===================================================== */

  async function explainWithAI(
    finding,
    findingKey
  ) {
    if (!finding) return;

    const key = findingKey || getFindingKey(finding);
    setAiLoadingId(key);
    setError("");

    try {
      const response =
        await fetch(
          `${API_BASE}/api/ai-explain`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",
            },

            body: JSON.stringify({
              findings: [finding],
              score:
                result?.score ?? 100,
            }),
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            "AI explanation failed."
        );
      }

      setAiResults(
        (previous) => ({
          ...previous,

          [key]:
            formatAIResult(
              data?.explanation ||
                data?.message ||
                data?.analysis ||
                "No AI explanation returned."
            ),
        })
      );
    } catch (err) {
      console.error(
        "AI explanation error:",
        err
      );

      // Free-tier AI providers can temporarily return 429/503 or run out of quota.
      // Keep the feature useful by generating a local security explanation.
      setAiResults(
        (previous) => ({
          ...previous,

          [key]: getOfflineAIExplanation(finding),
        })
      );
    } finally {
      setAiLoadingId(null);
    }
  }

  /* =====================================================
     COUNTS
  ===================================================== */

  const counts = useMemo(() => {
    return {
      critical: getCount(
        result?.counts,
        "CRITICAL"
      ),

      high: getCount(
        result?.counts,
        "HIGH"
      ),

      medium: getCount(
        result?.counts,
        "MEDIUM"
      ),

      low: getCount(
        result?.counts,
        "LOW"
      ),
    };
  }, [result]);

  const totalFindings =
    counts.critical +
    counts.high +
    counts.medium +
    counts.low;

  const filteredFindings = useMemo(() => {
    const findings = Array.isArray(result?.findings) ? result.findings : [];

    if (severityFilter === "ALL") {
      return findings;
    }

    return findings.filter(
      (finding) =>
        String(finding?.severity || "LOW").toUpperCase() === severityFilter
    );
  }, [result, severityFilter]);

  /* =====================================================
     RENDER
  ===================================================== */

  return (
    <div className="app">

      {/* HEADER */}

      <header className="top-header">
        <div className="brand">
          <div className="brand-icon">
            🛡️
          </div>

          <div>
            <h1>
              SECURITY ANALYSIS PLATFORM
            </h1>

           
          </div>
        </div>

        <div className="header-status">
          <span className="status-dot" />
          Scanner Online
        </div>
      </header>

      {/* MAIN */}

      <main className="container">

        {/* HERO */}

        <section className="hero">
          <h2>
            Find security vulnerabilities
            before attackers do.
          </h2>

          <p>
            Upload your source code or ZIP
            project and scan it for common
            security vulnerabilities with
            automated analysis and
            AI-powered explanations.
          </p>
        </section>

        {/* UPLOAD */}

        <section className="upload-section">
          <div
            className={`upload-box ${
              dragActive
                ? "drag-active"
                : ""
            }`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            <div className="upload-icon">
              📁
            </div>

            <h2>
              Upload Project
            </h2>

            <p>
              Select a ZIP file or supported
              source code file to start the
              security scan.
            </p>

            <label className="file-button">
              Choose File

              <input
                type="file"
                accept=".zip,.py,.js,.jsx,.ts,.tsx,.java,.php,.go,.cs,.cpp,.c,.html,.css,.sql,.json"
                onChange={
                  handleFileChange
                }
                hidden
              />
            </label>

            {selectedFile && (
              <div className="selected-file">
                <span>
                  📄
                </span>

                <span>
                  {selectedFile.name}
                </span>

                <span>
                  (
                  {(
                    selectedFile.size /
                    1024
                  ).toFixed(1)}
                  KB)
                </span>
              </div>
            )}

            <button
              className="scan-button"
              onClick={startScan}
              disabled={
                loading ||
                !selectedFile
              }
            >
              {loading
                ? "🔄 Scanning..."
                : "🔍 Start Security Scan"}
            </button>
          </div>
        </section>

        {/* ERROR */}

        {error && (
          <div className="error-box">
            <strong>
              ⚠️ Error
            </strong>

            <span>
              {error}
            </span>
          </div>
        )}

        {/* RESULTS */}

        {result && (
          <section className="results-section">

            <div className="section-heading">
              <div>
                <div className="section-label">
                  SECURITY DASHBOARD
                </div>

                <h2>
                  Scan Results
                </h2>

                <p>
                  {result.summary ||
                    `Detected ${totalFindings} security finding(s).`}
                </p>
              </div>

              <div className="result-file">
                <span>
                  📄{" "}
                  {result.filename || selectedFile?.name}
                </span>

                <button
                  type="button"
                  className="secondary-button pdf-download-button"
                  onClick={downloadPdfReport}
                >
                  📄 Download PDF Report
                </button>
              </div>
            </div>

            <ScoreCard
              score={result.score}
            />

            <div className="stats-grid">

              <StatCard
                title="Critical"
                value={counts.critical}
                icon="🔴"
              />

              <StatCard
                title="High"
                value={counts.high}
                icon="🟠"
              />

              <StatCard
                title="Medium"
                value={counts.medium}
                icon="🟡"
              />

              <StatCard
                title="Low"
                value={counts.low}
                icon="🔵"
              />

              <StatCard
                title="Files Scanned"
                value={
                  result.files_scanned ??
                  0
                }
                icon="📁"
              />

              <StatCard
                title="Lines Scanned"
                value={
                  result.lines_scanned ??
                  0
                }
                icon="📝"
              />

              <StatCard
                title="Total Findings"
                value={
                  totalFindings
                }
                icon="🚨"
              />

            </div>

            <SeverityChart
              result={result}
            />

            <SecurityOverview result={result} />

            <div className="findings-section">

              <div className="card-title">
                Security Findings
              </div>

              <div className="findings-toolbar">
                <div className="chart-subtitle">Detailed vulnerabilities detected in your project.</div>
                <div className="severity-filters">
                  {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => (
                    <button key={level} type="button" className={`severity-filter ${severityFilter === level ? "active" : ""}`} onClick={() => setSeverityFilter(level)}>
                      {level === "ALL" ? "All" : level}
                    </button>
                  ))}
                </div>
              </div>

              {!result.findings || result.findings.length === 0 ? (

                <div className="no-findings">

                  <div className="no-findings-icon">
                    ✅
                  </div>

                  <h3>
                    No security findings
                  </h3>

                  <p>
                    No supported security
                    issues were detected
                    in this project.
                  </p>

                </div>

              ) : filteredFindings.length === 0 ? (

                <div className="no-findings">
                  <div className="no-findings-icon">🔎</div>
                  <h3>No findings in this filter</h3>
                  <p>Try another severity filter to view the detected issues.</p>
                </div>

              ) : (

                <div className="findings-list">

                  {filteredFindings.map(
                    (
                      finding,
                      index
                    ) => (

                      <FindingCard
                        key={getFindingKey(finding)}
                        finding={finding}
                        index={index}
                        findingKey={getFindingKey(finding)}
                        onExplain={
                          explainWithAI
                        }
                        aiLoading={
                          aiLoadingId ===
                          getFindingKey(finding)
                        }
                        aiResult={
                          aiResults[getFindingKey(finding)]
                        }
                      />

                    )
                  )}

                </div>

              )}

            </div>

          </section>
        )}

        {/* HISTORY */}

        <section className="history-section">

          <div className="section-label">
            SCAN HISTORY
          </div>

          <h2>
            Previous Scans
          </h2>

          <HistoryTable
            history={history}
            onOpenDetails={
              openScanDetails
            }
          />

        </section>

      </main>

      {/* FOOTER */}

      <footer className="footer">
        <p>
          AI Secure Code Scanner
          {" • "}
          Automated security analysis
        </p>
      </footer>

      {/* SCAN DETAILS */}

      <ScanDetailsModal
        scan={selectedScan}
        loading={detailsLoading}
        onClose={() => {
          setSelectedScan(null);
          setDetailsLoading(false);
        }}
      />

    </div>
  );
}

/* =========================================================
   START REACT
========================================================= */

createRoot(
  document.getElementById("root")
).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);