const REPORT_API = "http://127.0.0.1:5003";

const generateButton = document.getElementById("generateReportBtn");
const downloadButton = document.getElementById("downloadReportBtn");
const reportContent = document.getElementById("reportContent");
const reportView = document.getElementById("reportView");
const emptyState = document.getElementById("emptyState");
const emptyStateTitle = document.getElementById("emptyStateTitle");
const emptyStateText = document.getElementById("emptyStateText");
const reportStatus = document.getElementById("statusMessage");
const apiStatus = document.getElementById("apiStatus");

let generatedReport = "";
let reportRequestActive = false;
let reportVisible = false;

const SEVERITY_NAMES = {
    CRITICAL: "Critical",
    HIGH: "High",
    MEDIUM: "Medium",
    LOW: "Low",
    INFO: "Informational",
    UNKNOWN: "Unknown"
};

function setStatus(message, kind) {
    if (!reportStatus) {
        return;
    }

    reportStatus.textContent = message || "";
    reportStatus.className = "status-message";
    reportStatus.style.color = "";

    if (!message) {
        reportStatus.style.display = "none";
        return;
    }

    reportStatus.style.display = "block";
    reportStatus.classList.add("status-" + (kind || "info"));
}

function setApiStatus(message) {
    if (apiStatus) {
        apiStatus.textContent = message || "";
    }
}

function readStoredAssessment() {
    const storedData = localStorage.getItem("reconAnalysis");

    if (!storedData) {
        return { state: "missing", data: null };
    }

    try {
        const reconData = JSON.parse(storedData);

        if (
            reconData === null ||
            typeof reconData !== "object" ||
            Array.isArray(reconData)
        ) {
            return { state: "invalid", data: null };
        }

        if (!Array.isArray(reconData.hosts)) {
            return { state: "incomplete", data: reconData };
        }

        return { state: "ready", data: reconData };
    } catch (error) {
        return { state: "invalid", data: null };
    }
}

function severityName(level) {
    const key = String(level || "UNKNOWN").toUpperCase();
    return SEVERITY_NAMES[key] || "Unknown";
}

function severityCountsFromFindings(findings) {
    const counts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
    };

    (findings || []).forEach(function (finding) {
        const key = String(finding.severity || "").toUpperCase();
        if (Object.prototype.hasOwnProperty.call(counts, key)) {
            counts[key] += 1;
        }
    });

    return counts;
}

function showEmptyState(title, message) {
    if (emptyStateTitle && title) {
        emptyStateTitle.textContent = title;
    }

    if (emptyStateText && message) {
        emptyStateText.textContent = message;
    }

    if (emptyState) {
        emptyState.hidden = false;
    }

    if (reportView) {
        reportView.hidden = true;
        reportView.replaceChildren();
    }

    if (reportContent) {
        reportContent.hidden = true;
    }
}

function refreshAssessmentState() {
    const stored = readStoredAssessment();

    if (generateButton) {
        generateButton.disabled = stored.state === "missing" || stored.state === "invalid";
    }

    if (stored.state === "missing") {
        showEmptyState(
            "No assessment saved",
            "No assessment is saved. Run Recon AI first, then generate the report."
        );
        setStatus("No assessment is saved.", "info");
        return;
    }

    if (stored.state === "invalid") {
        showEmptyState(
            "Assessment could not be read",
            "The saved assessment could not be read. Run Recon AI again."
        );
        setStatus("The saved assessment could not be read.", "error");
        return;
    }

    if (stored.state === "incomplete") {
        showEmptyState(
            "Assessment is incomplete",
            "The saved assessment does not include a host list. You can still generate a report that records the missing data."
        );
        setStatus("Assessment data is incomplete.", "warn");
        return;
    }

    const findingCount = stored.data.hosts.reduce(function (count, host) {
        const findings = host && Array.isArray(host.findings) ? host.findings.length : 0;
        return count + findings;
    }, 0);

    if (findingCount === 0) {
        showEmptyState(
            "Assessment contains no findings",
            "An assessment is saved, and it does not contain any findings. Generate the report to record that result."
        );
        setStatus(
            "Assessment completed. The saved result contains no findings.",
            "info"
        );
        return;
    }

    if (emptyStateTitle) {
        emptyStateTitle.textContent = "Assessment saved";
    }

    if (emptyStateText) {
        emptyStateText.textContent =
            findingCount + " finding(s) are saved. Generate the report to review them.";
    }

    setStatus(
        "Assessment completed. " + findingCount + " finding(s) are ready for the report.",
        "info"
    );

    if (emptyState) {
        emptyState.hidden = false;
    }
}

function addLongField(parent, label, text) {
    const block = document.createElement("div");
    block.className = "finding-field";
    addText(block, "p", "field-label", label);

    const value = String(text);

    if (value.length > 280) {
        const details = document.createElement("details");
        details.open = true;
        const summary = document.createElement("summary");
        summary.textContent = "Full " + label.toLowerCase();
        details.appendChild(summary);
        addText(details, "p", "field-body", value);
        block.appendChild(details);
    } else {
        addText(block, "p", "field-body", value);
    }

    parent.appendChild(block);
}

function addText(parent, tag, className, text) {
    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    element.textContent = text;
    parent.appendChild(element);
    return element;
}

function renderReport(view, narrative) {
    if (!reportView || !view) {
        return;
    }

    reportView.replaceChildren();
    reportView.hidden = false;
    reportVisible = true;

    const counts = view.severity_counts || severityCountsFromFindings(view.findings);
    const findingCount = Number.isInteger(view.finding_count)
        ? view.finding_count
        : (Array.isArray(view.findings) ? view.findings.length : 0);

    const overview = document.createElement("section");
    overview.className = "report-section report-summary";
    addText(overview, "h2", "", "Report summary");
    const overviewList = document.createElement("dl");
    overviewList.className = "summary-grid";
    [
        ["Target", view.target || "Not provided"],
        ["Assessment module", view.module || "Recon AI"],
        ["Assessment status", view.assessment_status || "Not provided"],
        ["Report status", view.report_status || "generated"],
        ["Risk level", severityName(view.risk_level)],
        ["Assessment timestamp", view.timestamp || "Not provided"],
        ["Number of findings", String(findingCount)]
    ].forEach(function (pair) {
        addText(overviewList, "dt", "", pair[0]);
        addText(overviewList, "dd", "", pair[1]);
    });
    overview.appendChild(overviewList);
    reportView.appendChild(overview);

    if (emptyState) {
        emptyState.hidden = true;
    }

    if (reportContent) {
        reportContent.hidden = true;
    }

    const badges = document.createElement("div");
    badges.className = "report-badges";
    addText(
        badges,
        "span",
        view.assessment_status === "completed" ? "report-badge good" : "report-badge warn",
        view.assessment_status === "completed"
            ? "Assessment completed"
            : "Assessment incomplete"
    );
    addText(badges, "span", "report-badge good", "Report generated");
    addText(
        badges,
        "span",
        view.narrative_status === "available" ? "report-badge good" : "report-badge warn",
        view.narrative_status === "available"
            ? "Model narrative available"
            : "Model narrative unavailable"
    );
    reportView.appendChild(badges);

    const summary = document.createElement("section");
    summary.className = "report-section";
    addText(summary, "h2", "", "Executive Summary");
    addText(summary, "p", "", view.summary || "No summary was returned.");
    reportView.appendChild(summary);

    const details = document.createElement("section");
    details.className = "report-section";
    addText(details, "h2", "", "Assessment Details");
    const detailList = document.createElement("ul");
    detailList.className = "report-meta";
    [
        "Module: " + (view.module || "Recon AI"),
        "Target: " + (view.target || "Not provided"),
        "Assessment: " + (view.assessment_status || "Not provided"),
        "Report: " + (view.report_status || "generated")
    ].forEach(function (line) {
        addText(detailList, "li", "", line);
    });
    details.appendChild(detailList);
    reportView.appendChild(details);

    const risk = document.createElement("section");
    risk.className = "report-section";
    addText(risk, "h2", "", "Risk Level");
    const riskLabel = severityName(view.risk_level);
    addText(
        risk,
        "p",
        "risk-banner severity-" + String(view.risk_level || "unknown").toLowerCase(),
        "Risk level: " + riskLabel
    );
    reportView.appendChild(risk);

    const countSection = document.createElement("section");
    countSection.className = "report-section";
    addText(countSection, "h2", "", "Findings by severity");
    const countList = document.createElement("ul");
    countList.className = "severity-counts";
    [
        ["Critical", counts.CRITICAL],
        ["High", counts.HIGH],
        ["Medium", counts.MEDIUM],
        ["Low", counts.LOW],
        ["Informational", counts.INFO]
    ].forEach(function (pair) {
        addText(countList, "li", "", pair[0] + ": " + pair[1]);
    });
    countSection.appendChild(countList);
    reportView.appendChild(countSection);

    const findings = document.createElement("section");
    findings.className = "report-section";
    addText(findings, "h2", "", "Findings");

    if (!Array.isArray(view.findings) || view.findings.length === 0) {
        addText(findings, "p", "", "No findings were present in the supplied assessment.");
    } else {
        view.findings.forEach(function (finding, index) {
            const card = document.createElement("article");
            const severity = String(finding.severity || "UNKNOWN").toLowerCase();
            card.className = "finding-card finding-" + severity;
            addText(card, "h3", "", (index + 1) + ". " + (finding.title || "Finding"));
            addText(card, "p", "", "Target: " + (finding.target || "Not provided"));
            const severityLine = document.createElement("p");
            severityLine.appendChild(document.createTextNode("Severity: "));
            addText(
                severityLine,
                "span",
                "severity severity-" + severity,
                severityName(finding.severity)
            );
            card.appendChild(severityLine);
            addLongField(
                card,
                "Finding",
                finding.detail || "No finding text was returned."
            );
            addLongField(
                card,
                "Evidence",
                finding.evidence || "No evidence was returned."
            );
            addLongField(
                card,
                "Recommendation",
                finding.recommendation || "No recommendation was returned."
            );
            findings.appendChild(card);
        });
    }

    if (view.finding_status) {
        addText(findings, "p", "", view.finding_status);
    }

    reportView.appendChild(findings);

    const evidence = document.createElement("section");
    evidence.className = "report-section";
    addText(evidence, "h2", "", "Evidence");
    const evidenceList = document.createElement("ul");
    (view.evidence || ["No evidence was present in the supplied assessment."]).forEach(function (line) {
        addText(evidenceList, "li", "", String(line).replace(/^- /, ""));
    });
    evidence.appendChild(evidenceList);
    reportView.appendChild(evidence);

    const recommendations = document.createElement("section");
    recommendations.className = "report-section";
    addText(recommendations, "h2", "", "Recommendations");
    const recommendationList = document.createElement("ul");
    (view.recommendations || ["No recommendations were returned."]).forEach(function (line) {
        addText(recommendationList, "li", "", String(line).replace(/^- /, ""));
    });
    recommendations.appendChild(recommendationList);
    reportView.appendChild(recommendations);

    const limits = document.createElement("section");
    limits.className = "report-section";
    addText(limits, "h2", "", "Limitations");
    const limitList = document.createElement("ul");
    (view.limitations || []).forEach(function (line) {
        addText(limitList, "li", "", line);
    });
    limits.appendChild(limitList);
    reportView.appendChild(limits);

    const time = document.createElement("section");
    time.className = "report-section";
    addText(time, "h2", "", "Timestamp");
    addText(time, "p", "", view.timestamp || "Not provided");
    reportView.appendChild(time);

    if (narrative) {
        const narrativeSection = document.createElement("section");
        narrativeSection.className = "report-section";
        addText(narrativeSection, "h2", "", "AI-generated narrative");
        addText(narrativeSection, "pre", "narrative-block", narrative);
        reportView.appendChild(narrativeSection);
    }
}

function narrativeFromReport(report) {
    const marker = "\n## AI-generated narrative\n\n";
    const index = report.indexOf(marker);

    if (index === -1) {
        return "";
    }

    return report.slice(index + marker.length).trim();
}

async function generateSecurityReport() {
    if (reportRequestActive) {
        return;
    }

    reportRequestActive = true;

    if (generateButton) {
        generateButton.disabled = true;
        generateButton.textContent = "Generating report...";
        generateButton.setAttribute("aria-busy", "true");
    }

    if (downloadButton) {
        downloadButton.disabled = true;
    }

    setStatus("Generating the security report.", "info");

    try {
        const stored = readStoredAssessment();

        if (!stored.data) {
            throw new Error(
                stored.state === "invalid"
                    ? "The saved assessment could not be read. Run Recon AI again."
                    : "No assessment is saved. Run Recon AI first."
            );
        }

        const response = await fetch(
            `${REPORT_API}/api/security-report/generate`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify(stored.data),
                signal: AbortSignal.timeout(180000)
            }
        );

        let result;

        try {
            result = await response.json();
        } catch (error) {
            throw new Error("The report API returned an unreadable response.");
        }

        if (!response.ok || result.status === "error") {
            throw new Error(result.error || "Report generation failed.");
        }

        const nextReport = result.report || "";

        if (!nextReport.trim()) {
            throw new Error("The report API returned an empty security report.");
        }

        generatedReport = nextReport;

        if (result.view) {
            renderReport(result.view, narrativeFromReport(generatedReport));
        } else if (reportContent) {
            reportContent.hidden = false;
            reportContent.textContent = generatedReport;
            if (emptyState) {
                emptyState.hidden = true;
            }
        }

        if (downloadButton) {
            downloadButton.disabled = false;
        }

        setStatus(
            result.message || "Security report generated successfully.",
            result.narrative_status === "unavailable" ? "warn" : "success"
        );
    } catch (error) {
        const errorMessage = error.name === "TimeoutError" || error.name === "AbortError"
            ? "The report request timed out."
            : (error instanceof TypeError
                ? "The report API is unavailable."
                : (error.message || "Report generation failed."));

        if (!reportVisible) {
            showEmptyState(
                "Report generation failed",
                "The report could not be generated. No assessment content was changed."
            );
        }

        setStatus(errorMessage, "error");
    } finally {
        reportRequestActive = false;

        if (generateButton) {
            const stored = readStoredAssessment();
            generateButton.disabled = stored.state === "missing" || stored.state === "invalid";
            generateButton.textContent = "Generate Security Report";
            generateButton.removeAttribute("aria-busy");
        }

        if (downloadButton) {
            downloadButton.disabled = !generatedReport.trim();
        }
    }
}

function downloadSecurityReport() {
    if (!generatedReport.trim()) {
        setStatus("Generate a security report before downloading.", "info");
        return;
    }

    const blob = new Blob(
        [generatedReport],
        { type: "text/markdown;charset=utf-8" }
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "security_report.md";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

if (generateButton) {
    generateButton.addEventListener("click", generateSecurityReport);
}

if (downloadButton) {
    downloadButton.addEventListener("click", downloadSecurityReport);
}

async function checkReportHealth() {
    try {
        const response = await fetch(
            `${REPORT_API}/api/security-report/health`,
            { signal: AbortSignal.timeout(2000) }
        );

        if (!response.ok) {
            throw new Error("offline");
        }

        const result = await response.json();

        if (result.status === "online") {
            setApiStatus("Report API is online.");
            return;
        }
    } catch (error) {
        setApiStatus("Report API is unavailable. Start security_report_api.py on port 5003.");
    }
}

refreshAssessmentState();
checkReportHealth();
