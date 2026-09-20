
"use strict";

// ============================================================
// RECON AI API CONFIGURATION
// ============================================================

const API_URL = "http://127.0.0.1:5002/api/recon/analyze";

const REQUEST_TIMEOUT = 180000; // 3 minutes


// ============================================================
// DOM ELEMENTS
// ============================================================

const nmapFile = document.getElementById("nmapFile");
const fileName = document.getElementById("fileName");
const analyzeButton = document.getElementById("analyzeButton");
const statusMessage = document.getElementById("statusMessage");

const resultsSection = document.getElementById("resultsSection");
const hostCount = document.getElementById("hostCount");
const findingCount = document.getElementById("findingCount");
const highRiskCount = document.getElementById("highRiskCount");
const hostResults = document.getElementById("hostResults");


// ============================================================
// INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {
    initializeReconPage();
});

function initializeReconPage() {
    if (!nmapFile) {
        console.error("Recon error: nmapFile element was not found.");
        return;
    }

    if (!fileName) {
        console.error("Recon error: fileName element was not found.");
        return;
    }

    if (!analyzeButton) {
        console.error(
            "Recon error: analyzeButton element was not found."
        );
        return;
    }

    if (!statusMessage) {
        console.error(
            "Recon error: statusMessage element was not found."
        );
        return;
    }

    nmapFile.addEventListener("change", handleFileSelection);

    analyzeButton.addEventListener(
        "click",
        analyzeNmapFile
    );

    analyzeButton.disabled = true;

    if (resultsSection) {
        resultsSection.style.display = "none";
    }

    console.log("Recon AI frontend initialized.");
    console.log("Recon API URL:", API_URL);
}


// ============================================================
// FILE SELECTION
// ============================================================

function handleFileSelection() {
    const file = nmapFile.files[0];

    clearStatus();

    if (!file) {
        fileName.textContent = "No file selected";
        analyzeButton.disabled = true;
        return;
    }

    fileName.textContent = file.name;

    if (!file.name.toLowerCase().endsWith(".xml")) {
        showError(
            "Please select a valid Nmap XML file."
        );

        analyzeButton.disabled = true;
        return;
    }

    if (file.size === 0) {
        showError(
            "The selected XML file is empty."
        );

        analyzeButton.disabled = true;
        return;
    }

    analyzeButton.disabled = false;

    console.log("Selected file:", {
        name: file.name,
        size: file.size,
        type: file.type
    });
}


// ============================================================
// ANALYZE NMAP XML FILE
// ============================================================

async function analyzeNmapFile() {
    const file = nmapFile.files[0];

    if (!file) {
        showError(
            "Please select an Nmap XML file first."
        );

        return;
    }

    if (!file.name.toLowerCase().endsWith(".xml")) {
        showError(
            "Please select a valid Nmap XML file."
        );

        return;
    }

    let timeoutId = null;

    try {
        setLoadingState(true);

        showLoading(
            "Reading Nmap XML file and analyzing security data..."
        );

        const xmlData = await file.text();

        if (!xmlData || !xmlData.trim()) {
            throw new Error(
                "The selected XML file is empty."
            );
        }

        if (
            !xmlData.includes("<nmaprun") &&
            !xmlData.includes("<nmaprun ")
        ) {
            console.warn(
                "The file does not appear to contain a standard Nmap XML root element."
            );
        }

        const requestBody = {
            xml: xmlData
        };

        console.log("Sending request to Recon API:", API_URL);
        console.log("XML file size:", xmlData.length);

        const controller = new AbortController();

        timeoutId = setTimeout(() => {
            controller.abort();
        }, REQUEST_TIMEOUT);

        const response = await fetch(API_URL, {
            method: "POST",

            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },

            body: JSON.stringify(requestBody),

            signal: controller.signal
        });

        if (timeoutId) {
            clearTimeout(timeoutId);
            timeoutId = null;
        }

        const responseText = await response.text();

        console.log(
            "Recon API HTTP status:",
            response.status
        );

        console.log(
            "Recon API raw response:",
            responseText
        );

        let data = null;

        try {
            data = responseText
                ? JSON.parse(responseText)
                : null;
        } catch (jsonError) {
            throw new Error(
                "The Recon API returned an invalid JSON response. " +
                `HTTP status: ${response.status}. ` +
                `Response: ${responseText.substring(0, 500)}`
            );
        }

        if (!response.ok) {
            const backendError =
                data?.error ||
                data?.message ||
                `Recon API returned HTTP ${response.status}.`;

            throw new Error(backendError);
        }

        if (!data || typeof data !== "object") {
            throw new Error(
                "The Recon API returned an empty or invalid response."
            );
        }

        if (data.status === "error") {
            throw new Error(
                data.error ||
                data.message ||
                "Recon API reported an error."
            );
        }

        if (
            !Array.isArray(data.hosts) &&
            !Array.isArray(data.results)
        ) {
            console.warn(
                "Recon API response does not contain a hosts or results array.",
                data
            );
        }

        // Save the complete Recon response for the Security Report page.
        localStorage.setItem(
            "reconAnalysis",
            JSON.stringify(data)
        );

        console.log(
            "Recon analysis response saved to localStorage."
        );

        renderResults(data);

        showSuccess(
            "Recon analysis completed successfully."
        );

    } catch (error) {
        if (timeoutId) {
            clearTimeout(timeoutId);
            timeoutId = null;
        }

        console.error(
            "Recon AI analysis error:",
            error
        );

        let errorMessage = error.message || String(error);

        if (error.name === "AbortError") {
            errorMessage =
                "The Recon API request timed out after 3 minutes. " +
                "Check the Recon API terminal for the processing error.";
        }

        if (
            error instanceof TypeError &&
            errorMessage.toLowerCase().includes("fetch")
        ) {
            errorMessage =
                "Could not connect to the Recon API. " +
                "Confirm that recon_ai_api.py is running on port 5002. " +
                `API URL: ${API_URL}`;
        }

        showError(
            "Recon AI analysis failed: " + errorMessage
        );

    } finally {
        setLoadingState(false);
    }
}


// ============================================================
// RENDER RECON RESULTS
// ============================================================

function renderResults(data) {
    if (!resultsSection || !hostResults) {
        console.error(
            "Recon results elements were not found in the HTML."
        );

        return;
    }

    resultsSection.style.display = "block";
    hostResults.replaceChildren();

    const hosts = Array.isArray(data.hosts)
        ? data.hosts
        : [];

    let totalFindings = 0;
    let totalHighRisk = 0;

    hosts.forEach((host) => {
        const findings = Array.isArray(host.findings)
            ? host.findings
            : [];

        totalFindings += findings.length;

        findings.forEach((finding) => {
            const riskLevel = String(
                finding.risk_level || ""
            ).toLowerCase();

            if (
                riskLevel === "high" ||
                riskLevel === "critical"
            ) {
                totalHighRisk++;
            }
        });

        const hostCard = createHostCard(host);

        hostResults.appendChild(hostCard);
    });

    if (hostCount) {
        hostCount.textContent = String(hosts.length);
    }

    if (findingCount) {
        findingCount.textContent = String(totalFindings);
    }

    if (highRiskCount) {
        highRiskCount.textContent = String(totalHighRisk);
    }

    if (hosts.length === 0) {
        const emptyMessage = document.createElement("p");

        emptyMessage.textContent =
            "No host results were returned by the Recon API.";

        hostResults.appendChild(emptyMessage);
    }

    resultsSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


// ============================================================
// CREATE HOST CARD
// ============================================================

function createHostCard(host) {
    const card = document.createElement("div");

    card.className = "host-card";

    const riskScore = Number(host.risk_score || 0);

    const findings = Array.isArray(host.findings)
        ? host.findings
        : [];

    const hostIp =
        host.ip ||
        host.address ||
        "Unknown host";

    const hostname =
        host.hostname ||
        "No hostname";

    const hostHeader = document.createElement("div");

    hostHeader.className = "host-header";

    const hostInfo = document.createElement("div");

    hostInfo.className = "host-info";

    const hostTitle = document.createElement("h3");

    hostTitle.textContent = String(hostIp);

    const hostnameText = document.createElement("p");

    hostnameText.textContent =
        `Hostname: ${String(hostname)}`;

    hostInfo.appendChild(hostTitle);
    hostInfo.appendChild(hostnameText);

    const riskScoreContainer = document.createElement("div");

    riskScoreContainer.className = "risk-score";

    const riskScoreValue = document.createElement("div");

    riskScoreValue.className = "risk-score-value";
    riskScoreValue.textContent = String(riskScore);

    const riskScoreLabel = document.createElement("div");

    riskScoreLabel.className = "risk-score-label";
    riskScoreLabel.textContent = "Risk Score / 100";

    riskScoreContainer.appendChild(riskScoreValue);
    riskScoreContainer.appendChild(riskScoreLabel);

    hostHeader.appendChild(hostInfo);
    hostHeader.appendChild(riskScoreContainer);

    const findingsTitle = document.createElement("h4");

    findingsTitle.className = "findings-title";
    findingsTitle.textContent = "Security Findings";

    const findingsContainer = document.createElement("div");

    findingsContainer.className = "findings-container";

    if (findings.length > 0) {
        findings.forEach((finding) => {
            findingsContainer.appendChild(
                createFindingElement(finding)
            );
        });
    } else {
        const noFindingsMessage = document.createElement("p");

        noFindingsMessage.textContent =
            "No security findings detected.";

        findingsContainer.appendChild(
            noFindingsMessage
        );
    }

    const aiAnalysisContainer = document.createElement("div");

    aiAnalysisContainer.className = "ai-analysis";

    const aiTitle = document.createElement("h4");

    aiTitle.textContent = "AI Security Analysis";

    const aiText = document.createElement("div");

    aiText.className = "ai-analysis-text";

    aiText.textContent =
        host.llm_analysis ||
        "AI analysis was not available.";

    aiAnalysisContainer.appendChild(aiTitle);
    aiAnalysisContainer.appendChild(aiText);

    card.appendChild(hostHeader);
    card.appendChild(findingsTitle);
    card.appendChild(findingsContainer);
    card.appendChild(aiAnalysisContainer);

    return card;
}


// ============================================================
// CREATE FINDING ELEMENT
// ============================================================

function createFindingElement(finding) {
    const findingContainer = document.createElement("div");

    findingContainer.className = "finding";

    const riskLevel = String(
        finding.risk_level || "info"
    ).toLowerCase();

    let riskClass = "risk-low";

    if (
        riskLevel === "high" ||
        riskLevel === "critical"
    ) {
        riskClass = "risk-high";
    } else if (riskLevel === "medium") {
        riskClass = "risk-medium";
    }

    const findingHeader = document.createElement("div");

    findingHeader.className = "finding-header";

    const findingPort = document.createElement("div");

    findingPort.className = "finding-port";

    const port = finding.port ?? "";
    const service = finding.service || "Unknown service";

    findingPort.textContent =
        `Port ${port} / ${service}`;

    const riskBadge = document.createElement("span");

    riskBadge.className =
        `risk-badge ${riskClass}`;

    riskBadge.textContent = riskLevel;

    findingHeader.appendChild(findingPort);
    findingHeader.appendChild(riskBadge);

    const description = document.createElement("div");

    description.className = "finding-description";

    description.textContent =
        finding.description ||
        "No description available.";

    const recommendation = document.createElement("div");

    recommendation.className =
        "finding-recommendation";

    const recommendationLabel = document.createElement("strong");

    recommendationLabel.textContent =
        "Recommendation: ";

    const recommendationText = document.createTextNode(
        finding.recommendation ||
        "Review and restrict access as appropriate."
    );

    recommendation.appendChild(recommendationLabel);
    recommendation.appendChild(recommendationText);

    findingContainer.appendChild(findingHeader);
    findingContainer.appendChild(description);
    findingContainer.appendChild(recommendation);

    return findingContainer;
}


// ============================================================
// BUTTON AND LOADING STATE
// ============================================================

function setLoadingState(isLoading) {
    if (!analyzeButton) {
        return;
    }

    analyzeButton.disabled = isLoading;

    if (isLoading) {
        analyzeButton.dataset.originalText =
            analyzeButton.textContent;

        analyzeButton.textContent =
            "Analyzing...";
    } else {
        analyzeButton.textContent =
            analyzeButton.dataset.originalText ||
            "Analyze with Recon AI";
    }
}


// ============================================================
// STATUS MESSAGES
// ============================================================

function showLoading(message) {
    if (!statusMessage) {
        return;
    }

    statusMessage.className =
        "status-message loading";

    statusMessage.textContent = message;
    statusMessage.style.display = "block";
}

function showError(message) {
    if (!statusMessage) {
        return;
    }

    statusMessage.className =
        "status-message error";

    statusMessage.textContent = message;
    statusMessage.style.display = "block";
}

function showSuccess(message) {
    if (!statusMessage) {
        return;
    }

    statusMessage.className =
        "status-message";

    statusMessage.textContent = message;
    statusMessage.style.display = "block";
}

function clearStatus() {
    if (!statusMessage) {
        return;
    }

    statusMessage.textContent = "";

    statusMessage.className =
        "status-message";

    statusMessage.style.display = "none";
}