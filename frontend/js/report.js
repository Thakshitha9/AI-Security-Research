
const REPORT_API = "http://127.0.0.1:5003";

const generateButton = document.getElementById("generateReportBtn");
const downloadButton = document.getElementById("downloadReportBtn");
const reportContent = document.getElementById("reportContent");
const reportStatus = document.getElementById("reportStatus");

let generatedReport = "";

function setStatus(message, isError = false) {
    if (!reportStatus) return;

    reportStatus.textContent = message;
    reportStatus.style.color = isError ? "red" : "";
}

function getReconData() {
    const storedData = localStorage.getItem("reconAnalysis");

    if (!storedData) {
        throw new Error(
            "No Recon AI assessment data found. Run Recon AI first."
        );
    }

    let reconData;

    try {
        reconData = JSON.parse(storedData);
    } catch (error) {
        throw new Error(
            "Recon AI data in localStorage is not valid JSON."
        );
    }

    if (
        reconData === null ||
        typeof reconData !== "object" ||
        Array.isArray(reconData)
    ) {
        throw new Error(
            "Recon AI data must be a valid JSON object."
        );
    }

    return reconData;
}

async function generateSecurityReport() {
    if (generateButton) {
        generateButton.disabled = true;
        generateButton.textContent = "Generating...";
    }

    if (downloadButton) {
        downloadButton.disabled = true;
    }

    if (reportContent) {
        reportContent.textContent = "";
    }

    setStatus(
        "Generating security report. Please wait...",
        false
    );

    try {
        const reconData = getReconData();

        console.log("Recon data sent to report API:", reconData);

        const response = await fetch(
            `${REPORT_API}/api/security-report/generate`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify(reconData)
            }
        );

        const responseText = await response.text();

        console.log(
            "Report API HTTP status:",
            response.status
        );

        console.log(
            "Report API raw response:",
            responseText
        );

        let result;

        try {
            result = JSON.parse(responseText);
        } catch (error) {
            throw new Error(
                `Backend returned a non-JSON response. HTTP status: ${response.status}. Response: ${responseText.substring(0, 500)}`
            );
        }

        if (!response.ok || result.status === "error") {
            throw new Error(
                result.error ||
                result.message ||
                `Report generation failed with HTTP status ${response.status}.`
            );
        }

        generatedReport = result.report || "";

        if (!generatedReport.trim()) {
            throw new Error(
                "The backend returned an empty security report."
            );
        }

        if (reportContent) {
            reportContent.textContent = generatedReport;
        }

        if (downloadButton) {
            downloadButton.disabled = false;
        }

        setStatus(
            "Security report generated successfully.",
            false
        );

        console.log(
            "Security report generated successfully:",
            result
        );

    } catch (error) {
        console.error(
            "Security report generation error:",
            error
        );

        const errorMessage = error.message || String(error);

        if (reportContent) {
            reportContent.textContent =
                "Unable to generate the security report.\n\n" +
                "Actual error:\n" +
                errorMessage;
        }

        setStatus(
            `Security report generation failed: ${errorMessage}`,
            true
        );

    } finally {
        if (generateButton) {
            generateButton.disabled = false;
            generateButton.textContent = "Generate Security Report";
        }
    }
}

function downloadSecurityReport() {
    if (!generatedReport.trim()) {
        alert("Generate a security report before downloading.");
        return;
    }

    const blob = new Blob(
        [generatedReport],
        {
            type: "text/markdown;charset=utf-8"
        }
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
    generateButton.addEventListener(
        "click",
        generateSecurityReport
    );
}

if (downloadButton) {
    downloadButton.addEventListener(
        "click",
        downloadSecurityReport
    );
}

async function checkReportHealth() {
    try {
        const response = await fetch(
            `${REPORT_API}/api/security-report/health`
        );

        const result = await response.json();

        console.log("Report API health:", result);

        if (result.status === "online") {
            setStatus(
                "Report API is online. Ready to generate.",
                false
            );
        }
    } catch (error) {
        console.error(
            "Report API health check failed:",
            error
        );

        setStatus(
            "Report API is unavailable.",
            true
        );
    }
}

checkReportHealth();