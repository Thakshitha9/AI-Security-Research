const analyzeButton = document.getElementById("analyzeButton");
const urlInput = document.getElementById("urlInput");

const resultContainer = document.getElementById("resultContainer");
const resultStatus = document.getElementById("resultStatus");
const riskBadge = document.getElementById("riskBadge");
const riskScore = document.getElementById("riskScore");
const confidenceScore = document.getElementById("confidenceScore");
const aiExplanation = document.getElementById("aiExplanation");
const formMessage = document.getElementById("formMessage");
const fieldRiskLevel = document.getElementById("fieldRiskLevel");
const fieldFinding = document.getElementById("fieldFinding");
const fieldEvidence = document.getElementById("fieldEvidence");
const fieldExplanation = document.getElementById("fieldExplanation");
const fieldRecommendation = document.getElementById("fieldRecommendation");

function showFormMessage(message, isError) {
    if (!formMessage) {
        return;
    }

    formMessage.hidden = false;
    formMessage.textContent = message;
    formMessage.className = isError
        ? "form-message error"
        : "form-message";
}

analyzeButton.addEventListener("click", async function () {

    const url = urlInput.value.trim();

    if (!url) {
        showFormMessage("Enter a website URL.", true);
        return;
    }

    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analyzing...";

    try {

        const response = await fetch(
            "http://127.0.0.1:5000/api/phishing/analyze",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: url
                }),
                signal: AbortSignal.timeout(130000)
            }
        );

        let data;

        try {
            data = await response.json();
        } catch (parseError) {
            throw new Error("The API returned an unreadable response.");
        }

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed");
        }

        if (formMessage) {
            formMessage.hidden = true;
        }

        // Show result section
        resultContainer.classList.remove("hidden");

        // Risk status
        resultStatus.textContent =
            data.risk_score >= 50
                ? "Potentially Suspicious"
                : "No Major Threat Detected";

        // Risk score
        riskScore.textContent = data.risk_score + "/100";

        // Risk badge
        if (data.risk_score >= 70) {
            riskBadge.textContent = "HIGH RISK";
        } else if (data.risk_score >= 40) {
            riskBadge.textContent = "MEDIUM RISK";
        } else {
            riskBadge.textContent = "LOW RISK";
        }

        // AI explanation
        if (data.ai_explanation) {

            aiExplanation.textContent = data.ai_explanation;

        } else {

            aiExplanation.textContent =
                "AI explanation is currently unavailable.";

        }

        const evidence = Array.isArray(data.evidence) && data.evidence.length
            ? data.evidence
            : (Array.isArray(data.indicators) ? data.indicators : []);

        if (fieldRiskLevel) {
            fieldRiskLevel.textContent = data.risk_level || riskBadge.textContent;
        }

        if (fieldFinding) {
            fieldFinding.textContent = data.finding || "No finding was returned.";
        }

        if (fieldEvidence) {
            fieldEvidence.textContent = evidence.length
                ? evidence.join("; ")
                : "No indicators were returned.";
        }

        if (fieldExplanation) {
            fieldExplanation.textContent = data.explanation
                || data.ai_explanation
                || "No explanation was returned.";
        }

        if (fieldRecommendation) {
            fieldRecommendation.textContent = data.recommendation
                || "No recommendation was returned.";
        }

        // We are not displaying a fake confidence value.
        confidenceScore.textContent = "Rule checks + optional AI";

    } catch (error) {

        console.error("Phishing analysis error:", error);

        let message = error.message || "The analysis could not be completed.";

        if (error.name === "TimeoutError" || error.name === "AbortError") {
            message = "The analysis timed out. The API did not respond in time.";
        } else if (error instanceof TypeError) {
            message = "Unable to reach the API on port 5000.";
        }

        showFormMessage(message, true);

    } finally {

        analyzeButton.disabled = false;
        analyzeButton.textContent = "Analyze URL";
    }
});
