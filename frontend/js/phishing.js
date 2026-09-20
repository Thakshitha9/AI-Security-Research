const analyzeButton = document.getElementById("analyzeButton");
const urlInput = document.getElementById("urlInput");

const resultContainer = document.getElementById("resultContainer");
const resultStatus = document.getElementById("resultStatus");
const riskBadge = document.getElementById("riskBadge");
const riskScore = document.getElementById("riskScore");
const confidenceScore = document.getElementById("confidenceScore");
const aiExplanation = document.getElementById("aiExplanation");

analyzeButton.addEventListener("click", async function () {

    const url = urlInput.value.trim();

    if (!url) {
        alert("Please enter a website URL.");
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
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed");
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

        // Display detected indicators
        if (data.indicators && data.indicators.length > 0) {

            aiExplanation.textContent +=
                "\n\nDetected Indicators:\n" +
                data.indicators
                    .map(indicator => "• " + indicator)
                    .join("\n");
        }

        // We are not displaying a fake confidence value.
        confidenceScore.textContent = "AI Analysis";

    } catch (error) {

        console.error("Phishing analysis error:", error);

        alert(
            "Unable to analyze the URL. " +
            "Please make sure the Flask API is running."
        );

    } finally {

        analyzeButton.disabled = false;
        analyzeButton.textContent = "Analyze URL";
    }
});
