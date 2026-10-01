const scanPromptButton =
    document.getElementById("scanPromptButton");

const promptText =
    document.getElementById("promptText");

const promptResult =
    document.getElementById("promptResult");

const resultTitle =
    document.getElementById("resultTitle");

const resultDescription =
    document.getElementById("resultDescription");

const recommendationBadge =
    document.getElementById("recommendationBadge");

const riskScore =
    document.getElementById("riskScore");

const detectionStatus =
    document.getElementById("detectionStatus");

const recommendation =
    document.getElementById("recommendation");

const patternMatches =
    document.getElementById("patternMatches");

const aiAnalysis =
    document.getElementById("aiAnalysis");

const promptMessage =
    document.getElementById("promptMessage");

function showPromptMessage(message, isError) {
    if (!promptMessage) {
        return;
    }

    promptMessage.hidden = !message;
    promptMessage.textContent = message || "";
    promptMessage.className = isError
        ? "form-message error"
        : "form-message";
}


scanPromptButton.addEventListener(
    "click",
    async function () {

        const text = promptText.value.trim();

        if (!text) {
            showPromptMessage("Enter text to analyze.", true);
            return;
        }

        showPromptMessage("", false);

        scanPromptButton.disabled = true;
        scanPromptButton.textContent = "Scanning...";

        try {

            const response = await fetch(
                "http://127.0.0.1:5001/api/prompt-guard/scan",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        text: text
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
                throw new Error(
                    data.error || "Prompt Guard scan failed"
                );
            }

            promptResult.classList.remove("hidden");

            // Risk score
            riskScore.textContent =
                data.risk_score + "/100";

            // Detection status
            detectionStatus.textContent =
                data.suspicious
                    ? "Suspicious"
                    : "Safe";

            // Recommendation
            recommendation.textContent =
                data.recommendation || "No recommendation";

            recommendationBadge.textContent =
                data.recommendation || "REVIEW";


            // Result title
            if (data.risk_score >= 70) {

                resultTitle.textContent =
                    "High-Risk Prompt Injection";

            } else if (data.risk_score >= 30) {

                resultTitle.textContent =
                    "Potential Prompt Injection";

            } else {

                resultTitle.textContent =
                    "No Major Injection Detected";
            }

            const evidenceText = Array.isArray(data.evidence) &&
                data.evidence.length > 0
                ? data.evidence.join("; ")
                : "No matched evidence was returned.";

            resultDescription.textContent = [
                "Risk Level: " + (data.risk_level || "Not returned"),
                "Finding: " + (data.finding || "Not returned"),
                "Evidence: " + evidenceText,
                "Explanation: " + (
                    data.explanation ||
                    data.ai_analysis ||
                    "No explanation was returned."
                ),
                "Recommendation: " + (
                    data.recommendation ||
                    "No recommendation was returned."
                )
            ].join("\n");


            // Clean pattern matches
            patternMatches.innerHTML = "";

            if (
                data.pattern_matches &&
                data.pattern_matches.length > 0
            ) {

                data.pattern_matches.forEach(
                    function (pattern) {

                        const card =
                            document.createElement("div");

                        card.className =
                            "rag-source-card";


                        const category =
                            document.createElement("div");

                        category.className =
                            "rag-source-title";

                        category.textContent =
                            "Category: " +
                            (pattern.category || "Unknown");


                        const severity =
                            document.createElement("div");

                        severity.className =
                            "rag-source-text";

                        severity.textContent =
                            "Severity: " +
                            (pattern.severity || "Unknown");


                        const matchedText =
                            document.createElement("div");

                        matchedText.className =
                            "rag-source-text";

                        matchedText.textContent =
                            "Matched Text: " +
                            (pattern.matched_text || "N/A");


                        const description =
                            document.createElement("div");

                        description.className =
                            "rag-source-text";

                        description.textContent =
                            "Description: " +
                            (pattern.description || "N/A");


                        card.appendChild(category);
                        card.appendChild(severity);
                        card.appendChild(matchedText);
                        card.appendChild(description);

                        patternMatches.appendChild(card);
                    }
                );

            } else {

                patternMatches.textContent =
                    "No suspicious patterns detected.";
            }


            // AI analysis
            aiAnalysis.textContent =
                data.ai_analysis ||
                "AI analysis is unavailable.";

        }
        catch (error) {

            console.error(
                "Prompt Guard error:",
                error
            );

            let message = error.message || "The scan could not be completed.";

            if (error.name === "TimeoutError" || error.name === "AbortError") {
                message = "The Prompt Guard request timed out.";
            } else if (error instanceof TypeError) {
                message = "Unable to reach the Prompt Guard API on port 5001.";
            }

            showPromptMessage(message, true);

        }
        finally {

            scanPromptButton.disabled = false;

            scanPromptButton.textContent =
                "Scan with Prompt Guard";
        }

    }
);