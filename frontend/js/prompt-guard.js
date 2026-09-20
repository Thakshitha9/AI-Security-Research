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


scanPromptButton.addEventListener(
    "click",
    async function () {

        const text = promptText.value.trim();

        if (!text) {
            alert("Please enter text to analyze.");
            return;
        }

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
                    })
                }
            );

            const data = await response.json();

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

                resultDescription.textContent =
                    "Strong indicators of a malicious prompt injection attempt were detected.";

            } else if (data.risk_score >= 30) {

                resultTitle.textContent =
                    "Potential Prompt Injection";

                resultDescription.textContent =
                    "Suspicious instruction patterns were detected.";

            } else {

                resultTitle.textContent =
                    "No Major Injection Detected";

                resultDescription.textContent =
                    "The submitted text contains no significant prompt injection indicators.";
            }


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

            alert(
                "Unable to analyze the text. " +
                "Please make sure the Prompt Guard API is running."
            );

        }
        finally {

            scanPromptButton.disabled = false;

            scanPromptButton.textContent =
                "Scan with Prompt Guard";
        }

    }
);