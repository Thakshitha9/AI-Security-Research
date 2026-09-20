const askRagButton = document.getElementById("askRagButton");
const ragQuestion = document.getElementById("ragQuestion");

const ragResult = document.getElementById("ragResult");
const ragAnswer = document.getElementById("ragAnswer");
const ragSources = document.getElementById("ragSources");


askRagButton.addEventListener("click", async function () {

    const question = ragQuestion.value.trim();

    if (!question) {
        alert("Please enter a security question.");
        return;
    }


    // ------------------------------------------
    // Loading state
    // ------------------------------------------

    askRagButton.disabled = true;
    askRagButton.textContent = "Analyzing...";


    try {

        const response = await fetch(
            "http://127.0.0.1:5000/api/rag/ask",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    question: question
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "RAG request failed"
            );

        }


        // ------------------------------------------
        // Show result container
        // ------------------------------------------

        ragResult.classList.remove("hidden");


        // ------------------------------------------
        // Display AI answer
        // ------------------------------------------

        ragAnswer.textContent =
            data.answer || "No answer was generated.";


        // ------------------------------------------
        // Display retrieved documents
        // ------------------------------------------

        ragSources.innerHTML = "";


        if (
            data.retrieved_documents &&
            data.retrieved_documents.length > 0
        ) {

            data.retrieved_documents.forEach(
                function (doc, index) {

                    const sourceCard =
                        document.createElement("div");

                    sourceCard.className =
                        "rag-source-card";


                    const sourceTitle =
                        document.createElement("div");

                    sourceTitle.className =
                        "rag-source-title";

                    sourceTitle.textContent =
                        "Source " +
                        (index + 1) +
                        ": " +
                        (doc.source || "Unknown");


                    const sourceText =
                        document.createElement("div");

                    sourceText.className =
                        "rag-source-text";

                    sourceText.textContent =
                        doc.text || "No document content available.";


                    sourceCard.appendChild(
                        sourceTitle
                    );

                    sourceCard.appendChild(
                        sourceText
                    );


                    ragSources.appendChild(
                        sourceCard
                    );

                }
            );

        } else {

            ragSources.textContent =
                "No relevant documents were retrieved.";

        }


    } catch (error) {

        console.error(
            "RAG analysis error:",
            error
        );


        alert(
            "Unable to get the AI response. " +
            "Please make sure the Flask API is running."
        );


    } finally {

        askRagButton.disabled = false;

        askRagButton.textContent =
            "Ask Security AI";

    }

});