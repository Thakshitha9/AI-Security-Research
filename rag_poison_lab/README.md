# RAG Poisoning Lab

**Offensive AI Security Tool** — Tests Retrieval-Augmented Generation (RAG) systems against knowledge-base poisoning attacks. Demonstrates how malicious documents injected into a vector store can manipulate LLM responses, even when the underlying model is well-aligned.

---

## What is RAG Poisoning?

RAG systems combine LLMs with a vector database of trusted documents. When a user asks a question, the system retrieves relevant docs and feeds them to the LLM as context. **If an attacker can inject a single malicious document into that knowledge base, they can manipulate the LLM's output without ever touching the model itself.**

This module builds a real RAG pipeline (ChromaDB + LLM), injects 5 categories of malicious payloads, and measures how often the attack succeeds.

---

## Attack Techniques

| Technique | Description | Severity |
|---|---|---|
| `direct_override` | Documents containing explicit instructions to override LLM behavior | Critical |
| `indirect_injection` | Hidden instructions disguised as legitimate policy/compliance updates | High |
| `context_hijacking` | Floods retrieved context with repeated false statements | High |
| `role_reassignment` | Attempts to redefine the AI's identity (e.g., "SysBot mode") | Critical |
| `trigger_based` | Conditional payloads activated only by specific keywords | High |

Each technique is paired with realistic probe questions and success indicators (keywords that prove the LLM swallowed the poison).

---

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│ Legitimate Docs │────▶│   ChromaDB       │◀────│   LLM Query  │
│  (15 documents) │     │  Vector Store    │     │              │
└─────────────────┘     └──────────────────┘     └──────────────┘
                                ▲                          │
┌─────────────────┐             │                          ▼
│ Poison Payloads │─── inject ──┘                   ┌──────────────┐
│  (10 malicious) │                                 │  Evaluator   │
└─────────────────┘                                 │  (success?)  │
                                                    └──────────────┘
```

1. Load a clean knowledge base of company policies into ChromaDB
2. Inject malicious documents with the chosen attack technique
3. Run probe questions through the RAG pipeline
4. Evaluate whether the LLM produced manipulated responses (keyword matching + optional LLM-as-judge)

---

## Usage

### Run a single attack technique
```bash
rag-poison attack --technique direct_override --verbose
```

### Run all techniques against the knowledge base
```bash
rag-poison attack --all --output
```

### Benchmark all techniques side-by-side
```bash
rag-poison benchmark
```

### Use LLM-as-judge for borderline cases
```bash
rag-poison attack --all --judge
```

### Query a clean RAG for baseline comparison
```bash
rag-poison ask "What are the password policy requirements?"
```

### List all available techniques
```bash
rag-poison list-techniques
```

---

## Example Output

![RAG Poisoning results — all probes flagged POISONED](../docs/screenshots/rag_poison_results.png)

*Sample run showing `direct_override` and `indirect_injection` techniques successfully manipulating the LLM into returning attacker-injected credentials and policy "updates".*

---

## Output

For each probe question:
- Whether the poisoned document was retrieved
- Which malicious indicators appeared in the LLM response
- Verdict: **POISONED** or **SAFE**

Per-technique breakdown:
- Success rate (%)
- Severity classification (CRITICAL / HIGH / MEDIUM / LOW)

Overall RAG resilience score with status: **CRITICAL**, **VULNERABLE**, or **RESILIENT**.

JSON reports saved to `reports/rag_poison_<timestamp>.json`.

---

## Datasets

- **`datasets/knowledge_base.json`** — 15 realistic company documents (HR policies, IT security, API docs, deployment processes)
- **`datasets/poison_payloads.json`** — 10 malicious payloads across 5 techniques, each with probe questions and success indicators

Both datasets are easily extensible — drop in your own JSON to test custom scenarios.

---

## Tech Stack

- **ChromaDB** — Persistent vector store with cosine similarity
- **Default embedding function** — sentence-transformers `all-MiniLM-L6-v2` (auto-downloaded on first run)
- **Core LLM client** — Reuses unified Ollama/Groq/HuggingFace abstraction

---

## Why This Matters

RAG poisoning is a **realistic, in-the-wild attack vector** for any organization deploying internal LLM assistants connected to wikis, SharePoint, Confluence, or Notion. An attacker with write access to even one document in the corpus can:

- Inject fake credentials that the LLM will repeat to other employees
- Override security policies with attacker-controlled "updates"
- Create conditional backdoors triggered by specific keywords
- Bypass model-level safety alignment entirely

This lab exists to **measure** how well RAG defenses hold up against these attacks — and to demonstrate that LLM-level safety training is not enough when the data layer is compromised.
