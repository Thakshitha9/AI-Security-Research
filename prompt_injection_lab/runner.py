from pathlib import Path

from core.llm_client import LLMClient
from core.utils import load_json
from .evaluator import EvalResult, evaluate_response, evaluate_with_llm_judge

TEST_CASES_DIR = Path(__file__).parent / "test_cases"


def load_test_cases(category: str | None = None) -> list[dict]:
    cases = []
    if category:
        path = TEST_CASES_DIR / f"{category}.json"
        if not path.exists():
            raise FileNotFoundError(f"Category not found: {category}")
        cases = load_json(path)
    else:
        for path in sorted(TEST_CASES_DIR.glob("*.json")):
            cases.extend(load_json(path))
    return cases


def list_categories() -> list[str]:
    return [p.stem for p in sorted(TEST_CASES_DIR.glob("*.json"))]


def run_single_test(
    client: LLMClient, test_case: dict, use_judge: bool = False
) -> EvalResult:
    if "turns" in test_case:
        return _run_multi_turn(client, test_case, use_judge)

    response = client.generate(
        test_case["prompt"],
        system_prompt=test_case.get("system_prompt"),
        temperature=0.3,
    )

    if use_judge:
        return evaluate_with_llm_judge(test_case, response, client)
    return evaluate_response(test_case, response)


def _run_multi_turn(
    client: LLMClient, test_case: dict, use_judge: bool
) -> EvalResult:
    """Run multi-turn attack: send each turn and evaluate the final response."""
    turns = test_case["turns"]
    responses = []

    for turn in turns:
        # Build context from previous turns
        context = ""
        for i, prev_resp in enumerate(responses):
            context += f"User: {turns[i]['content']}\nAssistant: {prev_resp}\n\n"
        context += f"User: {turn['content']}"

        response = client.generate(
            context,
            system_prompt=test_case.get("system_prompt"),
            temperature=0.3,
        )
        responses.append(response)

    # Evaluate based on the final response
    final_response = responses[-1]
    flat_case = {
        **test_case,
        "prompt": " | ".join(t["content"] for t in turns),
    }

    if use_judge:
        return evaluate_with_llm_judge(flat_case, final_response, client)
    return evaluate_response(flat_case, final_response)


def run_all(
    client: LLMClient,
    category: str | None = None,
    use_judge: bool = False,
    on_result=None,
) -> list[EvalResult]:
    cases = load_test_cases(category)
    results = []
    for case in cases:
        result = run_single_test(client, case, use_judge)
        results.append(result)
        if on_result:
            on_result(result)
    return results
