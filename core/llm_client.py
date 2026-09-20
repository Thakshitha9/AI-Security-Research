import json
import httpx

from .config import LLMProvider, get_provider_config, ProviderConfig


class LLMClient:
    def __init__(self, provider: LLMProvider | None = None):
        if provider:
            self.provider = provider
            self.config = get_provider_config(provider)
        else:
            self.provider, self.config = self._auto_detect()

        self._client = httpx.Client(timeout=120.0)

    def _auto_detect(self) -> tuple[LLMProvider, ProviderConfig]:
        # Try Ollama first (no API key needed)
        ollama_cfg = get_provider_config(LLMProvider.OLLAMA)

        try:
            r = httpx.get(
                f"{ollama_cfg.base_url}/api/tags",
                timeout=3.0
            )

            if r.status_code == 200:
                return LLMProvider.OLLAMA, ollama_cfg

        except httpx.ConnectError:
            pass

        # Try Groq
        groq_cfg = get_provider_config(LLMProvider.GROQ)

        if groq_cfg.api_key:
            return LLMProvider.GROQ, groq_cfg

        # Try Hugging Face
        hf_cfg = get_provider_config(LLMProvider.HUGGINGFACE)

        if hf_cfg.api_key:
            return LLMProvider.HUGGINGFACE, hf_cfg

        # Try Gemini
        gemini_cfg = get_provider_config(LLMProvider.GEMINI)

        if gemini_cfg.api_key:
            return LLMProvider.GEMINI, gemini_cfg

        raise RuntimeError(
            "No LLM provider available. Either:\n"
            "  1. Start Ollama locally (ollama serve)\n"
            "  2. Set GROQ_API_KEY in .env\n"
            "  3. Set HF_API_TOKEN in .env\n"
            "  4. Set GEMINI_API_KEY in .env"
        )

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
    ) -> str:

        if self.provider == LLMProvider.OLLAMA:
            return self._ollama_generate(
                prompt,
                system_prompt,
                temperature
            )

        elif self.provider == LLMProvider.GROQ:
            return self._openai_compatible_generate(
                prompt,
                system_prompt,
                temperature
            )

        elif self.provider == LLMProvider.HUGGINGFACE:
            return self._huggingface_generate(
                prompt,
                system_prompt,
                temperature
            )

        elif self.provider == LLMProvider.GEMINI:
            return self._gemini_generate(
                prompt,
                system_prompt,
                temperature
            )

        raise ValueError(f"Unknown provider: {self.provider}")

    def _ollama_generate(
        self,
        prompt: str,
        system_prompt: str | None,
        temperature: float
    ) -> str:

        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature
            },
        }

        if system_prompt:
            payload["system"] = system_prompt

        r = self._client.post(
            f"{self.config.base_url}/api/generate",
            json=payload
        )

        r.raise_for_status()

        return r.json()["response"]

    def _openai_compatible_generate(
        self,
        prompt: str,
        system_prompt: str | None,
        temperature: float
    ) -> str:

        messages = []

        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })

        messages.append({
            "role": "user",
            "content": prompt
        })

        r = self._client.post(
            f"{self.config.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": self.config.model,
                "messages": messages,
                "temperature": temperature,
            },
        )

        r.raise_for_status()

        return r.json()["choices"][0]["message"]["content"]

    def _huggingface_generate(
        self,
        prompt: str,
        system_prompt: str | None,
        temperature: float
    ) -> str:

        messages = []

        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt,
            })

        messages.append({
            "role": "user",
            "content": prompt,
        })

        r = self._client.post(
            "https://router.huggingface.co/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.config.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": 1024,
            },
        )

        if r.status_code != 200:
            print("HF ERROR:", r.text)

        r.raise_for_status()

        data = r.json()

        return data["choices"][0]["message"]["content"]

    def _gemini_generate(
        self,
        prompt: str,
        system_prompt: str | None,
        temperature: float
    ) -> str:

        contents = []

        if system_prompt:
            contents.append({
                "role": "user",
                "parts": [
                    {
                        "text": (
                            "System instructions:\n"
                            + system_prompt
                        )
                    }
                ],
            })

        contents.append({
            "role": "user",
            "parts": [
                {
                    "text": prompt
                }
            ],
        })

        r = self._client.post(
            f"{self.config.base_url}/models/"
            f"{self.config.model}:generateContent",
            params={
                "key": self.config.api_key
            },
            headers={
                "Content-Type": "application/json"
            },
            json={
                "contents": contents,
                "generationConfig": {
                    "temperature": temperature,
                    "maxOutputTokens": 8192
                }
            },
        )

        if r.status_code != 200:
            print("GEMINI ERROR:", r.text)

        r.raise_for_status()

        data = r.json()

        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]

        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                "Unexpected Gemini response: "
                + json.dumps(data)
            ) from exc

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()