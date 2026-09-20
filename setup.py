from setuptools import setup, find_packages

setup(
    name="ai-security-research",
    version="1.0.0",
    description="AI Security Research Lab — Offensive & defensive AI security tools",
    author="Bighiu Rares",
    author_email="bighiurares05@gmail.com",
    url="https://github.com/Raresney/AI-Security-Research",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.1",
        "httpx>=0.27",
        "rich>=13.0",
        "python-dotenv>=1.0",
        "chromadb>=0.5",
    ],
    entry_points={
        "console_scripts": [
            "injection-lab=prompt_injection_lab.cli:main",
            "recon-ai=recon_ai.cli:main",
            "phish-detect=phishing_detector.cli:main",
            "prompt-guard=prompt_guard.cli:main",
            "rag-poison=rag_poison_lab.cli:main",
            "honeypot=llm_honeypot.cli:main",
        ],
    },
)
