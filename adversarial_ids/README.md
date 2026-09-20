# Adversarial Attacks on AI-Based Intrusion Detection Systems

Demonstrates how adversarial machine learning techniques can evade a neural network-based IDS trained on the NSL-KDD dataset. The project trains a deep learning classifier to detect network intrusions, then crafts adversarial inputs using three attack methods to evaluate the model's robustness.

## Attack Methods

| Attack | Paper | Description |
|--------|-------|-------------|
| **FGSM** | Goodfellow et al., 2014 | Single-step gradient sign perturbation — fast but less effective |
| **PGD** | Madry et al., 2017 | Iterative projected gradient descent — stronger white-box attack |
| **C&W** | Carlini & Wagner, 2017 | Optimization-based L2 attack — finds minimal perturbations |

## Project Structure

```
adversarial_ids/
├── main.py                  # Full pipeline: train → attack → evaluate
├── data/
│   └── loader.py            # NSL-KDD download & preprocessing
├── models/
│   └── ids_model.py         # PyTorch MLP classifier + trainer
├── attacks/
│   └── adversarial.py       # FGSM, PGD, C&W implementations
├── utils/
│   └── evaluation.py        # Metrics, confusion matrices, charts
├── results/                 # Generated plots and saved model
└── requirements.txt
```

## Setup

```bash
cd adversarial_ids
pip install -r requirements.txt
```

## Usage

```bash
# Run full pipeline (default: binary classification, ε=0.1)
python main.py

# Custom parameters
python main.py --epochs 50 --epsilon 0.2 --attack-samples 10000

# Multi-class classification (normal / dos / probe / r2l / u2r)
python main.py --no-binary
```

## Output

The pipeline generates:
- `results/training_history.png` — loss and accuracy curves during training
- `results/accuracy_comparison.png` — bar chart of clean vs. adversarial accuracy
- `results/confusion_matrices.png` — side-by-side confusion matrices
- `results/perturbation_analysis.png` — most perturbed features per attack
- `results/ids_model.pt` — saved model weights

## Dataset

**NSL-KDD** — improved version of the KDD Cup 1999 dataset for network intrusion detection. Contains 125,973 training records and 22,544 test records across 41 features (network connection attributes). Auto-downloaded on first run.

## Key Findings

After training, the IDS typically achieves **~95-98% accuracy** on clean test data. Under adversarial attack:
- **FGSM** (ε=0.1): accuracy drops by ~20-40%
- **PGD** (ε=0.1, 40 steps): accuracy drops by ~40-60%
- **C&W** (L2): accuracy drops by ~50-70%

This demonstrates that ML-based security systems can be significantly degraded by adversarial perturbations that remain within a small ε-ball of the original input.

## References

- Goodfellow, I. J., Shlens, J., & Szegedy, C. (2014). *Explaining and Harnessing Adversarial Examples.* arXiv:1412.6572
- Madry, A., Makelov, A., Schmidt, L., Tsipras, D., & Vladu, A. (2017). *Towards Deep Learning Models Resistant to Adversarial Attacks.* arXiv:1706.06083
- Carlini, N. & Wagner, D. (2017). *Towards Evaluating the Robustness of Neural Networks.* IEEE S&P
- Tavallaee, M. et al. (2009). *A Detailed Analysis of the KDD CUP 99 Data Set.* IEEE CISDA
