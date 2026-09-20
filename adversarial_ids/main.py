"""
Adversarial Attacks on AI-Based Intrusion Detection Systems
============================================================
Main pipeline: load data → train IDS → attack → evaluate → visualize.
"""

import argparse
import os
import sys
from pathlib import Path

import numpy as np

from data.loader import NSLKDDLoader
from models.ids_model import IDSTrainer
from attacks.adversarial import AdversarialAttacker
from utils.evaluation import (
    compute_metrics,
    plot_accuracy_comparison,
    plot_confusion_matrices,
    plot_perturbation_analysis,
    plot_training_history,
)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Adversarial attacks on AI-based IDS"
    )
    parser.add_argument("--epochs", type=int, default=30, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--epsilon", type=float, default=0.1, help="Perturbation budget")
    parser.add_argument("--binary", action="store_true", default=True, help="Binary classification")
    parser.add_argument("--no-binary", dest="binary", action="store_false")
    parser.add_argument("--attack-samples", type=int, default=5000, help="Number of samples to attack")
    return parser.parse_args()


def main():
    args = parse_args()
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # ── 1. Load & preprocess NSL-KDD ──
    print("\n[1/4] Loading NSL-KDD dataset...")
    loader = NSLKDDLoader(binary=args.binary)
    data = loader.load()
    print(f"  Train: {data['X_train'].shape}  Val: {data['X_val'].shape}  Test: {data['X_test'].shape}")

    # ── 2. Train IDS model ──
    print("\n[2/4] Training IDS model...")
    input_dim = data["X_train"].shape[1]
    num_classes = len(np.unique(data["y_train"]))
    trainer = IDSTrainer(input_dim=input_dim, num_classes=num_classes, lr=args.lr)
    history = trainer.train(
        data["X_train"], data["y_train"],
        data["X_val"], data["y_val"],
        epochs=args.epochs, batch_size=args.batch_size,
    )
    plot_training_history(history, RESULTS_DIR)

    # Baseline evaluation
    y_pred_clean = trainer.predict(data["X_test"])
    clean_metrics = compute_metrics(data["y_test"], y_pred_clean, label="Clean Test Data")
    clean_acc = clean_metrics["accuracy"]

    model_path = os.path.join(RESULTS_DIR, "ids_model.pt")
    trainer.save(model_path)
    print(f"  Model saved to {model_path}")

    # ── 3. Adversarial attacks ──
    print("\n[3/4] Generating adversarial examples...")
    n = min(args.attack_samples, len(data["X_test"]))
    X_subset = data["X_test"][:n]
    y_subset = data["y_test"][:n]

    attacker = AdversarialAttacker(trainer.model, trainer.device)
    adversarial_samples = attacker.run_all(X_subset, y_subset, epsilon=args.epsilon)

    # ── 4. Evaluate attacks ──
    print("\n[4/4] Evaluating adversarial robustness...")
    accuracies = {"Clean": clean_acc}
    predictions = {"Clean": trainer.predict(X_subset)}

    for attack_name, X_adv in adversarial_samples.items():
        y_pred_adv = trainer.predict(X_adv)
        metrics = compute_metrics(y_subset, y_pred_adv, label=f"{attack_name.upper()} Attack")
        accuracies[attack_name.upper()] = metrics["accuracy"]
        predictions[attack_name.upper()] = y_pred_adv

    # ── Visualizations ──
    print("\nGenerating visualizations...")
    plot_accuracy_comparison(accuracies, RESULTS_DIR)
    plot_confusion_matrices(y_subset, predictions, RESULTS_DIR)
    plot_perturbation_analysis(X_subset, adversarial_samples, RESULTS_DIR)

    # ── Summary ──
    print(f"\n{'='*60}")
    print("  RESULTS SUMMARY")
    print(f"{'='*60}")
    for name, acc in accuracies.items():
        drop = ((clean_acc - acc) / clean_acc * 100) if name != "Clean" else 0
        indicator = f"  (drop {drop:.1f}%)" if drop > 0 else ""
        print(f"  {name:>8}: {acc:.4f}{indicator}")
    print(f"\n  Results saved to: {RESULTS_DIR}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
