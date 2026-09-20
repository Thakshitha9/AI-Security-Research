"""Evaluation metrics and visualization for adversarial IDS experiments."""

import os
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, label: str = "") -> dict:
    acc = accuracy_score(y_true, y_pred)
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    if label:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")
    print(f"  Accuracy: {acc:.4f}")
    print(classification_report(y_true, y_pred, zero_division=0))
    return {"accuracy": acc, "report": report}


def plot_confusion_matrices(
    y_true: np.ndarray,
    predictions: dict[str, np.ndarray],
    output_dir: str,
    class_names: list[str] = None,
):
    if class_names is None:
        class_names = ["Normal", "Attack"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    n = len(predictions)
    fig, axes = plt.subplots(1, n, figsize=(6 * n, 5))
    if n == 1:
        axes = [axes]

    for ax, (name, y_pred) in zip(axes, predictions.items()):
        cm = confusion_matrix(y_true, y_pred)
        disp = ConfusionMatrixDisplay(cm, display_labels=class_names)
        disp.plot(ax=ax, cmap="Blues", colorbar=False)
        acc = accuracy_score(y_true, y_pred)
        ax.set_title(f"{name}\nAcc: {acc:.4f}")

    plt.tight_layout()
    path = output_path / "confusion_matrices.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved confusion matrices to {path}")


def plot_accuracy_comparison(
    accuracies: dict[str, float],
    output_dir: str,
):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    names = list(accuracies.keys())
    values = list(accuracies.values())
    colors = ["#2ecc71"] + ["#e74c3c"] * (len(names) - 1)

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(names, values, color=colors, edgecolor="black", linewidth=0.8)

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.01,
            f"{val:.2%}",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=11,
        )

    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Accuracy", fontsize=12)
    ax.set_title("IDS Accuracy: Clean vs. Adversarial Inputs", fontsize=14, fontweight="bold")
    ax.axhline(y=values[0], color="#2ecc71", linestyle="--", alpha=0.4)
    ax.grid(axis="y", alpha=0.3)

    path = output_path / "accuracy_comparison.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved accuracy comparison to {path}")


def plot_training_history(history: dict, output_dir: str):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    epochs = range(1, len(history["train_loss"]) + 1)
    ax1.plot(epochs, history["train_loss"], label="Train Loss", color="#3498db")
    ax1.plot(epochs, history["val_loss"], label="Val Loss", color="#e74c3c")
    ax1.set_xlabel("Epoch")
    ax1.set_ylabel("Loss")
    ax1.set_title("Training & Validation Loss")
    ax1.legend()
    ax1.grid(alpha=0.3)

    ax2.plot(epochs, history["val_acc"], label="Val Accuracy", color="#2ecc71")
    ax2.set_xlabel("Epoch")
    ax2.set_ylabel("Accuracy")
    ax2.set_title("Validation Accuracy")
    ax2.legend()
    ax2.grid(alpha=0.3)

    plt.tight_layout()
    path = output_path / "training_history.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved training history to {path}")


def plot_perturbation_analysis(
    X_clean: np.ndarray,
    adversarial_samples: dict[str, np.ndarray],
    output_dir: str,
):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(1, len(adversarial_samples), figsize=(6 * len(adversarial_samples), 5))
    if len(adversarial_samples) == 1:
        axes = [axes]

    for ax, (name, X_adv) in zip(axes, adversarial_samples.items()):
        perturbations = np.abs(X_adv - X_clean)
        mean_pert = perturbations.mean(axis=0)

        top_k = 20
        top_indices = np.argsort(mean_pert)[-top_k:]
        ax.barh(range(top_k), mean_pert[top_indices], color="#e74c3c", alpha=0.8)
        ax.set_yticks(range(top_k))
        ax.set_yticklabels([f"Feature {i}" for i in top_indices], fontsize=8)
        ax.set_xlabel("Mean Perturbation")
        ax.set_title(f"{name.upper()} — Top {top_k} Perturbed Features")

    plt.tight_layout()
    path = output_path / "perturbation_analysis.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved perturbation analysis to {path}")
