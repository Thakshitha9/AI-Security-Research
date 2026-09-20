"""Adversarial attack implementations against the IDS model."""

import numpy as np
import torch
import torch.nn as nn


class AdversarialAttacker:
    """Generates adversarial examples using FGSM, PGD, and C&W attacks."""

    def __init__(self, model: nn.Module, device: torch.device = None):
        self.model = model
        self.device = device or next(model.parameters()).device
        self.model.eval()

    def _to_tensor(self, X: np.ndarray) -> torch.Tensor:
        return torch.tensor(X, dtype=torch.float32, device=self.device)

    def fgsm(self, X: np.ndarray, y: np.ndarray, epsilon: float = 0.1) -> np.ndarray:
        """Fast Gradient Sign Method (Goodfellow et al., 2014)."""
        X_t = self._to_tensor(X).requires_grad_(True)
        y_t = torch.tensor(y, dtype=torch.long, device=self.device)

        logits = self.model(X_t)
        loss = nn.CrossEntropyLoss()(logits, y_t)
        loss.backward()

        perturbation = epsilon * X_t.grad.sign()
        X_adv = (X_t + perturbation).clamp(0, 1)
        return X_adv.detach().cpu().numpy()

    def pgd(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epsilon: float = 0.1,
        alpha: float = 0.01,
        num_steps: int = 40,
    ) -> np.ndarray:
        """Projected Gradient Descent (Madry et al., 2017)."""
        X_t = self._to_tensor(X)
        y_t = torch.tensor(y, dtype=torch.long, device=self.device)
        X_adv = X_t.clone().detach().requires_grad_(True)

        for _ in range(num_steps):
            logits = self.model(X_adv)
            loss = nn.CrossEntropyLoss()(logits, y_t)
            loss.backward()

            with torch.no_grad():
                X_adv = X_adv + alpha * X_adv.grad.sign()
                delta = torch.clamp(X_adv - X_t, -epsilon, epsilon)
                X_adv = torch.clamp(X_t + delta, 0, 1).requires_grad_(True)

        return X_adv.detach().cpu().numpy()

    def cw(
        self,
        X: np.ndarray,
        y: np.ndarray,
        c: float = 1.0,
        kappa: float = 0.0,
        num_steps: int = 100,
        lr: float = 0.01,
    ) -> np.ndarray:
        """Carlini & Wagner L2 attack (Carlini & Wagner, 2017)."""
        X_t = self._to_tensor(X)
        y_t = torch.tensor(y, dtype=torch.long, device=self.device)
        num_classes = self.model(X_t[:1]).shape[1]

        w = torch.zeros_like(X_t, requires_grad=True, device=self.device)
        optimizer = torch.optim.Adam([w], lr=lr)

        best_adv = X_t.clone()
        best_l2 = torch.full((X_t.shape[0],), float("inf"), device=self.device)

        for _ in range(num_steps):
            X_adv = torch.clamp(X_t + w, 0, 1)
            logits = self.model(X_adv)

            one_hot = torch.zeros(y_t.size(0), num_classes, device=self.device)
            one_hot.scatter_(1, y_t.unsqueeze(1), 1)

            real = (one_hot * logits).sum(dim=1)
            other = ((1 - one_hot) * logits - one_hot * 1e4).max(dim=1).values

            f_loss = torch.clamp(real - other + kappa, min=0)
            l2_dist = torch.sum((X_adv - X_t) ** 2, dim=1)
            loss = l2_dist.sum() + c * f_loss.sum()

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            with torch.no_grad():
                improved = (l2_dist < best_l2) & (f_loss <= 0)
                best_l2[improved] = l2_dist[improved]
                best_adv[improved] = X_adv[improved]

        return best_adv.detach().cpu().numpy()

    def run_all(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epsilon: float = 0.1,
        batch_size: int = 1024,
    ) -> dict[str, np.ndarray]:
        """Run all attacks and return adversarial examples."""
        results = {}

        for name, attack_fn, kwargs in [
            ("fgsm", self.fgsm, {"epsilon": epsilon}),
            ("pgd", self.pgd, {"epsilon": epsilon}),
            ("cw", self.cw, {"c": 1.0}),
        ]:
            print(f"  Running {name.upper()} attack...")
            adv_batches = []
            for i in range(0, len(X), batch_size):
                X_batch = X[i : i + batch_size]
                y_batch = y[i : i + batch_size]
                adv_batches.append(attack_fn(X_batch, y_batch, **kwargs))
            results[name] = np.concatenate(adv_batches, axis=0)

        return results
