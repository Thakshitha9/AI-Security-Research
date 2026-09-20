"""Deep neural network IDS classifier."""

import torch
import torch.nn as nn
import numpy as np
from torch.utils.data import DataLoader, TensorDataset


class IDSNet(nn.Module):
    """Multi-layer perceptron for intrusion detection."""

    def __init__(self, input_dim: int, num_classes: int = 2):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class IDSTrainer:
    """Handles training and evaluation of the IDS model."""

    def __init__(
        self,
        input_dim: int,
        num_classes: int = 2,
        lr: float = 1e-3,
        device: str = None,
    ):
        self.device = torch.device(
            device or ("cuda" if torch.cuda.is_available() else "cpu")
        )
        self.model = IDSNet(input_dim, num_classes).to(self.device)
        self.criterion = nn.CrossEntropyLoss()
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        self.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer, patience=3, factor=0.5
        )

    def _make_loader(self, X: np.ndarray, y: np.ndarray, batch_size: int, shuffle: bool):
        dataset = TensorDataset(
            torch.tensor(X, dtype=torch.float32),
            torch.tensor(y, dtype=torch.long),
        )
        return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle)

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        epochs: int = 30,
        batch_size: int = 256,
    ) -> dict:
        train_loader = self._make_loader(X_train, y_train, batch_size, shuffle=True)
        val_loader = self._make_loader(X_val, y_val, batch_size, shuffle=False)

        history = {"train_loss": [], "val_loss": [], "val_acc": []}
        best_val_acc = 0.0

        for epoch in range(1, epochs + 1):
            self.model.train()
            total_loss = 0.0
            for X_batch, y_batch in train_loader:
                X_batch, y_batch = X_batch.to(self.device), y_batch.to(self.device)
                self.optimizer.zero_grad()
                logits = self.model(X_batch)
                loss = self.criterion(logits, y_batch)
                loss.backward()
                self.optimizer.step()
                total_loss += loss.item() * X_batch.size(0)

            avg_train_loss = total_loss / len(train_loader.dataset)
            val_loss, val_acc = self.evaluate(val_loader)
            self.scheduler.step(val_loss)

            history["train_loss"].append(avg_train_loss)
            history["val_loss"].append(val_loss)
            history["val_acc"].append(val_acc)

            if val_acc > best_val_acc:
                best_val_acc = val_acc
                self.best_state = self.model.state_dict().copy()

            if epoch % 5 == 0 or epoch == 1:
                print(
                    f"  Epoch {epoch:3d}/{epochs} | "
                    f"Train Loss: {avg_train_loss:.4f} | "
                    f"Val Loss: {val_loss:.4f} | "
                    f"Val Acc: {val_acc:.4f}"
                )

        self.model.load_state_dict(self.best_state)
        print(f"  Best validation accuracy: {best_val_acc:.4f}")
        return history

    def evaluate(self, loader: DataLoader = None, X: np.ndarray = None, y: np.ndarray = None):
        if loader is None:
            loader = self._make_loader(X, y, batch_size=512, shuffle=False)

        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0

        with torch.no_grad():
            for X_batch, y_batch in loader:
                X_batch, y_batch = X_batch.to(self.device), y_batch.to(self.device)
                logits = self.model(X_batch)
                loss = self.criterion(logits, y_batch)
                total_loss += loss.item() * X_batch.size(0)
                preds = logits.argmax(dim=1)
                correct += (preds == y_batch).sum().item()
                total += y_batch.size(0)

        return total_loss / total, correct / total

    def predict(self, X: np.ndarray) -> np.ndarray:
        self.model.eval()
        tensor = torch.tensor(X, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            logits = self.model(tensor)
        return logits.argmax(dim=1).cpu().numpy()

    def save(self, path: str):
        torch.save(self.model.state_dict(), path)

    def load(self, path: str):
        self.model.load_state_dict(torch.load(path, map_location=self.device, weights_only=True))
