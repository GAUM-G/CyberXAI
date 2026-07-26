"""PyTorch LSTM classifier for Step 11 sequence-based attack detection."""

from __future__ import annotations

import torch
from torch import Tensor, nn


class LSTMClassifier(nn.Module):
    """Classify a fixed-length sequence using its final LSTM output."""

    def __init__(
        self,
        input_size: int,
        num_classes: int,
        *,
        hidden_size: int = 64,
        num_layers: int = 1,
        dropout: float = 0.30,
    ) -> None:
        super().__init__()

        if input_size <= 0:
            raise ValueError("input_size must be greater than zero")
        if num_classes < 2:
            raise ValueError("num_classes must be at least two")
        if hidden_size <= 0:
            raise ValueError("hidden_size must be greater than zero")
        if num_layers <= 0:
            raise ValueError("num_layers must be greater than zero")
        if not 0.0 <= dropout < 1.0:
            raise ValueError("dropout must be between 0 and 1")

        self.input_size = input_size
        self.num_classes = num_classes
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.dropout_rate = dropout

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(hidden_size, num_classes)

    def forward(self, inputs: Tensor) -> Tensor:
        """Return unnormalized class scores with shape (batch, classes)."""

        if inputs.ndim != 3:
            raise ValueError(
                "LSTM input must have shape "
                "(batch, time_steps, features)"
            )

        if inputs.shape[2] != self.input_size:
            raise ValueError(
                f"Expected {self.input_size} features, "
                f"received {inputs.shape[2]}"
            )

        sequence_outputs, _ = self.lstm(inputs)
        final_output = sequence_outputs[:, -1, :]
        return self.classifier(self.dropout(final_output))

    def get_config(self) -> dict[str, int | float]:
        """Return the model settings required to recreate the network."""

        return {
            "input_size": self.input_size,
            "num_classes": self.num_classes,
            "hidden_size": self.hidden_size,
            "num_layers": self.num_layers,
            "dropout": self.dropout_rate,
        }
