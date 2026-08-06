"""PyTorch LSTM classifier for Step 11 sequence-based attack detection."""

from __future__ import annotations

import torch
from torch import Tensor, nn
from torch.nn.utils.rnn import pack_padded_sequence


class LSTMClassifier(nn.Module):
    """Classify a fixed-length sequence while ignoring left-zero padding."""

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
        """Return class scores while excluding leading zero-padding steps."""

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

        valid_steps = torch.any(inputs != 0, dim=2)
        sequence_lengths = valid_steps.sum(dim=1)

        if torch.any(sequence_lengths == 0):
            raise ValueError(
                "Each LSTM sequence must contain at least one non-padding step"
            )

        # The preprocessing contract permits exact-zero padding only on the
        # left. Reject an all-zero timestep after real data because silently
        # compacting such a gap would change event order.
        has_internal_gap = torch.any(
            valid_steps[:, :-1] & ~valid_steps[:, 1:]
        )
        if has_internal_gap:
            raise ValueError(
                "Zero padding must appear only before real sequence steps"
            )

        time_steps = inputs.shape[1]
        positions = torch.arange(
            time_steps,
            device=inputs.device,
        ).unsqueeze(0)
        left_padding = time_steps - sequence_lengths
        source_positions = positions + left_padding.unsqueeze(1)
        source_positions = source_positions.clamp(max=time_steps - 1)

        gather_indexes = source_positions.unsqueeze(2).expand(
            -1,
            -1,
            self.input_size,
        )
        right_padded = torch.gather(inputs, 1, gather_indexes)
        right_valid_steps = positions < sequence_lengths.unsqueeze(1)
        right_padded = right_padded * right_valid_steps.unsqueeze(2).to(
            inputs.dtype
        )

        packed_inputs = pack_padded_sequence(
            right_padded,
            sequence_lengths.detach().cpu(),
            batch_first=True,
            enforce_sorted=False,
        )
        _, (hidden_state, _) = self.lstm(packed_inputs)
        final_output = hidden_state[-1]
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
