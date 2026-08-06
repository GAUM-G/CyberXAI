"""Tests for causal left-padding handling in the Step 11 LSTM."""

from __future__ import annotations

import unittest

import torch

from machine_learning.lstm_model import LSTMClassifier


class LSTMClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        torch.manual_seed(42)
        self.model = LSTMClassifier(
            input_size=4,
            num_classes=3,
            hidden_size=8,
            dropout=0.0,
        )
        self.model.eval()

    def test_output_shape_matches_batch_and_classes(self) -> None:
        inputs = torch.randn(5, 10, 4)

        with torch.no_grad():
            outputs = self.model(inputs)

        self.assertEqual(tuple(outputs.shape), (5, 3))
        self.assertTrue(torch.isfinite(outputs).all().item())

    def test_left_zero_padding_does_not_change_prediction(self) -> None:
        real_steps = torch.tensor(
            [
                [1.0, 0.5, -0.2, 0.8],
                [0.7, -0.1, 0.3, 1.1],
                [0.2, 0.9, 0.4, -0.6],
            ],
            dtype=torch.float32,
        ).unsqueeze(0)
        left_padded = torch.zeros(1, 10, 4)
        left_padded[:, -3:, :] = real_steps

        with torch.no_grad():
            unpadded_output = self.model(real_steps)
            padded_output = self.model(left_padded)

        torch.testing.assert_close(
            padded_output,
            unpadded_output,
            rtol=1e-6,
            atol=1e-6,
        )

    def test_mixed_sequence_lengths_are_supported(self) -> None:
        inputs = torch.zeros(3, 10, 4)
        inputs[0, -1:, :] = torch.randn(1, 4)
        inputs[1, -4:, :] = torch.randn(4, 4)
        inputs[2, :, :] = torch.randn(10, 4)

        with torch.no_grad():
            outputs = self.model(inputs)

        self.assertEqual(tuple(outputs.shape), (3, 3))
        self.assertTrue(torch.isfinite(outputs).all().item())

    def test_all_zero_sequence_is_rejected(self) -> None:
        inputs = torch.zeros(2, 10, 4)
        inputs[1, -1, 0] = 1.0

        with self.assertRaisesRegex(
            ValueError,
            "at least one non-padding step",
        ):
            self.model(inputs)

    def test_zero_gap_after_real_data_is_rejected(self) -> None:
        inputs = torch.zeros(1, 5, 4)
        inputs[0, 1, 0] = 1.0
        inputs[0, 3, 0] = 2.0

        with self.assertRaisesRegex(
            ValueError,
            "only before real sequence steps",
        ):
            self.model(inputs)

    def test_gradients_flow_through_packed_sequences(self) -> None:
        self.model.train()
        inputs = torch.zeros(2, 10, 4)
        inputs[0, -2:, :] = torch.randn(2, 4)
        inputs[1, -5:, :] = torch.randn(5, 4)

        loss = self.model(inputs).sum()
        loss.backward()

        gradients = [
            parameter.grad
            for parameter in self.model.parameters()
            if parameter.requires_grad
        ]
        self.assertTrue(all(gradient is not None for gradient in gradients))
        self.assertTrue(
            all(torch.isfinite(gradient).all().item() for gradient in gradients)
        )


if __name__ == "__main__":
    unittest.main()
