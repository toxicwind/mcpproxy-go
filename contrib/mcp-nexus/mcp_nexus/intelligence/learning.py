"""Reusable online learning primitives for the intelligence layer."""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass(frozen=True)
class OnlineRankerConfig:
    """Inspectable hyperparameters for the online transition model."""

    initial_learning_rate: float = 0.35
    l2_regularization: float = 0.0005
    min_probability: float = 1e-9


@dataclass
class ContextualSoftmaxRanker:
    """Sparse online softmax ranker for next-tool prediction."""

    config: OnlineRankerConfig = field(default_factory=OnlineRankerConfig)
    weights: dict[str, dict[str, float]] = field(default_factory=dict)
    biases: dict[str, float] = field(default_factory=dict)
    updates: int = 0

    def feature_count(self) -> int:
        names: set[str] = set()
        for weight_map in self.weights.values():
            names.update(weight_map)
        return len(names)

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(sorted(self.weights))

    def observe(self, features: dict[str, float], label: str) -> None:
        dense_features = self._prepare_features(features)
        self.weights.setdefault(label, {})
        self.biases.setdefault(label, 0.0)
        probabilities = self.probabilities(dense_features)
        if not probabilities:
            probabilities = {label_name: 1.0 if label_name == label else 0.0 for label_name in self.labels}
        learning_rate = self.config.initial_learning_rate / math.sqrt(self.updates + 1.0)
        decay = 1.0 - (learning_rate * self.config.l2_regularization)

        for label_name in self.labels:
            target = 1.0 if label_name == label else 0.0
            error = target - probabilities.get(label_name, 0.0)
            self.biases[label_name] = (self.biases.get(label_name, 0.0) * decay) + (learning_rate * error)
            weight_map = self.weights.setdefault(label_name, {})
            for feature_name, feature_value in dense_features.items():
                previous = weight_map.get(feature_name, 0.0)
                updated = (previous * decay) + (learning_rate * error * feature_value)
                if abs(updated) <= self.config.min_probability:
                    weight_map.pop(feature_name, None)
                else:
                    weight_map[feature_name] = updated

        self.updates += 1

    def probabilities(
        self,
        features: dict[str, float],
        *,
        allowed_labels: set[str] | None = None,
    ) -> dict[str, float]:
        dense_features = self._prepare_features(features)
        labels = self._candidate_labels(allowed_labels)
        if not labels:
            return {}

        raw_scores: dict[str, float] = {}
        max_score = float("-inf")
        for label in labels:
            score = self.biases.get(label, 0.0)
            weight_map = self.weights.get(label, {})
            for feature_name, feature_value in dense_features.items():
                score += weight_map.get(feature_name, 0.0) * feature_value
            raw_scores[label] = score
            max_score = max(max_score, score)

        total = 0.0
        exps: dict[str, float] = {}
        for label, score in raw_scores.items():
            exp_score = math.exp(score - max_score)
            exps[label] = exp_score
            total += exp_score
        if total <= 0:
            return {}
        return {label: exp_score / total for label, exp_score in exps.items()}

    def has_signal(
        self,
        features: dict[str, float],
        *,
        allowed_labels: set[str] | None = None,
    ) -> bool:
        dense_features = self._prepare_features(features)
        labels = self._candidate_labels(allowed_labels)
        for feature_name, feature_value in dense_features.items():
            if feature_name == "__bias__" or feature_value == 0:
                continue
            for label in labels:
                if abs(self.weights.get(label, {}).get(feature_name, 0.0)) > self.config.min_probability:
                    return True
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "config": {
                "initial_learning_rate": self.config.initial_learning_rate,
                "l2_regularization": self.config.l2_regularization,
                "min_probability": self.config.min_probability,
            },
            "weights": self.weights,
            "biases": self.biases,
            "updates": self.updates,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> ContextualSoftmaxRanker:
        config_payload = payload.get("config", {})
        if not isinstance(config_payload, dict):
            config_payload = {}
        config = OnlineRankerConfig(
            initial_learning_rate=float(config_payload.get("initial_learning_rate", 0.35)),
            l2_regularization=float(config_payload.get("l2_regularization", 0.0005)),
            min_probability=float(config_payload.get("min_probability", 1e-9)),
        )
        weights_payload = payload.get("weights", {})
        biases_payload = payload.get("biases", {})
        weights = {
            str(label): {str(name): float(value) for name, value in weight_map.items()}
            for label, weight_map in weights_payload.items()
            if isinstance(weight_map, dict)
        } if isinstance(weights_payload, dict) else {}
        biases = {
            str(label): float(value) for label, value in biases_payload.items()
        } if isinstance(biases_payload, dict) else {}
        updates = int(payload.get("updates", 0))
        return cls(config=config, weights=weights, biases=biases, updates=updates)

    def _candidate_labels(self, allowed_labels: set[str] | None) -> list[str]:
        labels = set(self.weights)
        if allowed_labels is not None:
            labels &= set(allowed_labels)
        return sorted(labels)

    @staticmethod
    def _prepare_features(features: dict[str, float]) -> dict[str, float]:
        dense_features = {
            str(name): float(value)
            for name, value in features.items()
            if value not in (None, 0, 0.0)
        }
        dense_features["__bias__"] = 1.0
        return dense_features
