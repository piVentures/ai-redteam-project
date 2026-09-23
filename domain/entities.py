"""Domain entities. Plain dataclasses, no framework dependencies."""
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class Prediction:
    class_name: str
    confidence: float
    probabilities: Optional[Dict[str, float]] = None

    def to_dict_vulnerable(self) -> dict:
        return {
            "class": self.class_name,
            "probabilities": self.probabilities,
        }

    def to_dict_hardened(self) -> dict:
        return {
            "class": self.class_name,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class PredictionEvent:
    ts: float
    client_ip: str
    top_class: str
    confidence: float
    entropy: float
    noise_score: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "client_ip": self.client_ip,
            "top_class": self.top_class,
            "confidence": self.confidence,
            "entropy": self.entropy,
            "noise_score": self.noise_score,
        }


@dataclass
class AttackResult:
    attack_name: str
    success: bool
    metrics: Dict[str, float] = field(default_factory=dict)
    evidence_path: Optional[str] = None
