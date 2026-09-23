"""
Model loading. Contains the [VULN-02] unsafe deserialization in vulnerable mode.
"""
import torch
from domain import SmallCNN
from defense.secure_loader import safe_load


def load_model(model_path: str, security_mode: str) -> SmallCNN:
    model = SmallCNN()
    if security_mode == "vulnerable":
        # [VULN-02] Unsafe deserialization.
        # ATLAS: AML.T0010 (ML Supply Chain Compromise)
        state = torch.load(model_path, map_location="cpu", weights_only=False)
    else:
        state = safe_load(model_path)
    model.load_state_dict(state)
    model.eval()
    return model
