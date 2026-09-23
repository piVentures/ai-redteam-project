"""
Safe model loading.

Closes AML.T0010. safetensors is a pure tensor format with no pickle
opcodes, so there is no code-execution surface. Falls back to
torch.load(weights_only=True) if only a .pt is available.
"""
import os
import torch
from safetensors.torch import load_file


def safe_load(path: str):
    st_path = path.rsplit(".", 1)[0] + ".safetensors"
    if os.path.exists(st_path):
        return load_file(st_path)
    return torch.load(path, map_location="cpu", weights_only=True)
