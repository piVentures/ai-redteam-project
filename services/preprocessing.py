"""Image bytes -> normalized tensor. No framework dependencies."""
import io
import torch
from PIL import Image
from torchvision import transforms

from domain.constants import CIFAR_MEAN, CIFAR_STD


_TRANSFORM = transforms.Compose([
    transforms.Resize((32, 32)),
    transforms.ToTensor(),
    transforms.Normalize(CIFAR_MEAN, CIFAR_STD),
])


def preprocess(image_bytes: bytes) -> torch.Tensor:
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    return _TRANSFORM(img).unsqueeze(0)


def noise_score_from_bytes(image_bytes: bytes) -> float:
    import numpy as np
    arr = np.array(Image.open(io.BytesIO(image_bytes)).convert("L"), dtype=np.float32)
    return float(np.mean(np.abs(np.diff(arr, axis=0))))
