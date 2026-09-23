"""
Attack algorithms as pure functions. No I/O, no HTTP.
Each function takes tensors and returns tensors or metrics.
"""
import torch
import torch.nn.functional as F


def fgsm(model, x: torch.Tensor, y: torch.Tensor, eps: float = 0.03) -> torch.Tensor:
    """Fast Gradient Sign Method. Untargeted."""
    x = x.clone().detach().requires_grad_(True)
    loss = F.cross_entropy(model(x), y)
    loss.backward()
    return (x + eps * x.grad.sign()).clamp(-1, 1).detach()


def pgd(model, x: torch.Tensor, y: torch.Tensor,
        eps: float = 0.03, alpha: float = 0.007, steps: int = 10) -> torch.Tensor:
    """Projected Gradient Descent. Stronger than FGSM."""
    x_adv = x.clone().detach()
    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = F.cross_entropy(model(x_adv), y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = (x_adv + alpha * grad.sign()).clamp(x - eps, x + eps).clamp(-1, 1).detach()
    return x_adv
