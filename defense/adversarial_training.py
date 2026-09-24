"""
Adversarial training with PGD-5 augmentation.

Defense against evasion attacks (FGSM, PGD).
Runs on Google Colab (T4 GPU). Saves baseline_robust.pt and
robustness_curve.json to /content/.

MITRE ATLAS: AML.T0043 (Craft Adversarial Data)
NIST AI RMF: MANAGE (MG-2), MEASURE (MS-2)
"""
import os
import sys
import time
import json
import random
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import DataLoader, Subset, random_split
from torchvision import datasets, transforms

sys.path.insert(0, "/content")
from net import SmallCNN, CLASSES, CIFAR_MEAN, CIFAR_STD


# -----------------------------------------------------------
# Configuration
# -----------------------------------------------------------
TARGET_LABELS = [0, 1, 2, 3]
OUT_PATH = "/content/baseline_robust.pt"
CURVE_PATH = "/content/robustness_curve.json"
CONFIG_PATH = "/content/config_robust.json"

EPOCHS = 20
BATCH_SIZE = 128
LEARNING_RATE = 1e-3
SEED = 42
VAL_FRACTION = 0.1

EPS_MAX = 8 / 255
EPS_START = 4 / 255
WARMUP_EPOCHS = 5
PGD_STEPS = 5
PGD_ALPHA = EPS_MAX / 4
CLEAN_WEIGHT = 0.4
ADV_WEIGHT = 0.6

EVAL_EPS = 8 / 255
EVAL_PGD_STEPS = 20
EVAL_SAMPLES_FINAL = 500
EVAL_SAMPLES_PER_EPOCH = 200


def set_seeds(seed=SEED):
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    np.random.seed(seed)
    random.seed(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


_mean_t = torch.tensor(CIFAR_MEAN).view(1, 3, 1, 1)
_std_t = torch.tensor(CIFAR_STD).view(1, 3, 1, 1)
VALID_MIN = ((0.0 - _mean_t) / _std_t)
VALID_MAX = ((1.0 - _mean_t) / _std_t)


def clamp_valid(x):
    lo = VALID_MIN.to(x.device)
    hi = VALID_MAX.to(x.device)
    return torch.max(torch.min(x, hi), lo)


def get_loaders(batch_size=BATCH_SIZE, val_fraction=VAL_FRACTION):
    tfm = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize(CIFAR_MEAN, CIFAR_STD),
    ])
    train_ds = datasets.CIFAR10(root="/content/data", train=True, download=True, transform=tfm)
    test_ds = datasets.CIFAR10(root="/content/data", train=False, download=True, transform=tfm)

    train_idx = [i for i, (_, y) in enumerate(train_ds) if y in TARGET_LABELS]
    test_idx = [i for i, (_, y) in enumerate(test_ds) if y in TARGET_LABELS]

    train_subset = Subset(train_ds, train_idx)
    test_subset = Subset(test_ds, test_idx)

    val_size = int(len(train_subset) * val_fraction)
    train_size = len(train_subset) - val_size
    train_split, val_split = random_split(
        train_subset, [train_size, val_size],
        generator=torch.Generator().manual_seed(SEED),
    )

    return (
        DataLoader(train_split, batch_size=batch_size, shuffle=True, num_workers=2),
        DataLoader(val_split, batch_size=batch_size, shuffle=False, num_workers=2),
        DataLoader(test_subset, batch_size=batch_size, shuffle=False, num_workers=2),
    )


_eval_test_loader = None


def get_eval_loader():
    global _eval_test_loader
    if _eval_test_loader is None:
        _, _, _eval_test_loader = get_loaders(batch_size=256)
    return _eval_test_loader


def fgsm_attack(model, x, y, eps):
    x = x.clone().detach().requires_grad_(True)
    loss = F.cross_entropy(model(x), y)
    grad = torch.autograd.grad(loss, x)[0]
    x_adv = x + eps * grad.sign()
    return clamp_valid(x_adv).detach()


def pgd_attack(model, x, y, eps, alpha, steps):
    x_adv = x.clone().detach()
    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = F.cross_entropy(model(x_adv), y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv + alpha * grad.sign()
        x_adv = torch.max(torch.min(x_adv, x + eps), x - eps)
        x_adv = clamp_valid(x_adv).detach()
    return x_adv


def current_epsilon(epoch):
    if epoch >= WARMUP_EPOCHS:
        return EPS_MAX
    progress = epoch / WARMUP_EPOCHS
    return EPS_START + (EPS_MAX - EPS_START) * progress


def evaluate_robustness(model, device, n_samples):
    test_loader = get_eval_loader()
    model.eval()

    clean_correct, fgsm_correct, pgd_correct, total = 0, 0, 0, 0

    for x, y in test_loader:
        if total >= n_samples:
            break
        x, y = x.to(device), y.to(device)

        with torch.no_grad():
            clean_pred = model(x).argmax(1)
        clean_correct += (clean_pred == y).sum().item()

        x_fgsm = fgsm_attack(model, x, y, EVAL_EPS)
        with torch.no_grad():
            fgsm_pred = model(x_fgsm).argmax(1)
        fgsm_correct += (fgsm_pred == y).sum().item()

        x_pgd = pgd_attack(model, x, y, EVAL_EPS, EVAL_EPS / 4, EVAL_PGD_STEPS)
        with torch.no_grad():
            pgd_pred = model(x_pgd).argmax(1)
        pgd_correct += (pgd_pred == y).sum().item()

        total += y.size(0)

    model.train()
    return {
        "clean": clean_correct / total,
        "fgsm": fgsm_correct / total,
        "pgd": pgd_correct / total,
        "n": total,
    }


def adversarial_train(epochs=EPOCHS):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    print(f"Training attacker: PGD-{PGD_STEPS} at eps up to {EPS_MAX:.4f}")
    print(f"Loss weights: clean={CLEAN_WEIGHT}, adv={ADV_WEIGHT}")
    print(f"Warmup: eps ramps from {EPS_START:.4f} to {EPS_MAX:.4f} over {WARMUP_EPOCHS} epochs")
    print(f"Per-epoch eval on {EVAL_SAMPLES_PER_EPOCH} samples; "
          f"final eval on {EVAL_SAMPLES_FINAL} samples")
    print()

    set_seeds(SEED)

    train_loader, val_loader, _ = get_loaders(batch_size=BATCH_SIZE)
    print(f"Train batches: {len(train_loader)}")
    print(f"Val batches: {len(val_loader)}")

    model = SmallCNN().to(device)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    criterion = nn.CrossEntropyLoss()

    best_val_acc = 0.0
    curve = []
    start = time.time()

    for epoch in range(epochs):
        eps = current_epsilon(epoch)
        model.train()
        running_loss = 0.0
        running_clean = 0.0
        running_adv = 0.0

        for x, y in train_loader:
            x, y = x.to(device), y.to(device)
            x_adv = pgd_attack(model, x, y, eps, eps / 4, PGD_STEPS)

            optimizer.zero_grad()
            logits_clean = model(x)
            loss_clean = criterion(logits_clean, y)
            logits_adv = model(x_adv)
            loss_adv = criterion(logits_adv, y)
            loss = CLEAN_WEIGHT * loss_clean + ADV_WEIGHT * loss_adv
            loss.backward()
            optimizer.step()

            running_loss += loss.item()
            running_clean += loss_clean.item()
            running_adv += loss_adv.item()

        scheduler.step()

        avg_loss = running_loss / len(train_loader)
        avg_clean = running_clean / len(train_loader)
        avg_adv = running_adv / len(train_loader)

        model.eval()
        val_correct, val_total = 0, 0
        with torch.no_grad():
            for x, y in val_loader:
                x, y = x.to(device), y.to(device)
                pred = model(x).argmax(1)
                val_correct += (pred == y).sum().item()
                val_total += y.size(0)
        val_acc = val_correct / val_total

        epoch_rob = evaluate_robustness(model, device, n_samples=EVAL_SAMPLES_PER_EPOCH)

        elapsed = time.time() - start
        print(f"epoch {epoch+1:02d}/{epochs} | "
              f"eps={eps:.4f} | "
              f"loss={avg_loss:.4f} (clean={avg_clean:.4f} adv={avg_adv:.4f}) | "
              f"val_acc={val_acc:.4f} | "
              f"fgsm={epoch_rob['fgsm']:.4f} pgd={epoch_rob['pgd']:.4f} | "
              f"t={elapsed:.0f}s")

        row = {
            "epoch": epoch + 1,
            "eps": round(eps, 4),
            "loss": round(avg_loss, 4),
            "loss_clean": round(avg_clean, 4),
            "loss_adv": round(avg_adv, 4),
            "val_acc": round(val_acc, 4),
            "fgsm_acc": round(epoch_rob["fgsm"], 4),
            "pgd_acc": round(epoch_rob["pgd"], 4),
            "elapsed": round(elapsed, 1),
        }
        curve.append(row)

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), OUT_PATH)
            print(f"  -> saved best (val_acc={val_acc:.4f})")

    print()
    print("=" * 60)
    print(f"Final robustness measurement ({EVAL_SAMPLES_FINAL} test images)")
    print("=" * 60)
    model.load_state_dict(torch.load(OUT_PATH, map_location=device, weights_only=True))
    robustness = evaluate_robustness(model, device, n_samples=EVAL_SAMPLES_FINAL)
    print(f"Clean accuracy: {robustness['clean']:.4f}")
    print(f"FGSM accuracy:  {robustness['fgsm']:.4f}")
    print(f"PGD accuracy:   {robustness['pgd']:.4f}")
    print(f"(n = {robustness['n']})")

    with open(CURVE_PATH, "w") as f:
        json.dump(curve, f, indent=2)

    config = {
        "classes": CLASSES,
        "num_classes": len(CLASSES),
        "input_shape": [1, 3, 32, 32],
        "normalization": {"mean": list(CIFAR_MEAN), "std": list(CIFAR_STD)},
        "training": {
            "epochs": epochs,
            "batch_size": BATCH_SIZE,
            "optimizer": "Adam",
            "learning_rate": LEARNING_RATE,
            "scheduler": "CosineAnnealingLR",
            "seed": SEED,
            "val_fraction": VAL_FRACTION,
            "dataset": "CIFAR-10 (classes 0-3)",
            "training_attacker": f"PGD-{PGD_STEPS}",
            "eps_start": round(EPS_START, 4),
            "eps_max": round(EPS_MAX, 4),
            "warmup_epochs": WARMUP_EPOCHS,
            "clean_weight": CLEAN_WEIGHT,
            "adv_weight": ADV_WEIGHT,
            "per_epoch_eval_samples": EVAL_SAMPLES_PER_EPOCH,
            "final_eval_samples": EVAL_SAMPLES_FINAL,
            "trained_on": datetime.utcnow().isoformat() + "Z",
        },
        "metrics": {
            "best_val_acc": round(best_val_acc, 4),
            "final_clean": round(robustness["clean"], 4),
            "final_fgsm": round(robustness["fgsm"], 4),
            "final_pgd": round(robustness["pgd"], 4),
        },
        "parameters": sum(p.numel() for p in model.parameters()),
    }
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

    print()
    print(f"Saved: {OUT_PATH}")
    print(f"Saved: {CURVE_PATH}")
    print(f"Saved: {CONFIG_PATH}")

    return model, curve, robustness


if __name__ == "__main__":
    adversarial_train(epochs=EPOCHS)
