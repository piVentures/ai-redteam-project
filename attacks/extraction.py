"""
Model extraction attack against the AI serving pipeline.

Strategy:
  1. Query the victim API with unlabeled CIFAR-10 images.
  2. Collect (image, soft-label) pairs from the vulnerable API.
  3. Train a substitute SmallCNN on those pairs using KL divergence.
  4. Measure fidelity: how often the substitute agrees with the victim.
  5. Compare soft-label extraction vs hard-label extraction.
  6. Run against the hardened API to measure the defense.

Metrics:
  - Fidelity: agreement rate between substitute and victim
  - Query budget: number of API calls
  - Null baseline: fidelity of a randomly initialized model

MITRE ATLAS: AML.T0024 (Exfiltration via AI Inference API)
NIST AI RMF: MANAGE (MG-2), MEASURE (MS-2)
OWASP API Top 10: API4:2023, API6:2023
"""
import argparse
import io
import json
import os
import time
from collections import defaultdict

import requests
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from PIL import Image
from torchvision import datasets, transforms

from domain import SmallCNN, CLASSES, CIFAR_MEAN, CIFAR_STD


# ============================================================
# Argument parsing
# ============================================================

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:8000")
    p.add_argument("--api-key", default=None)
    p.add_argument("--queries", type=int, default=2000)
    p.add_argument("--substitute-epochs", type=int, default=30)
    p.add_argument("--substitute-batch-size", type=int, default=64)
    p.add_argument("--output-dir", default="results/extraction")
    p.add_argument("--budget-curve", action="store_true",
                   help="Compute fidelity at multiple query budgets")
    p.add_argument("--max-queries-for-hardened", type=int, default=30,
                   help="Cap queries against hardened API to observe rate limiting")
    return p.parse_args()


# ============================================================
# Victim API client
# ============================================================

def tensor_to_png_bytes(tensor):
    """Convert a normalized tensor back to PNG bytes for HTTP upload."""
    img = tensor.squeeze(0).permute(1, 2, 0).numpy()
    img = img * CIFAR_STD + CIFAR_MEAN
    img = img.clip(0, 1)
    buf = io.BytesIO()
    Image.fromarray((img * 255).astype("uint8")).save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


def query_victim(target, image_bytes, api_key=None):
    """POST an image to the API and return the JSON response."""
    headers = {"x-api-key": api_key} if api_key else {}
    r = requests.post(
        f"{target}/predict",
        files={"file": ("q.png", image_bytes, "image/png")},
        headers=headers,
        timeout=30,
    )
    if r.status_code == 429:
        return {"rate_limited": True, "detail": r.json().get("detail", "")}
    r.raise_for_status()
    return r.json()


def extract_soft_label(response):
    """Return a (4,) probability tensor from the response.
    Vulnerable mode: full softmax.
    Hardened mode: only top-1 + rounded confidence.
    """
    if "probabilities" in response:
        probs = response["probabilities"]
        return torch.tensor([probs.get(c, 0.0) for c in CLASSES])
    elif "class" in response and "confidence" in response:
        # Hardened: construct a coarse distribution
        vec = torch.zeros(len(CLASSES))
        idx = CLASSES.index(response["class"])
        vec[idx] = response["confidence"]
        # Distribute the rest evenly (best we can do with top-1 only)
        remaining = (1.0 - response["confidence"]) / (len(CLASSES) - 1)
        for i in range(len(CLASSES)):
            if i != idx:
                vec[i] = remaining
        return vec
    return None


# ============================================================
# Data loading
# ============================================================

def build_query_pool(n):
    """Load CIFAR-10 test images to query the victim with."""
    ds = datasets.CIFAR10(
        root="./data", train=False, download=False,
        transform=transforms.ToTensor(),
    )
    target_labels = [0, 1, 2, 3]
    idx = [i for i, (_, y) in enumerate(ds) if y in target_labels][:n]
    xs = []
    for i in idx:
        img, _ = ds[i]
        xs.append(transforms.Normalize(CIFAR_MEAN, CIFAR_STD)(img))
    return torch.stack(xs)

def build_holdout_set(n=500, offset=2000):
    """Load a held-out set that does NOT overlap with the query pool.
    The query pool uses the first `offset` images; the holdout starts
    at index `offset` so the substitute is evaluated on unseen data.
    """
    ds = datasets.CIFAR10(
        root="./data", train=False, download=False,
        transform=transforms.ToTensor(),
    )
    target_labels = [0, 1, 2, 3]
    idx = [i for i, (_, y) in enumerate(ds) if y in target_labels][offset:offset + n]
    xs = []
    for i in idx:
        img, _ = ds[i]
        xs.append(transforms.Normalize(CIFAR_MEAN, CIFAR_STD)(img))
    return torch.stack(xs)

# ============================================================
# Query collection
# ============================================================

def collect_queries(target, images, api_key=None, log_path=None):
    """Query the victim API with each image and collect responses."""
    soft_labels = []
    hard_labels = []
    rate_limit_hits = 0
    t0 = time.time()

    for i, img in enumerate(images):
        try:
            resp = query_victim(target, tensor_to_png_bytes(img.unsqueeze(0)), api_key)
        except Exception as e:
            print(f"  [query {i}] error: {e}")
            continue

        if resp.get("rate_limited"):
            rate_limit_hits += 1
            if rate_limit_hits > 3:
                print(f"  rate limited consistently after {i} queries")
                break
            continue

        soft = extract_soft_label(resp)
        if soft is None:
            continue

        soft_labels.append(soft)
        hard_labels.append(soft.argmax().item())

        if (i + 1) % 200 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            print(f"  {i+1}/{len(images)} queries | {rate:.1f} q/s | "
                  f"rate_limits={rate_limit_hits}")

        if log_path and (i + 1) % 100 == 0:
            with open(log_path, "a") as f:
                f.write(json.dumps({
                    "i": i, "class": resp.get("class"),
                    "confidence": resp.get("confidence"),
                }) + "\n")

    return torch.stack(soft_labels), torch.tensor(hard_labels), rate_limit_hits


# ============================================================
# Substitute training
# ============================================================

def train_substitute(images, soft_labels, hard_labels, mode,
                     epochs=30, batch_size=64):
    """Train a fresh SmallCNN on collected pairs.
    mode='soft' uses KL divergence on soft labels.
    mode='hard' uses cross-entropy on hard labels (argmax).
    """
    model = SmallCNN()
    opt = optim.Adam(model.parameters(), lr=1e-3)
    n = len(images)
    print(f"  training substitute ({mode} labels) on {n} pairs, {epochs} epochs")

    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(n)
        total_loss = 0.0
        batches = 0

        for start in range(0, n, batch_size):
            idx = perm[start:start + batch_size]
            x = images[idx]

            if mode == "soft":
                y = soft_labels[idx]
                logits = model(x)
                log_probs = F.log_softmax(logits, dim=1)
                loss = F.kl_div(log_probs, y, reduction="batchmean")
            else:
                y = hard_labels[idx]
                loss = F.cross_entropy(model(x), y)

            opt.zero_grad()
            loss.backward()
            opt.step()
            total_loss += loss.item()
            batches += 1

        if (epoch + 1) % 5 == 0 or epoch == epochs - 1:
            avg = total_loss / batches
            print(f"    epoch {epoch+1:02d}/{epochs} | loss={avg:.4f}")

    model.eval()
    return model


# ============================================================
# Fidelity measurement
# ============================================================

def measure_fidelity(substitute, holdout_images, victim_target, api_key=None):
    """Compute agreement between the substitute and the victim."""
    agree = 0
    total = 0

    for img in holdout_images:
        try:
            resp = query_victim(victim_target, tensor_to_png_bytes(img.unsqueeze(0)), api_key)
        except Exception:
            continue

        if resp.get("rate_limited"):
            continue

        victim_class = resp.get("class")
        if victim_class is None:
            continue

        with torch.no_grad():
            sub_pred = substitute(img.unsqueeze(0)).argmax(1).item()
        sub_class = CLASSES[sub_pred]

        if sub_class == victim_class:
            agree += 1
        total += 1

    return agree / total if total > 0 else 0.0


# ============================================================
# Plotting
# ============================================================

def plot_confidence_histogram(soft_labels, save_path):
    """Show the distribution of victim confidences."""
    confidences = soft_labels.max(dim=1).values.numpy()
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(confidences, bins=30, color="#4f9cf9", edgecolor="black", alpha=0.8)
    ax.set_xlabel("Victim confidence (max probability)")
    ax.set_ylabel("Frequency")
    ax.set_title("Distribution of victim confidences\nacross 2000 queried images")
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_fidelity_curve(budgets, fidelities, save_path):
    """Fidelity as a function of query budget."""
    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.plot(budgets, fidelities, marker="o", linewidth=2, markersize=8,
            color="#4f9cf9")
    ax.axhline(0.25, color="grey", linestyle="--", alpha=0.5,
               label="Random baseline (0.25)")
    ax.set_xlabel("Query budget")
    ax.set_ylabel("Fidelity (substitute-victim agreement)")
    ax.set_title("Extraction fidelity vs query budget\nSmallCNN victim, soft-label attack")
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 1.02)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()


# ============================================================
# Main
# ============================================================

def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Target: {args.target}")
    print(f"Query budget: {args.queries}")
    print()

    # --- Build query pool ---
    print("Loading query images...")
    query_images = build_query_pool(args.queries)
    print(f"  {len(query_images)} images loaded")

    print("Loading holdout set...")
    holdout = build_holdout_set(500, offset=args.queries)    
    print(f"  {len(holdout)} holdout images loaded")
    print()

    # --- Collect soft-label queries ---
    print(f"Collecting queries from {args.target}...")
    log_path = os.path.join(args.output_dir, "query_log.jsonl")
    if os.path.exists(log_path):
        os.remove(log_path)

    soft_labels, hard_labels, rate_limits = collect_queries(
        args.target, query_images, args.api_key, log_path
    )
    print(f"  collected: {len(soft_labels)} soft labels")
    print(f"  rate limit hits: {rate_limits}")
    print()

    if len(soft_labels) < 100:
        print("Too few queries succeeded. Check the API.")
        return

    # --- Soft-label substitute ---
    print("Training soft-label substitute...")
    sub_soft = train_substitute(
        query_images[:len(soft_labels)], soft_labels, hard_labels,
        mode="soft", epochs=args.substitute_epochs,
        batch_size=args.substitute_batch_size,
    )
    torch.save(sub_soft.state_dict(), os.path.join(args.output_dir, "substitute_soft.pt"))

    print("Measuring soft-label fidelity...")
    fid_soft = measure_fidelity(sub_soft, holdout[:200], args.target, args.api_key)
    print(f"  soft-label fidelity: {fid_soft:.4f}")
    print()

    # --- Hard-label substitute ---
    print("Training hard-label substitute (baseline)...")
    sub_hard = train_substitute(
        query_images[:len(soft_labels)], soft_labels, hard_labels,
        mode="hard", epochs=args.substitute_epochs,
        batch_size=args.substitute_batch_size,
    )
    torch.save(sub_hard.state_dict(), os.path.join(args.output_dir, "substitute_hard.pt"))

    print("Measuring hard-label fidelity...")
    fid_hard = measure_fidelity(sub_hard, holdout[:200], args.target, args.api_key)
    print(f"  hard-label fidelity: {fid_hard:.4f}")
    print()

    # --- Random baseline ---
    print("Computing random baseline...")
    sub_random = SmallCNN()
    fid_random = measure_fidelity(sub_random, holdout[:200], args.target, args.api_key)
    print(f"  random baseline: {fid_random:.4f}")
    print()

    # --- Hardened comparison ---
    print(f"Running against hardened API ({args.max_queries_for_hardened} query cap)...")
    hardened_soft, hardened_hard, hardened_rate_limits = collect_queries(
        "http://localhost:8001",
        query_images[:args.max_queries_for_hardened],
        api_key="dev-local-key-change-me",
    )
    print(f"  hardened queries succeeded: {len(hardened_soft)}")
    print(f"  hardened rate limit hits: {hardened_rate_limits}")
    print()

    # --- Budget curve ---
    fidelity_curve = None
    if args.budget_curve:
        print("Computing fidelity vs query budget curve...")
        budgets = [100, 250, 500, 1000, min(2000, len(soft_labels))]
        fidelities = []
        for b in budgets:
            if b > len(soft_labels):
                break
            sub = train_substitute(
                query_images[:b], soft_labels[:b], hard_labels[:b],
                mode="soft", epochs=15, batch_size=64,
            )
            f = measure_fidelity(sub, holdout[:100], args.target, args.api_key)
            fidelities.append(f)
            print(f"  budget={b} | fidelity={f:.4f}")
        fidelity_curve = {"budgets": budgets[:len(fidelities)], "fidelities": fidelities}
        plot_fidelity_curve(budgets[:len(fidelities)], fidelities,
                            os.path.join(args.output_dir, "fidelity_curve.png"))
        print()

    # --- Plots ---
    plot_confidence_histogram(soft_labels,
                              os.path.join(args.output_dir, "confidence_histogram.png"))

    # --- Alerts ---
    try:
        alerts = requests.get("http://localhost:8002/alerts", timeout=5).json()
    except Exception:
        alerts = []

    # --- Save metrics ---
    metrics = {
        "target": args.target,
        "query_budget": len(soft_labels),
        "rate_limit_hits": rate_limits,
        "fidelity_soft_label": round(fid_soft, 4),
        "fidelity_hard_label": round(fid_hard, 4),
        "fidelity_random_baseline": round(fid_random, 4),
        "hardened": {
            "queries_attempted": args.max_queries_for_hardened,
            "queries_succeeded": len(hardened_soft),
            "rate_limit_hits": hardened_rate_limits,
        },
        "detector_alerts_count": len(alerts),
        "detector_alerts_sample": alerts[-10:],
        "fidelity_curve": fidelity_curve,
    }

    metrics_path = os.path.join(args.output_dir, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    # --- Print summary ---
    print("=" * 60)
    print("EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Query budget:              {len(soft_labels)}")
    print(f"Soft-label fidelity:       {fid_soft:.4f}")
    print(f"Hard-label fidelity:       {fid_hard:.4f}")
    print(f"Random baseline:           {fid_random:.4f}")
    print(f"Hardened rate limit hits:  {hardened_rate_limits}")
    print(f"Detector alerts:           {len(alerts)}")
    print()
    print(f"Metrics saved to: {metrics_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
