"""
Membership inference attack against the AI serving pipeline.

Determines whether a specific image was part of the model's training set
by observing the model's confidence. Models trained with standard
cross-entropy are more confident on training members than on non-members.

Attack procedure:
  1. Send N images from the training set (members) to the API.
  2. Send N images from the test set (non-members) to the API.
  3. Record the top-1 confidence for each.
  4. Set a threshold. Classify as member if confidence > threshold.
  5. Measure attack accuracy against ground truth.
  6. Compare against the majority-class baseline.

Metrics:
  - Attack accuracy
  - Majority-class baseline
  - Confidence distributions for members and non-members

MITRE ATLAS: AML.T0025 (Expose ML Model)
NIST AI RMF: MEASURE (MS-2), MANAGE (MG-2)
"""
import argparse
import io
import json
import os
import time

import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import torch
from PIL import Image
from torchvision import datasets, transforms

from domain import CLASSES, CIFAR_MEAN, CIFAR_STD


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:8000")
    p.add_argument("--api-key", default=None)
    p.add_argument("--samples-per-class", type=int, default=50,
                   help="number of members and non-members per class")
    p.add_argument("--sleep", type=float, default=0.0,
                   help="Seconds between queries (use 3.5 for hardened API)")
    p.add_argument("--seed", type=int, default=42,
                   help="Random seed for image selection (same seed = same images)")
    p.add_argument("--output-dir", default="results/membership_inference")
    return p.parse_args()


def tensor_to_png_bytes(tensor):
    img = tensor.squeeze(0).permute(1, 2, 0).numpy()
    img = img * CIFAR_STD + CIFAR_MEAN
    img = img.clip(0, 1)
    buf = io.BytesIO()
    Image.fromarray((img * 255).astype("uint8")).save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


def post_image(target, image_bytes, api_key=None):
    headers = {"x-api-key": api_key} if api_key else {}
    r = requests.post(
        f"{target}/predict",
        files={"file": ("q.png", image_bytes, "image/png")},
        headers=headers,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def get_confidence(response):
    """Extract top-1 confidence from the response.
    Vulnerable API: full softmax, use max.
    Hardened API: rounded confidence already present.
    """
    if "confidence" in response:
        return float(response["confidence"])
    if "probabilities" in response:
        return float(max(response["probabilities"].values()))
    return None


def build_dataset(is_train, n_per_class, seed=42):
    """Randomly sample n_per_class images per class from train or test split.
    The same seed always produces the same set of images, so two runs with
    the same seed are matched.
    """
    import random
    rng = random.Random(seed)

    ds = datasets.CIFAR10(
        root="./data", train=is_train, download=False,
        transform=transforms.ToTensor(),
    )
    target_labels = [0, 1, 2, 3]

    # Collect all indices per class
    indices_by_class = {c: [] for c in target_labels}
    for i, (_, label) in enumerate(ds):
        if label in target_labels:
            indices_by_class[label].append(i)

    # Randomly sample n_per_class from each class
    xs = []
    ys = []
    for c in target_labels:
        chosen = rng.sample(indices_by_class[c], n_per_class)
        for i in chosen:
            img, label = ds[i]
            x = transforms.Normalize(CIFAR_MEAN, CIFAR_STD)(img)
            xs.append(x.unsqueeze(0))
            ys.append(label)

    return xs, ys


def query_batch(xs, target, api_key, sleep_between=0.0):
    """Send each image to the API, collect the top-1 confidence.
    sleep_between: seconds to sleep between queries (for rate-limited APIs).
    Retries on 429 with a 60-second wait.
    """
    confidences = []
    total = len(xs)
    for i, x in enumerate(xs):
        try:
            resp = post_image(target, tensor_to_png_bytes(x), api_key)
            c = get_confidence(resp)
            confidences.append(c if c is not None else 0.0)
        except Exception as e:
            if "429" in str(e):
                print(f"  rate limited at query {i}, waiting 60s...")
                time.sleep(60)
                try:
                    resp = post_image(target, tensor_to_png_bytes(x), api_key)
                    c = get_confidence(resp)
                    confidences.append(c if c is not None else 0.0)
                except Exception as e2:
                    print(f"  retry failed: {e2}")
                    confidences.append(0.0)
            else:
                print(f"  query {i} failed: {e}")
                confidences.append(0.0)

        if (i + 1) % 20 == 0:
            print(f"    {i+1}/{total} queries complete")

        if sleep_between > 0:
            time.sleep(sleep_between)

    return confidences


def run_attack(member_confs, nonmember_confs, threshold):
    """Classify each image as member or non-member by threshold.
    A prediction of "member" is correct if the image is actually a member.
    """
    member_preds = [c > threshold for c in member_confs]
    nonmember_preds = [c > threshold for c in nonmember_confs]

    # True positives: member correctly classified as member
    tp = sum(member_preds)
    # False positives: non-member incorrectly classified as member
    fp = sum(nonmember_preds)

    total = len(member_confs) + len(nonmember_confs)
    correct = tp + (len(nonmember_confs) - fp)

    # Majority-class baseline: predict the more frequent class
    majority = max(len(member_confs), len(nonmember_confs)) / total

    return {
        "accuracy": correct / total,
        "majority_baseline": majority,
        "threshold": threshold,
        "tp": tp,
        "fp": fp,
        "total_members": len(member_confs),
        "total_nonmembers": len(nonmember_confs),
    }


def plot_confidence_histogram(member_confs, nonmember_confs, save_path):
    fig, ax = plt.subplots(figsize=(10, 5.5))
    bins = np.linspace(0.5, 1.0, 30)
    ax.hist(member_confs, bins=bins, alpha=0.6, label="Members (train set)",
            color="#4f9cf9", edgecolor="black")
    ax.hist(nonmember_confs, bins=bins, alpha=0.6, label="Non-members (test set)",
            color="#ef4444", edgecolor="black")
    ax.set_xlabel("Top-1 confidence returned by the API", fontsize=12)
    ax.set_ylabel("Number of images", fontsize=12)
    ax.set_title("MIA confidence distributions: members vs non-members", fontsize=13)
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()


def plot_threshold_curve(member_confs, nonmember_confs, save_path):
    """Attack accuracy as a function of threshold."""
    thresholds = np.linspace(0.5, 1.0, 50)
    accs = []
    for t in thresholds:
        member_preds = sum(1 for c in member_confs if c > t)
        nonmember_preds = sum(1 for c in nonmember_confs if c > t)
        correct = member_preds + (len(nonmember_confs) - nonmember_preds)
        accs.append(correct / (len(member_confs) + len(nonmember_confs)))

    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.plot(thresholds, accs, linewidth=2.2, color="#4f9cf9")
    best_idx = int(np.argmax(accs))
    best_t = thresholds[best_idx]
    best_acc = accs[best_idx]
    ax.axvline(best_t, color="grey", linestyle="--", alpha=0.7,
               label=f"Best threshold: {best_t:.2f} (acc {best_acc:.3f})")
    ax.axhline(0.5, color="grey", linestyle=":", alpha=0.6, label="Random baseline")
    ax.set_xlabel("Threshold", fontsize=12)
    ax.set_ylabel("Attack accuracy", fontsize=12)
    ax.set_title("MIA attack accuracy vs threshold", fontsize=13)
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0.4, 1.0)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Target: {args.target}")
    print(f"Samples per class: {args.samples_per_class}")
    print(f"Sleep between queries: {args.sleep}s")
    print()

    print("Loading member images (train set)...")
    member_xs, member_ys = build_dataset(
        is_train=True, n_per_class=args.samples_per_class, seed=args.seed
    )
    print(f"  {len(member_xs)} members loaded")

    print("Loading non-member images (test set)...")
    nonmember_xs, nonmember_ys = build_dataset(
        is_train=False, n_per_class=args.samples_per_class, seed=args.seed
    )
    print(f"  {len(nonmember_xs)} non-members loaded")

    # Query the API
    print("Querying member images...")
    member_confs = query_batch(member_xs, args.target, args.api_key,
                               sleep_between=args.sleep)
    print(f"  mean confidence: {np.mean(member_confs):.4f}")

    print("Querying non-member images...")
    nonmember_confs = query_batch(nonmember_xs, args.target, args.api_key,
                                  sleep_between=args.sleep)
    print(f"  mean confidence: {np.mean(nonmember_confs):.4f}")
    print()

    # Run the attack at several thresholds
    results = []
    for t in [0.80, 0.85, 0.90, 0.95, 0.99]:
        r = run_attack(member_confs, nonmember_confs, t)
        results.append(r)
        print(f"  threshold={t:.2f} | accuracy={r['accuracy']:.4f} | "
              f"majority={r['majority_baseline']:.4f} | TP={r['tp']} FP={r['fp']}")

    # Best threshold
    best = max(results, key=lambda r: r["accuracy"])
    print()
    print(f"Best threshold: {best['threshold']}")
    print(f"Best accuracy:  {best['accuracy']:.4f}")
    print(f"Majority baseline: {best['majority_baseline']:.4f}")

    # Plots
    plot_confidence_histogram(
        member_confs, nonmember_confs,
        os.path.join(args.output_dir, "confidence_histogram.png")
    )
    plot_threshold_curve(
        member_confs, nonmember_confs,
        os.path.join(args.output_dir, "threshold_curve.png")
    )

    # Save metrics
    metrics = {
        "target": args.target,
        "samples_per_class": args.samples_per_class,
        "total_members": len(member_confs),
        "total_nonmembers": len(nonmember_confs),
        "member_mean_confidence": float(np.mean(member_confs)),
        "member_median_confidence": float(np.median(member_confs)),
        "nonmember_mean_confidence": float(np.mean(nonmember_confs)),
        "nonmember_median_confidence": float(np.median(nonmember_confs)),
        "results": results,
        "best": best,
    }
    with open(os.path.join(args.output_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print()
    print(f"Saved: {args.output_dir}/metrics.json")
    print(f"Saved: {args.output_dir}/confidence_histogram.png")
    print(f"Saved: {args.output_dir}/threshold_curve.png")


if __name__ == "__main__":
    main()
