"""
Evasion attacks (FGSM, PGD) against the AI serving pipeline.

Workflow:
  1. Load baseline.pt locally for white-box gradients.
  2. For each sample: generate FGSM and PGD perturbations via
     services.attacks.
  3. POST clean and adversarial images to the target API.
  4. Save visualizations to results/evasion/.
  5. Run an epsilon sweep on 200 test images.
  6. Query the detector for alerts.

MITRE ATLAS: AML.T0043 (Craft Adversarial Data)
NIST AI RMF: MEASURE (MS-2)
"""
import argparse
import io
import json
import os

import requests
import torch
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from PIL import Image
from torchvision import datasets, transforms

from domain import SmallCNN, CLASSES, CIFAR_MEAN, CIFAR_STD
from services.attacks import fgsm, pgd


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:8000")
    p.add_argument("--api-key", default=None)
    p.add_argument("--model-path", default="model/artifacts/baseline.pt")  
    p.add_argument("--eps", type=float, default=8/255)
    p.add_argument("--alpha", type=float, default=2/255)
    p.add_argument("--steps", type=int, default=40)
    p.add_argument("--samples", nargs="+", default=[
        "data/samples/cat_0.png",
        "data/samples/bird_0.png",
        "data/samples/airplane_0.png",
    ])
    p.add_argument("--output-dir", default="results/evasion")
    return p.parse_args()


def load_image(path):
    img = Image.open(path).convert("RGB").resize((32, 32))
    tfm = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize(CIFAR_MEAN, CIFAR_STD),
    ])
    return tfm(img).unsqueeze(0)


def denormalize(tensor):
    img = tensor.squeeze(0).permute(1, 2, 0).numpy()
    img = img * CIFAR_STD + CIFAR_MEAN
    return img.clip(0, 1)


def tensor_to_png_bytes(tensor):
    img = denormalize(tensor)
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


def get_alerts():
    try:
        return requests.get("http://localhost:8002/alerts", timeout=5).json()
    except Exception:
        return []


def visualize(original, adversarial, perturbation, clean_class, adv_class,
              save_path, subtitle=""):
    fig, axes = plt.subplots(1, 4, figsize=(16, 4))

    axes[0].imshow(denormalize(original))
    axes[0].set_title(f"Original\n{clean_class}", fontsize=11)
    axes[0].axis("off")

    axes[1].imshow(denormalize(adversarial))
    axes[1].set_title(f"Adversarial\n{adv_class}", fontsize=11)
    axes[1].axis("off")

    pert = perturbation.squeeze(0).permute(1, 2, 0).numpy()
    pert_disp = (pert - pert.min()) / (pert.max() - pert.min() + 1e-8)
    axes[2].imshow(pert_disp)
    axes[2].set_title(f"Perturbation (amplified)\n{subtitle}", fontsize=11)
    axes[2].axis("off")

    diff = abs(pert).sum(axis=2)
    axes[3].imshow(diff, cmap="hot")
    axes[3].set_title("Absolute difference", fontsize=11)
    axes[3].axis("off")

    plt.suptitle(f"{clean_class} \u2192 {adv_class}", fontsize=13, y=1.02)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()


def build_test_batch(n=200):
    ds = datasets.CIFAR10(
    root="./data", train=False, download=True,
    transform=transforms.ToTensor(),
)
    target_labels = [0, 1, 2, 3]
    idx = [i for i, (_, y) in enumerate(ds) if y in target_labels][:n]
    xs, ys = [], []
    for i in idx:
        img, label = ds[i]
        xs.append(transforms.Normalize(CIFAR_MEAN, CIFAR_STD)(img))
        ys.append(label)
    return torch.stack(xs), torch.tensor(ys)


def run_epsilon_sweep(model, epsilons, batch_size=100):
    xs, ys = build_test_batch(n=200)
    results = []
    for eps in epsilons:
        with torch.no_grad():
            clean_acc = (model(xs[:batch_size]).argmax(1) == ys[:batch_size]).float().mean().item()

        x_fgsm = fgsm(model, xs[:batch_size], ys[:batch_size], eps=eps)
        with torch.no_grad():
            fgsm_acc = (model(x_fgsm).argmax(1) == ys[:batch_size]).float().mean().item()

        if eps > 0:
            x_pgd = pgd(model, xs[:batch_size], ys[:batch_size],
                        eps=eps, alpha=eps/4, steps=20)
            with torch.no_grad():
                pgd_acc = (model(x_pgd).argmax(1) == ys[:batch_size]).float().mean().item()
        else:
            pgd_acc = clean_acc

        results.append({
            "eps": round(eps, 4),
            "clean_acc": round(clean_acc, 4),
            "fgsm_acc": round(fgsm_acc, 4),
            "pgd_acc": round(pgd_acc, 4),
        })
        print(f"  eps={eps:.4f} | clean={clean_acc:.4f} | fgsm={fgsm_acc:.4f} | pgd={pgd_acc:.4f}")
    return results


def plot_epsilon_sweep(sweep, save_path):
    fig, ax = plt.subplots(figsize=(9, 5.5))
    eps = [s["eps"] for s in sweep]
    ax.plot(eps, [s["clean_acc"] for s in sweep],
            label="Clean", marker="o", linewidth=2, markersize=8)
    ax.plot(eps, [s["fgsm_acc"] for s in sweep],
            label="FGSM", marker="s", linewidth=2, markersize=8)
    ax.plot(eps, [s["pgd_acc"] for s in sweep],
            label="PGD", marker="^", linewidth=2, markersize=8)
    ax.axvline(8/255, color="grey", linestyle="--", alpha=0.5,
               label=r"$\varepsilon = 8/255$")
    ax.set_xlabel(r"Perturbation budget $\varepsilon$ (L$_\infty$)", fontsize=12)
    ax.set_ylabel("Accuracy", fontsize=12)
    ax.set_title("Accuracy vs. Perturbation Budget\nSmallCNN, 4-class CIFAR-10",
                 fontsize=13)
    ax.legend(fontsize=11, loc="upper right")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(-0.02, 1.02)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    model = SmallCNN()
    model.load_state_dict(
    torch.load(args.model_path, map_location="cpu", weights_only=True)
)
    model.eval()
    print(f"Model loaded: {sum(p.numel() for p in model.parameters())} params")
    print(f"Target: {args.target}")
    print(f"\u03b5={args.eps:.4f} | steps={args.steps} | \u03b1={args.alpha:.4f}")
    print()

    summary = {"target": args.target, "eps": args.eps, "samples": []}

    for sample_path in args.samples:
        if not os.path.exists(sample_path):
            print(f"[skip] {sample_path} not found")
            continue

        name = os.path.splitext(os.path.basename(sample_path))[0]
        true_class = name.split("_")[0]
        if true_class not in CLASSES:
            print(f"[skip] {sample_path} — cannot infer class")
            continue

        y = torch.tensor([CLASSES.index(true_class)])
        x = load_image(sample_path)

        print(f"=== {name} ===")

        clean_resp = post_image(args.target, tensor_to_png_bytes(x), args.api_key)
        print(f"  clean  \u2192 {clean_resp.get('class')}")

        x_fgsm = fgsm(model, x, y, eps=args.eps)
        fgsm_resp = post_image(args.target, tensor_to_png_bytes(x_fgsm), args.api_key)
        fgsm_success = fgsm_resp.get("class") != clean_resp.get("class")
        print(f"  fgsm   \u2192 {fgsm_resp.get('class')}  (success={fgsm_success})")

        x_pgd = pgd(model, x, y, eps=args.eps, alpha=args.alpha, steps=args.steps)
        pgd_resp = post_image(args.target, tensor_to_png_bytes(x_pgd), args.api_key)
        pgd_success = pgd_resp.get("class") != clean_resp.get("class")
        print(f"  pgd    \u2192 {pgd_resp.get('class')}  (success={pgd_success})")

        visualize(
            x, x_fgsm, x_fgsm - x,
            clean_resp.get("class"), fgsm_resp.get("class"),
            os.path.join(args.output_dir, f"fgsm_{name}.png"),
            subtitle=f"L\u221e = {float((x_fgsm - x).abs().max()):.4f}",
        )
        visualize(
            x, x_pgd, x_pgd - x,
            clean_resp.get("class"), pgd_resp.get("class"),
            os.path.join(args.output_dir, f"pgd_{name}.png"),
            subtitle=f"L\u221e = {float((x_pgd - x).abs().max()):.4f}",
        )

        summary["samples"].append({
            "name": name,
            "true_class": true_class,
            "clean": clean_resp.get("class"),
            "fgsm": fgsm_resp.get("class"),
            "pgd": pgd_resp.get("class"),
            "fgsm_success": fgsm_success,
            "pgd_success": pgd_success,
            "fgsm_l_inf": float((x_fgsm - x).abs().max()),
            "pgd_l_inf": float((x_pgd - x).abs().max()),
        })

    print("\n=== epsilon sweep ===")
    epsilons = [0.0, 0.01, 0.02, 0.03, 0.05, 0.08, 0.1]
    sweep = run_epsilon_sweep(model, epsilons)

    with open(os.path.join(args.output_dir, "epsilon_sweep.json"), "w") as f:
        json.dump(sweep, f, indent=2)

    plot_epsilon_sweep(sweep, os.path.join(args.output_dir, "accuracy_vs_epsilon.png"))
    print(f"\nSaved: {args.output_dir}/accuracy_vs_epsilon.png")

    alerts = get_alerts()
    summary["alerts_after_attack"] = len(alerts)
    summary["epsilon_sweep"] = sweep

    with open(os.path.join(args.output_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n=== detector alerts: {len(alerts)} ===")
    for a in alerts[-5:]:
        print(f"  {a}")

    print(f"\nSummary: {args.output_dir}/summary.json")


if __name__ == "__main__":
    main()
