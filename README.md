<div align="center">

# AI Red Team Assessment

### Containerized Image Classifier — Local Red Team Operation

**Two model-level attacks · Nine system findings · Three defenses**
**Full MITRE ATLAS · NIST AI RMF 1.0 · OWASP API Top 10 (2023) alignment**

<br />

[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Python](https://img.shields.io/badge/Python-3.10-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.1.2-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)](https://pytorch.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)

[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-1c3d5a?style=for-the-badge)](https://atlas.mitre.org/)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF%201.0-005ea2?style=for-the-badge)](https://www.nist.gov/itl/ai-risk-management-framework)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010%202023-000000?style=for-the-badge)](https://owasp.org/API-Security/)
[![License](https://img.shields.io/badge/License-MIT-3DA639?style=for-the-badge)](LICENSE)

<br />

**Status:** Complete · **Hosting:** Local Docker · **Scope:** Assessment target only

</div>

---

## Table of Contents

- [Overview](#overview)
- [At a Glance](#at-a-glance)
- [System Under Test](#system-under-test)
- [Quick Start](#quick-start)
- [Repository Layout](#repository-layout)
- [Architecture](#architecture)
- [Attacks](#attacks)
- [Defenses](#defenses)
- [Detection and Notification](#detection-and-notification)
- [Results](#results)
- [Verification and Reproducibility](#verification-and-reproducibility)
- [Framework Alignment](#framework-alignment)
- [Limitations](#limitations)
- [Ethics and Scope](#ethics-and-scope)
- [AI Usage](#ai-usage)
- [License](#license)

---

## Overview

This repository contains a **complete red team assessment** of a local,
containerized image classifier. The target is a small convolutional neural
network served over HTTP by FastAPI and packaged in Docker.

Two model-level attacks — **evasion** and **model extraction** — are
demonstrated end to end, along with a bonus **membership inference** attack.
Nine system-level findings in the Docker pipeline are documented with
captured evidence. Each finding is paired with a remediation, and every
remediation is verified by re-running the attack against the hardened
endpoint.

The project is intentionally self-contained. It runs on an **8 GB Linux host**
with Docker and no cloud dependency. **No external system is targeted.**

---

## At a Glance

| | |
|:---|:---|
| **Model** | SmallCNN — 3 conv layers · 2 FC layers · 618,820 parameters |
| **Dataset** | CIFAR-10, 4-class subset (airplane, automobile, bird, cat) |
| **Baseline accuracy** | 87.10% validation · 85.42% test |
| **Robust accuracy** | 85.55% clean · 66.80% FGSM · 64.26% PGD at ε = 8/255 |
| **Attacks demonstrated** | FGSM · PGD · Model Extraction · Membership Inference |
| **System findings** | 9 (metadata leaks, container misconfiguration, missing controls) |
| **Detector rules** | 3, one per MITRE ATLAS technique |
| **Frameworks** | MITRE ATLAS · NIST AI RMF 1.0 · OWASP API Top 10 (2023) |
| **Hosting** | Local Docker only — no cloud, no deployment |

---

## System Under Test

### Model

- **Architecture:** SmallCNN — 3 convolutional layers (3→32→64→128), 2 fully-connected layers (2048→256→4), dropout 0.3.
- **Parameters:** 618,820.
- **Dataset:** CIFAR-10, 4-class subset (airplane, automobile, bird, cat).
- **Normalization:** mean = std = `(0.5, 0.5, 0.5)`.
- **Baseline accuracy:** 87.10% validation · 85.42% test.
- **Robust accuracy** (after adversarial training): 85.55% clean · 66.80% FGSM@8/255 · 64.26% PGD@8/255.

Model artifacts are in `model/artifacts/`:

| File | Purpose |
|:-----|:--------|
| `baseline.pt` | Baseline weights (vulnerable endpoint) |
| `baseline_robust.pt` | Adversarially trained weights (hardened endpoint) |
| `baseline_robust.safetensors` | Same weights, safe format |
| `config.json` | Baseline training config and metrics |
| `config_robust.json` | Robust training config and final robustness numbers |
| `curve.json` | Baseline per-epoch training curve |
| `robustness_curve.json` | Robust per-epoch robustness curve |

### Serving Pipeline

- **Framework:** FastAPI 0.111.0 · Uvicorn 0.30.1
- **Runtime:** Python 3.10 slim · CPU-only PyTorch 2.1.2+cpu
- **Container user:** `appuser` (non-root)
- **Memory limit:** 1 GiB (APIs) · 256 MiB (detector) · 128 MiB (alerts API) · 64 MiB (notifier)
- **CPU limit:** 1.0 core (APIs) · 0.5 (detector/alerts) · 0.25 (notifier)

---

## Quick Start

### Prerequisites

- Linux host (tested on Ubuntu)
- Docker 24+ and Docker Compose v2
- `make`
- ~3 GB free disk for images and CIFAR-10 cache
- 8 GB RAM recommended
- Python 3.10+ for the host-side attack scripts

Attack scripts require `torch`, `torchvision`, `requests`, `matplotlib`,
`pillow`, `numpy`. Install via:

```bash
make setup
```

This creates `./venv/` and installs `requirements.txt` into it.

### Bring Up the Stack

```bash
git clone <repo-url> ai-redteam-project
cd ai-redteam-project

# Create the local environment file (gitignored)
cat > .env <<'EOF'
API_KEY=dev-local-key-change-me
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
EOF

make up
sleep 10
```

After ~10 seconds the stack is live:

- `http://localhost:8000` — vulnerable API
- `http://localhost:8001` — hardened API (requires `x-api-key` header)
- `http://localhost:8002/alerts` — detector alerts

### Verify the Stack

```bash
bash scripts/verify.sh
```

Expected output ends with **`All checks passed.`** The script asserts:

- Both APIs respond on `/health` with the correct mode
- `/docs`, `/redoc`, `/openapi.json` are exposed on `:8000` and 404 on `:8001`
- Hardened `/predict` returns 401 without a key and 200 with one
- Both containers run as `appuser`
- The alerts API returns a JSON list
- Memory limits are visible via `docker stats`

### Run an Attack

```bash
source venv/bin/activate

# Evasion — FGSM and PGD
python -m attacks.evasion_fgsm_pgd --target http://localhost:8000

# Model extraction — 200 queries
python -m attacks.extraction --target http://localhost:8000 --queries 200

# Membership inference — throttled against the hardened endpoint
python -m attacks.membership_inference \
    --target http://localhost:8001 \
    --api-key dev-local-key-change-me \
    --samples-per-class 50 \
    --sleep 3.5
```

### Tear Down

```bash
make down
```

---

## Repository Layout

```
.
├── adapters/          HTTP · auth · rate limiting · validators · detector rules
├── attacks/           Attack scripts (evasion · extraction · MIA · system)
├── defense/           Adversarial training · safe model loading
├── domain/            SmallCNN · CLASSES · entities (no project deps)
├── interfaces/        Entry points (API · detector · alerts)
├── services/          Preprocessing · inference · attack math
├── usecases/          serve_prediction (orchestration)
├── scripts/           verify.sh · notify.sh · notify_only.sh · test_notifier.sh
├── model/artifacts/   Trained weights and configs
├── results/           Measured numbers, plots, evidence
│   ├── evasion/           Epsilon sweep · per-sample visualizations
│   ├── extraction/        Fidelity metrics · substitute models
│   ├── membership_inference/
│   ├── defense/           Before/after comparison · robustness curve
│   └── system/            Nine findings with structured evidence
├── colab/             Notebooks for baseline and robust training
├── docker-compose.yml
├── Dockerfile
├── Dockerfile.notifier
├── Makefile
├── requirements.txt
├── AI_USAGE_LOG.md
└── README.md
```

---

## Architecture

### Clean Layering

The codebase follows a **five-layer clean architecture**. Dependencies point
inward: outer layers may import inner layers; inner layers **never** import
outer layers.

```
┌─────────────────────────────────────────────────────────┐
│  interfaces/   FastAPI entry points · detector · alerts │
├─────────────────────────────────────────────────────────┤
│  adapters/     HTTP · auth · rate limit · validators    │
├─────────────────────────────────────────────────────────┤
│  usecases/     serve_prediction (orchestration)         │
├─────────────────────────────────────────────────────────┤
│  services/     preprocessing · inference · attack math  │
├─────────────────────────────────────────────────────────┤
│  domain/       SmallCNN · CLASSES · entities (pure)     │
└─────────────────────────────────────────────────────────┘
```

Every deliberate vulnerability lives in the **`adapters/`** layer, because
that is where the system meets untrusted input. The `domain/` and
`services/` layers are pure — no I/O, no framework imports — so they can be
unit-tested with tensors alone.

### Container Topology

```
                ┌──────────────────┐
   attacker ───►│  api-vuln  :8000 │──┐
   (host)       │  SECURITY_MODE=  │  │
                │  vulnerable      │  │
                └──────────────────┘  │   logs/predictions.jsonl
                ┌──────────────────┐  │
   attacker ───►│api-hardened :8001│──┼──────────►┌───────────┐
   (host)       │  SECURITY_MODE=  │  │           │  detector │
                │  hardened        │  │           └─────┬─────┘
                └──────────────────┘  │                 │
                                      │                 │ alerts
                                      │                 ▼
                                      │     results/alerts.jsonl
                                      │                 │
                                      │           ┌─────┴──────┐
                                      └──────────►│ alerts-api │
                                                  │    :8002   │
                                                  └────────────┘
                                                        │
                                                        ▼
                                              ┌───────────────────┐
                                              │ telegram-notifier │ ──► Telegram
                                              │ (optional)        │
                                              └───────────────────┘
```

**Five containers.** Only `api-vuln` and `api-hardened` expose ports. The
detector has no network exposure. The alerts API is read-only. The notifier
mounts the results directory read-only and writes nothing.

### Two Security Modes, One Codebase

A single `SECURITY_MODE` environment variable switches behavior between the
two APIs. Every vulnerable behavior is tagged inline with `[VULN-NN]` and
its MITRE ATLAS technique, so the diff between the vulnerable and hardened
configurations reads as the remediation itself.

---

## Attacks

### Evasion — FGSM and PGD

> **Script:** `attacks/evasion_fgsm_pgd.py`  
> **ATLAS:** `AML.T0043` — *Craft Adversarial Data*  
> **RMF:** `MEASURE (MS-2)`

The attacker loads the baseline model locally for white-box gradients,
generates FGSM and PGD perturbations, and submits them as PNG uploads.
Success is measured as a change in the returned top-1 class.

```bash
python -m attacks.evasion_fgsm_pgd --target http://localhost:8000
```

**Outputs:** `results/evasion/` — epsilon sweep JSON, four-panel
visualizations, `accuracy_vs_epsilon.png`.

### Model Extraction

> **Script:** `attacks/extraction.py`  
> **ATLAS:** `AML.T0024` — *Exfiltration via AI Inference API*  
> **OWASP API 2023:** API4, API6

The attacker sends unlabeled CIFAR-10 test images to the vulnerable API,
collects soft labels (full softmax) and hard labels (argmax), and trains two
substitute models. Fidelity is measured as agreement with the victim on a
held-out set that does **not** overlap the query pool.

```bash
python -m attacks.extraction --target http://localhost:8000 --queries 200
```

**Outputs:** `results/extraction/` — `metrics.json`, substitute models,
`confidence_histogram.png`.

### Membership Inference

> **Script:** `attacks/membership_inference.py`  
> **ATLAS:** `AML.T0025` — *Expose ML Model*

The attacker sends matched samples of training-set and test-set images,
records top-1 confidence, and sweeps a threshold classifier.

```bash
python -m attacks.membership_inference \
    --target http://localhost:8000 \
    --samples-per-class 50
```

**Outputs:** `results/membership_inference/` — metrics, confidence histogram,
threshold curve.

### System-Level Findings

> **Script:** `attacks/system_attacks.py`  
> **ATLAS:** `AML.T0000`, `T0007`, `T0010`, `T0024`  
> **RMF:** `MAP (MP-2)`, `GOVERN (GV-6)`, `MEASURE (MS-2)`

Nine findings captured with structured JSON evidence. The script **observes
only** — it does not modify the running system.

```bash
python -m attacks.system_attacks
```

---

## Defenses

### Adversarial Training

> **Script:** `defense/adversarial_training.py`  
> **ATLAS:** `AML.T0043` (mitigation)  
> **RMF:** `MANAGE (MG-2)`

The robust model is trained with **PGD-5** adversarial examples during
training, with an epsilon ramp from **4/255 → 8/255** over five warmup epochs
and a **0.4 / 0.6** clean-to-adversarial loss weighting.

### Safe Model Loading

> **Script:** `defense/secure_loader.py`  
> **ATLAS:** `AML.T0010` — *ML Supply Chain Compromise*

The hardened endpoint loads weights from `.safetensors` when available,
falling back to `torch.load(weights_only=True)`. This closes the unsafe
deserialization vulnerability. The vulnerable endpoint retains
`weights_only=False` to preserve **VULN-02** as a demonstration.

### Input Validation and Rate Limiting

> **Scripts:** `adapters/validators.py`, `adapters/rate_limit.py`

Hardened mode applies:

- **2 MB** size cap
- **512 × 512** dimension cap
- **PNG / JPEG** only
- Coarse noise heuristic
- **20 requests / 60 s / IP** token-bucket rate limit

---

## Detection and Notification

### Detector Service

> **Script:** `adapters/detector.py`  
> **Version:** `v2-cooldown-2026-09-23`

A separate container tails `logs/predictions.jsonl` and evaluates three
rules. Each rule maps to one MITRE ATLAS technique.

| Rule | ATLAS | Trigger |
|:-----|:------|:--------|
| `check_extraction_volume` | `AML.T0024` | > 40 queries from one IP in 60 s |
| `check_mia_confidence_sweep` | `AML.T0025` | ≥ 80% of last 20 queries above 0.95 confidence |
| `check_adversarial_noise` | `AML.T0043` | Noise score > 45 |

Per-rule per-IP cooldown of **60 seconds** prevents alert flooding. Before
the cooldown was added, a sustained extraction attack produced ~50 alerts;
after, the same attack produces **~2**.

### Telegram Notification

> **Script:** `scripts/notify.sh`  
> **ATLAS:** `AML.T0000` (detection)  
> **RMF:** `MANAGE (MG-2)`, `GOVERN (GV-6)`

An optional fifth container polls `results/alerts.jsonl` every 5 seconds,
batches new alerts for 30 seconds, and posts them to a Telegram chat via
`curl`. It runs on a small Alpine image (**~15 MB**) with no Python
dependency and mounts the results directory **read-only**.

The notifier is **rule-agnostic**: it forwards any alert the detector
emits. Verified by writing a synthesized alert for a rule the detector does
not implement (`model_info_probe`, `AML.T0007`) and confirming the notifier
delivered it without modification.

> **Note:** Disabled by default. If `TELEGRAM_BOT_TOKEN` or
> `TELEGRAM_CHAT_ID` is unset, the container logs `[notifier] disabled` and
> idles. The project reproduces without a Telegram account.

#### Enable

```bash
# Add credentials to .env, then:
docker compose restart telegram-notifier
docker compose logs -f telegram-notifier
# expect: [notifier] watching results/alerts.jsonl (poll 5s, batch 30s)
```

#### Verify

```bash
bash scripts/test_notifier.sh sim-multi-alert
```

Writes a synthesized multi-alert batch and confirms Telegram delivery. Use
`sim-multi-alert` for a single demo message containing every alert type, or
run individual scenarios with `bash scripts/test_notifier.sh list`.

#### Send-Only Test Runs

```bash
bash scripts/notify_only.sh extraction
```

Runs an attack with output to `/tmp`, waits for the notifier to log a
delivered batch, then truncates the alerts and prediction logs and restarts
the detector — leaving the repository clean.

---

## Results

> All numbers below are **measured**. They appear in the referenced artifact
> files and were not predicted or estimated.

### Evasion — Baseline vs Robust at ε = 8/255

| Model | Clean | FGSM | PGD |
|:------|:-----:|:----:|:---:|
| **Baseline** | 0.88 | 0.05 | **0.00** |
| **Robust** | 0.84 | 0.33 | **0.18** |

The robust model shows a **6.6× improvement on FGSM** and a **return from
zero on PGD**, at a cost of 4 points of clean accuracy.

> `results/evasion/epsilon_sweep.json`  
> `results/defense/adversarial_training/robust/epsilon_sweep.json`

### Model Extraction

| Metric | Value |
|:-------|------:|
| Query budget | 2,000 |
| Soft-label fidelity | **0.835** |
| Hard-label fidelity | 0.825 |
| Random baseline | 0.275 |
| Detector alerts during attack | 9 |

Against the hardened endpoint with a 30-query cap: **20 succeeded**, **4
rate-limited**.

> `results/extraction/metrics.json`

### Membership Inference

| Endpoint | Best accuracy | Majority baseline |
|:---------|:-------------:|:-----------------:|
| Vulnerable | 0.5425 | 0.50 |
| Hardened | 0.5575 | 0.50 |

Both endpoints show a **weak but measurable signal**. The difference between
endpoints is within binomial sampling error (n = 400) and is not
statistically significant.

> `results/membership_inference/`

### Adversarial Training — Final Robustness

Twenty epochs on CPU. Final numbers on 500 test images at ε = 8/255:

| Metric | Value |
|:-------|------:|
| Best validation accuracy | 0.8715 |
| Clean accuracy | 0.8555 |
| FGSM accuracy | 0.6680 |
| PGD accuracy | 0.6426 |

> `model/artifacts/config_robust.json`  
> `results/defense/adversarial_training/robustness_curve.json`

---

## Verification and Reproducibility

```bash
# Full stack verification
bash scripts/verify.sh

# Notifier scenario suite (all alert types)
bash scripts/test_notifier.sh all

# Send-only attack with clean repo state
bash scripts/notify_only.sh extraction
```

| Script | Purpose |
|:-------|:--------|
| `verify.sh` | Asserts **11 properties** of the running stack · exits `0` on success |
| `test_notifier.sh` | Runs **10 scenarios** · reports PASS/FAIL per scenario |
| `notify_only.sh` | Runs an attack · confirms delivery · cleans up |

### Fresh-Checkout Reproduction

```bash
cd /tmp
git clone <repo-url> ai-redteam-test
cd ai-redteam-test
echo "API_KEY=dev-local-key-change-me" > .env
make up
sleep 10
bash scripts/verify.sh
```

---

## Framework Alignment

### MITRE ATLAS

| Technique | ID | Where applied |
|:----------|:---|:--------------|
| ML Artifact Collection | `AML.T0000` | Findings 06, 07, 09 |
| Discover ML Artifacts | `AML.T0007` | Findings 01, 02, 04 |
| ML Supply Chain Compromise | `AML.T0010` | Finding 05, VULN-02 |
| Exfiltration via AI Inference API | `AML.T0024` | Extraction attack · detector rule |
| Expose ML Model | `AML.T0025` | MIA attack · detector rule |
| Craft Adversarial Data | `AML.T0043` | Evasion · adversarial training · detector rule |

### NIST AI RMF 1.0

| Function | Category | Where applied |
|:---------|:---------|:--------------|
| **GOVERN** | GV-6 (credential management) | `.env` · token rotation |
| **MAP** | MP-2 (scientific integrity) | Threat model · attack scope |
| **MEASURE** | MS-2 (evaluation) | All attack measurements |
| **MANAGE** | MG-2 (risk response) | Adversarial training · detector · notifier |

### OWASP API Security Top 10 (2023)

| Category | Finding |
|:---------|:--------|
| API4 — Unrestricted Resource Consumption | Finding 03 (no rate limit) |
| API6 — Unrestricted Access to Sensitive Business Flows | Model extraction |
| API9 — Improper Inventory Management | Finding 01 (`/model-info` leak) |

---

## Limitations

The following were **explicitly not assessed**. Every claim in this
repository is bounded by their omission.

- **Data poisoning and backdoor attacks** — the training pipeline is offline
  and the dataset is CIFAR-10 from torchvision. No poisoning was attempted.
- **Transfer attacks** — evasion was evaluated against the same model used
  to generate perturbations (white-box). Cross-model transfer was not
  measured.
- **Adaptive attacks against the detector** — the detector is a heuristic.
  An attacker who knows the thresholds could craft inputs that stay below
  them.
- **Extraction at full budget against the hardened endpoint** — rate limiting
  caps queries at 20 per 60 seconds, so the full extraction was only run
  against the vulnerable endpoint.
- **Denial of service** — no stress testing beyond 200 requests. No memory
  or connection exhaustion was attempted.
- **Supply chain of the PyTorch wheel** — pulled from the official index;
  not independently verified.
- **Notifier is not corrective** — it posts messages; it does not block
  traffic. Converting notification into enforcement is scoped out.

---

## Ethics and Scope

Every attack in this project targets a **system built for the assessment**,
running on **local hardware**. No external system was targeted. No real user
data is involved. The CIFAR-10 dataset is public. The API key is a
development placeholder and has no value.

The attacks implemented are **standard, published techniques**:

| Paper | Technique |
|:------|:----------|
| Goodfellow et al. 2015 | FGSM |
| Madry et al. 2018 | PGD · adversarial training |
| Tramèr et al. 2016 | Model extraction |
| Shokri et al. 2017 | Membership inference |

They are included here for defensive research and reproducibility, in a
contained local environment.

---

## AI Usage

An honest record of every AI tool used on this project is in
[`AI_USAGE_LOG.md`](AI_USAGE_LOG.md). The architecture, all attack design
decisions, and the final submission are the author's. AI was used as a
**reviewer and pair programmer**; it did not execute commands, modify the
repository, or make decisions.

---

## License

**MIT License.** This is an assessment artifact and is not intended for
production deployment.

---

<div align="center">

**Kirubel M. Sahle · 2026**

<sub>Local · Reproducible · Measured</sub>

</div>