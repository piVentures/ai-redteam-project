# AI Red Team Assessment project — Containerized Image Classifier

A local-only red team assessment of a containerized AI serving pipeline.
Two model-level attacks (evasion, extraction) and one bonus attack
(membership inference) are demonstrated against a deliberately vulnerable
FastAPI service, along with nine system-level findings in the Docker
pipeline. Each attack is paired with a remediation and a re-test.

**Frameworks:** MITRE ATLAS · NIST AI RMF 1.0 · OWASP API Top 10 (2023)
**Scope:** Local Docker only. No external network targets. 8 GB Linux host.
**Status:** Pending. See [Results](#results).

---

## Table of Contents

- [Overview](#overview)
- [System Under Test](#system-under-test)
- [Quickstart](#quickstart)
- [Repository Layout](#repository-layout)
- [Architecture](#architecture)
- [Attacks](#attacks)
  - [Evasion (FGSM, PGD)](#evasion-fgsm-pgd)
  - [Model Extraction](#model-extraction)
  - [Membership Inference](#membership-inference)
  - [System-Level Findings](#system-level-findings)
- [Defenses](#defenses)
  - [Adversarial Training](#adversarial-training)
  - [Safe Model Loading](#safe-model-loading)
  - [Input Validation & Rate Limiting](#input-validation--rate-limiting)
  - [Detector Service](#detector-service)
- [Results](#results)
- [Verification](#verification)
- [Reproducing Adversarial Training](#reproducing-adversarial-training)
- [Framework Mappings](#framework-mappings)
- [Limitations & Out of Scope](#limitations--out-of-scope)
- [Ethics Statement](#ethics-statement)
- [AI Usage](#ai-usage)
- [License](#license)

---

## Overview

This repository contains the full assessment of a containerized image
classifier. The target system is a FastAPI service wrapping a small
convolutional neural network. It is deployed in two configurations:

| Service | Port | Mode | Purpose |
|---|---|---|---|
| `api-vuln` | 8000 | `vulnerable` | Deliberately misconfigured. Used to demonstrate attacks. |
| `api-hardened` | 8001 | `hardened` | Same model with controls applied. Used to measure defenses. |
| `detector` | — | — | Tails prediction logs and emits alerts on suspected attacks. |
| `alerts-api` | 8002 | — | Read-only HTTP endpoint for detector alerts. |

The assessment demonstrates:

- **Evasion** against the serving API with FGSM and PGD (3/3 samples flipped at ε = 8/255).
- **Model extraction** at 0.835 soft-label fidelity with a 2,000-query budget.
- **Membership inference** producing a weak, statistically honest signal.
- **Nine system-level findings** covering metadata leaks, container misconfiguration, and missing controls.

Every attack is followed by a remediation and, where applicable, a re-test
against the hardened endpoint. Measured results are in [Results](#results).

---

## System Under Test

### Model

- **Architecture:** SmallCNN — 3 convolutional layers (3→32→64→128), 2 fully-connected layers (2048→256→4), dropout 0.3.
- **Parameters:** 618,820.
- **Dataset:** CIFAR-10, 4-class subset (airplane, automobile, bird, cat).
- **Normalization:** mean = std = `(0.5, 0.5, 0.5)`.
- **Baseline accuracy:** 87.10% validation, 85.42% test.
- **Robust accuracy** (after adversarial training): 85.55% clean, 66.80% FGSM@8/255, 64.26% PGD@8/255.

Model artifacts are in `model/artifacts/`:

| File | Purpose |
|---|---|
| `baseline.pt` | Baseline weights (vulnerable endpoint). |
| `baseline_robust.pt` | Adversarially trained weights (hardened endpoint). |
| `baseline_robust.safetensors` | Same weights, safe format. |
| `config.json` | Baseline training config and metrics. |
| `config_robust.json` | Robust training config and final robustness numbers. |
| `curve.json` | Baseline per-epoch training curve. |
| `robustness_curve.json` | Robust per-epoch robustness curve. |

### Serving pipeline

- **Framework:** FastAPI 0.111.0, Uvicorn 0.30.1.
- **Runtime:** Python 3.10 slim, CPU-only PyTorch 2.1.2+cpu.
- **Container user:** `appuser` (non-root).
- **Memory limit:** 1 GiB for APIs, 256 MiB for detector, 128 MiB for alerts API.
- **CPU limit:** 1.0 core for APIs, 0.5 for detector and alerts API.

---

## Quickstart

### Prerequisites

- Linux host (tested on Ubuntu)
- Docker 24+ and Docker Compose v2
- `make`
- ~3 GB free disk for images and CIFAR-10 cache
- 8 GB RAM recommended

Attack scripts additionally require Python 3.10+ with `torch`, `torchvision`,
`requests`, `matplotlib`, `pillow`, `numpy`. Install via:

```bash
make setup
This creates ./venv/ and installs requirements.txt into it.

Bring up the stack
bash

git clone <repo-url> ai-redteam-project
cd ai-redteam-project

# Create the local API key file (gitignored)
echo "API_KEY=dev-local-key-change-me" > .env

make up
After ~10 seconds the stack is live:

http://localhost:8000 — vulnerable API

http://localhost:8001 — hardened API (requires x-api-key header)

http://localhost:8002/alerts — detector alerts

Verify the stack
bash

bash scripts/verify.sh
Expected output ends with All checks passed. This script asserts:

Both APIs respond on /health with the correct mode.

/docs, /redoc, /openapi.json are exposed on :8000 and 404 on :8001.

Hardened /predict returns 401 without a key and 200 with one.

Both containers run as appuser.

The alerts API returns a JSON list.

Memory limits are visible via docker stats.

Tear down

make down
Repository Layout

.
├── adapters/          HTTP layer, auth, rate limiting, validators, detector rules
├── attacks/           Attack scripts (evasion, extraction, MIA, system)
├── defense/           Adversarial training, safe model loading
├── domain/            Model, constants, entities (no project dependencies)
├── interfaces/        Entry points (API, detector, alerts)
├── services/          Preprocessing, inference, attack math
├── usecases/          Orchestration (serve_prediction)
├── scripts/           verify.sh, dump_code.sh, export_for_ai.sh
├── model/artifacts/   Trained weights and configs
├── results/           Measured numbers, plots, evidence
│   ├── evasion/       FGSM/PGD epsilon sweep + visualizations
│   ├── extraction/    Model extraction metrics + substitute models
│   ├── membership_inference/
│   ├── defense/       Before/after comparison + robustness curve
│   └── system/        Nine system-level findings with evidence
├── colab/             Notebooks for baseline and robust training
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── requirements.txt
├── README.md
├── AI_USAGE_LOG.md
└── report/            (see report/README.md)

Architecture
Five-layer clean architecture. Dependencies point inward.

interfaces/    entry points (api_main, detector_main, alerts_main)
     │
     ▼
adapters/      FastAPI, logging, model_loader, auth, rate_limit,
               validators, detector rules
     │
     ▼
usecases/      orchestration (serve_prediction)
     │
     ▼
services/      preprocessing, inference, attack math
     │
     ▼
domain/        SmallCNN, CLASSES, entities (no project imports)

Design rationale. Every deliberate vulnerability lives in the adapter layer, because that is where the system meets the untrusted world. The domain and services layers contain no I/O and no framework imports, so they are trivially unit-testable and cannot themselves be the source of a leak.The detector and alerts-api services are separate containers so that a compromise of the serving layer cannot disable detection.

Container topology

                 ┌──────────────────┐
   attacker ────►│  api-vuln :8000  │──┐
                 └──────────────────┘  │
                 ┌──────────────────┐  │   logs/predictions.jsonl
   attacker ────►│api-hardened :8001│──┼───────────────►┌───────────┐
                 └──────────────────┘  │                │ detector  │
                                       │                └─────┬─────┘
                                       │                      │ alerts
                                       │                      ▼
                                       │            results/alerts.jsonl
                                       │                      │
                                       │                ┌─────┴──────┐
                                       └───────────────►│alerts-api  │
                                                        │  :8002     │
                                                        └────────────┘
The api-vuln and api-hardened services share the model directory read-only, the logs directory read-write, and the code directories read-only. The detector has no network exposure; it only consumes predictions.jsonl. The alerts API is read-only and has no write access to the log directory.

Ethics Statement
This assessment was performed against a system built for the assessment,running on local hardware. No external system was targeted. No real user data is involved. The CIFAR-10 dataset is public. The API key is a development placeholder (dev-local-key-change-me) and has no value.

AI Usage
An honest record of AI assistance on this project is in AI_USAGE_LOG.md. The architecture, all attack design
decisions, and the final submission are the author's. AI was used as a reviewer and pair programmer; it did not execute commands, modify the repository, or make decisions.

License
MIT — or your institution's preferred license.

# Kirubel M. sahle - 2026