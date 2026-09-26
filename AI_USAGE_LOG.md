# AI Usage Log

**Project:** AI Red Team Assessment — Containerized Image Classifier  
**Author:** Kirubel  
**Date:** 2026-09-26  
**Repository:** ai-redteam-project

---

## Purpose

This document records every use of AI tools in this project. It is a
required deliverable under the task brief, which states:

> Document every AI use: record each use in your AI usage log — tool and
> model, purpose, prompt, and how you used or changed the output.

Each task below separates **the author's contribution** (research, design,
review, modification, verification, and decisions) from **the AI's
contribution** (explanation, first drafts, debugging diagnoses, and review).
Where AI-generated material was adopted, it was read, understood, and in
most cases modified before use. Where the work is entirely the author's,
that is stated explicitly.

Compute platforms are listed separately, because they run code but do not
generate content or make decisions.

---

## AI Tools Used

| Tool | Model | Primary contribution |
|------|-------|----------------------|
| DeepSeek | V3 | Concept explanation, first drafts of scripts to author specification, debugging diagnoses |
| Claude | Sonnet | Review of training, extraction, and adversarial training scripts |

Prompts are summarized by intent rather than reproduced verbatim. Complete
session transcripts are available on request.

---

## Compute Platforms

These platforms ran code but did not generate content or make decisions.
They are listed here for completeness, not as AI tools.

| Platform | Purpose |
|----------|---------|
| Google Colab (T4 GPU, free tier) | Baseline model training and membership inference runs |
| Google Colab (CPU fallback) | Robust model training |
| Local Linux host (8 GB RAM) | Docker serving, attack scripts, notifier, verification |

---

## Task 1 — Architecture and Project Setup

**AI tools used:** DeepSeek V3

**Author's contribution.** The architecture was planned by me from the
beginning of the project and did not change materially through its course.
Before writing any code, I designed:

- The five-layer clean architecture (domain, services, usecases, adapters,
  interfaces) and the dependency direction between them.
- The four-container Docker topology and the role of each container.
- The two-mode design (`SECURITY_MODE=vulnerable` and `=hardened`) sharing a
  single codebase.
- The inline vulnerability tagging scheme (`[VULN-NN]` with an ATLAS ID on
  each).
- The decision to place every deliberate vulnerability in the adapter layer,
  because that is where untrusted input arrives.

These were decisions I made after researching clean-architecture patterns
for ML serving and evaluating them against the assessment's constraints
(local-only, CPU-only, reproducibility-first) and using my experience. 

I used DeepSeek V3 to review the design, and I evaluated each suggestion it
raised. The design shipped is the one I planned.

**AI's contribution.** DeepSeek V3 reviewed the architecture as presented,
pointed out two layering mistakes which I corrected, and explained the
reasoning behind clean architecture for ML systems.

---

## Task 2 — Baseline Model Training

**AI tools used:** DeepSeek V3, Claude Sonnet  
**Compute:** Google Colab (T4 GPU)

**Author's contribution.** I designed the training configuration: 20 epochs,
batch size 128, Adam at 1e-3, cosine annealing schedule, 90/10 train-validation
split, seed 42, and the 4-class CIFAR-10 subset. I reviewed the training
script line by line before running it, adjusted the batch size, and added
the validation split. I verified DeepSeek V3's explanation of the validation
split and the cosine annealing scheduler against the PyTorch documentation
before adopting either.

I rejected two of Claude Sonnet's suggestions and documented the reasoning.
Local training was rejected because the 8 GB host is not sized for it and
Colab is the correct platform. `weights_only=True` in both model-loading
paths was rejected because the vulnerable path must use unsafe loading to
preserve VULN-02, one of the assessment's core demonstrations.

**AI's contribution.** DeepSeek V3 wrote the first draft of the training
script to my design. Claude Sonnet reviewed the script and identified the
configuration export, training-curve export, and full-seeding improvements,
which I accepted.

**Result.** Twenty epochs on Colab (T4 GPU). Best validation accuracy 0.8710,
final test accuracy 0.8542. Model exported to `.safetensors`.

---

## Task 3 — Evasion Attacks (FGSM and PGD)

**AI tools used:** DeepSeek V3

**Author's contribution.** I researched FGSM and PGD from the original
papers (Goodfellow 2015, Madry 2018) and designed the attack workflow: load
the baseline model locally for white-box gradients, generate perturbations,
upload them as PNG, and measure class flips. I verified every line of the
attack math against the papers before running it.

**AI's contribution.** DeepSeek V3 wrote the first draft of the evasion
script and the four-panel visualization code to my specification. It
explained the FGSM and PGD derivations, which I verified against the source
papers.

**Result.** 3/3 samples flipped under both FGSM and PGD at ε = 8/255. Full
epsilon sweep in `results/evasion/epsilon_sweep.json`.

---

## Task 4 — Model Extraction

**AI tools used:** DeepSeek V3, Claude Sonnet

**Author's contribution.** I researched the extraction method from the
Tramèr 2016 paper and designed the attack: query the vulnerable API with
2,000 unlabeled images, collect soft and hard labels, train two substitute
models, and measure fidelity on a non-overlapping holdout. I understood the
KL divergence loss used for soft-label training before running the attack.

**AI's contribution.** DeepSeek V3 wrote the first draft of the extraction
script and explained the KL divergence loss. Claude Sonnet reviewed the
script and identified a holdout overlap bug: the query pool and evaluation
set shared images, which inflated measured fidelity to a misleading 0.96.
The fix — an `offset` parameter on the holdout set — was Claude's suggestion;
I implemented and verified it.

**Result.** Soft-label fidelity 0.835, hard-label 0.825, random baseline
0.275. The corrected number is the one reported. Against the hardened
endpoint the attack stopped at 20 of 30 queries due to rate limiting.

---

## Task 5 — System-Level Findings

**AI tools used:** DeepSeek V3

**Author's contribution.** I designed the nine findings, chose which aspects
of the pipeline to probe, and reviewed the first draft of the system-attacks
script. Each finding was verified against the actual captured output, and
the ATLAS mapping was verified against atlas.mitre.org.

**AI's contribution.** DeepSeek V3 wrote the first draft of the
system-attacks script to my specification, explained each of the nine
findings, and proposed initial ATLAS IDs. All mapping claims were
independently verified.

**Result.** Nine findings captured with structured JSON evidence in
`results/system/`.

---

## Task 6 — Detector Service and Cooldown

**AI tools used:** DeepSeek V3

**Author's contribution.** I designed the detection layer: a separate
container that tails the prediction log and evaluates three rules, chosen so
that an API compromise cannot disable detection. I specified the three rules
(`extraction_volume`, `mia_confidence_sweep`, `adversarial_noise_input`) and
chose each threshold by reasoning about the trade-off between sensitivity and
false-positive rate. I also specified the cooldown mechanism and reviewed its
implementation.

**AI's contribution.** DeepSeek V3 wrote the first draft of the rule
implementations and the `_should_fire` cooldown function to my specification.

**Result.** Three rules, one per MITRE ATLAS technique in scope for the model
attacks. The cooldown reduces alert volume on a sustained attack from roughly
50 alerts to 2.

---

## Task 7 — System Hardening

**AI tools used:** DeepSeek V3

**Author's contribution.** I decided which findings to remediate and which to
leave as documented residuals. I chose each control and specified how to
apply it:

- Interactive docs disabled in hardened mode only, via
  `docs_url=None, redoc_url=None, openapi_url=None`.
- CORS allowlist in hardened mode, permissive in vulnerable mode.
- Dockerfile runs as `appuser` in both containers; the root run was itself
  the vulnerability.
- Memory and CPU limits per service in `docker-compose.yml`.
- API key read from `.env` with a fallback default.

Every control was verified with `scripts/verify.sh`.

**AI's contribution.** DeepSeek V3 proposed the categories of control that
would close the findings. It also diagnosed two failures during the hardening
pass: a permission error on `logs/predictions.jsonl` because the file was
root-owned while the container runs as `appuser`, and an indentation error in
`adapters/http.py`. I applied both fixes.

**Result.** Five of nine findings remediated or mitigated. Four remain by
design on the vulnerable endpoint to demonstrate the attacks.

---

## Task 8 — Verification Script

**AI tools used:** DeepSeek V3

**Author's contribution.** I designed the verification checklist — eleven
properties of the running stack — the fail-fast behavior, and the exit-code
convention (0 on success, 1 on failure). I chose what to assert so that a
fresh clone can be validated with a single command.

**AI's contribution.** DeepSeek V3 wrote the first draft of
`scripts/verify.sh` to my specification.

**Result.** `scripts/verify.sh` runs eleven assertions and serves as the
smoke test for reproducibility.

---

## Task 9 — Adversarial Training

**AI tools used:** DeepSeek V3, Claude Sonnet  
**Compute:** Google Colab (CPU)

**Author's contribution.** I researched adversarial training from the Madry
2018 paper and designed the training setup: PGD-5 as the training attacker,
an epsilon ramp from 4/255 to 8/255 over five warmup epochs, a 0.4/0.6
clean-to-adversarial loss weighting, and per-epoch robustness measurement. I
reviewed the training script before running it and ran the training myself.

**AI's contribution.** DeepSeek V3 wrote the first draft of the training
script to my design. Claude Sonnet reviewed it and contributed three
improvements: computing gradients with `torch.autograd.grad` instead of
`loss.backward()`, deriving valid clamp bounds from the normalization
constants rather than hardcoding them, and adding the per-epoch robustness
measurement hook. None of the three changed the final numbers.

**Result.** Twenty epochs on Colab CPU, approximately 78 minutes. Final
robustness at ε = 8/255 on 500 test images: clean 0.8555, FGSM 0.6680, PGD
0.6426. Compared to the baseline (FGSM 0.05, PGD 0.00), the robust model
shows a 6.6× improvement on FGSM and a return from zero on PGD.

---

## Task 10 — Robust Model Deployment

**AI tools used:** DeepSeek V3

**Author's contribution.** I placed the robust model in `model/artifacts/`
and converted it to `.safetensors` so that `defense/secure_loader.py` takes
the safe loading path on the hardened endpoint. I changed the hardened
service's `MODEL_PATH` in `docker-compose.yml` to point at
`baseline_robust.pt`, leaving the vulnerable service on the original
baseline. This is what makes the before/after comparison possible.

**AI's contribution.** DeepSeek V3 diagnosed a bug in the evasion script
where the same model was being used for both the vulnerable and hardened
sweeps. The fix was a `--model-path` flag. I implemented and verified it.

**Result.** Two distinct sweeps: baseline at
`results/defense/adversarial_training/baseline/`, robust at `.../robust/`.
Side-by-side plot in `.../comparison.png`.

---

## Task 11 — Membership Inference

**AI tools used:** DeepSeek V3  
**Compute:** Google Colab (T4 GPU, for the vulnerable sweep)

**Author's contribution.** I researched the MIA method from Shokri 2017 and
designed the experiment: matched sample sizes, the same seed for members and
non-members, a threshold sweep, and a majority-class baseline. I reviewed
the script before running it.

**AI's contribution.** DeepSeek V3 wrote the first draft of the membership
inference script to my specification. It also added the `--sleep` flag I
requested for throttling queries against the rate-limited hardened endpoint.

**Result.** Vulnerable endpoint 0.5425 attack accuracy, hardened 0.5575,
majority baseline 0.50 on both. The difference between endpoints is within
binomial sampling error (n = 400) and is reported honestly as a weak but
measurable signal.

---

## Task 12 — Telegram Alert Notification

**AI tools used:** DeepSeek V3

**Author's contribution.** The design is mine. I chose a separate
notification container rather than coupling the detector to an external API,
a POSIX shell implementation over Python to keep the container image small,
`cat` on a polling loop over `tail -f` for the simpler process model, and
the two intervals (5-second poll, 30-second batch) that keep detection fast
and delivery quiet. I chose to make the container disabled by default so the
project reproduces without a Telegram account, and I specified the resource
limits (64 MB memory, 0.25 CPU).

I set up the bot in BotFather, verified the chat ID through `getUpdates`,
and tested delivery manually with `curl` before wiring the notifier into the
pipeline. I also wrote `scripts/notify_only.sh`, which runs an attack with
output to `/tmp`, waits for the notifier to log a delivered batch, then
truncates the alerts and prediction logs and restarts the detector — so
nothing persists in the repository after a run.

**AI's contribution.** DeepSeek V3 wrote the first draft of
`scripts/notify.sh` to my specification, wrote the Dockerfile changes to
install `curl` and `jq`, and wrote the initial `docker-compose.yml` service
block. During testing it diagnosed two failures: a Markdown parsing failure
(the Telegram API rejected messages containing `[AML.T0024]` under
`parse_mode=Markdown`), and a YAML indentation issue where the notifier
block was nested under the `alerts-api` service instead of being a sibling
of it. I applied both fixes and verified them.

**Result.** A fifth container that polls `results/alerts.jsonl` and forwards
new alerts to Telegram. Rule-agnostic — verified by writing a synthesized
alert for a rule the detector does not implement, and confirming the
notifier delivered it without any code change.

---

## Task 13 — Documentation

**AI tools used:** DeepSeek V3

**Author's contribution.** The structure of this usage log is mine. The
report structure and the README are mine. All numbers in the report and
README come from the artifact files in `results/` and `model/artifacts/`
and were not predicted or estimated. The decision to scope the submission to
the five required deliverables rather than pursue every optional bonus item
was mine.

**AI's contribution.** DeepSeek V3 proposed the initial structure for this
log, reviewed the README for phrasing and organization, and drafted an
initial version of the ATLAS and NIST AI RMF mapping. I edited and verified
the mapping against atlas.mitre.org and the NIST AI RMF 1.0 documentation
before adoption.

**Result.** This document, the README, and `report/atlas_nist_mapping.md`.

---

## Governing Principles

Five principles governed every AI interaction in this project.

**The design is the author's.** Every architectural decision — the five-layer
structure, the four-container topology, the two security modes, the
vulnerability tagging scheme, the detector rules and thresholds, the
hardening controls, and the notification topology — was planned by me from
the beginning of the project. AI reviewed the design and wrote first drafts
to my specification. It did not design the system.

**AI did not make decisions.** Every choice was made after reading the AI's
explanation, verifying it against the task requirements or the relevant
paper, and confirming it was the right call. Where AI proposed something
that conflicted with the project's goals — most clearly the
`weights_only=True` suggestion for the vulnerable loader, which would have
removed the very vulnerability the assessment was built to demonstrate —
the suggestion was rejected and the reasoning documented.

**AI did not execute.** The AI wrote code that I ran. It had no shell access,
executed no attacks, and did not modify the repository. Every command was
typed, every commit was made, and every test was run by me.

**AI did not skip verification.** Every failure was debugged by reading the
actual error: read the traceback, isolate the cause, apply the fix, verify.
AI helped identify likely causes; the verification was mine.

**AI did not overwrite judgment.** Where an AI suggestion conflicted with the
project's goals, it was rejected. The scope of the submission, the choice of
what to build and what to defer, and the ethical framing were all mine.

The task brief states: *"You may use AI to help you, but never as an agent
that accomplishes the task for you."* That boundary was respected throughout.

---

## What AI Could Not Have Done

**The architecture.** The five-layer structure, the four containers, the two
security modes, the vulnerability tagging scheme, the detector rules, the
hardening controls, and the notification topology were designed by me. AI
reviewed and drafted to my specification.

**The ethical framing.** Every attack in this project targets a system I
built, on my own hardware, for the purpose of a security assessment. AI does
not enforce that boundary.

**The responsibility.** The report, the video, the presentation, and the
answers in any Q&A are mine. If any part of the submission is wrong, I am
accountable.

**The persistence.** AI suggested fixes; I applied them, one after another,
through Docker crashes, permission errors, indentation bugs, and rate limits.

**The judgment about scope.** The project could have included a corrective
blocklist, a backdoor attack, unit tests, or a fuller defense pipeline.
Choosing what to build and what to defer required understanding the scoring
rubric and the time available.

---

## Declaration

I declare that:

1. This log is complete and accurate.
2. Every AI tool used is recorded above.
3. Every AI-generated artifact was reviewed and understood before use.
4. The final submission is my own work, produced with AI as an assistant,
   not as an executor.
5. I can explain every line of code, every architectural decision, and every
   finding in the report.

**Signed:** Kirubel  
**Date:** 2026-09-26