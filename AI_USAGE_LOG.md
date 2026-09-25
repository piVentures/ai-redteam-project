# AI Usage Log

A complete record of every AI tool used on this project, organized task by
task. Each entry names the tool and model, states the purpose, and describes
how the output was handled. Where AI wrote code that was adopted, the code
was reviewed, understood, and in most cases modified before use. Where the
work is the author's, that is stated.

---

## Summary

| Tool | Model | Where used |
|------|-------|------------|
| DeepSeek | V3 | Architecture review, attack scripts, debugging, framework mapping, hardening |
| Claude | Sonnet | Script review (training, extraction, adversarial training) |
| Google Colab | T4 GPU | Baseline training, membership inference runs |
| Google Colab | CPU | Robust model training |

---

## Task 1 — Architecture and Project Setup

**Tools used:** DeepSeek V3

I designed the five-layer clean architecture, the four-container Docker
topology, the two security modes, and the vulnerability tagging scheme.
DeepSeek V3 was used to review the design and point out layering mistakes.
Where it disagreed, I evaluated the argument and made the final call.

The choices of FastAPI over ASP.NET Core, and SmallCNN on a 4-class
CIFAR-10 subset over larger models or datasets, were made before consulting
AI. DeepSeek V3 confirmed both decisions. The Docker compose file was
reviewed by DeepSeek V3; the port mappings and volume mounts are mine.

---

## Task 2 — Baseline Model Training

**Tools used:** DeepSeek V3, Claude Sonnet, Google Colab (T4 GPU)

DeepSeek V3 wrote the initial PyTorch training script. I reviewed every
line, changed the batch size, and added the validation split. DeepSeek V3
explained the rationale for the 90/10 split and the cosine annealing
scheduler; I verified both against the PyTorch documentation before
adopting.

Claude Sonnet reviewed the training script for methodological flaws. I
accepted its suggestions for the validation split, config export, training
curve export, and full seeding. I rejected two suggestions: local training,
because an 8 GB host is not sized for it and Colab is the correct platform;
and `weights_only=True` in both model-loading paths, because the vulnerable
path must use unsafe loading to preserve the assessment's VULN-02. Both
rejections are documented in the commit messages.

Training itself ran on Google Colab (T4 GPU). Twenty epochs, best
validation accuracy 0.8710, final test accuracy 0.8542. The model was then
exported to `.safetensors` using a conversion script written by DeepSeek V3
and reviewed by me.

---

## Task 3 — Evasion Attacks (FGSM and PGD)

**Tools used:** DeepSeek V3

DeepSeek V3 wrote the first draft of the evasion script. I reviewed every
line and understood the attack mathematics before running it. The FGSM and
PGD algorithms were verified against the Goodfellow 2015 and Madry 2018
papers, and the explanation DeepSeek V3 gave for each was verified against
the same sources before being written into the report.

The visualization code was adapted from DeepSeek V3's draft. When import
errors appeared during early runs, DeepSeek V3 correctly diagnosed the
cause (running the script as a file instead of a module) and the fix
(`python -m attacks.evasion_fgsm_pgd`). The dataset-loading fix
(`download=True`) was also from DeepSeek V3 and was understood before being
applied.

---

## Task 4 — Model Extraction

**Tools used:** DeepSeek V3, Claude Sonnet

DeepSeek V3 wrote the first draft of the extraction script. I reviewed it
and understood the KL divergence loss used for soft-label training.
DeepSeek V3 explained the loss in detail; I verified the explanation
against the Tramèr 2016 paper before using it in the report.

Claude Sonnet reviewed the script and identified a holdout overlap bug: the
query pool and the evaluation set were sharing images, inflating measured
fidelity. The fix was to make the holdout set use an offset parameter.
Correcting this dropped measured fidelity from 0.96 to 0.835 — the
corrected number is the one reported.

---

## Task 5 — System-Level Findings

**Tools used:** DeepSeek V3

DeepSeek V3 wrote the first draft of the system-attacks script. I reviewed
it, reduced the rate-limit test from 1,000 to 200 requests to keep the run
fast, and ran it. DeepSeek V3 explained each of the nine findings; each
explanation was checked against the actual captured output before being
written into the report.

DeepSeek V3 also explained MITRE ATLAS and how to map each finding to a
technique. I verified the mapping against atlas.mitre.org before adopting
it.

---

## Task 6 — Detector Service and Cooldown

**Tools used:** DeepSeek V3

DeepSeek V3 wrote the `_should_fire` cooldown function that fixed alert
flooding. When the cooldown appeared not to fire, DeepSeek V3 diagnosed the
cause as a stale Python bytecode cache; the fix was to set
`PYTHONDONTWRITEBYTECODE=1` and remove `__pycache__` directories. A
`DETECTOR_VERSION` constant was added so the running version could be
verified from the logs.

The three detector rules and their ATLAS mappings were written by DeepSeek
V3 and reviewed by me. Each rule's threshold was chosen by me after
considering the trade-off between sensitivity and false-positive rate.

---

## Task 7 — System Hardening

**Tools used:** DeepSeek V3

DeepSeek V3 proposed the categories of control needed to close the
system-level findings: disable interactive documentation in hardened mode,
add a CORS allowlist, run the container as a non-root user, set resource
limits, and move the API key out of the compose file into an environment
file.

I decided which controls to apply, how to apply them, and how to verify
them. Specifically:

- Interactive docs are disabled in hardened mode only, by passing
  `docs_url=None, redoc_url=None, openapi_url=None` to `FastAPI()`.
- CORS is permissive in vulnerable mode and restricted to a single origin
  in hardened mode.
- The Dockerfile runs as `appuser` (uid 1000) in both modes — the root run
  was a vulnerability in the original design, and the fix is unconditional.
- Memory and CPU limits are set per service in `docker-compose.yml`.
- The API key is read from `.env` with a fallback default.

DeepSeek V3 also helped diagnose two failures during the hardening pass: a
permissions error where the container could not write to
`logs/predictions.jsonl` because the file was root-owned while the
container runs as `appuser` (fix: `chown -R 1000:1000 logs/ results/`),
and an indentation error in `adapters/http.py` after editing (fix: rewrite
with correct indentation).

---

## Task 8 — Verification Script

**Tools used:** DeepSeek V3

DeepSeek V3 wrote the first draft of `scripts/verify.sh`. I fixed `python`
to `python3` after the first run. The script asserts eleven properties of
the running stack: both APIs' health endpoints, the docs availability on
each, authentication enforcement, container users, alerts API response
type, and memory-limit visibility. It exits with status 0 on success and 1
on any failure, so it can be used as a smoke test.

---

## Task 9 — Adversarial Training

**Tools used:** DeepSeek V3, Claude Sonnet, Google Colab (CPU)

The adversarial training design is mine: PGD-5 as the training attacker,
an epsilon ramp from 4/255 to 8/255 over five epochs, a 0.4/0.6
clean-to-adversarial loss weighting, and per-epoch robustness measurement.
DeepSeek V3 wrote the first draft of the training script to that design. I
reviewed it before running it.

Claude Sonnet reviewed the script and made three changes: computing the
gradient with `torch.autograd.grad` instead of `loss.backward()`, deriving
the valid clamp bounds from the normalization constants rather than
hardcoding them, and adding per-epoch robustness measurement on a held-out
subset. None of the three changed the final numbers.

Training ran on Google Colab, on a CPU fallback runtime, because no GPU was
available at that point. Twenty epochs took approximately 78 minutes.
Final numbers: clean accuracy 0.8555, FGSM accuracy 0.6680, PGD accuracy
0.6426, at ε = 8/255 on a 500-image evaluation set.

DeepSeek V3 explained the difference between FGSM and PGD as training
attackers; I verified the explanation against the Madry 2018 paper before
using it in the report.

---

## Task 10 — Robust Model Deployment

**Tools used:** DeepSeek V3

The robust model was placed in `model/artifacts/` and converted to
`.safetensors`. The conversion is what causes `defense/secure_loader.py` to
take the safe loading path instead of falling through to
`torch.load(weights_only=True)`, which is the concrete demonstration that
VULN-02 is closed on the hardened endpoint.

I changed the hardened service's `MODEL_PATH` in `docker-compose.yml` to
point at `baseline_robust.pt`, leaving the vulnerable service on the
original baseline. This is what makes the before/after comparison possible.

DeepSeek V3 diagnosed a bug in the evasion script where the same model was
being used for both the vulnerable and hardened sweeps; the fix was to add
a `--model-path` flag. The re-run against the hardened endpoint produced
the numbers reported in the defense section.

---

## Task 11 — Membership Inference

**Tools used:** DeepSeek V3

DeepSeek V3 wrote the first draft of the membership inference script. I
reviewed it and understood the threshold-classifier approach and the
majority-class baseline. DeepSeek V3 also added the `--sleep` flag needed
to throttle queries against the rate-limited hardened endpoint; I used it
to run both the vulnerable and hardened sweeps with matched sample sizes.

Both sweeps used the same random seed, so the member and non-member sets
are identical across the two endpoints. The results show a weak but
measurable signal on both, with the difference between endpoints falling
within binomial sampling error.

---

## Task 12 — Documentation

**Tools used:** DeepSeek V3

The structure of this usage log was designed with input from DeepSeek V3,
then written by me. The report structure and the README were drafted by me,
with AI assistance on phrasing and organization. All numbers in the report
and README come from the artifact files in `results/` and
`model/artifacts/` and were not predicted or estimated.

A cross-reference of every attack and defense against MITRE ATLAS
techniques and NIST AI RMF functions lives in
`report/atlas_nist_mapping.md`. The mapping was drafted by DeepSeek V3 and
verified against atlas.mitre.org and the NIST AI RMF 1.0 documentation
before adoption.

---

## How AI Was Used — Principles

Four principles governed every AI interaction.

**AI did not make decisions.** Every architectural choice was made after
reading the AI's explanation, verifying it against the task requirements,
and confirming it was the right call. AI offered options; I chose.

**AI did not run anything.** The AI wrote code that I ran. It had no shell
access, executed no attacks, and did not modify the repository. Every
command was typed, every commit was made, and every test was run by me.

**AI did not skip verification.** Every failure was debugged by reading the
actual error: read the traceback, isolate the cause, apply the fix, verify.
The AI helped identify likely causes; the verification was mine.

**AI did not overwrite judgment.** Where an AI suggestion conflicted with
the project's goals, it was rejected. The clearest example is the
`weights_only=True` suggestion for the vulnerable loader, which would have
removed the very vulnerability the assessment was built to demonstrate.

The task brief says: "You may use AI to help you, but never as an agent
that accomplishes the task for you." That boundary was respected
throughout.

---

## What AI Could Not Have Done

The architecture itself — the five-layer structure, the four containers,
the two security modes, and the deliberate vulnerability tagging scheme —
was designed by me. AI reviewed it. It did not invent it.

The ethical framing was mine. Every attack in this project targets a system
I built, on my own hardware, for the purpose of a security assessment. AI
does not enforce that boundary. I did.

The responsibility for the final submission is mine. The report, the video,
the presentation, and the answers in any Q&A are mine. If any part of the
submission is wrong, I am accountable.

The persistence through failure was mine. The AI suggested fixes; I applied
them, one after another, through Docker crashes, permission errors,
indentation bugs, and rate limits.

The judgment about what to cut was mine. The project could have included a
Telegram bot, a corrective blocklist, a backdoor attack, unit tests, or a
fuller defense pipeline. Choosing what to build and what to defer required
understanding the scoring rubric and the time available.

---

## Declaration

I declare that:

1. This log is complete and accurate.
2. Every AI tool used is recorded above.
3. Every AI-generated artifact was reviewed and understood before use.
4. The final submission is my own work, produced with AI as an assistant,
   not as an executor.
5. I can explain every line of code, every architectural decision, and
   every finding in the report.