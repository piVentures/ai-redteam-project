"""
System-level attack script.

Documents infrastructure and metadata weaknesses in the Docker pipeline.

Each finding is captured to results/system/ as structured evidence.
The script does not modify anything. It observes and records.

MITRE ATLAS: AML.T0000, T0007, T0010, T0024
NIST AI RMF: MAP (MP-2), GOVERN (GV-6), MEASURE (MS-2)
"""
import argparse
import json
import os
import subprocess
import time

import requests


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--vuln", default="http://localhost:8000")
    p.add_argument("--hardened", default="http://localhost:8001")
    p.add_argument("--api-key", default="dev-local-key-change-me")
    p.add_argument("--output-dir", default="results/system")
    p.add_argument("--rate-test-count", type=int, default=200)
    return p.parse_args()


def sh(cmd):
    """Run a shell command, return stdout as string."""
    try:
        return subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, text=True
        )
    except subprocess.CalledProcessError as e:
        return e.output


# ============================================================
# Finding 1 — /model-info architecture leak
# ============================================================

def finding_model_info(vuln, hardened, api_key, out_dir):
    print("[1] /model-info architecture leak (AML.T0007)")

    # Vulnerable
    try:
        r = requests.get(f"{vuln}/model-info", timeout=10)
        vuln_result = {
            "status": r.status_code,
            "body": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text,
        }
    except Exception as e:
        vuln_result = {"error": str(e)}

    # Hardened
    try:
        r = requests.get(f"{hardened}/model-info", timeout=10)
        hard_result = {
            "status": r.status_code,
            "body": r.text[:200],
        }
    except Exception as e:
        hard_result = {"error": str(e)}

    evidence = {
        "finding": "model_info_leak",
        "atlas": "AML.T0007",
        "vulnerable": vuln_result,
        "hardened": hard_result,
        "notes": "Vulnerable endpoint returns full architecture, class list, "
                 "parameter count, and torch version. Hardened endpoint returns 404."
    }

    with open(os.path.join(out_dir, "01_model_info.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"    vuln status: {vuln_result.get('status')}")
    print(f"    hardened status: {hard_result.get('status')}")
    return evidence


# ============================================================
# Finding 2 — Verbose error traces
# ============================================================

def finding_verbose_errors(vuln, hardened, api_key, out_dir):
    print("[2] Verbose error traces (AML.T0007)")

    # Send a malformed "image"
    files = {"file": ("bad.txt", b"not an image", "text/plain")}

    try:
        r = requests.post(f"{vuln}/predict", files=files, timeout=10)
        vuln_result = {"status": r.status_code, "body": r.text[:2000]}
    except Exception as e:
        vuln_result = {"error": str(e)}

    try:
        r = requests.post(
            f"{hardened}/predict",
            files={"file": ("bad.txt", b"not an image", "text/plain")},
            headers={"x-api-key": api_key},
            timeout=10,
        )
        hard_result = {"status": r.status_code, "body": r.text[:500]}
    except Exception as e:
        hard_result = {"error": str(e)}

    evidence = {
        "finding": "verbose_error_traces",
        "atlas": "AML.T0007",
        "vulnerable": vuln_result,
        "hardened": hard_result,
        "notes": "Vulnerable returns a full stack trace with file paths and "
                 "library versions. Hardened returns a generic error."
    }

    with open(os.path.join(out_dir, "02_verbose_errors.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"    vuln status: {vuln_result.get('status')}")
    print(f"    hardened status: {hard_result.get('status')}")
    return evidence


# ============================================================
# Finding 3 — No rate limiting on vulnerable API
# ============================================================

def finding_no_rate_limit(vuln, out_dir, count=200):
    print(f"[3] No rate limiting on vulnerable API (AML.T0024)")
    print(f"    sending {count} rapid requests...")

    ok = 0
    rate_limited = 0
    errors = 0
    t0 = time.time()

    for i in range(count):
        try:
            r = requests.get(f"{vuln}/health", timeout=5)
            if r.status_code == 200:
                ok += 1
            elif r.status_code == 429:
                rate_limited += 1
            else:
                errors += 1
        except Exception:
            errors += 1

    elapsed = time.time() - t0
    rps = count / elapsed if elapsed > 0 else 0

    evidence = {
        "finding": "no_rate_limit_vulnerable",
        "atlas": "AML.T0024",
        "requests_sent": count,
        "ok": ok,
        "rate_limited": rate_limited,
        "errors": errors,
        "elapsed_seconds": round(elapsed, 2),
        "requests_per_second": round(rps, 2),
        "notes": f"{count} requests sent in {elapsed:.1f}s at {rps:.1f} req/s. "
                 f"{ok} succeeded, {rate_limited} were rate-limited. "
                 f"The vulnerable API has no rate limit.",
    }

    with open(os.path.join(out_dir, "03_no_rate_limit.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"    ok: {ok} | rate_limited: {rate_limited} | errors: {errors}")
    print(f"    {rps:.1f} req/s")
    return evidence


# ============================================================
# Finding 4 — Auto-docs exposed
# ============================================================

def finding_docs_exposed(vuln, out_dir):
    print("[4] Auto-docs exposed (AML.T0007)")

    try:
        r = requests.get(f"{vuln}/docs", timeout=10)
        status = r.status_code
        length = len(r.text)
    except Exception as e:
        status = "error"
        length = 0

    try:
        r_openapi = requests.get(f"{vuln}/openapi.json", timeout=10)
        openapi = r_openapi.json() if r_openapi.ok else {}
        endpoints = list(openapi.get("paths", {}).keys())
    except Exception:
        endpoints = []

    evidence = {
        "finding": "auto_docs_exposed",
        "atlas": "AML.T0007",
        "docs_status": status,
        "docs_length": length,
        "openapi_endpoints": endpoints,
        "notes": "FastAPI auto-generates /docs and /openapi.json. These are "
                 "disabled in hardened mode but exposed on the vulnerable API. "
                 "An attacker can map the entire API surface without any "
                 "guesswork."
    }

    with open(os.path.join(out_dir, "04_docs_exposed.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"    /docs status: {status}")
    print(f"    endpoints in openapi: {len(endpoints)}")
    return evidence


# ============================================================
# Finding 5 — Env-var secrets in container
# ============================================================

def finding_env_secrets(out_dir):
    print("[5] Environment variable secret exposure (AML.T0010)")

    raw = sh("docker inspect redteam-api-hardened --format '{{json .Config.Env}}'")
    try:
        env = json.loads(raw.strip())
    except Exception:
        env = raw

    evidence = {
        "finding": "env_var_secrets",
        "atlas": "AML.T0010",
        "raw": env,
        "notes": "The API key is exposed in plaintext in the container's "
                 "environment. Any process with access to the Docker daemon "
                 "(or the container) can read it. In production this should "
                 "come from a secret store."
    }

    with open(os.path.join(out_dir, "05_env_secrets.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    # Search for the API key
    if isinstance(env, list):
        api_key_lines = [line for line in env if "API_KEY" in line]
        print(f"    API_KEY lines found: {len(api_key_lines)}")
    return evidence


# ============================================================
# Finding 6 — Root container
# ============================================================

def finding_root_user(out_dir):
    print("[6] Container runs as root (AML.T0000)")

    whoami = sh("docker compose exec -T api-vuln whoami").strip()
    id_output = sh("docker compose exec -T api-vuln id").strip()

    evidence = {
        "finding": "root_container",
        "atlas": "AML.T0000",
        "whoami": whoami,
        "id": id_output,
        "notes": "The container runs as root. A compromise of the FastAPI "
                 "process (e.g., via unsafe torch.load) inherits container-root. "
                 "A non-root user would limit the blast radius."
    }

    with open(os.path.join(out_dir, "06_root_container.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"    whoami: {whoami}")
    return evidence


# ============================================================
# Finding 7 — Volume mounts expose host paths
# ============================================================

def finding_volume_mounts(out_dir):
    print("[7] Volume mounts expose host paths (AML.T0000)")

    raw = sh("docker inspect redteam-api-vuln --format '{{json .Mounts}}'")
    try:
        mounts = json.loads(raw.strip())
    except Exception:
        mounts = raw

    evidence = {
        "finding": "volume_mounts_exposed",
        "atlas": "AML.T0000",
        "mounts": mounts,
        "notes": "Logs and results are mounted from the host. An attacker who "
                 "achieves container compromise can tamper with logs or write "
                 "to results. The model directory is read-only, which limits "
                 "some attacks."
    }

    with open(os.path.join(out_dir, "07_volume_mounts.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    if isinstance(mounts, list):
        print(f"    mounts found: {len(mounts)}")
    return evidence


# ============================================================
# Finding 8 — No resource limits
# ============================================================

def finding_no_resource_limits(out_dir):
    print("[8] No resource limits (DoS via exhaustion)")

    raw = sh("docker inspect redteam-api-vuln --format '{{json .HostConfig}}'")
    try:
        host_config = json.loads(raw.strip())
    except Exception:
        host_config = {}

    memory = host_config.get("Memory", 0)
    cpu_quota = host_config.get("CpuQuota", 0)

    evidence = {
        "finding": "no_resource_limits",
        "atlas": "—",
        "memory_limit": memory,
        "cpu_quota": cpu_quota,
        "notes": "The container has no memory limit and no CPU quota. A "
                 "malicious client can exhaust host resources by sending "
                 "large or numerous requests, causing a denial of service "
                 "for other containers or the host itself."
    }

    with open(os.path.join(out_dir, "08_no_resource_limits.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"    Memory limit: {memory} bytes (0 = unlimited)")
    print(f"    CPU quota: {cpu_quota}")
    return evidence


# ============================================================
# Finding 9 — CORS behavior (documented, not tested via browser)
# ============================================================

def finding_cors(vuln, out_dir):
    print("[9] CORS behavior (documented)")

    # Send a preflight-like request with an Origin header
    headers = {"Origin": "http://localhost:3000"}
    try:
        r = requests.options(f"{vuln}/predict", headers=headers, timeout=10)
        acao = r.headers.get("access-control-allow-origin", "not set")
        status = r.status_code
    except Exception as e:
        acao = f"error: {e}"
        status = 0

    evidence = {
        "finding": "cors_behavior",
        "atlas": "AML.T0000",
        "origin_sent": "http://localhost:3000",
        "response_status": status,
        "access_control_allow_origin": acao,
        "notes": "The vulnerable API does not set CORS headers explicitly. "
                 "FastAPI's default allows the browser to make requests from "
                 "any origin. A malicious page can therefore send requests "
                 "to the API on behalf of the user. Documented as a residual "
                 "risk. Full browser-based verification is in the testing "
                 "console at http://localhost:3000."
    }

    with open(os.path.join(out_dir, "09_cors.json"), "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"    Origin sent: http://localhost:3000")
    print(f"    ACAO header: {acao}")
    return evidence


# ============================================================
# Main
# ============================================================

def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs(os.path.join(args.output_dir, "screenshots"), exist_ok=True)

    findings = []

    findings.append(finding_model_info(args.vuln, args.hardened, args.api_key, args.output_dir))
    findings.append(finding_verbose_errors(args.vuln, args.hardened, args.api_key, args.output_dir))
    findings.append(finding_no_rate_limit(args.vuln, args.output_dir, args.rate_test_count))
    findings.append(finding_docs_exposed(args.vuln, args.output_dir))
    findings.append(finding_env_secrets(args.output_dir))
    findings.append(finding_root_user(args.output_dir))
    findings.append(finding_volume_mounts(args.output_dir))
    findings.append(finding_no_resource_limits(args.output_dir))
    findings.append(finding_cors(args.vuln, args.output_dir))

    # Write summary
    summary_path = os.path.join(args.output_dir, "findings_summary.json")
    with open(summary_path, "w") as f:
        json.dump(findings, f, indent=2, default=str)

    print()
    print("=" * 60)
    print(f"Total findings captured: {len(findings)}")
    print(f"Evidence saved to: {args.output_dir}/")
    print(f"Summary: {summary_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
