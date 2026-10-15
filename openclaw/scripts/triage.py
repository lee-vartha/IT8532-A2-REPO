#!/usr/bin/env python3

import json
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PREDICT_SCRIPT = BASE_DIR / "predict.py"

LLM_URL = "http://192.168.100.20:8001/v1/chat/completions"
LLM_MODEL = "shredr-tuned"

GITEA_URL = "http://192.168.100.22:3000"
GITEA_OWNER = "beetle"
GITEA_REPO = "shredr-incidents"
TOKEN_FILE = Path("/home/openclaw/.config/shredr/gitea-token")


def output_result(data, exit_code=0):
    print(json.dumps(data, indent=2))
    sys.exit(exit_code)


def main():
    if len(sys.argv) != 2:
        output_result({
            "status": "manual_review",
            "reason": "Expected exactly one JSON feature object."
        }, 1)

    feature_json = sys.argv[1]

    # ---------------------------------------------------------
    # 1. Run existing deterministic classifier + guardrails
    # ---------------------------------------------------------

    try:
        result = subprocess.run(
            [sys.executable, str(PREDICT_SCRIPT), feature_json],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        output_result({
            "status": "manual_review",
            "reason": "Prediction helper timed out."
        }, 1)

    try:
        prediction = json.loads(result.stdout)
    except json.JSONDecodeError:
        output_result({
            "status": "manual_review",
            "reason": "Prediction helper returned invalid output."
        }, 1)

    # Stop safely on prediction failure.
    if prediction.get("status") != "ok":
        output_result({
            "status": "manual_review",
            "stage": "prediction",
            "prediction": prediction,
            "reason": prediction.get(
                "reason",
                "Prediction failed."
            )
        })

    # Stop safely for near-threshold predictions.
    if prediction.get("human_review_required") is True:
        output_result({
            "status": "manual_review",
            "stage": "guardrail",
            "prediction": prediction,
            "reason": "Prediction is within the locked near-threshold review boundary."
        })

    # ---------------------------------------------------------
    # 2. Ask tuned SHREDR model to generate incident report
    # ---------------------------------------------------------

    classification = prediction["classification"]
    probability = prediction["malware_probability"]
    threshold = prediction["decision_threshold"]

    prompt = f"""
Generate a concise SHREDR malware triage report.

Use ONLY the classifier evidence supplied below.
Do not invent malware indicators, file behaviour, signatures,
family names, or technical evidence.

Classification: {classification}
Malware probability: {probability:.6f}
Decision threshold: {threshold:.2f}
Human review required: {prediction["human_review_required"]}
Guardrail: {prediction["guardrail"]}

The report must contain:
Risk assessment:
Evidence interpretation:
Recommended action:
"""

    llm_payload = json.dumps({
        "model": LLM_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are SHREDR AI, a malware triage assistant. "
                    "Use only supplied evidence. Do not invent malware "
                    "indicators or claim certainty beyond classifier evidence."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0,
        "max_tokens": 300
    }).encode("utf-8")

    llm_request = urllib.request.Request(
        LLM_URL,
        data=llm_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(llm_request, timeout=60) as response:
            llm_result = json.loads(response.read().decode("utf-8"))

        report = llm_result["choices"][0]["message"]["content"].strip()

        if not report:
            raise ValueError("Empty model response")

    except Exception as exc:
        output_result({
            "status": "manual_review",
            "stage": "language_model",
            "prediction": prediction,
            "reason": f"Language model failed: {type(exc).__name__}"
        }, 1)

    # ---------------------------------------------------------
    # 3. Create exactly one Gitea incident issue
    # ---------------------------------------------------------

    try:
        token = TOKEN_FILE.read_text().strip()

        if not token:
            raise ValueError("Empty Gitea token")

    except Exception:
        output_result({
            "status": "manual_review",
            "stage": "gitea",
            "prediction": prediction,
            "report": report,
            "reason": "Gitea token unavailable."
        }, 1)

    title = (
        f"SHREDR Incident - "
        f"{classification.upper()} - "
        f"{probability:.1%}"
    )

    body = f"""# SHREDR AI Incident Report

{report}

## Verified classifier evidence

- Classification: `{classification}`
- Malware probability: `{probability:.6f}`
- Decision threshold: `{threshold:.2f}`
- Human review required: `{prediction["human_review_required"]}`
- Guardrail: `{prediction["guardrail"]}`

---
Generated by the SHREDR AI malware triage subsystem.
No executable was executed, modified, uploaded, deleted, or quarantined.
"""

    issue_payload = json.dumps({
        "title": title,
        "body": body
    }).encode("utf-8")

    issue_request = urllib.request.Request(
        f"{GITEA_URL}/api/v1/repos/{GITEA_OWNER}/{GITEA_REPO}/issues",
        data=issue_payload,
        headers={
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(issue_request, timeout=15) as response:
            issue = json.loads(response.read().decode("utf-8"))

        issue_number = issue["number"]
        issue_url = issue["html_url"]

    except Exception as exc:
        output_result({
            "status": "manual_review",
            "stage": "gitea",
            "prediction": prediction,
            "report": report,
            "reason": f"Gitea issue creation failed: {type(exc).__name__}"
        }, 1)

    # ---------------------------------------------------------
    # STOPPING CONDITION
    # ---------------------------------------------------------
    # Successful workflow terminates immediately after exactly
    # one Gitea issue has been returned by the Gitea API.

    output_result({
        "status": "completed",
        "prediction": prediction,
        "report": report,
        "gitea_issue_number": issue_number,
        "gitea_issue_url": issue_url,
        "stopping_condition": "One verified Gitea incident issue created."
    })


if __name__ == "__main__":
    main()
