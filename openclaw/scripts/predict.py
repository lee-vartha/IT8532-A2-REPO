#!/usr/bin/env python3

import json
import math
import sys
import urllib.request
import urllib.error

PREDICT_URL = "http://192.168.100.20:8080/predict"

# Locked during validation before final test evaluation.
DECISION_THRESHOLD = 0.10

# Human review boundary: ±0.02 around the decision threshold.
REVIEW_MARGIN = 0.02


def safe_result(reason):
    return {
        "status": "manual_review",
        "classification": "unknown",
        "human_review_required": True,
        "reason": reason,
    }


def main():
    if len(sys.argv) != 2:
        print(json.dumps(
            safe_result("Expected exactly one JSON feature object.")
        ))
        return 1

    try:
        features = json.loads(sys.argv[1])
    except json.JSONDecodeError:
        print(json.dumps(
            safe_result("Input is not valid JSON.")
        ))
        return 1

    if not isinstance(features, dict):
        print(json.dumps(
            safe_result("Features must be supplied as a JSON object.")
        ))
        return 1

    # Reject non-numeric and non-finite values before calling the model.
    for name, value in features.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            print(json.dumps(
                safe_result(f"Feature '{name}' is not numeric.")
            ))
            return 1

        if not math.isfinite(float(value)):
            print(json.dumps(
                safe_result(f"Feature '{name}' is not finite.")
            ))
            return 1

    payload = json.dumps({"features": features}).encode("utf-8")

    request = urllib.request.Request(
        PREDICT_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as exc:
        print(json.dumps(
            safe_result(f"Prediction service rejected input with HTTP {exc.code}.")
        ))
        return 1

    except (urllib.error.URLError, TimeoutError):
        print(json.dumps(
            safe_result("Prediction service unavailable.")
        ))
        return 1

    except (json.JSONDecodeError, ValueError):
        print(json.dumps(
            safe_result("Prediction service returned an invalid response.")
        ))
        return 1

    required = {
        "classification",
        "malware_probability",
        "decision_threshold",
    }

    if not required.issubset(result):
        print(json.dumps(
            safe_result("Prediction response is missing required fields.")
        ))
        return 1

    try:
        probability = float(result["malware_probability"])
        threshold = float(result["decision_threshold"])
    except (TypeError, ValueError):
        print(json.dumps(
            safe_result("Prediction response contains invalid numeric values.")
        ))
        return 1

    if not math.isfinite(probability) or not math.isfinite(threshold):
        print(json.dumps(
            safe_result("Prediction response contains non-finite values.")
        ))
        return 1

    # Do not allow the service threshold to silently differ from the
    # threshold locked during model validation.
    if abs(threshold - DECISION_THRESHOLD) > 1e-9:
        print(json.dumps(
            safe_result("Prediction service threshold does not match the locked threshold.")
        ))
        return 1

    boundary_distance = abs(probability - threshold)

    human_review_required = boundary_distance <= REVIEW_MARGIN

    output = {
        "status": "ok",
        "classification": result["classification"],
        "malware_probability": probability,
        "decision_threshold": threshold,
        "human_review_required": human_review_required,
        "guardrail": (
            "near_threshold"
            if human_review_required
            else "none"
        ),
    }

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())

