from pathlib import Path
import json

import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from xgboost import XGBClassifier


# -------------------------------------------------
# Paths
# -------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"

MODEL_PATH = MODEL_DIR / "shredr_xgboost.json"
FEATURE_PATH = MODEL_DIR / "shredr_features.json"
CONFIG_PATH = MODEL_DIR / "shredr_model_config.json"


# -------------------------------------------------
# Load model artefacts
# -------------------------------------------------

model = XGBClassifier()
model.load_model(MODEL_PATH)

with open(FEATURE_PATH, "r") as f:
    expected_features = json.load(f)

with open(CONFIG_PATH, "r") as f:
    model_config = json.load(f)

DECISION_THRESHOLD = model_config["decision_threshold"]


# -------------------------------------------------
# API
# -------------------------------------------------

app = FastAPI(
    title="SHREDR AI Prediction Service",
    description=(
        "XGBoost malware-risk prediction service for the "
        "SHREDR AI malware triage prototype."
    ),
    version="1.0.0"
)


class PredictionRequest(BaseModel):
    features: dict[str, float]


@app.get("/health", tags=["System"])
def health():
    return {
        "status": "ok",
        "model": "SHREDR XGBoost",
        "feature_count": len(expected_features),
        "threshold": DECISION_THRESHOLD
    }


@app.post("/predict", tags=["Prediction"])
def predict(request: PredictionRequest):

    supplied_features = set(request.features.keys())
    required_features = set(expected_features)

    missing_features = sorted(
        required_features - supplied_features
    )

    extra_features = sorted(
        supplied_features - required_features
    )

    if missing_features:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "missing_features",
                "count": len(missing_features),
                "features": missing_features
            }
        )

    if extra_features:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unexpected_features",
                "count": len(extra_features),
                "features": extra_features
            }
        )

    try:
        ordered_values = [
            float(request.features[feature])
            for feature in expected_features
        ]

    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_feature_value",
                "message": "All feature values must be numeric."
            }
        )

    input_df = pd.DataFrame(
        [ordered_values],
        columns=expected_features
    )

    probability = float(
        model.predict_proba(input_df)[0, 1]
    )

    predicted_class = (
        1 if probability >= DECISION_THRESHOLD else 0
    )

    classification = (
        model_config["positive_class_name"]
        if predicted_class == 1
        else model_config["negative_class_name"]
    )

    return {
        "classification": classification,
        "class_id": predicted_class,
        "malware_probability": round(probability, 6),
        "decision_threshold": DECISION_THRESHOLD,
        "feature_count": len(expected_features)
    }

# -------------------------------------------------
# Demonstration endpoints
# -------------------------------------------------

EXAMPLE_DIR = BASE_DIR / "api" / "examples"


def load_example(filename: str):
    example_path = EXAMPLE_DIR / filename

    with open(example_path, "r") as f:
        example_data = json.load(f)

    return PredictionRequest(**example_data)


@app.get("/demo/benign", tags=["Demonstration"])
def demo_benign():
    request = load_example("benign_example.json")

    result = predict(request)

    return {
        "example": "benign",
        "expected_class": "benign",
        "prediction": result
    }


@app.get("/demo/malware", tags=["Demonstration"])
def demo_malware():
    request = load_example("malware_example.json")

    result = predict(request)

    return {
        "example": "malware",
        "expected_class": "malware",
        "prediction": result
    }