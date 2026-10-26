"""Small FastAPI service that returns an ML risk score (0-100) for a login's signals."""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel, Field

bundle = joblib.load(Path(__file__).resolve().parent / "models" / "rf.joblib")
MODEL, FEATURES = bundle["model"], bundle["features"]

app = FastAPI(title="Risk ML service")


class Signals(BaseModel):
    first_login: int = Field(ge=0, le=1)
    new_device: int = Field(ge=0, le=1)
    new_country: int = Field(ge=0, le=1)
    unusual_hour: int = Field(ge=0, le=1)
    failed_by_email: int = Field(ge=0, le=1000)
    failed_by_ip: int = Field(ge=0, le=100000)
    hour: int = Field(ge=0, le=23)
    is_weekend: int = Field(ge=0, le=1)


@app.get("/health")
def health():
    return {"status": "ok", "features": FEATURES}


@app.post("/predict")
def predict(s: Signals):
    row = s.model_dump()
    row["hour_sin"] = float(np.sin(2 * np.pi * row["hour"] / 24))
    row["hour_cos"] = float(np.cos(2 * np.pi * row["hour"] / 24))
    X = pd.DataFrame([row])[FEATURES]
    p = float(MODEL.predict_proba(X)[0, 1])
    return {"ml_score": int(round(p * 100)), "probability": round(p, 4)}