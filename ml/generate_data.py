"""Generate a synthetic login dataset for the risk model.

Each row is the signal vector the Java framework computes at login time
(see ContextSignals), labelled 1 if the login was an attack.
The data is synthetic: it encodes assumptions about genuine users and attackers.
"""
from pathlib import Path

import numpy as np
import pandas as pd

OUT_DIR = Path(__file__).resolve().parent.parent / "datasets"

NIGHT_W = np.ones(24)
NIGHT_W[0:6] = 4.0           # hours 00-05 are 4x more likely
NIGHT_W = NIGHT_W / NIGHT_W.sum()


def hours_normal(rng, n):
    return np.round(rng.normal(15, 4.5, n)).astype(int) % 24


def hours_night(rng, n):
    return rng.choice(24, size=n, p=NIGHT_W)


def bern(rng, n, p):
    return rng.random(n) < p


def frame(first, nd, nc, odd, fe, fi, hour, weekend, label, scenario):
    return pd.DataFrame({
        "first_login": first.astype(int),
        "new_device": nd.astype(int),
        "new_country": nc.astype(int),
        "unusual_hour": odd.astype(int),
        "failed_by_email": np.asarray(fe).astype(int),
        "failed_by_ip": np.asarray(fi).astype(int),
        "hour": np.asarray(hour).astype(int),
        "is_weekend": weekend.astype(int),
        "is_attack": label,
        "scenario": scenario,
    })


def legit(rng, n):
    """Genuine users: mostly familiar, with realistic noise (new phone, travel, typos)."""
    first = bern(rng, n, 0.03)
    new_country = bern(rng, n, 0.03) & ~first
    new_device = np.where(new_country, bern(rng, n, 0.30), bern(rng, n, 0.06)) & ~first
    unusual = np.where(new_country, bern(rng, n, 0.40), bern(rng, n, 0.10)) & ~first
    failed_email = rng.choice(5, size=n, p=[0.88, 0.08, 0.03, 0.008, 0.002])
    failed_ip = np.where(bern(rng, n, 0.05), rng.integers(1, 4, n), 0)   # shared networks
    hour = np.where(unusual, hours_night(rng, n), hours_normal(rng, n))
    weekend = bern(rng, n, 0.28)
    return frame(first, new_device, new_country, unusual, failed_email, failed_ip,
                 hour, weekend, 0, "legit")


def attack(rng, n, kind, hard):
    if kind == "stuffing":        # many accounts tried from one IP
        fe, fi = rng.integers(0, 3, n), rng.integers(5, 41, n)
        p_dev, p_ctry, p_odd = 0.95, 0.70, 0.50
    elif kind == "stolen":        # correct stolen password, used once
        fe, fi = rng.choice(2, size=n, p=[0.85, 0.15]), rng.integers(0, 3, n)
        p_dev, p_ctry, p_odd = 0.97, 0.85, 0.55
    elif kind == "brute":         # guessing one account
        # the Java hard rule blocks at 5 failures, so scored attempts have at most 4
        fe, fi = rng.integers(3, 5, n), rng.integers(1, 21, n)
        p_dev, p_ctry, p_odd = 0.90, 0.50, 0.50
    else:                         # "takeover": attacker in the victim's own country
        fe, fi = rng.choice(2, size=n, p=[0.90, 0.10]), rng.integers(0, 2, n)
        p_dev, p_ctry, p_odd = 0.95, 0.05, 0.40

    if hard:   # sophisticated: cloned fingerprints, local proxies, slow and quiet
        p_dev, p_ctry = p_dev * 0.35, p_ctry * 0.35
        fe = np.minimum(fe, rng.integers(0, 3, n))
        fi = np.minimum(fi, rng.integers(0, 3, n))

    nd, nc, odd = bern(rng, n, p_dev), bern(rng, n, p_ctry), bern(rng, n, p_odd)
    hour = np.where(odd, hours_night(rng, n), hours_normal(rng, n))
    first = np.zeros(n, dtype=bool)
    return frame(first, nd, nc, odd, fe, fi, hour, bern(rng, n, 0.30), 1, kind)


def build(seed, n_legit, attack_counts, hard):
    rng = np.random.default_rng(seed)
    parts = [legit(rng, n_legit)]
    for kind, n in attack_counts.items():
        parts.append(attack(rng, n, kind, hard))
    df = pd.concat(parts, ignore_index=True)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


if __name__ == "__main__":
    OUT_DIR.mkdir(exist_ok=True)
    std = build(42, 28200, {"stuffing": 600, "stolen": 600, "brute": 300, "takeover": 300}, hard=False)
    hard = build(7, 5640, {"stuffing": 120, "stolen": 120, "brute": 60, "takeover": 60}, hard=True)
    std.to_csv(OUT_DIR / "logins.csv", index=False)
    hard.to_csv(OUT_DIR / "logins_hard.csv", index=False)
    for name, d in (("logins.csv", std), ("logins_hard.csv", hard)):
        print(f"{name}: {len(d)} rows, attack rate {d['is_attack'].mean():.1%}")
        print(d["scenario"].value_counts().to_string(), "\n")