#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║            HDT ENGINE  —  Hybrid Detection Tapestry Algorithm Core          ║
║            Testimony Chimberengwa R236592N | BSc Computer Engineering       ║
║                                                                              ║
║  This module implements the four-layer HDT detection stack:                 ║
║                                                                              ║
║   L1 — Adaptive Gaussian Mixture Model (GMM)                                ║
║         EM fitting with exponential forgetting factor λ=0.05                ║
║         Detects: anomalous byte volumes per connection entity               ║
║                                                                              ║
║   L2 — Global Kernel Density Estimator (KDE)                                ║
║         Scott's Rule bandwidth, rolling observation window                  ║
║         Detects: traffic entering historically low-density feature space    ║
║                                                                              ║
║   L3 — LOWESS Trend Analyser                                                ║
║         Locally Weighted Scatterplot Smoothing via statsmodels              ║
║         Detects: rising byte-volume gradient over time (exfil ramp-up)     ║
║                                                                              ║
║   ADS — Adversarial Drift Sentinel                                          ║
║         Signed anchor snapshot of GMM parameters at baseline                ║
║         Detects: when μk has been re-baselined by slow poisoning attacks    ║
║                                                                              ║
║  All layers are unsupervised — they self-baseline from observed traffic.    ║
║  No training data required. Proof-of-concept implementation.                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import numpy as np
import time
import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from scipy.stats import gaussian_kde

# Try importing statsmodels, fallback to simple weighted regression if lowess is unavailable
try:
    from statsmodels.nonparametric.smoothers_lowess import lowess
    HAS_LOWESS = True
except ImportError:
    HAS_LOWESS = False


# ─────────────────────────────────────────────────────────────────────────────
# SHARED CONSTANTS  (match your Chapter 3 methodology values)
# ─────────────────────────────────────────────────────────────────────────────

LAMBDA           = 0.05    # exponential forgetting factor for GMM
N_COMPONENTS     = 3       # GMM mixture components (low / normal / high traffic)
MIN_OBS          = 8       # minimum observations before scoring is active
LOWESS_FRAC      = 0.4     # LOWESS smoothing fraction
ADS_DRIFT_THRESH = 0.30    # 30% parameter drift triggers ADS alert
KDE_WINDOW       = 60      # max observations in KDE rolling window
LOWESS_WINDOW    = 20      # observations used for LOWESS trend analysis

# Fusion layer weights  (L1, L2, L3, ADS)
FUSION_WEIGHTS   = [0.25, 0.35, 0.25, 0.15]

# Alert thresholds
THRESH_LOW       = 0.35
THRESH_MEDIUM    = 0.55
THRESH_HIGH      = 0.75


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConnectionRecord:
    """One observed network connection — the atomic unit of HDT analysis."""
    src_ip:        str
    src_port:      int
    dst_port:      int
    byte_count:    int
    timestamp:     float = field(default_factory=time.time)
    payload_label: str   = ""

    @property
    def kb(self):
        return self.byte_count / 1024

    @property
    def mb(self):
        return self.byte_count / (1024 * 1024)


@dataclass
class LayerScores:
    """Score bundle from one full HDT evaluation pass."""
    l1_gmm:    float = 0.0
    l2_kde:    float = 0.0
    l3_lowess: float = 0.0
    ads:       float = 0.0
    fusion:    float = 0.0
    alert:     str   = "MONITORING"
    obs_count: int   = 0


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 — ADAPTIVE GMM with EM + Exponential Forgetting
# ─────────────────────────────────────────────────────────────────────────────

class AdaptiveGMM:
    """
    Online Gaussian Mixture Model with exponential forgetting.
    """

    def __init__(self, n_components=N_COMPONENTS, lam=LAMBDA):
        self.K    = n_components
        self.lam  = lam
        self.means_   = None
        self.vars_    = None
        self.weights_ = None
        self.n_obs    = 0
        self.history  = deque(maxlen=200)

    def _init_params(self, X):
        self.means_   = np.percentile(X, [20, 50, 80]).astype(float)
        self.vars_    = np.full(self.K, np.var(X) + 1e-6)
        self.weights_ = np.ones(self.K) / self.K

    def _gaussian(self, x, mu, sigma2):
        sigma2 = max(sigma2, 1e-6)
        return (1.0 / np.sqrt(2 * np.pi * sigma2)) * np.exp(
            -0.5 * ((x - mu) ** 2) / sigma2
        )

    def _e_step(self, x):
        r = np.array([
            self.weights_[k] * self._gaussian(x, self.means_[k], self.vars_[k])
            for k in range(self.K)
        ])
        total = r.sum()
        return r / total if total > 1e-300 else np.ones(self.K) / self.K

    def _m_step_online(self, x, r):
        for k in range(self.K):
            w_new  = (1 - self.lam) * self.weights_[k] + self.lam * r[k]
            mu_new = (
                (1 - self.lam) * self.weights_[k] * self.means_[k]
                + self.lam * r[k] * x
            ) / (w_new + 1e-300)
            var_new = (
                (1 - self.lam) * self.weights_[k] * (
                    self.vars_[k] + (self.means_[k] - mu_new) ** 2
                )
                + self.lam * r[k] * (x - mu_new) ** 2
            ) / (w_new + 1e-300) + 1e-6
            self.means_[k]   = mu_new
            self.vars_[k]    = var_new
            self.weights_[k] = w_new
        self.weights_ /= self.weights_.sum()

    def update_and_score(self, x):
        self.history.append(x)
        self.n_obs += 1
        if self.n_obs == MIN_OBS:
            self._init_params(np.array(self.history))
            return 0.0
        if self.means_ is None:
            return 0.0
        r = self._e_step(x)
        self._m_step_online(x, r)
        likelihood = sum(
            self.weights_[k] * self._gaussian(x, self.means_[k], self.vars_[k])
            for k in range(self.K)
        )
        peak = max(
            self.weights_[k] * self._gaussian(
                self.means_[k], self.means_[k], self.vars_[k]
            )
            for k in range(self.K)
        )
        score = 1.0 - min(likelihood / (peak + 1e-300), 1.0)
        return float(np.clip(score, 0.0, 1.0))

    def get_params(self):
        if self.means_ is None:
            return {}
        return {
            "means":   self.means_.tolist(),
            "vars":    self.vars_.tolist(),
            "weights": self.weights_.tolist(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 2 — GLOBAL KDE with Scott's Rule Bandwidth
# ─────────────────────────────────────────────────────────────────────────────

class GlobalKDE:
    """
    Kernel Density Estimator over the global byte-volume feature space.
    """

    def __init__(self, window=KDE_WINDOW):
        self.window       = window
        self.obs          = deque(maxlen=window)
        self._kde         = None
        self._max_density = 1.0

    def _scotts_bandwidth(self, data):
        n = len(data)
        if n < 2:
            return 1.0
        return n ** (-0.2) * np.std(data)

    def update_and_score(self, x):
        self.obs.append(x)
        if len(self.obs) < MIN_OBS:
            return 0.0
        data      = np.array(self.obs)
        bw        = self._scotts_bandwidth(data)
        bw_factor = bw / (np.std(data) + 1e-9)
        try:
            self._kde = gaussian_kde(data, bw_method=float(bw_factor))
        except Exception:
            return 0.0
        density_at_x      = float(self._kde.evaluate(np.array([x]))[0])
        peak              = float(self._kde.evaluate(np.array([np.mean(data)]))[0])
        self._max_density = max(self._max_density, peak)
        score             = 1.0 - min(density_at_x / (self._max_density + 1e-300), 1.0)
        return float(np.clip(score, 0.0, 1.0))


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 3 — LOWESS TREND ANALYSER
# ─────────────────────────────────────────────────────────────────────────────

class LOWESSTrend:
    """
    LOWESS trend detector using statsmodels sequence regression.
    """

    def __init__(self, window=LOWESS_WINDOW, frac=LOWESS_FRAC):
        self.window      = window
        self.frac        = frac
        self.history     = deque(maxlen=window)
        self._last_slope     = 0.0
        self._max_slope_seen = 1.0

    def update_and_score(self, x):
        self.history.append(x)
        if len(self.history) < max(6, int(self.window * self.frac) + 1):
            return 0.0
        y = np.array(self.history, dtype=float)
        t = np.arange(len(y), dtype=float)
        
        # Check if we can smooth using statsmodels lowess
        if HAS_LOWESS:
            try:
                smoothed = lowess(y, t, frac=self.frac, it=3, return_sorted=False)
            except Exception:
                smoothed = self._fallback_smoothing(y)
        else:
            smoothed = self._fallback_smoothing(y)
            
        if len(smoothed) < 4:
            return 0.0
        diffs = np.diff(smoothed[-4:])
        slope = float(np.mean(diffs))
        self._last_slope     = slope
        self._max_slope_seen = max(self._max_slope_seen, abs(slope))
        if slope <= 0:
            return 0.0
        score = slope / (self._max_slope_seen + 1e-9)
        return float(np.clip(score, 0.0, 1.0))

    def _fallback_smoothing(self, y):
        # A simple rolling exponential fallback to compute a smooth trajectory without statsmodels
        smoothed = []
        alpha = 0.4
        curr = y[0]
        for val in y:
            curr = (1 - alpha) * curr + alpha * val
            smoothed.append(curr)
        return np.array(smoothed)

    @property
    def slope(self):
        return self._last_slope


# ─────────────────────────────────────────────────────────────────────────────
# ADS — ADVERSARIAL DRIFT SENTINEL
# ─────────────────────────────────────────────────────────────────────────────

class AdversarialDriftSentinel:
    """
    Detects when the GMM baseline has been re-baselined by slow poisoning.
    """

    def __init__(self, drift_threshold=ADS_DRIFT_THRESH):
        self.threshold      = drift_threshold
        self._anchor        = None
        self._anchor_hash   = None
        self._drift_history = deque(maxlen=50)
        self.anchored       = False

    def set_anchor(self, gmm):
        params = gmm.get_params()
        if not params:
            return
        self._anchor = {
            "means":     np.array(params["means"]),
            "vars":      np.array(params["vars"]),
            "weights":   np.array(params["weights"]),
            "timestamp": time.time(),
        }
        anchor_str = json.dumps({
            k: v.tolist() if isinstance(v, np.ndarray) else v
            for k, v in self._anchor.items()
        }, sort_keys=True)
        self._anchor_hash = hashlib.sha256(anchor_str.encode()).hexdigest()
        self.anchored = True

    def _verify_anchor(self):
        if self._anchor is None:
            return False
        anchor_str = json.dumps({
            k: v.tolist() if isinstance(v, np.ndarray) else v
            for k, v in self._anchor.items()
        }, sort_keys=True)
        return hashlib.sha256(anchor_str.encode()).hexdigest() == self._anchor_hash

    def score(self, gmm):
        if not self.anchored or self._anchor is None:
            return 0.0
        if not self._verify_anchor():
            return 1.0
        current = gmm.get_params()
        if not current:
            return 0.0
        mu_curr  = np.array(current["means"])
        var_curr = np.array(current["vars"])
        w_curr   = np.array(current["weights"])
        d_mu  = np.abs(mu_curr  - self._anchor["means"])  / (np.abs(self._anchor["means"])  + 1e-9)
        d_var = np.abs(var_curr - self._anchor["vars"])   / (np.abs(self._anchor["vars"])   + 1e-9)
        d_w   = np.abs(w_curr   - self._anchor["weights"])/ (np.abs(self._anchor["weights"])+ 1e-9)
        delta_vec = np.concatenate([d_mu, d_var, d_w])
        drift     = float(np.clip(np.linalg.norm(delta_vec) / np.sqrt(len(delta_vec)), 0.0, 1.0))
        self._drift_history.append(drift)
        if drift >= self.threshold:
            score = min(1.0, 0.5 + (drift - self.threshold) / (1.0 - self.threshold + 1e-9))
        else:
            score = drift / self.threshold * 0.5
        return float(np.clip(score, 0.0, 1.0))

    @property
    def drift_magnitude(self):
        return float(self._drift_history[-1]) if self._drift_history else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# FUSION LAYER
# ─────────────────────────────────────────────────────────────────────────────

def fuse_scores(l1, l2, l3, ads):
    w         = FUSION_WEIGHTS
    composite = float(np.clip(w[0]*l1 + w[1]*l2 + w[2]*l3 + w[3]*ads, 0.0, 1.0))
    if composite >= THRESH_HIGH:
        alert = "HIGH"
    elif composite >= THRESH_MEDIUM:
        alert = "MEDIUM"
    elif composite >= THRESH_LOW:
        alert = "LOW"
    else:
        alert = "MONITORING"
    return composite, alert


# ─────────────────────────────────────────────────────────────────────────────
# HDT ENGINE — per-entity orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class HDTEngine:
    """One engine instance per tracked source IP entity."""

    def __init__(self, entity_id):
        self.entity_id  = entity_id
        self.gmm        = AdaptiveGMM()
        self.kde        = GlobalKDE()
        self.lowess_    = LOWESSTrend()
        self.ads        = AdversarialDriftSentinel()
        self.n_obs      = 0
        self._anchored  = False
        self.ANCHOR_AT  = MIN_OBS + 2

    def evaluate(self, conn):
        x        = float(conn.byte_count)
        self.n_obs += 1
        l1       = self.gmm.update_and_score(x)
        l2       = self.kde.update_and_score(x)
        l3       = self.lowess_.update_and_score(x)
        if self.n_obs == self.ANCHOR_AT and not self._anchored:
            self.ads.set_anchor(self.gmm)
            self._anchored = True
        ads_score        = self.ads.score(self.gmm)
        composite, alert = fuse_scores(l1, l2, l3, ads_score)
        return LayerScores(
            l1_gmm    = round(l1, 4),
            l2_kde    = round(l2, 4),
            l3_lowess = round(l3, 4),
            ads       = round(ads_score, 4),
            fusion    = round(composite, 4),
            alert     = alert,
            obs_count = self.n_obs,
        )

    @property
    def gmm_drift(self):
        return self.ads.drift_magnitude

    @property
    def lowess_slope(self):
        return self.lowess_.slope

    @property
    def is_anchored(self):
        return self._anchored


# ─────────────────────────────────────────────────────────────────────────────
# ENTITY REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

class EntityRegistry:
    """Maintains one HDTEngine per source IP."""

    def __init__(self):
        self._engines = {}

    def get_or_create(self, src_ip):
        if src_ip not in self._engines:
            self._engines[src_ip] = HDTEngine(entity_id=src_ip)
        return self._engines[src_ip]

    def evaluate(self, conn):
        engine = self.get_or_create(conn.src_ip)
        scores = engine.evaluate(conn)
        return engine, scores

    @property
    def entity_count(self):
        return len(self._engines)

    def all_entities(self):
        return list(self._engines.keys())


# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS  (imported by listener)
# ─────────────────────────────────────────────────────────────────────────────

ALERT_COLORS = {
    "MONITORING": "\033[32m",
    "LOW":        "\033[33m",
    "MEDIUM":     "\033[33m",
    "HIGH":       "\033[31m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"

def threat_bar(score, width=30):
    filled = int(score * width)
    bar    = "\u2588" * filled + "\u2591" * (width - filled)
    pct    = int(score * 100)
    if score >= THRESH_HIGH:
        colour = "\033[31m"
    elif score >= THRESH_MEDIUM:
        colour = "\033[33m"
    else:
        colour = "\033[32m"
    return f"{colour}{bar}{RESET} {pct:3d}%"

def sparkline(values, width=10):
    bars = " \u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
    if not values:
        return " " * width
    mn, mx = min(values), max(values)
    rng    = mx - mn if mx != mn else 1
    chars  = [bars[int((v - mn) / rng * 8)] for v in values[-width:]]
    return "".join(chars)

def alert_badge(level):
    colour = ALERT_COLORS.get(level, "")
    return f"{colour}{BOLD}[ {level:^12} ]{RESET}"


if __name__ == "__main__":
    print("\n  HDT Engine Module Loaded Successfully.\n")
