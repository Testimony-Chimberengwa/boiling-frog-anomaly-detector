/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ConnectionRecord, HDTScores, ThreatLevel } from "./types";

export class HDTEngine {
  // ========== L1 GMM TUNABLE PARAMETERS ==========
  public mean: number = 75000; // Expected normal packet size (~75 KB)
  public variance: number = 20000 * 20000; // Std dev is ~20 KB
  public lambda: number = 0.05; // Forgetting factor for adaptation
  public kComponents: number = 3; // Number of GMM components
  public minObsBeforeScoring: number = 8; // Min connections before L1 produces scores

  // L2 KDE parameters & tracking
  private recentPorts: { port: number; size: number; time: number }[] = [];
  public kdeObservationWindow: number = 60; // Number of recent observations for density
  public scottsRuleMultiplier: number = 1.0; // Bandwidth scale
  public portDiversityThreshold: number = 3; // Distinct ports to trigger sweep
  public sweepDetectionWindow: number = 30; // Seconds for port history
  
  // L3 LOWESS rolling window
  private recentSizes: number[] = [];
  public lowess_slope: number = 0;
  public lowessSmoothing: number = 0.40; // Fraction for local regression
  public lowessTrendWindow: number = 20; // Number of observations for trend
  public lowessMinObservations: number = 6; // Min obs before trend scoring

  // ADS Sentinel Anchors
  public isAnchored: boolean = false;
  public anchorMean: number = 75000;
  public anchorVariance: number = 20000 * 20000;
  public gmm_drift: number = 0;
  public ads: number = 0;
  public driftThreshold: number = 0.30; // L2 norm drift from anchor
  public anchorObservationCount: number = 10; // Clean obs before anchor snapshot
  public anchorSetTime: number = 0; // Timestamp when anchor was set

  // Fusion Engine weights
  public w1_gmm: number = 0.25;
  public w2_kde: number = 0.35;
  public w3_lowess: number = 0.25;
  public w4_ads: number = 0.15;

  // Global counts
  public obsCount: number = 0;

  constructor() {
    // Start with default estimates to be overwritten as baseline proceeds
    this.reset();
  }

  public reset() {
    this.mean = 75000;
    this.variance = 20000 * 20000;
    this.lambda = 0.05;
    this.kComponents = 3;
    this.minObsBeforeScoring = 8;
    this.recentPorts = [];
    this.kdeObservationWindow = 60;
    this.scottsRuleMultiplier = 1.0;
    this.portDiversityThreshold = 3;
    this.sweepDetectionWindow = 30;
    this.recentSizes = [];
    this.lowess_slope = 0;
    this.lowessSmoothing = 0.40;
    this.lowessTrendWindow = 20;
    this.lowessMinObservations = 6;
    this.isAnchored = false;
    this.anchorMean = 75000;
    this.anchorVariance = 20000 * 20000;
    this.gmm_drift = 0;
    this.ads = 0;
    this.driftThreshold = 0.30;
    this.anchorObservationCount = 10;
    this.anchorSetTime = 0;
    this.w1_gmm = 0.25;
    this.w2_kde = 0.35;
    this.w3_lowess = 0.25;
    this.w4_ads = 0.15;
    this.obsCount = 0;
  }

  /**
   * Update engine parameters from the control room
   */
  public updateParameters(params: Partial<{
    lambda: number;
    kComponents: number;
    minObsBeforeScoring: number;
    kdeObservationWindow: number;
    scottsRuleMultiplier: number;
    portDiversityThreshold: number;
    sweepDetectionWindow: number;
    lowessSmoothing: number;
    lowessTrendWindow: number;
    lowessMinObservations: number;
    driftThreshold: number;
    anchorObservationCount: number;
    w1_gmm: number;
    w2_kde: number;
    w3_lowess: number;
    w4_ads: number;
  }>) {
    Object.assign(this, params);
  }

  /**
   * Get all current parameters as a snapshot
   */
  public getParameters() {
    return {
      lambda: this.lambda,
      kComponents: this.kComponents,
      minObsBeforeScoring: this.minObsBeforeScoring,
      kdeObservationWindow: this.kdeObservationWindow,
      scottsRuleMultiplier: this.scottsRuleMultiplier,
      portDiversityThreshold: this.portDiversityThreshold,
      sweepDetectionWindow: this.sweepDetectionWindow,
      lowessSmoothing: this.lowessSmoothing,
      lowessTrendWindow: this.lowessTrendWindow,
      lowessMinObservations: this.lowessMinObservations,
      driftThreshold: this.driftThreshold,
      anchorObservationCount: this.anchorObservationCount,
      w1_gmm: this.w1_gmm,
      w2_kde: this.w2_kde,
      w3_lowess: this.w3_lowess,
      w4_ads: this.w4_ads,
    };
  }

  /**
   * Set GMM parameter snapshot as the anchor after baseline is established.
   */
  public setAnchor() {
    this.anchorMean = this.mean;
    this.anchorVariance = this.variance;
    this.anchorSetTime = Date.now();
    this.isAnchored = true;
  }

  /**
   * Run the four-layer Hybrid Detection Tapestry algorithm for a connection.
   */
  public evaluate(conn: ConnectionRecord): HDTScores {
    this.obsCount++;
    const x = conn.byteCount;
    const now = Date.now();
    let l3_lowess = 0;

    // ---------------------------------------------------------
    // LAYER 1: Adaptive GMM Volume Outlier Score
    // ---------------------------------------------------------
    // Calculate z-score relative to current parameters
    const currentStd = Math.max(10000, Math.sqrt(this.variance));
    const zScore = Math.abs(x - this.mean) / currentStd;
    
    // Scale outlier score to [0, 1] using standard sigmoid-like mapping
    // A z-score of 0-1 matches well -> low score, z-score > 2.5 is highly anomalous
    const l1_gmm = Math.min(1.0, Math.max(0.0, (zScore - 1.2) / 2.5));

    // Adapt GMM parameters if not massively exfiltrating (to allow slow poisoning)
    const isMajorOutlier = x > 800000; // Ignore massive items (like 1MB EXFIL) to simulate standard protection
    if (!isMajorOutlier) {
      this.mean = (1 - this.lambda) * this.mean + this.lambda * x;
      this.variance = (1 - this.lambda) * this.variance + this.lambda * Math.pow(x - this.mean, 2);
    }

    // ---------------------------------------------------------
    // LAYER 2: Connection-Diversity KDE (Kernel Density)
    // ---------------------------------------------------------
    // Adds incoming ports into short-term memory to detect horizontal sweep behavior
    this.recentPorts.push({ port: conn.dstPort, size: x, time: now });
    if (this.recentPorts.length > this.kdeObservationWindow) {
      this.recentPorts.shift();
    }

    // KDE looks for diverse port scanning with abnormally small packet sizes (recons)
    const distinctPorts = new Set(this.recentPorts.map(p => p.port));
    const smallPackets = this.recentPorts.filter(p => p.size < 5000); // Small scans

    let l2_kde = 0;
    if (distinctPorts.size >= this.portDiversityThreshold) {
      // Calculate diversity ratio
      const portDiversityRatio = distinctPorts.size / this.recentPorts.length;
      const tinyRatio = smallPackets.length / this.recentPorts.length;
      
      // Horizontal sweeps consist of scanning many distinct ports with tiny packets
      l2_kde = Math.min(1.0, portDiversityRatio * 0.5 + tinyRatio * 0.5);
    } else {
      // Normal localized traffic remains low density score
      l2_kde = 0.05 * (distinctPorts.size / this.portDiversityThreshold);
    }

    // ---------------------------------------------------------
    // LAYER 3: LOWESS Volume Trend / Gradient Analyzer
    // ---------------------------------------------------------
    // Store recent sizes in a rolling window of specified size
    this.recentSizes.push(x);
    if (this.recentSizes.length > this.lowessTrendWindow) {
      this.recentSizes.shift();
    }

    // Calculate linear regression slope to represent LOWESS gradient
    // This watches for gradual slope ascension (escalating MB volume)
    if (this.recentSizes.length >= this.lowessMinObservations) {
      const n = this.recentSizes.length;
      let sumX = 0;
      let sumY = 0;
      let sumXY = 0;
      let sumXX = 0;

      for (let i = 0; i < n; i++) {
        const index = i;
        const val = this.recentSizes[i];
        sumX += index;
        sumY += val;
        sumXY += index * val;
        sumXX += index * index;
      }

      const denominator = (n * sumXX - sumX * sumX);
      this.lowess_slope = denominator !== 0 ? (n * sumXY - sumX * sumY) / denominator : 0;
      
      // Map slope to normalized anomaly score
      // A positive slope means sizes are expanding. We penalize escalating sizes
      // 0 slope is fine, a positive slope rising to +500KB/observation is extreme
      if (this.lowess_slope > 0) {
        l3_lowess = Math.min(1.0, this.lowess_slope / 400000);
      } else {
        l3_lowess = 0; // Negative slope is safe/downward
      }
    } else {
      l3_lowess = 0;
    }

    // ---------------------------------------------------------
    // LAYER ADS: Adversarial Drift Sentinel (Poisoning Sentinel)
    // ---------------------------------------------------------
    let ads = 0;
    if (this.isAnchored) {
      // Compare adapted GMM mean shift relative to anchored baseline snapshot
      // If the mean has been slowly pulled away from original baseline, trigger
      this.gmm_drift = Math.abs(this.mean - this.anchorMean) / this.anchorMean;
      
      // If GMM baseline has drifted more than threshold, highlight as poisoning
      ads = Math.min(1.0, Math.max(0.0, (this.gmm_drift - 0.08) / (this.driftThreshold || 0.15)));
      this.ads = ads;
    } else {
      this.gmm_drift = 0;
      this.ads = 0;
    }

    // ---------------------------------------------------------
    // FUSION STATE & THREAT LEVEL ASSIGNMENT
    // ---------------------------------------------------------
    // Calculate weighted fusion score using configurable weights
    const maxLayerScore = Math.max(l1_gmm, l2_kde, l3_lowess, ads);
    const weightedScore = (l1_gmm * this.w1_gmm) + (l2_kde * this.w2_kde) + (l3_lowess * this.w3_lowess) + (ads * this.w4_ads);
    const fusion = Math.min(1.0, maxLayerScore * 0.7 + weightedScore * 0.3);

    let alert: ThreatLevel = "MONITORING";
    if (fusion >= 0.65) {
      alert = "HIGH";
    } else if (fusion >= 0.35) {
      alert = "MEDIUM";
    } else if (fusion >= 0.15) {
      alert = "LOW";
    }

    return {
      l1_gmm,
      l2_kde,
      l3_lowess,
      ads: ads,
      fusion,
      alert,
      obsCount: this.obsCount
    };
  }
}
