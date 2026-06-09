import React, { useState, useEffect, useCallback } from "react";
import { Layers, ChevronDown, ChevronUp, RotateCcw, TrendingUp, TrendingDown, AlertCircle, CheckCircle2 } from "lucide-react";

interface ModelsViewTabProps {
  gmmMean: number;
  gmmStd: number;
  anchorMean: number;
  gmmDrift: number;
  lowessSlope: number;
  isAnchored: boolean;
  activePortsCount: number;
  liveObservations?: any[];
}

interface EngineParams {
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
}

const DEFAULTS: EngineParams = {
  lambda: 0.05,
  kComponents: 3,
  minObsBeforeScoring: 8,
  kdeObservationWindow: 60,
  scottsRuleMultiplier: 1.0,
  portDiversityThreshold: 3,
  sweepDetectionWindow: 30,
  lowessSmoothing: 0.40,
  lowessTrendWindow: 20,
  lowessMinObservations: 6,
  driftThreshold: 0.30,
  anchorObservationCount: 10,
  w1_gmm: 0.25,
  w2_kde: 0.35,
  w3_lowess: 0.25,
  w4_ads: 0.15,
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export default function ModelsViewTab({
  gmmMean,
  gmmStd,
  anchorMean,
  gmmDrift,
  lowessSlope,
  isAnchored,
  activePortsCount,
  liveObservations,
}: ModelsViewTabProps) {
  const [params, setParams] = useState<EngineParams>(DEFAULTS);
  const [expandedLayers, setExpandedLayers] = useState({
    L1: true,
    L2: false,
    L3: false,
    ADS: false,
    Fusion: false,
  });

  const toggleLayer = (layer: keyof typeof expandedLayers) => {
    setExpandedLayers((prev) => ({
      ...prev,
      [layer]: !prev[layer],
    }));
  };

  const handleParamChange = useCallback((key: keyof EngineParams, value: number) => {
    setParams((prev) => ({
      ...prev,
      [key]: value,
    }));
  }, []);

  const resetAllDefaults = () => {
    setParams(DEFAULTS);
  };

  const fusionSum = params.w1_gmm + params.w2_kde + params.w3_lowess + params.w4_ads;
  const fusionValid = Math.abs(fusionSum - 1.0) < 0.01;

  return (
    <div className="p-6 space-y-6 text-[#E2E8F0]">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-3xl font-bold text-white flex items-center gap-2">
          <Layers className="w-8 h-8 text-blue-400" />
          MODELS VIEW — ALGORITHM CONTROL ROOM
        </h1>
        <p className="text-sm text-slate-400">
          Research Methodology: Real-time anomaly detection system with four-layer hybrid detection tapestry (HDT) architecture.
        </p>
      </div>

      {/* Tuning Mode Banner */}
      <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-center justify-between">
        <div className="flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-amber-500" />
          <div>
            <p className="font-bold text-amber-400">PARAMETER TUNING MODE</p>
            <p className="text-xs text-amber-400/80">Changes apply to live detection in real time</p>
          </div>
        </div>
        <button
          onClick={resetAllDefaults}
          className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 rounded text-xs font-mono transition-colors flex items-center gap-1"
        >
          <RotateCcw className="w-3 h-3" />
          RESET ALL TO DEFAULTS
        </button>
      </div>

      {/* Layer 1: GMM */}
      <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45">
        <button
          onClick={() => toggleLayer("L1")}
          className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
        >
          <div className="flex items-center gap-3">
            <span className="w-7 h-7 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center justify-center font-bold">
              L1
            </span>
            <div>
              <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Layer 1 — Adaptive GMM</span>
              <span className="text-[10px] text-slate-500">Gaussian Mixture Model for outlier detection</span>
            </div>
          </div>
          <div className="text-emerald-400 font-bold">
            {expandedLayers.L1 ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>
        {expandedLayers.L1 && (
          <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 space-y-3">
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Lambda (Learning Rate): {params.lambda.toFixed(2)}</label>
              <input
                type="range"
                min="0.01"
                max="0.20"
                step="0.01"
                value={params.lambda}
                onChange={(e) => handleParamChange("lambda", parseFloat(e.target.value))}
                className="w-full"
              />
              <p className="text-[9px] text-slate-500 mt-1">Controls GMM adaptation speed (lower = more stable)</p>
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Components: {params.kComponents}</label>
              <input
                type="range"
                min="1"
                max="5"
                step="1"
                value={params.kComponents}
                onChange={(e) => handleParamChange("kComponents", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Min Obs Before Scoring: {params.minObsBeforeScoring}</label>
              <input
                type="range"
                min="5"
                max="20"
                step="1"
                value={params.minObsBeforeScoring}
                onChange={(e) => handleParamChange("minObsBeforeScoring", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
          </div>
        )}
      </div>

      {/* Layer 2: KDE */}
      <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45">
        <button
          onClick={() => toggleLayer("L2")}
          className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
        >
          <div className="flex items-center gap-3">
            <span className="w-7 h-7 rounded-lg bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 flex items-center justify-center font-bold">
              L2
            </span>
            <div>
              <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Layer 2 — Kernel Density Estimate</span>
              <span className="text-[10px] text-slate-500">Port sweep and connection diversity analysis</span>
            </div>
          </div>
          <div className="text-yellow-400 font-bold">
            {expandedLayers.L2 ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>
        {expandedLayers.L2 && (
          <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 space-y-3">
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Observation Window: {params.kdeObservationWindow}s</label>
              <input
                type="range"
                min="15"
                max="120"
                step="5"
                value={params.kdeObservationWindow}
                onChange={(e) => handleParamChange("kdeObservationWindow", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Scott's Rule Multiplier: {params.scottsRuleMultiplier.toFixed(2)}</label>
              <input
                type="range"
                min="0.5"
                max="2.0"
                step="0.1"
                value={params.scottsRuleMultiplier}
                onChange={(e) => handleParamChange("scottsRuleMultiplier", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Port Diversity Threshold: {params.portDiversityThreshold}</label>
              <input
                type="range"
                min="2"
                max="8"
                step="1"
                value={params.portDiversityThreshold}
                onChange={(e) => handleParamChange("portDiversityThreshold", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Sweep Detection Window: {params.sweepDetectionWindow}s</label>
              <input
                type="range"
                min="10"
                max="60"
                step="5"
                value={params.sweepDetectionWindow}
                onChange={(e) => handleParamChange("sweepDetectionWindow", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
          </div>
        )}
      </div>

      {/* Layer 3: LOWESS */}
      <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45">
        <button
          onClick={() => toggleLayer("L3")}
          className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
        >
          <div className="flex items-center gap-3">
            <span className="w-7 h-7 rounded-lg bg-orange-500/10 text-orange-400 border border-orange-500/30 flex items-center justify-center font-bold">
              L3
            </span>
            <div>
              <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Layer 3 — LOWESS Trend</span>
              <span className="text-[10px] text-slate-500">Slow data exfiltration trend detection</span>
            </div>
          </div>
          <div className="text-orange-400 font-bold">
            {expandedLayers.L3 ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>
        {expandedLayers.L3 && (
          <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 space-y-3">
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Smoothing Factor: {params.lowessSmoothing.toFixed(2)}</label>
              <input
                type="range"
                min="0.1"
                max="0.8"
                step="0.05"
                value={params.lowessSmoothing}
                onChange={(e) => handleParamChange("lowessSmoothing", parseFloat(e.target.value))}
                className="w-full"
              />
              <p className="text-[9px] text-slate-500 mt-1">Controls regression smoothness (lower = more responsive)</p>
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Trend Window: {params.lowessTrendWindow}</label>
              <input
                type="range"
                min="10"
                max="40"
                step="1"
                value={params.lowessTrendWindow}
                onChange={(e) => handleParamChange("lowessTrendWindow", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Min Observations: {params.lowessMinObservations}</label>
              <input
                type="range"
                min="3"
                max="15"
                step="1"
                value={params.lowessMinObservations}
                onChange={(e) => handleParamChange("lowessMinObservations", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
          </div>
        )}
      </div>

      {/* Layer 4: ADS */}
      <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45">
        <button
          onClick={() => toggleLayer("ADS")}
          className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
        >
          <div className="flex items-center gap-3">
            <span className="w-7 h-7 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30 flex items-center justify-center font-bold">
              L4
            </span>
            <div>
              <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Layer 4 — Adversarial Drift Sentinel</span>
              <span className="text-[10px] text-slate-500">Baseline poisoning attack detection</span>
            </div>
          </div>
          <div className="text-red-400 font-bold">
            {expandedLayers.ADS ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>
        {expandedLayers.ADS && (
          <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 space-y-3">
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Drift Threshold: {params.driftThreshold.toFixed(2)}</label>
              <input
                type="range"
                min="0.1"
                max="0.5"
                step="0.05"
                value={params.driftThreshold}
                onChange={(e) => handleParamChange("driftThreshold", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase">Anchor Observation Count: {params.anchorObservationCount}</label>
              <input
                type="range"
                min="5"
                max="30"
                step="1"
                value={params.anchorObservationCount}
                onChange={(e) => handleParamChange("anchorObservationCount", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
          </div>
        )}
      </div>

      {/* Fusion Weights */}
      <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45">
        <button
          onClick={() => toggleLayer("Fusion")}
          className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
        >
          <div className="flex items-center gap-3">
            <span className="w-7 h-7 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30 flex items-center justify-center font-bold">
              ⚙️
            </span>
            <div>
              <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Fusion Weights</span>
              <span className="text-[10px] text-slate-500">Weighted combination of all four layers</span>
            </div>
          </div>
          <div className={`font-bold ${fusionValid ? "text-purple-400" : "text-red-400"}`}>
            {fusionValid ? "✓ Valid" : `✗ Sum: ${fusionSum.toFixed(2)}`}
          </div>
        </button>
        {expandedLayers.Fusion && (
          <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 space-y-3">
            <div>
              <label className="text-xs font-bold text-emerald-400 uppercase">W1 (GMM): {params.w1_gmm.toFixed(2)}</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={params.w1_gmm}
                onChange={(e) => handleParamChange("w1_gmm", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-yellow-400 uppercase">W2 (KDE): {params.w2_kde.toFixed(2)}</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={params.w2_kde}
                onChange={(e) => handleParamChange("w2_kde", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-orange-400 uppercase">W3 (LOWESS): {params.w3_lowess.toFixed(2)}</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={params.w3_lowess}
                onChange={(e) => handleParamChange("w3_lowess", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="text-xs font-bold text-red-400 uppercase">W4 (ADS): {params.w4_ads.toFixed(2)}</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={params.w4_ads}
                onChange={(e) => handleParamChange("w4_ads", parseFloat(e.target.value))}
                className="w-full"
              />
            </div>
            <div className={`p-3 rounded mt-4 text-xs font-mono ${fusionValid ? "bg-purple-500/10 border border-purple-500/30 text-purple-400" : "bg-red-500/10 border border-red-500/30 text-red-400"}`}>
              Sum = {fusionSum.toFixed(2)} {fusionValid ? "✓" : "⚠️ Must equal 1.00"}
            </div>
          </div>
        )}
      </div>

      {/* Live Observations */}
      {liveObservations && liveObservations.length > 0 && (
        <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45">
          <div className="p-4 bg-[#111418] flex items-center justify-between">
            <h3 className="font-bold text-[#E2E8F0] uppercase text-sm flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
              Live Observations Feed
            </h3>
            <span className="text-xs text-slate-500">Last 15 observations</span>
          </div>
          <div className="overflow-auto max-h-96">
            <table className="w-full text-[9px] font-mono">
              <thead className="sticky top-0 bg-[#0b0e14] border-b border-[#1F2937]/50">
                <tr>
                  <th className="p-2 text-left text-cyan-400">Timestamp</th>
                  <th className="p-2 text-left text-yellow-400">Source IP</th>
                  <th className="p-2 text-left text-orange-400">Port</th>
                  <th className="p-2 text-left text-slate-400">Bytes</th>
                  <th className="p-2 text-center text-emerald-400">L1</th>
                  <th className="p-2 text-center text-yellow-400">L2</th>
                  <th className="p-2 text-center text-orange-400">L3</th>
                  <th className="p-2 text-center text-red-400">L4</th>
                  <th className="p-2 text-center text-purple-400">Fusion</th>
                  <th className="p-2 text-center text-slate-400">Alert</th>
                </tr>
              </thead>
              <tbody>
                {liveObservations.slice(-15).map((obs, idx) => (
                  <tr key={idx} className="border-b border-[#1F2937]/20 hover:bg-[#1F2937]/10">
                    <td className="p-2 text-cyan-400">{new Date(obs.timestamp).toLocaleTimeString()}</td>
                    <td className="p-2 text-yellow-400">{obs.srcIp}</td>
                    <td className="p-2 text-orange-400">{obs.port}</td>
                    <td className="p-2 text-slate-300">{formatBytes(obs.bytes)}</td>
                    <td className="p-2 text-center text-emerald-400">{obs.l1Score?.toFixed(2) || "—"}</td>
                    <td className="p-2 text-center text-yellow-400">{obs.l2Score?.toFixed(2) || "—"}</td>
                    <td className="p-2 text-center text-orange-400">{obs.l3Score?.toFixed(2) || "—"}</td>
                    <td className="p-2 text-center text-red-400">{obs.l4Score?.toFixed(2) || "—"}</td>
                    <td className="p-2 text-center text-purple-400">{obs.fusionScore?.toFixed(2) || "—"}</td>
                    <td className="p-2 text-center text-slate-400">{obs.alert ? "🚨" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
