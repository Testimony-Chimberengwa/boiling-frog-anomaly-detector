import React, { useState } from "react";
import { Layers, ChevronDown, ChevronUp, Cpu, Database, Flame, Activity } from "lucide-react";

interface ModelsViewTabProps {
  gmmMean: number;
  gmmStd: number;
  anchorMean: number;
  gmmDrift: number;
  lowessSlope: number;
  isAnchored: boolean;
  activePortsCount: number;
}

export default function ModelsViewTab({
  gmmMean,
  gmmStd,
  anchorMean,
  gmmDrift,
  lowessSlope,
  isAnchored,
  activePortsCount
}: ModelsViewTabProps) {
  const [expandedLayers, setExpandedLayers] = useState<Record<string, boolean>>({
    L1: true,
    L2: false,
    L3: false,
    ADS: false
  });

  const toggleLayer = (layer: string) => {
    setExpandedLayers(prev => ({
      ...prev,
      [layer]: !prev[layer]
    }));
  };

  const formatBytes = (n: number) => {
    if (n >= 1048576) return `${(n / 1048576).toFixed(2)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto py-2">
      
      {/* Introduction Card */}
      <div className="p-5 rounded-xl bg-[#111418]/60 border border-[#1F2937]/75 backdrop-blur-md">
        <h2 className="text-sm font-mono font-bold text-emerald-400 tracking-wider uppercase flex items-center gap-2 mb-2">
          <Layers className="w-4 h-4" />
          Supervisor Algorithm Reference Center
        </h2>
        <p className="text-xs text-slate-400 leading-relaxed">
          The <strong>Boiling Frog Hybrid Detection Tapestry (HDT)</strong> operates on four distinct mathematical layers. 
          Unlink classical threshold engines, HDT monitors local variance, multi-port density, volume regression gradients, and anchor drift. 
          Toggle the cards below to audit the core algorithms and live evaluation coefficients.
        </p>
      </div>

      <div className="space-y-4">
        
        {/* Layer 1: Adaptive GMM */}
        <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45 transition-colors duration-150">
          <button
            onClick={() => toggleLayer("L1")}
            className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
          >
            <div className="flex items-center gap-3">
              <span className="w-7 h-7 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center justify-center font-bold">
                L1
              </span>
              <div>
                <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Layer 1 — Adaptive GMM Outlier</span>
                <span className="text-[10px] text-slate-500">Watches: Volumetric Sudden Spikes</span>
              </div>
            </div>
            <div className="flex items-center gap-4 text-emerald-400 font-bold">
              <span>ACTIVE</span>
              {expandedLayers.L1 ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>

          {expandedLayers.L1 && (
            <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 text-xs space-y-4 leading-relaxed text-slate-300">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Mathematical Formulation:</h4>
                  <div className="p-3 bg-[#0b0e14] border border-[#1F2937]/80 rounded font-mono text-emerald-300 text-center select-all">
                    Z = |x - μ| / σ <br />
                    Score = min(1.0, max(0.0, (Z - 1.2) / 2.5))
                  </div>
                </div>
                <div>
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Live Parameter Tracking:</h4>
                  <div className="grid grid-cols-2 gap-3 font-mono">
                    <div className="p-2.5 bg-[#111418] border border-[#1F2937]/50 rounded text-center">
                      <div className="text-[9px] text-slate-500">DYNAMIC MEAN (μ)</div>
                      <div className="text-white font-bold mt-1 text-sm">{formatBytes(gmmMean)}</div>
                    </div>
                    <div className="p-2.5 bg-[#111418] border border-[#1F2937]/50 rounded text-center">
                      <div className="text-[9px] text-slate-500">DYNAMIC STD (σ)</div>
                      <div className="text-white font-bold mt-1 text-sm">{formatBytes(gmmStd)}</div>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Plain English Breakdown:</h4>
                <p className="text-slate-400">
                  Fits an adaptive single-component <strong>Gaussian Mixture Model (GMM)</strong> over incoming packet lengths. 
                  By calculating the mathematical standard deviation, it learns what an organization's "normal" payload size looks like (typically ~75KB). 
                  If an abnormal 1MB+ upload occurs, L1 triggers an outliers score based on the statistical Z-score distance. GMM adapts continuously using a forgetting learning rate (λ = 0.05).
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Layer 2: Global KDE */}
        <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45 transition-colors duration-150">
          <button
            onClick={() => toggleLayer("L2")}
            className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
          >
            <div className="flex items-center gap-3">
              <span className="w-7 h-7 rounded-lg bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 flex items-center justify-center font-bold">
                L2
              </span>
              <div>
                <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Layer 2 — Kernel Density Estimate (KDE)</span>
                <span className="text-[10px] text-slate-500">Watches: Connection Port Sweep Footprints</span>
              </div>
            </div>
            <div className="flex items-center gap-4 text-yellow-400 font-bold">
              <span>ACTIVE</span>
              {expandedLayers.L2 ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>

          {expandedLayers.L2 && (
            <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 text-xs space-y-4 leading-relaxed text-slate-300">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Mathematical Formulation:</h4>
                  <div className="p-3 bg-[#0b0e14] border border-[#1F2937]/80 rounded font-mono text-yellow-300 text-center">
                    Diversity = U_ports / BufferSize <br />
                    Score = min(1.0, Diversity * 0.5 + TinyRatio * 0.5)
                  </div>
                </div>
                <div>
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Live Parameter Tracking:</h4>
                  <div className="grid grid-cols-2 gap-3 font-mono">
                    <div className="p-2.5 bg-[#111418] border border-[#1F2937]/50 rounded text-center">
                      <div className="text-[9px] text-slate-500">PORT MEMORY</div>
                      <div className="text-white font-bold mt-1 text-sm">15 Sliding Slots</div>
                    </div>
                    <div className="p-2.5 bg-[#111418] border border-[#1F2937]/50 rounded text-center">
                      <div className="text-[9px] text-slate-500">UNIQUE PORTS TOUCHED</div>
                      <div className="text-white font-bold mt-1 text-sm">{activePortsCount} / 10</div>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Plain English Breakdown:</h4>
                <p className="text-slate-400">
                  KDE transforms discrete port engagements into continuous probability vectors. Scan bots target multiple listener sockets (ranging from 5001-5010) within short timing intervals using featherweight packets (150B) to look for open listening channels. 
                  L2 evaluates the ratio of unique distinct ports hit relative to sliding slots, signaling reconnaissance sweeps with pinpoint precision.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Layer 3: LOWESS Trend */}
        <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45 transition-colors duration-150">
          <button
            onClick={() => toggleLayer("L3")}
            className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
          >
            <div className="flex items-center gap-3">
              <span className="w-7 h-7 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30 flex items-center justify-center font-bold">
                L3
              </span>
              <div>
                <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Layer 3 — Robust LOWESS Trend</span>
                <span className="text-[10px] text-slate-500">Watches: Slow Rising-Volume Upload Exfiltration</span>
              </div>
            </div>
            <div className="flex items-center gap-4 text-rose-400 font-bold">
              <span>ACTIVE</span>
              {expandedLayers.L3 ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>

          {expandedLayers.L3 && (
            <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 text-xs space-y-4 leading-relaxed text-slate-300">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Mathematical Formulation:</h4>
                  <div className="p-3 bg-[#0b0e14] border border-[#1F2937]/80 rounded font-mono text-rose-300 text-center">
                    Slope = LeastSquaresRegression(rolling_win_10) <br />
                    Score = max(0.0, min(1.0, Slope / 400,000))
                  </div>
                </div>
                <div>
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Live Parameter Tracking:</h4>
                  <div className="grid grid-cols-2 gap-3 font-mono">
                    <div className="p-2.5 bg-[#111418] border border-[#1F2937]/50 rounded text-center">
                      <div className="text-[9px] text-slate-500">SLOPE WINDOW</div>
                      <div className="text-white font-bold mt-1 text-sm">10 Observations</div>
                    </div>
                    <div className="p-2.5 bg-[#111418] border border-[#1F2937]/50 rounded text-center">
                      <div className="text-[9px] text-slate-500">ESTIMATED GROWTH RATE</div>
                      <div className="text-[#F87171] font-bold mt-1 text-sm">
                        {lowessSlope > 0 ? `+${formatBytes(lowessSlope)}/obs` : "Stable / Nominal"}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Plain English Breakdown:</h4>
                <p className="text-slate-400">
                  Cybercriminals deploy "low-and-slow" exfiltration by gradually expanding packet weight ratios over large, sporadic periods to remain invisible to static threshold alarms. 
                  L3 fits a local polynomial regression trend over a sliding timeline filter. If an entity maintains a step-by-step upward growth slope (e.g. 1MB &rarr; 2MB &rarr; 6MB), robust LOWESS captures the ascension coefficient and alarms.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Layer 4: ADS Adversarial Drift Sentinel */}
        <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden bg-[#111418]/45 transition-colors duration-150">
          <button
            onClick={() => toggleLayer("ADS")}
            className="w-full p-4 flex items-center justify-between bg-[#111418] hover:bg-[#161B22]/80 transition-all font-mono text-xs cursor-pointer text-left"
          >
            <div className="flex items-center gap-3">
              <span className="w-7 h-7 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30 flex items-center justify-center font-bold">
                ADS
              </span>
              <div>
                <span className="font-bold text-[#E2E8F0] uppercase text-sm block">Layer 4 — ADS Adversarial Drift Sentinel</span>
                <span className="text-[10px] text-slate-500">Watches: Baseline Poisoning Attempts</span>
              </div>
            </div>
            <div className="flex items-center gap-4 text-purple-400 font-bold">
              <span>ACTIVE</span>
              {expandedLayers.ADS ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>

          {expandedLayers.ADS && (
            <div className="p-5 border-t border-[#1F2937]/45 bg-[#0b0e14]/40 text-xs space-y-4 leading-relaxed text-slate-300">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Mathematical Formulation:</h4>
                  <div className="p-3 bg-[#0b0e14] border border-[#1F2937]/80 rounded font-mono text-purple-300 text-center">
                    Drift Coefficient (D) = |μ_current - μ_anchor| / μ_anchor <br />
                    Score = min(1.0, max(0.0, (D - 0.08) / 0.15))
                  </div>
                </div>
                <div>
                  <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Live Parameter Tracking:</h4>
                  <div className="grid grid-cols-2 gap-3 font-mono">
                    <div className="p-2.5 bg-[#111418] border border-[#1F2937]/50 rounded text-center">
                      <div className="text-[9px] text-slate-500">BASELINE ANCHOR (μ)</div>
                      <div className="text-white font-bold mt-1 text-sm">
                        {isAnchored ? formatBytes(anchorMean) : "░ NOT LOCKED"}
                      </div>
                    </div>
                    <div className="p-2.5 bg-[#111418] border border-[#1F2937]/50 rounded text-center">
                      <div className="text-[9px] text-slate-500">GMM MEAN DRIFT</div>
                      <div className="text-purple-400 font-bold mt-1 text-sm">
                        {isAnchored ? `${(gmmDrift * 100).toFixed(1)}%` : "N/A"}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 font-bold">Plain English Breakdown:</h4>
                <p className="text-slate-400">
                  Because GMM adapts dynamically, sophisticated threat actors seed incremental byte multipliers (+5% per round) to slowly slip past outlier filters—essentially "poisoning" what the model learns to expect. 
                  The <strong>Adversarial Drift Sentinel</strong> locks down a frozen "anchor snapshot" after your baseline warming sequence completes. If adaptive weights drift too far from this locked anchor, the Sentinel triggers.
                </p>
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
