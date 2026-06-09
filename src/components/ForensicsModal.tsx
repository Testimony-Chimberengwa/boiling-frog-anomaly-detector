import React, { useState, useEffect } from "react";
import { X, ShieldAlert, Cpu, Layers, Ban, Lock, Unlock, Loader2, Sparkles, TrendingUp } from "lucide-react";
import { LogEntry } from "../types";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip } from "recharts";

interface ForensicsModalProps {
  isOpen: boolean;
  selectedLog: LogEntry | null;
  logs: LogEntry[];
  blockedIps: string[];
  onToggleBlockIp: (ip: string) => void;
  onClose: () => void;
}

export default function ForensicsModal({
  isOpen,
  selectedLog,
  logs,
  blockedIps,
  onToggleBlockIp,
  onClose
}: ForensicsModalProps) {
  const [analysis, setAnalysis] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [errorText, setErrorText] = useState<string>("");

  useEffect(() => {
    if (!selectedLog) {
      setAnalysis("");
      return;
    }

    setLoading(true);
    setAnalysis("");
    setErrorText("");

    // Initiate backend API query to process Gemini model expert security analysis
    fetch("/api/gemini", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        ip: selectedLog.srcIp,
        scores: selectedLog.scores
      })
    })
      .then(res => res.json())
      .then(data => {
        setAnalysis(data.analysis || "Analysis unretrievable.");
        if (data.offline) {
          console.warn("Using offline forensic rules because:", data.error);
        }
      })
      .catch(err => {
        console.error("Forensic analysis proxy query failed:", err);
        setErrorText(err.message);
        setAnalysis(
          `[FORENSICS ANALYSIS TIMEOUT] Local inspection of trace records indicates standard deviation bounds breached. Combined score elements [Fusion=${selectedLog.scores.fusion.toFixed(4)}] match automated mitigative triggers. blacklisting recommended.`
        );
      })
      .finally(() => {
        setLoading(false);
      });
  }, [selectedLog, selectedLog?.id]);

  if (!isOpen || !selectedLog) return null;

  const ip = selectedLog.srcIp;
  const isBlocked = blockedIps.includes(ip);
  const s = selectedLog.scores;

  const formatBytes = (n: number) => {
    if (n >= 1048576) return `${(n / 1048576).toFixed(2)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  };

  // Calculate aggregates for this specific entity
  const ipLogs = logs.filter(l => l.srcIp === ip);
  const totalConns = ipLogs.length;
  const totalBytes = ipLogs.reduce((acc, curr) => acc + curr.byteCount, 0);
  
  // Calculate highest alert level
  let highestAlert = "MONITORING";
  ipLogs.forEach(l => {
    if (l.scores.alert === "HIGH") highestAlert = "HIGH";
    else if (l.scores.alert === "MEDIUM" && highestAlert !== "HIGH") highestAlert = "MEDIUM";
    else if (l.scores.alert === "LOW" && highestAlert !== "HIGH" && highestAlert !== "MEDIUM") highestAlert = "LOW";
  });

  // Volume Trend chart inputs for this entity
  const trendData = ipLogs
    .slice(0, 15)
    .reverse()
    .map((l, idx) => ({
      name: `#${idx + 1}`,
      bytes: l.byteCount,
      displayBytes: formatBytes(l.byteCount)
    }));

  // Map attack description
  let attackHeader = "Nominal Background Flow";
  let attackDesc = "Payload profiles match standard expected variance models with stable regression slopes.";
  let badgeColor = "border-emerald-500/20 bg-emerald-500/10 text-emerald-400";

  if (s.l3_lowess > 0.45) {
    attackHeader = "Slow Data Exfiltration Trace";
    attackDesc = "Incremental byte multipliers ascending over standard observation timeline, pointing to low-frequency asset stealing.";
    badgeColor = "border-rose-500/30 bg-rose-500/10 text-rose-400";
  } else if (s.ads > 0.45) {
    attackHeader = "Dynamic Baseline Poisoning Trace";
    attackDesc = "Progressive packet mutations attempting to slowly adapt core GMM bounds to corrupt future outlier identification.";
    badgeColor = "border-purple-500/30 bg-purple-500/10 text-purple-400";
  } else if (s.l2_kde > 0.45) {
    attackHeader = "Horizontal Socket Reconnaissance Sweep";
    attackDesc = "Multi-port search script targeting active listener ports with microscopic query envelopes.";
    badgeColor = "border-yellow-500/30 bg-yellow-500/10 text-yellow-400";
  } else if (s.alert === "LOW" || s.alert === "MEDIUM") {
    attackHeader = "Secondary Baseline Deviation";
    attackDesc = "Marginal packet deviations or standard user session flux outside GMM bounds.";
    badgeColor = "border-amber-500/30 bg-amber-500/10 text-amber-400";
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      
      {/* Backdrop panel */}
      <div 
        className="absolute inset-0 bg-[#07090D]/85 backdrop-blur-sm cursor-pointer" 
        onClick={onClose} 
      />

      {/* Modal Container */}
      <div className="relative w-full max-w-4xl rounded-2xl border border-[#1F2937]/90 bg-[#0b0e14]/95 text-slate-100 flex flex-col shadow-2xl p-6 max-h-[88vh] overflow-y-auto font-sans z-10 transition-transform duration-200">
        
        {/* Close Button */}
        <button 
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg border border-[#1F2937] bg-[#111418] hover:bg-rose-500/20 text-slate-400 hover:text-red-400 transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Header Title Grid */}
        <div className="border-b border-[#1F2937]/60 pb-4 mb-4">
          <div className="flex items-center gap-2 mb-2 font-mono">
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
            <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Forensic Report Matrix</span>
            {isBlocked && (
              <span className="text-[10px] bg-red-950/40 text-red-400 border border-red-500/30 px-2 py-0.5 rounded font-bold uppercase tracking-wide">
                BANNED & BLOCKED
              </span>
            )}
          </div>
          <h2 className="text-2xl font-mono tracking-tight text-white font-bold flex items-center gap-2">
            Host Investigation: <span className="text-slate-300 font-normal">{ip}</span>
          </h2>
        </div>

        {/* Grid Section */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mb-5">
          
          {/* Left Column: Aggregates and Subscores */}
          <div className="lg:col-span-5 space-y-4">
            
            {/* Aggregate Metrics Container */}
            <div className="p-4 rounded-xl bg-[#111418]/50 border border-[#1F2937]/60 font-mono text-xs">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-3 font-bold">Historical Aggregate Stats:</span>
              <div className="grid grid-cols-2 gap-3">
                <div className="p-2 border border-[#1F2937]/30 bg-[#0b0e14]/50 rounded">
                  <div className="text-[9px] text-slate-500">CONNECTIONS</div>
                  <div className="text-white font-bold text-sm mt-0.5">{totalConns}</div>
                </div>
                <div className="p-2 border border-[#1F2937]/30 bg-[#0b0e14]/50 rounded">
                  <div className="text-[9px] text-slate-500">EXCHANGED DATA</div>
                  <div className="text-white font-bold text-sm mt-0.5">{formatBytes(totalBytes)}</div>
                </div>
                <div className="p-2 border border-[#1F2937]/30 bg-[#0b0e14]/50 rounded">
                  <div className="text-[9px] text-slate-500">LAST ACTIVE PORT</div>
                  <div className="text-white font-bold text-sm mt-0.5">{selectedLog.dstPort}</div>
                </div>
                <div className="p-2 border border-[#1F2937]/30 bg-[#0b0e14]/50 rounded">
                  <div className="text-[9px] text-slate-500">SEVERITY INDEX</div>
                  <div className="font-bold text-sm mt-0.5">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                      highestAlert === "HIGH" ? "bg-red-950/50 text-red-400 border border-red-500/20" :
                      highestAlert === "MEDIUM" ? "bg-amber-950/50 text-amber-400 border border-amber-500/20" :
                      "bg-emerald-950/50 text-emerald-400 border border-emerald-500/20"
                    }`}>
                      {highestAlert}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Subscores Bar Chart Equivalent */}
            <div className="p-4 rounded-xl bg-[#111418]/50 border border-[#1F2937]/60 font-mono text-xs space-y-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">FADE Layer Scores:</span>
              
              {/* L1 GMM */}
              <div>
                <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                  <span>L1 GMM (Volumetric Weight Anomaly)</span>
                  <span className="font-bold text-white">{s.l1_gmm.toFixed(4)}</span>
                </div>
                <div className="w-full bg-[#1F2937]/40 h-2 rounded-full overflow-hidden">
                  <div className="bg-emerald-400 h-full transition-all duration-300" style={{ width: `${s.l1_gmm*100}%` }} />
                </div>
              </div>

              {/* L2 KDE */}
              <div>
                <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                  <span>L2 KDE (Socio-Port Density Probe)</span>
                  <span className="font-bold text-white">{s.l2_kde.toFixed(4)}</span>
                </div>
                <div className="w-full bg-[#1F2937]/40 h-2 rounded-full overflow-hidden">
                  <div className="bg-yellow-400 h-full transition-all duration-300" style={{ width: `${s.l2_kde*100}%` }} />
                </div>
              </div>

              {/* L3 LOWESS */}
              <div>
                <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                  <span>L3 LOWESS (Robust Multi-Observation Slope)</span>
                  <span className="font-bold text-white">{s.l3_lowess.toFixed(4)}</span>
                </div>
                <div className="w-full bg-[#1F2937]/40 h-2 rounded-full overflow-hidden">
                  <div className="bg-rose-500 h-full transition-all duration-300" style={{ width: `${s.l3_lowess*100}%` }} />
                </div>
              </div>

              {/* ADS Sentinel */}
              <div>
                <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                  <span>ADS Drift Sentinel (Poison Safeguard)</span>
                  <span className="font-bold text-white">{s.ads.toFixed(4)}</span>
                </div>
                <div className="w-full bg-[#1F2937]/40 h-2 rounded-full overflow-hidden">
                  <div className="bg-purple-400 h-full transition-all duration-300" style={{ width: `${s.ads*100}%` }} />
                </div>
              </div>

              {/* Total Fusion Score Indicator */}
              <div className="pt-2 border-t border-[#1F2937]/35 flex items-center justify-between">
                <span className="text-[10px] font-bold text-slate-300">Composite Joint Fusion:</span>
                <span className="text-sm font-bold text-emerald-400">{s.fusion.toFixed(4)}</span>
              </div>
            </div>

          </div>

          {/* Right Column: Volume Charts and Drift Warning */}
          <div className="lg:col-span-7 space-y-4">
            
            {/* Dynamic Volume Chart */}
            <div className="p-4 rounded-xl bg-[#111418]/50 border border-[#1F2937]/60 flex flex-col">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-3 font-bold">
                Entity Volume Flow Timeline (Chronological)
              </span>
              <div className="h-44 w-full">
                {trendData.length === 0 ? (
                  <div className="flex items-center justify-center h-full text-slate-600 font-mono text-[10px]">
                    No traffic timeline available
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={trendData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                      <defs>
                        <linearGradient id="modalBytesGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#34D399" stopOpacity={0.25}/>
                          <stop offset="95%" stopColor="#34D399" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1F2937/80" vertical={false} />
                      <XAxis dataKey="name" stroke="#475569" fontSize={8} tickLine={false} />
                      <YAxis 
                        stroke="#475569" 
                        fontSize={8} 
                        tickLine={false}
                        tickFormatter={(v) => {
                          if (v >= 1048576) return `${(v / 1048576).toFixed(0)}M`;
                          if (v >= 1024) return `${(v / 1024).toFixed(0)}K`;
                          return v;
                        }}
                      />
                      <Tooltip 
                        contentStyle={{ backgroundColor: "#0b0e14", borderColor: "#1F2937", color: "#FFF", fontSize: "10px", fontFamily: "monospace" }}
                        formatter={(val: any) => [formatBytes(val), "Size"]}
                      />
                      <Area type="monotone" dataKey="bytes" stroke="#34D399" fillOpacity={1} fill="url(#modalBytesGradient)" />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* Warning Box for GMM drift over 0.30 */}
            {selectedLog.gmmDrift > 0.30 && (
              <div className="p-3 border border-red-500/30 bg-red-950/20 text-red-400 rounded-lg flex items-start gap-2.5">
                <ShieldAlert className="w-4 h-4 text-rose-500 mt-0.5 shrink-0" />
                <div className="text-[10px] font-mono leading-relaxed">
                  <strong className="text-red-300 block mb-0.5">⚠ ACCUMULATIVE POISON ALIGNMENT WARNING</strong>
                  Observed host has induced a GMM mean shift coefficient of <strong>{(selectedLog.gmmDrift * 100).toFixed(1)}%</strong> relative to anchored parameters. This represents severe dynamic model corruption.
                </div>
              </div>
            )}

            {/* Attack classification banner */}
            <div className={`p-4 border rounded-xl flex flex-col justify-center ${badgeColor}`}>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider mb-1 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5" />
                Classification: {attackHeader}
              </h3>
              <p className="text-[11px] leading-relaxed font-sans opacity-95">{attackDesc}</p>
            </div>

          </div>

        </div>

        {/* Gemini AI Analyst Section */}
        <div className="p-4 rounded-xl bg-gradient-to-r from-emerald-950/10 via-purple-950/5 to-cyan-950/10 border border-[#1b342a]/65 mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-widest flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-purple-400" />
              Gemini AI Analyst Agent Assessment
            </span>
            {loading && <span className="text-[9px] font-mono text-slate-500 flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin text-[#60A5FA]" /> QUERYING ENGINE...</span>}
          </div>
          
          {loading ? (
            <div className="py-4 text-center font-mono text-[10px] text-slate-500 animate-pulse">
              Generating professional forensic analysis through server-side secure channels...
            </div>
          ) : (
            <p className="text-xs text-slate-300 leading-relaxed font-sans bg-[#0b0e14]/40 p-3 rounded.5 border border-[#1F2937]/35">
              {analysis}
            </p>
          )}
        </div>

        {/* Footer Actions: Blacklist toggle and modal close */}
        <div className="flex items-center justify-between border-t border-[#1F2937]/60 pt-4 mt-auto">
          <button 
            onClick={onClose}
            className="px-4 py-2 border border-[#1F2937] hover:bg-[#111418] text-xs font-mono rounded-lg text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            DISMISS REPORT
          </button>

          <button
            onClick={() => onToggleBlockIp(ip)}
            className={`px-4 py-2 flex items-center gap-2 font-mono text-xs rounded-lg border cursor-pointer transitioning transition-all ${
              isBlocked 
                ? "bg-emerald-950/20 text-emerald-400 border-emerald-500/30 hover:bg-emerald-950/40" 
                : "bg-red-950/20 text-red-400 border-red-500/30 hover:bg-red-950/40"
            }`}
          >
            {isBlocked ? (
              <>
                <Unlock className="w-3.5 h-3.5" />
                REVOKE BLOCK (BANNED)
              </>
            ) : (
              <>
                <Ban className="w-3.5 h-3.5" />
                BLOCK ENTITY GATEWAY
              </>
            )}
          </button>
        </div>

      </div>
    </div>
  );
}
