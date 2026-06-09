import React from "react";
import { 
  Play, Pause, Square, Zap, RefreshCw, Terminal, 
  Flame, Database, Compass, Radio, ArrowRight, ShieldAlert 
} from "lucide-react";
import { SimStatus } from "../types";

interface TestLabTabProps {
  simStatus: SimStatus;
  simIndex: number;
  simSequenceLength: number;
  isAutoPlay: boolean;
  simSpeed: number;
  onStartSim: (type: "EXFIL" | "POISON" | "SWEEP") => void;
  onBuildBaseline: () => void;
  onResetSystem: () => void;
  attackLog: string[];
  detectionLog: string[];
  customPort: number;
  setCustomPort: (port: number) => void;
  customBytes: number;
  setCustomBytes: (bytes: number) => void;
  customPayload: string;
  setCustomPayload: (payload: string) => void;
  customIp: string;
  setCustomIp: (ip: string) => void;
  onInjectCustom: () => void;
  onTogglePause: () => void;
  onStopSim: () => void;
  setSimSpeed: (speed: number) => void;
}

export default function TestLabTab({
  simStatus,
  simIndex,
  simSequenceLength,
  isAutoPlay,
  simSpeed,
  onStartSim,
  onBuildBaseline,
  onResetSystem,
  attackLog,
  detectionLog,
  customPort,
  setCustomPort,
  customBytes,
  setCustomBytes,
  customPayload,
  setCustomPayload,
  customIp,
  setCustomIp,
  onInjectCustom,
  onTogglePause,
  onStopSim,
  setSimSpeed
}: TestLabTabProps) {

  const formatBytes = (n: number) => {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  };

  return (
    <div className="space-y-6 py-2">
      
      {/* Top Controller Ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-[#111418]/60 border border-[#1F2937]/75 backdrop-blur-md">
        <div>
          <h2 className="text-sm font-mono font-bold text-emerald-400 tracking-wider uppercase flex items-center gap-2 mb-1">
            <Radio className="w-4 h-4" />
            Vulnerability Simulation & Testing Deck
          </h2>
          <p className="text-[11px] text-slate-400 max-w-xl">
            Prime the machine learning layers using static normal data or launch targeted adversarial profiles to audit model boundaries.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={onBuildBaseline}
            disabled={simStatus.startsWith("running_")}
            className="px-3.5 py-1.5 bg-emerald-900/40 hover:bg-emerald-950/60 border border-emerald-500/30 hover:border-emerald-500/60 text-emerald-400 text-xs font-mono font-bold rounded-lg cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed transition-all inline-flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            WARM UP HDT ENGINE (15 OBS)
          </button>
          
          <button
            onClick={onResetSystem}
            className="px-3.5 py-1.5 bg-rose-950/20 hover:bg-rose-950/40 border border-rose-500/30 hover:border-rose-500/60 text-rose-400 text-xs font-mono font-bold rounded-lg cursor-pointer transition-all inline-flex items-center gap-1.5"
          >
            RESET SYSTEM MATRIX
          </button>
        </div>
      </div>

      {/* Simulator Overlay Progress Line */}
      {simStatus !== "idle" && (
        <div className="p-4 rounded-xl bg-slate-900/10 border border-[#1b342a]/55 font-mono text-xs flex flex-wrap items-center justify-between gap-4 animate-pulse">
          <div className="flex items-center gap-3">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <div>
              <span className="text-[#94A3B8] mr-2">PROCESS VECTOR:</span>
              <span className="text-white font-bold uppercase tracking-wider">{simStatus} SIMULATION ACTIVE</span>
            </div>
          </div>
          
          {/* Progress Indicators */}
          <div className="flex items-center gap-4">
            <div className="bg-[#111418] border border-[#1F2937]/75 px-3 py-1 rounded text-[11px] text-[#A7F3D0]">
              ROUND {simIndex} / {simSequenceLength} COMPLETED
            </div>

            {/* Governer controls */}
            <div className="flex items-center gap-1 bg-[#111418] border border-[#1F2937]/75 px-2 py-0.5 rounded text-[11px]">
              <span className="text-slate-500 mr-1.5 text-[10px]">SPEED:</span>
              <button 
                onClick={() => setSimSpeed(1500)} 
                className={`px-1.5 py-0.5 rounded cursor-pointer ${simSpeed === 1500 ? "bg-emerald-920 text-emerald-400 font-bold" : "text-slate-400"}`}
              >
                1x
              </button>
              <button 
                onClick={() => setSimSpeed(500)} 
                className={`px-1.5 py-0.5 rounded cursor-pointer ${simSpeed === 500 ? "bg-emerald-920 text-emerald-400 font-bold" : "text-slate-400"}`}
              >
                3x
              </button>
            </div>

            {/* Direct controller triggers */}
            <div className="flex items-center gap-1.5 border-l border-[#1F2937] pl-4">
              <button
                onClick={onTogglePause}
                className="p-1 rounded hover:bg-[#1F2937] text-white hover:text-emerald-400 cursor-pointer"
                title={isAutoPlay ? "Pause Simulation" : "Resume Simulation"}
              >
                {isAutoPlay ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              </button>
              <button
                onClick={onStopSim}
                className="p-1 rounded hover:bg-[#1F2937] text-rose-400 cursor-pointer"
                title="Stop Simulation"
              >
                <Square className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* THREE ATTACK SCENARIOS SIDE-BY-SIDE */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        
        {/* Scenario 1: Slow Exfiltration */}
        <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/30 flex flex-col justify-between h-56">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-rose-400 flex items-center gap-1.5 bg-rose-950/20 px-2 py-0.5 rounded border border-rose-500/20">
                <Flame className="w-3.5 h-3.5" />
                Scenario 1
              </span>
              <span className="text-[10px] font-mono text-slate-500 font-bold">L3 TARGETED</span>
            </div>
            <h3 className="text-sm font-mono text-white uppercase font-bold mb-1">Slow Exfiltration Profile</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Triggers ascending volumetric layers over 6 steps (1MB → 6MB). Bypasses naive packet volume bounds but gets trapped by polynomial regression gradients.
            </p>
          </div>
          <button
            onClick={() => onStartSim("EXFIL")}
            disabled={simStatus.startsWith("running_")}
            className="w-full py-1.5 bg-[#1F2937] hover:bg-rose-950/20 border border-[#1F2937] hover:border-rose-500/40 text-slate-300 hover:text-rose-400 font-mono text-xs font-bold rounded-lg cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-1.5"
          >
            DEPLOY TARGET PROFILE
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Scenario 2: Baseline Poisoning */}
        <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/30 flex flex-col justify-between h-56">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-purple-400 flex items-center gap-1.5 bg-purple-950/20 px-2 py-0.5 rounded border border-purple-500/20">
                <Database className="w-3.5 h-3.5" />
                Scenario 2
              </span>
              <span className="text-[10px] font-mono text-slate-500 font-bold">L1/ADS TARGETED</span>
            </div>
            <h3 className="text-sm font-mono text-white uppercase font-bold mb-1">Baseline Poisoning</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Fires 12 steps, drifting payloads by +5% each loop. Adapts dynamic bounds silently until checked by the Adversarial Drift Sentinel (ADS) snapshot.
            </p>
          </div>
          <button
            onClick={() => onStartSim("POISON")}
            disabled={simStatus.startsWith("running_")}
            className="w-full py-1.5 bg-[#1F2937] hover:bg-purple-950/20 border border-[#1F2937] hover:border-purple-500/40 text-slate-300 hover:text-purple-400 font-mono text-xs font-bold rounded-lg cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-1.5"
          >
            DEPLOY TARGET PROFILE
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Scenario 3: Horizontal Recon Sweep */}
        <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/30 flex flex-col justify-between h-56">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-yellow-400 flex items-center gap-1.5 bg-yellow-950/20 px-2 py-0.5 rounded border border-yellow-500/20">
                <Compass className="w-3.5 h-3.5" />
                Scenario 3
              </span>
              <span className="text-[10px] font-mono text-slate-500 font-bold">L2 TARGETED</span>
            </div>
            <h3 className="text-sm font-mono text-white uppercase font-bold mb-1">Recon Sweep</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Fires rapid micro-packets across all 10 socket listeners. Evades volume spikes as they are tiny, but gets caught by KDE spatial port density profiling.
            </p>
          </div>
          <button
            onClick={() => onStartSim("SWEEP")}
            disabled={simStatus.startsWith("running_")}
            className="w-full py-1.5 bg-[#1F2937] hover:bg-yellow-950/20 border border-[#1F2937] hover:border-yellow-500/40 text-slate-300 hover:text-yellow-400 font-mono text-xs font-bold rounded-lg cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-1.5"
          >
            DEPLOY TARGET PROFILE
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

      </div>

      {/* MONOSPACE SPLIT TERMINALS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 font-mono text-xs">
        
        {/* Left Terminal: Attack Logs */}
        <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden shadow-md flex flex-col h-[32rem]">
          <div className="bg-[#111418] px-4 py-2 flex items-center gap-2 border-b border-[#1F2937]/50 shrink-0">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
            <span className="text-slate-400 font-bold text-[10px] uppercase tracking-wider">Attack Log Terminal (Outbound Outlines)</span>
          </div>
          <div className="p-4 bg-[#07090D] overflow-y-auto grow flex flex-col-reverse text-[#34D399] select-text scrollbar-thin scrollbar-thumb-zinc-800 leading-relaxed font-mono text-[10px]">
            {attackLog.map((line, idx) => (
              <div 
                key={`atk-${idx}`} 
                className={`py-0.5 whitespace-pre-wrap shrink-0 ${
                  line.includes("⛔") || line.includes("Dropped") ? "text-red-400 font-bold bg-red-950/15 p-1 rounded my-0.5 border border-red-900/35" : 
                  line.includes("🚨") || line.includes("EXFIL") ? "text-rose-400 font-bold" :
                  line.includes("🧪") || line.includes("POISON") ? "text-purple-400" :
                  line.includes("🔍") || line.includes("RECON") ? "text-yellow-300" :
                  "text-[#34D399] opacity-80"
                }`}
              >
                {line}
              </div>
            ))}
          </div>
        </div>

        {/* Right Terminal: Detection Logs */}
        <div className="rounded-xl border border-[#1F2937]/60 overflow-hidden shadow-md flex flex-col h-[32rem]">
          <div className="bg-[#111418] px-4 py-2 flex items-center gap-2 border-b border-[#1F2937]/50 shrink-0">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span className="text-slate-400 font-bold text-[10px] uppercase tracking-wider">Detection core logs (Inbound Audit)</span>
          </div>
          <div className="p-4 bg-[#07090D] overflow-y-auto grow flex flex-col-reverse text-[#34D399] select-text scrollbar-thin scrollbar-thumb-zinc-800 leading-relaxed font-mono text-[10px]">
            {detectionLog.map((line, idx) => (
              <div 
                key={`det-${idx}`} 
                className={`py-0.5 whitespace-pre-wrap shrink-0 ${
                  line.includes("🛡️") || line.includes("FIREWALL") ? "text-red-400 bg-red-950/15 p-1 rounded my-0.5 border border-red-900/35 font-bold" :
                  line.includes("[HIGH]") ? "text-rose-500 font-bold" : 
                  line.includes("[MEDIUM]") ? "text-amber-500" : 
                  line.includes("[LOW]") ? "text-yellow-400/90" : 
                  "text-[#10B981] opacity-75"
                }`}
              >
                {line}
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* PORT EXPANSION: MANUAL PACKET INJECTOR */}
      <div className="p-5 rounded-xl border border-[#1F2937]/60 bg-[#111418]/50">
        <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2 mb-4">
          <Zap className="text-cyan-400 w-4 h-4" />
          Adaptive Manual Packet Injection Form
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          
          {/* Source IP Input */}
          <div className="flex flex-col space-y-1 font-mono text-[11px]">
            <label className="text-slate-400 font-bold uppercase">Source IP Address:</label>
            <input 
              type="text" 
              value={customIp}
              onChange={(e) => setCustomIp(e.target.value)}
              className="px-3 py-1.5 rounded bg-[#0b0e14] border border-[#1F2937] text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 text-xs"
              placeholder="e.g. 192.168.1.100"
            />
          </div>

          {/* Dest Port Dropdown */}
          <div className="flex flex-col space-y-1 font-mono text-[11px]">
            <label className="text-slate-400 font-bold uppercase">Destination Port Target:</label>
            <select
              value={customPort}
              onChange={(e) => setCustomPort(parseInt(e.target.value))}
              className="px-3 py-1.5 rounded bg-[#0b0e14] border border-[#1F2937] text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 text-xs cursor-pointer"
            >
              {Array.from({ length: 10 }).map((_, i) => {
                const p = 5001 + i;
                return <option key={p} value={p}>Port {p} (Socket)</option>;
              })}
            </select>
          </div>

          {/* Bytes Slider */}
          <div className="flex flex-col space-y-1 font-mono text-[11px] md:col-span-2">
            <div className="flex justify-between items-center text-slate-400">
              <span className="font-bold uppercase">Exchanged Data Volume:</span>
              <span className="font-bold text-white bg-[#0b0e14] border border-[#1F2937] px-2 py-0.5 rounded text-[10px]">
                {formatBytes(customBytes)}
              </span>
            </div>
            <div className="flex items-center gap-3 pt-1">
              <span className="text-[10px] text-slate-500">100 B</span>
              <input 
                type="range" 
                min={100}
                max={5 * 1024 * 1024} // 5 MB Max
                step={500}
                value={customBytes}
                onChange={(e) => setCustomBytes(parseInt(e.target.value))}
                className="grow h-1.5 bg-[#1F2937]/85 cursor-ew-resize accent-cyan-400"
              />
              <span className="text-[10px] text-slate-500">5 MB</span>
            </div>
          </div>

        </div>

        {/* Payload description textarea */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-[11px]">
          <div className="flex flex-col space-y-1 md:col-span-3">
            <label className="text-slate-400 font-bold uppercase">Raw Payload Check String:</label>
            <input
              type="text"
              value={customPayload}
              onChange={(e) => setCustomPayload(e.target.value)}
              className="px-3 py-2 rounded bg-[#0b0e14] border border-[#1F2937] text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 text-xs"
              placeholder="Inject custom testing descriptions..."
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={onInjectCustom}
              className="w-full py-2 bg-slate-900/40 hover:bg-cyan-950/20 border border-cyan-500/30 hover:border-cyan-500/60 text-[#38BDF8] font-bold text-xs rounded-lg cursor-pointer transition-all inline-flex items-center justify-center gap-1.5"
            >
              <Zap className="w-3.5 h-3.5 fill-cyan-400/10" />
              INJECT DIRECT TCP STREAM
            </button>
          </div>
        </div>

      </div>

    </div>
  );
}
