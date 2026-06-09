import React, { useState, useRef, useEffect } from "react";
import { 
  Shield, Activity, Cpu, Clock, Terminal, Zap, Layers, RefreshCw, AlertTriangle,
  Eye, Radar, Skull, Globe, Tag
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

import { ConnectionRecord, LogEntry, PortState, SimStatus, ThreatLevel } from "./types";
import { HDTEngine } from "./hdtEngine";
import { 
  generateBaselineSequence, 
  generateExfilSequence, 
  generatePoisoningSequence, 
  generateSweepSequence,
  generateMockHexPayload
} from "./simulator";

// Import modular components
import TestLabTab from "./components/TestLabTab";
import ModelsViewTab from "./components/ModelsViewTab";
import MetricsTab from "./components/MetricsTab";
import AlertsTab from "./components/AlertsTab";
import DevicesTab from "./components/DevicesTab";
import ForensicsModal from "./components/ForensicsModal";

// Recharts components for Dashboard bottom-line chart
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip
} from "recharts";

export default function App() {
  // Instantiate HDT Engine inside ref
  const engineRef = useRef(new HDTEngine());

  // Global Active Navigation state
  const [activeTab, setActiveTab] = useState<"DASHBOARD" | "TEST_LAB" | "MODELS" | "METRICS" | "ALERTS" | "DEVICES">("DASHBOARD");

  // Dynamic ticking clock for status bar
  const [sessionUptime, setSessionUptime] = useState<number>(0);
  useEffect(() => {
    const timer = setInterval(() => {
      setSessionUptime(prev => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatUptime = (seconds: number) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h.toString().padStart(2, "0")}h ${m.toString().padStart(2, "0")}m ${s.toString().padStart(2, "0")}s`;
  };

  const getAttackType = (payloadLabel: string) => {
    const uppercaseLabel = payloadLabel.toUpperCase();
    if (uppercaseLabel.includes("NMAP-PORT-SWEEP")) return "Nmap Port Sweep";
    if (uppercaseLabel.includes("NMAP-SYN-PROBE")) return "Nmap SYN Probe";
    if (uppercaseLabel.includes("HTTP-PROBE")) return "HTTP Probe";
    if (uppercaseLabel.includes("NETCAT-MANUAL")) return "Netcat Manual";
    if (uppercaseLabel.includes("SLOW-EXFIL")) return "Slow Exfiltration";
    if (uppercaseLabel.includes("BASELINE-POISON")) return "Baseline Poisoning";
    if (uppercaseLabel.includes("RECON-SWEEP")) return "Recon Sweep Mode";
    if (uppercaseLabel.includes("UNKNOWN-PROBE")) return "Unknown Probe";
    if (uppercaseLabel.includes("BASELINE")) return "Baseline Traffic";
    if (uppercaseLabel.includes("EXFIL")) return "Exfiltration (L&S)";
    if (uppercaseLabel.includes("POISON")) return "GMM Poisoning";
    if (uppercaseLabel.includes("RECON") || uppercaseLabel.includes("SWEEP")) return "Recon Sweep Mode";
    if (uppercaseLabel.includes("MANUAL")) return "Manual TCP Injection";
    return payloadLabel || "Generic Stream";
  };

  const getAttackBadge = (payloadLabel: string) => {
    const uppercaseLabel = payloadLabel.toUpperCase();
    if (uppercaseLabel.includes("SLOW-EXFIL")) {
      return { label: "SLOW-EXFIL", icon: <AlertTriangle className="w-3 h-3" />, className: "bg-red-950/40 text-red-300 border border-red-500/20" };
    }
    if (uppercaseLabel.includes("BASELINE-POISON")) {
      return { label: "BASELINE-POISON", icon: <Skull className="w-3 h-3" />, className: "bg-purple-950/40 text-purple-300 border border-purple-500/20" };
    }
    if (uppercaseLabel.includes("RECON-SWEEP")) {
      return { label: "RECON-SWEEP", icon: <Radar className="w-3 h-3" />, className: "bg-yellow-950/40 text-yellow-300 border border-yellow-500/20" };
    }
    if (uppercaseLabel.includes("NMAP-PORT-SWEEP")) {
      return { label: "NMAP-PORT-SWEEP", icon: <Eye className="w-3 h-3" />, className: "bg-orange-950/40 text-orange-300 border border-orange-500/20" };
    }
    if (uppercaseLabel.includes("NMAP-SYN-PROBE")) {
      return { label: "NMAP-SYN-PROBE", icon: <Zap className="w-3 h-3" />, className: "bg-orange-950/40 text-orange-300 border border-orange-500/20" };
    }
    if (uppercaseLabel.includes("NETCAT-MANUAL")) {
      return { label: "NETCAT-MANUAL", icon: <Terminal className="w-3 h-3" />, className: "bg-cyan-950/40 text-cyan-300 border border-cyan-500/20" };
    }
    if (uppercaseLabel.includes("HTTP-PROBE")) {
      return { label: "HTTP-PROBE", icon: <Globe className="w-3 h-3" />, className: "bg-sky-950/40 text-sky-300 border border-sky-500/20" };
    }
    if (uppercaseLabel.includes("UNKNOWN-PROBE")) {
      return { label: "UNKNOWN-PROBE", icon: <Shield className="w-3 h-3" />, className: "bg-slate-950/40 text-slate-300 border border-slate-500/20" };
    }
    return { label: getAttackType(payloadLabel), icon: <Tag className="w-3 h-3" />, className: "bg-slate-950/30 text-slate-300 border border-slate-500/20" };
  };

  // React states mirroring engine metrics
  const [obsCount, setObsCount] = useState(0);
  const [isAnchored, setIsAnchored] = useState(false);
  const [gmmMean, setGmmMean] = useState(75000);
  const [gmmStd, setGmmStd] = useState(20000);
  const [anchorMean, setAnchorMean] = useState(75000);
  const [gmmDrift, setGmmDrift] = useState(0);
  const [lowessSlope, setLowessSlope] = useState(0);

  // Global logging stack
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [blockedIps, setBlockedIps] = useState<string[]>([]);
  
  // Port state tracking for port lightnings
  const [ports, setPorts] = useState<PortState[]>(
    Array.from({ length: 10 }).map((_, i) => ({
      port: 5001 + i,
      lastHitTime: 0,
      flashType: null,
      count: 0
    }))
  );

  // System accumulators
  const [totalBytes, setTotalBytes] = useState(0);
  const [totalConnections, setTotalConnections] = useState(0);
  const [captureRate, setCaptureRate] = useState(0.2); // pkts/s
  const [cpuTemp, setCpuTemp] = useState(38.2);
  const [systemAlert, setSystemAlert] = useState<ThreatLevel>("MONITORING");

  // Simulation Sequence controllers
  const [simStatus, setSimStatus] = useState<SimStatus>("baseline_ready_to_run");
  const [simIndex, setSimIndex] = useState(0);
  const [simSequence, setSimSequence] = useState<Omit<ConnectionRecord, "id" | "index">[]>([]);
  const [simSpeed, setSimSpeed] = useState<number>(500); // delay step
  const [isAutoPlay, setIsAutoPlay] = useState(false);
  const [simMessage, setSimMessage] = useState<string>("Threat detection stack idle.");

  // Manual Injected Inputs state
  const [customPort, setCustomPort] = useState<number>(5001);
  const [customBytes, setCustomBytes] = useState<number>(75000);
  const [customPayload, setCustomPayload] = useState<string>("GET /api/v1/telemetry HTTP/1.1");
  const [customIp, setCustomIp] = useState<string>("10.0.12.91");

  // Terminal history strings
  const [attackLog, setAttackLog] = useState<string[]>([
    "🌀 DRIFT WATCH NDR Attack Simulator Initialized.",
    "░ System idling. Select a simulation profile above to target listeners."
  ]);
  const [detectionLog, setDetectionLog] = useState<string[]>([
    "🐸 Unified Detection Core listening on Ports 5001-5010.",
    "░ State engines primed. Waiting for ingress traffic..."
  ]);

  // Selected Entity IP for global filters
  const [selectedEntityIp, setSelectedEntityIp] = useState<string>("");

  // Background fluctuations simulating server hardware
  useEffect(() => {
    const timer = setInterval(() => {
      setCaptureRate(prev => {
        if (simStatus.startsWith("running_")) {
          return parseFloat((Math.random() * 2.5 + 1.8).toFixed(1));
        }
        return parseFloat((Math.random() * 0.4 + 0.1).toFixed(1));
      });
      setCpuTemp(prev => {
        if (simStatus.startsWith("running_")) {
          return parseFloat((prev + (Math.random() * 0.3 - 0.05)).toFixed(1));
        }
        return parseFloat((38.2 + (Math.random() * 1.2 - 0.6)).toFixed(1));
      });
    }, 1500);
    return () => clearInterval(timer);
  }, [simStatus]);

  // Main simulation running autoplay loop hook
  useEffect(() => {
    let playTimer: NodeJS.Timeout;
    
    if (isAutoPlay && simStatus.startsWith("running_")) {
      if (simIndex < simSequence.length) {
        playTimer = setTimeout(() => {
          processNextConnection();
        }, simSpeed);
      } else {
        setIsAutoPlay(false);
        if (simStatus === "running_baseline") {
          setSimStatus("baseline_complete");
          setSimMessage("✓ Baseline analysis complete. Anchor Locked! Tapestry layers activated.");
          engineRef.current.setAnchor();
          setIsAnchored(true);
          setAnchorMean(engineRef.current.mean);
        } else {
          setSimStatus("attack_complete");
          setSimMessage(`✓ Attack simulation sequence completed.`);
        }
      }
    }

    return () => clearTimeout(playTimer);
  }, [isAutoPlay, simIndex, simSequence, simStatus, simSpeed]);

  const processNextConnection = () => {
    if (simIndex >= simSequence.length) return;

    const rawConn = simSequence[simIndex];
    triggerConnection({
      id: `conn-${Date.now()}-${simIndex}`,
      index: totalConnections + 1,
      ...rawConn
    });

    setSimIndex(prev => prev + 1);
  };

  const handleSystemReset = () => {
    engineRef.current.reset();
    setObsCount(0);
    setIsAnchored(false);
    setGmmMean(75000);
    setGmmStd(20000);
    setAnchorMean(75000);
    setGmmDrift(0);
    setLowessSlope(0);
    
    setLogs([]);
    setSelectedLog(null);
    setBlockedIps([]);
    setTotalBytes(0);
    setTotalConnections(0);
    setSystemAlert("MONITORING");
    setSelectedEntityIp("");
    setPorts(
      Array.from({ length: 10 }).map((_, i) => ({
        port: 5001 + i,
        lastHitTime: 0,
        flashType: null,
        count: 0
      }))
    );

    setSimStatus("baseline_ready_to_run");
    setSimIndex(0);
    setSimSequence([]);
    setIsAutoPlay(false);
    setSimMessage("Threat detection stack rebooted. Static weights established.");
    setAttackLog([
      "🐸 SECURITY ENVIRONMENT REBOOTED - ALL TELEMETRY SCRUBBED",
      "░ System idling. Select a simulation profile above to target listeners."
    ]);
    setDetectionLog([
      "🐸 SECURITY DETECTION CORE COLD-REBOOT COMPLETE",
      "░ Waiting for baseline establishment..."
    ]);
  };

  const handleLoadBaseline = () => {
    handleSystemReset();
    const seq = generateBaselineSequence();
    setSimSequence(seq);
    setSimStatus("running_baseline");
    setIsAutoPlay(true);
    setSimIndex(0);
    setSimMessage("Injecting normal enterprise volume flow variables to align dynamic parameters...");
  };

  const verifyBaselineAndDeploy = (type: "EXFIL" | "POISON" | "SWEEP") => {
    if (!isAnchored) {
      alert("WARNING: Prime GMM parameters by completing baseline warmup before triggering attacks!");
      return;
    }

    let seq: Omit<ConnectionRecord, "id" | "index">[] = [];
    let status: SimStatus = "baseline_ready_to_run";
    let message = "";

    if (type === "EXFIL") {
      seq = generateExfilSequence();
      status = "running_attack_exfil";
      message = "Deploying EXFIL sequence. Elevating upload thresholds relative to regression bounds...";
    } else if (type === "POISON") {
      seq = generatePoisoningSequence();
      status = "running_attack_poison";
      message = "Deploying POISONING sequence. Seeding minor payload drifts (+5% per index)...";
    } else if (type === "SWEEP") {
      seq = generateSweepSequence();
      status = "running_attack_sweep";
      message = "Deploying RECON SWEEP sequence. Firing rapid query probes over multiple port listeners...";
    }

    setSimSequence(seq);
    setSimStatus(status);
    setIsAutoPlay(true);
    setSimIndex(0);
    setSimMessage(message);
  };

  const handleInjectCustom = () => {
    const label = `MANUAL|PORT=${customPort}|LEN=${customBytes}B`;
    const hex = generateMockHexPayload(customBytes, "MANUAL", totalConnections + 1, "custom_inject");
    
    triggerConnection({
      id: `inject-${Date.now()}`,
      index: totalConnections + 1,
      srcIp: customIp,
      srcPort: Math.floor(Math.random() * 8000) + 41000,
      dstPort: customPort,
      byteCount: customBytes,
      timestamp: new Date().toLocaleTimeString(),
      payloadLabel: label,
      rawPayload: hex
    }, true);
  };

  const triggerConnection = (conn: ConnectionRecord, isCustom = false) => {
    const timeStr = new Date().toLocaleTimeString();
    
    // Core Block Evaluation
    const isIpBlocked = blockedIps.includes(conn.srcIp);
    
    if (isIpBlocked) {
      // Direct drop! Log drop inside terminal frames and ignore engine evaluation
      setAttackLog(prev => [
        `[${timeStr}] ⛔ BLACKLIST DROP: Firewall prevented TCP stream from blocked IP ${conn.srcIp} on DST_PORT ${conn.dstPort} (${formatBytes(conn.byteCount)})`,
        ...prev
      ].slice(0, 50));
      
      setDetectionLog(prev => [
        `[${timeStr}] 🛡️ ACCESS VIOLATION: Source host ${conn.srcIp} is banned. Direct telemetry socket rejected.`,
        ...prev
      ].slice(0, 50));
      
      setTotalConnections(prev => prev + 1);
      return;
    }

    // Process normal evaluations via HDTEngine instance
    const scores = engineRef.current.evaluate(conn);
    
    // Keep React states in structural alignment
    setObsCount(engineRef.current.obsCount);
    setGmmMean(Math.floor(engineRef.current.mean));
    setGmmStd(Math.floor(Math.sqrt(engineRef.current.variance)));
    setGmmDrift(engineRef.current.gmm_drift);
    setLowessSlope(Math.floor(engineRef.current.lowess_slope));

    // Dynamic Flashers
    let flashType: "normal" | "exfil" | "poison" | "sweep" = "normal";
    if (conn.payloadLabel.includes("EXFIL")) flashType = "exfil";
    else if (conn.payloadLabel.includes("POISON")) flashType = "poison";
    else if (conn.payloadLabel.includes("RECON")) flashType = "sweep";

    setPorts(prev => prev.map(p => {
      if (p.port === conn.dstPort) {
        return {
          ...p,
          lastHitTime: Date.now(),
          flashType,
          count: p.count + 1
        };
      }
      return p;
    }));

    // Accumulators
    setTotalBytes(prev => prev + conn.byteCount);
    setTotalConnections(prev => prev + 1);

    // Save LogEntry
    const logEntry: LogEntry = {
      id: conn.id,
      timestamp: conn.timestamp,
      srcIp: conn.srcIp,
      srcPort: conn.srcPort,
      dstPort: conn.dstPort,
      byteCount: conn.byteCount,
      payloadLabel: conn.payloadLabel,
      scores,
      isCustomManual: isCustom,
      gmmDrift: engineRef.current.gmm_drift
    };

    setLogs(prev => [logEntry, ...prev]);

    // Format Split Monospace terminal logs
    const scoreSummaries = `L1_GMM=${scores.l1_gmm.toFixed(3)} L2_KDE=${scores.l2_kde.toFixed(3)} L3_LOW=${scores.l3_lowess.toFixed(3)} ADS=${scores.ads.toFixed(3)}`;
    const detLine = `[${timeStr}] EVAL: src=${conn.srcIp} -> dst_port=${conn.dstPort} (${formatBytes(conn.byteCount)}) | Fusion=${scores.fusion.toFixed(4)} [${scores.alert}] | ${scoreSummaries}`;
    setDetectionLog(prev => [detLine, ...prev].slice(0, 50));

    let attackDesc = "";
    if (conn.payloadLabel.includes("BASELINE")) {
      attackDesc = `[${timeStr}] ░ STREAM: Ingesting standard enterprise profile observation #${conn.index} from IP ${conn.srcIp}`;
    } else if (conn.payloadLabel.includes("EXFIL")) {
      attackDesc = `[${timeStr}] 🚨 EXFILTRATION INJECT: Rising-volume telemetry frames | step size=${formatBytes(conn.byteCount)}`;
    } else if (conn.payloadLabel.includes("POISON")) {
      attackDesc = `[${timeStr}] 🧪 GMM CORRUPTION INJECT: Poison adjustments | size=${formatBytes(conn.byteCount)} (${conn.payloadLabel.split("|SIZE=")[1]?.split("|")[0] || ""})`;
    } else if (conn.payloadLabel.includes("RECON")) {
      attackDesc = `[${timeStr}] 🔍 SCAN TARGET PROBE: TCP connect query hits socket:${conn.dstPort}`;
    } else {
      attackDesc = `[${timeStr}] ⚡ USER TCP MANUAL INJECT: Source IP=${conn.srcIp} -> dst_port=${conn.dstPort} (${formatBytes(conn.byteCount)})`;
    }
    setAttackLog(prev => [attackDesc, ...prev].slice(0, 50));

    // Force detail inspect on HIGH threat alerts
    if (scores.alert === "HIGH") {
      setSelectedLog(logEntry);
    }

    // Set Global highest system level indicator
    setSystemAlert(prev => {
      const levels: Record<ThreatLevel, number> = { "MONITORING": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3 };
      if (levels[scores.alert] > levels[prev]) {
        return scores.alert;
      }
      return prev;
    });
  };

  const formatBytes = (n: number) => {
    if (n >= 1048576) return `${(n / 1048576).toFixed(2)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  };

  const handleToggleBlockIp = (ip: string) => {
    setBlockedIps(prev => {
      if (prev.includes(ip)) {
        return prev.filter(blocked => blocked !== ip);
      } else {
        return [...prev, ip];
      }
    });
  };

  // 🌟 Live Physical Python Script Webhook Ingestion Hook
  const processedLiveIdsRef = useRef<Set<string>>(new Set());
  const [isLiveBridgeConnected, setIsLiveBridgeConnected] = useState<boolean>(true);
  const [livePacketsCount, setLivePacketsCount] = useState<number>(0);
  const triggerConnectionRef = useRef(triggerConnection);

  useEffect(() => {
    triggerConnectionRef.current = triggerConnection;
  });

  useEffect(() => {
    let active = true;
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch("/api/observations");
        if (!response.ok) throw new Error("Offline");
        const data = await response.json();
        
        if (!active) return;
        setIsLiveBridgeConnected(true);

        if (Array.isArray(data)) {
          data.forEach((obs: any) => {
            if (!processedLiveIdsRef.current.has(obs.id)) {
              processedLiveIdsRef.current.add(obs.id);
              setLivePacketsCount(prev => prev + 1);
              
              triggerConnectionRef.current({
                id: obs.id,
                index: obs.index || Math.floor(Date.now() / 1000),
                srcIp: obs.srcIp,
                srcPort: obs.srcPort,
                dstPort: obs.dstPort,
                byteCount: obs.byteCount,
                timestamp: obs.timestamp,
                payloadLabel: obs.payloadLabel,
                rawPayload: obs.rawPayload || "LIVE AGENT PACKET INGESTION"
              });
            }
          });
        }
      } catch (err) {
        if (!active) return;
        setIsLiveBridgeConnected(false);
      }
    }, 1000);

    return () => {
      active = false;
      clearInterval(pollInterval);
    };
  }, []);

  // Compile tracked entities map from the total logs history
  const entityMap = new Map<string, { ip: string; totalConns: number; totalBytes: number; highestAlert: ThreatLevel }>();
  logs.forEach(log => {
    const key = log.srcIp;
    const existing = entityMap.get(key);
    if (!existing) {
      entityMap.set(key, {
        ip: key,
        totalConns: 1,
        totalBytes: log.byteCount,
        highestAlert: log.scores.alert
      });
    } else {
      let nextHighest = existing.highestAlert;
      const levels: Record<ThreatLevel, number> = { "MONITORING": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3 };
      if (levels[log.scores.alert] > levels[existing.highestAlert]) {
        nextHighest = log.scores.alert;
      }
      entityMap.set(key, {
        ip: key,
        totalConns: existing.totalConns + 1,
        totalBytes: existing.totalBytes + log.byteCount,
        highestAlert: nextHighest
      });
    }
  });
  const trackedEntities = Array.from(entityMap.values());

  // Alerts feed (Clickable CARDS showing latest 20 alerts)
  const alertFeedLogs = logs
    .filter(log => log.scores.alert !== "MONITORING")
    .slice(0, 20);

  // Bottom Line-Chart Data represents fusion score over observation history for the MOST RECENTLY ACTIVE IP
  const mostRecentIp = logs[0]?.srcIp;
  const recentEntityLogs = mostRecentIp 
    ? logs.filter(log => log.srcIp === mostRecentIp).slice(0, 20).reverse()
    : [];

  const bottomChartData = recentEntityLogs.map((log, index) => ({
    name: `Obs ${index + 1}`,
    score: parseFloat(log.scores.fusion.toFixed(4)),
    limit: 0.35
  }));

  const activePortsTouchedCount = ports.filter(p => p.count > 0).length;

  return (
    <div className="min-h-screen text-[#E2E8F0] font-sans bg-[#0b0e14] grid-dots selection:bg-emerald-500 selection:text-[#0b0e14] relative overflow-x-hidden flex flex-col">
      
      {/* GLOWING AMBIENT GRAPHICS */}
      <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-emerald-500/5 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-10 right-10 w-[400px] h-[400px] bg-teal-500/5 rounded-full blur-[100px] pointer-events-none" />
      {systemAlert === "HIGH" && (
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-rose-600 via-orange-500 to-rose-600 animate-pulse pointer-events-none z-50" />
      )}

      {/* PERSISTENT TOP NAVIGATION BAR */}
      <header className="border-b border-[#1F2937]/90 bg-[#0b0e14]/95 backdrop-blur-md sticky top-0 z-40 transition-all font-mono">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          
          {/* Logo element */}
          <div className="flex items-center gap-2">
            <span className="text-xl">🐸</span>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-slate-100 text-sm tracking-tight uppercase">Drift Watch NDR</span>
                <span className="text-[9px] px-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded">TAPESTRY v4.1</span>
              </div>
            </div>
          </div>

          {/* Navigation Bar centers */}
          <nav className="flex items-center gap-1 bg-[#111418] border border-[#1F2937]/60 p-1 rounded-lg">
            {(["DASHBOARD", "TEST_LAB", "DEVICES", "MODELS", "METRICS", "ALERTS"] as const).map(tab => {
              const active = activeTab === tab;
              return (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-3 py-1.5 rounded-md text-[11px] font-bold tracking-wider cursor-pointer transitioning transition-colors ${
                    active 
                      ? "bg-[#1F2937] text-white py-1.5 shadow" 
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {tab === "TEST_LAB" ? "TEST LAB" : tab === "MODELS" ? "MODELS VIEW" : tab === "ALERTS" ? "ALERTS" : tab === "DEVICES" ? "DEVICES" : tab}
                </button>
              );
            })}
          </nav>

          {/* Right Status Dot bar */}
          <div className="flex items-center gap-4 text-[11px] select-none">
            <div className="flex items-center gap-3">
              <span className="text-slate-500 font-bold uppercase">System:</span>
              <div className="flex items-center gap-1.5 font-bold">
                {systemAlert === "HIGH" ? (
                  <>
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
                    <span className="text-red-400 tracking-widest uppercase">HIGH ALERT</span>
                  </>
                ) : (
                  <>
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="text-emerald-400 uppercase">STATUS OK</span>
                  </>
                )}
              </div>
            </div>

            <span className="text-slate-700">|</span>

            <div className="flex items-center gap-3">
              <span className="text-[#94A3B8] font-bold uppercase">Live Bridge:</span>
              <div className="flex items-center gap-1.5 font-bold">
                {isLiveBridgeConnected ? (
                  <>
                    <span className={`w-2 h-2 rounded-full ${livePacketsCount > 0 ? "bg-cyan-400 animate-pulse" : "bg-emerald-500"}`} />
                    <span className={`${livePacketsCount > 0 ? "text-cyan-400" : "text-emerald-400"} uppercase`} title="Streaming live captures from drift_watch_listener.py">
                      {livePacketsCount > 0 ? `STREAMING (${livePacketsCount} PKTS)` : "LISTENING"}
                    </span>
                  </>
                ) : (
                  <>
                    <span className="w-2 h-2 rounded-full bg-amber-500" />
                    <span className="text-amber-500 uppercase">OFFLINE</span>
                  </>
                )}
              </div>
            </div>
          </div>

        </div>
      </header>

      {/* CORE FRAME CONTAINER */}
      <main className="flex-grow max-w-7xl w-full mx-auto px-6 py-6 font-sans">
        
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.15 }}
          >
            {/* TAB 1: DASHBOARD */}
            {activeTab === "DASHBOARD" && (
              <div className="space-y-6">
                
                {/* 1. TOP LIVE SYSTEM STATUS BAR */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  
                  {/* Uptime box */}
                  <div className="p-4 rounded-xl border border-[#1F2937]/50 bg-[#111418]/30 backdrop-blur-sm flex flex-col justify-between h-20 font-mono">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1 font-bold">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      Session Uptime
                    </span>
                    <span className="text-slate-200 font-bold text-sm tracking-tight">{formatUptime(sessionUptime)}</span>
                  </div>

                  {/* Total connections box */}
                  <div className="p-4 rounded-xl border border-[#1F2937]/50 bg-[#111418]/30 backdrop-blur-sm flex flex-col justify-between h-20 font-mono">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1 font-bold">
                      <Activity className="w-3.5 h-3.5 text-cyan-400" />
                      Total Connections
                    </span>
                    <span className="text-slate-200 font-bold text-base mt-auto">{totalConnections}</span>
                  </div>

                  {/* Total bytes box */}
                  <div className="p-4 rounded-xl border border-[#1F2937]/50 bg-[#111418]/30 backdrop-blur-sm flex flex-col justify-between h-20 font-mono">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1 font-bold">
                      <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                      Ingested Volume
                    </span>
                    <span className="text-slate-200 font-bold text-base mt-auto">{formatBytes(totalBytes)}</span>
                  </div>

                  {/* Unique IPs box */}
                  <div className="p-4 rounded-xl border border-[#1F2937]/50 bg-[#111418]/30 backdrop-blur-sm flex flex-col justify-between h-20 font-mono">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1 font-bold">
                      <Layers className="w-3.5 h-3.5 text-yellow-400" />
                      Unique Hosts
                    </span>
                    <span className="text-slate-200 font-bold text-base mt-auto">{trackedEntities.length}</span>
                  </div>

                  {/* Highest alert status box */}
                  <div className="p-4 rounded-xl border border-[#1F2937]/50 bg-[#111418]/30 backdrop-blur-sm flex flex-col justify-between h-20 col-span-2 md:col-span-1 font-mono">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1 font-bold">
                      <Shield className="w-3.5 h-3.5 text-rose-500" />
                      Highest alert
                    </span>
                    <span className={`text-[11px] px-2 py-0.5 rounded font-bold uppercase text-center mt-auto border ${
                      systemAlert === "HIGH" ? "bg-red-950/40 text-red-400 border-red-500/20" :
                      systemAlert === "MEDIUM" ? "bg-amber-950/40 text-amber-400 border-amber-500/20" :
                      systemAlert === "LOW" ? "bg-yellow-950/40 text-yellow-400 border-yellow-500/20" :
                      "bg-emerald-950/40 text-emerald-405 border-emerald-500/20"
                    }`}>
                      {systemAlert}
                    </span>
                  </div>

                </div>

                {/* 2. ENTITY TABLE & LIVE ALERT FEED split rows */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  
                  {/* Left panel: Entities Table */}
                  <div className="lg:col-span-8 p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 flex flex-col">
                    <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-4">
                      Observed Entities Mapping (Source Hosts Index)
                    </h3>

                    {trackedEntities.length === 0 ? (
                      <div className="flex flex-col items-center justify-center p-12 text-center h-64 border border-dashed border-[#1F2937]/45 rounded-xl">
                        <span className="text-[10px] font-mono text-slate-500">░ NO TRAFFIC DIRECT RESERVED ░</span>
                        <span className="text-xs text-slate-400 mt-2 max-w-sm">
                          Dynamic model tracking matrices are vacant. Run simulation baselines under <strong>TEST LAB</strong> to populate active entity maps.
                        </span>
                      </div>
                    ) : (
                      <div className="overflow-x-auto grow">
                        <table className="w-full text-left font-mono text-[11px]">
                          <thead>
                            <tr className="border-b border-[#1F2937] text-slate-500 font-bold">
                              <th className="pb-3 text-left">IP Address</th>
                              <th className="pb-3 text-center">Exchanged Sessions</th>
                              <th className="pb-3 text-right">Data Exchanged</th>
                              <th className="pb-3 text-center">Threat Severity</th>
                              <th className="pb-3 text-center">Block Status</th>
                              <th className="pb-3 text-right">Gateways</th>
                            </tr>
                          </thead>
                          <tbody>
                            {trackedEntities.map(entity => {
                              const isBlocked = blockedIps.includes(entity.ip);
                              return (
                                <tr key={entity.ip} className="border-b border-[#1F2937]/30 hover:bg-[#111418]/45 transition-colors">
                                  <td className="py-3 text-slate-200 font-bold">{entity.ip}</td>
                                  <td className="py-3 text-center text-slate-400">{entity.totalConns}</td>
                                  <td className="py-3 text-right text-slate-400">{formatBytes(entity.totalBytes)}</td>
                                  <td className="py-3 text-center">
                                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                                      entity.highestAlert === "HIGH" ? "bg-red-950/50 text-red-400 border border-red-500/10" :
                                      entity.highestAlert === "MEDIUM" ? "bg-amber-950/20 text-amber-400 border border-amber-500/10" :
                                      entity.highestAlert === "LOW" ? "bg-yellow-950/20 text-yellow-400 border border-yellow-500/10" :
                                      "bg-emerald-950/20 text-emerald-400"
                                    }`}>
                                      {entity.highestAlert}
                                    </span>
                                  </td>
                                  <td className="py-3 text-center">
                                    {isBlocked ? (
                                      <span className="text-[10px] text-red-400 bg-red-950/35 border border-red-500/20 px-1.5 py-0.5 rounded font-bold uppercase">
                                        BANNED
                                      </span>
                                    ) : (
                                      <span className="text-[10px] text-slate-500">ACTIVE</span>
                                    )}
                                  </td>
                                  <td className="py-3 text-right">
                                    <button 
                                      onClick={() => {
                                        // Pick the most recent log of this entity
                                        const eLog = logs.find(l => l.srcIp === entity.ip);
                                        if (eLog) setSelectedLog(eLog);
                                      }}
                                      className="px-2 py-1 border border-[#1F2937] hover:border-[#10B981] hover:bg-[#10B981]/10 text-[10px] font-bold text-slate-300 hover:text-white rounded cursor-pointer transition-colors"
                                    >
                                      VIEW DETAILS
                                    </button>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  {/* Right panel: Live Alerts Feed card roll */}
                  <div className="lg:col-span-4 p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 flex flex-col h-[24rem]">
                    <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-3">
                      Threat Alerts Feed (Click card of last 20)
                    </h3>
                    
                    <div className="overflow-y-auto space-y-2.5 grow scrollbar-thin select-none pr-1">
                      {alertFeedLogs.length === 0 ? (
                        <div className="flex flex-col items-center justify-center p-8 text-center h-full text-slate-500 font-mono text-[10px]">
                          <span>░ NO ACTIVE ALERTS YET ░</span>
                          <span className="text-[9px] text-slate-600 mt-1">Normal baseline flows do not yield alert threat thresholds.</span>
                        </div>
                      ) : (
                        alertFeedLogs.map(log => {
                          const isBlocked = blockedIps.includes(log.srcIp);
                          return (
                            <div
                              key={log.id}
                              onClick={() => setSelectedLog(log)}
                              className="p-3 rounded-lg bg-[#0b0e14] border border-[#1F2937] hover:border-emerald-500/40 cursor-pointer transition-all font-mono text-left relative overflow-hidden"
                            >
                              <div className="flex justify-between items-start text-[10px] mb-1.5">
                                <span className="text-slate-400 font-bold">{log.srcIp}</span>
                                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                                  log.scores.alert === "HIGH" ? "bg-red-950/40 text-red-400 border border-red-500/10" :
                                  log.scores.alert === "MEDIUM" ? "bg-amber-950/40 text-amber-400" :
                                  "bg-yellow-950/30 text-yellow-400"
                                }`}>
                                  {log.scores.alert}
                                </span>
                              </div>
                              <div className="text-[10px] text-slate-500">
                                Size: {formatBytes(log.byteCount)} | Port: {log.dstPort}
                              </div>
                              <div className="text-[9px] text-slate-600 mt-1 truncate flex items-center gap-2">
                                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold uppercase ${getAttackBadge(log.payloadLabel).className}`}>
                                  {getAttackBadge(log.payloadLabel).icon}
                                  {getAttackBadge(log.payloadLabel).label}
                                </span>
                              </div>
                              {isBlocked && (
                                <div className="absolute inset-0 bg-[#07090D]/50 flex items-center justify-center backdrop-blur-xs font-bold text-[10px] text-red-400 uppercase tracking-widest">
                                  BANNED AT THE EDGE HANDSHAKE
                                </div>
                              )}
                            </div>
                          );
                        })
                      )}
                    </div>

                    {/* View All Alerts action button */}
                    <button
                      onClick={() => setActiveTab("ALERTS")}
                      className="mt-3.5 w-full py-2 border border-emerald-500/30 hover:border-emerald-500/80 bg-emerald-500/5 hover:bg-emerald-500/15 text-[10px] font-mono font-bold tracking-wider text-emerald-400 hover:text-white rounded-lg transition-all flex items-center justify-center gap-1.5 cursor-pointer uppercase shrink-0"
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      View All Alerts ({logs.filter(l => l.scores.alert !== "MONITORING").length})
                    </button>
                  </div>

                </div>

                {/* 3. BOTTOM LIVE COMPOSITE SCORE LINE CHART FOR RECENT ENTITY */}
                <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 flex flex-col">
                  <div className="flex items-center justify-between gap-4 flex-wrap mb-4 font-mono">
                    <div>
                      <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                        Live Joint Fusion Score Timeline (Most Recently Active IP)
                      </h3>
                      <p className="text-[10px] text-slate-500 mt-1">
                        Displaying composite regression indexes for client host: <span className="text-emerald-400 font-bold">{mostRecentIp || "None"}</span>
                      </p>
                    </div>
                    {mostRecentIp && (
                      <span className="text-[10px] bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded">
                        Active Monitoring Focus
                      </span>
                    )}
                  </div>

                  {bottomChartData.length === 0 ? (
                    <div className="flex flex-col items-center justify-center p-12 text-center h-48 border border-dashed border-[#1F2937]/35 rounded font-mono text-slate-500 text-[10px]">
                      Waiting for active traffic signals to plot fusion charts.
                    </div>
                  ) : (
                    <div className="h-44 w-full mt-auto">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={bottomChartData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                          <defs>
                            <linearGradient id="dashFusionGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#10B981" stopOpacity={0.2}/>
                              <stop offset="95%" stopColor="#10B981" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <XAxis dataKey="name" stroke="#475569" fontSize={8} tickLine={false} />
                          <YAxis stroke="#475569" fontSize={8} domain={[0, 1.0]} tickLine={false} />
                          <Tooltip contentStyle={{ backgroundColor: "#0b0e14", borderColor: "#1F2937", color: "#FFF", fontSize: "10px", fontFamily: "monospace" }} />
                          <Area type="monotone" dataKey="score" stroke="#10B981" strokeWidth={2.5} fillOpacity={1} fill="url(#dashFusionGradient)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </div>

              </div>
            )}

            {/* TAB 2: TEST LAB */}
            {activeTab === "TEST_LAB" && (
              <TestLabTab
                simStatus={simStatus}
                simIndex={simIndex}
                simSequenceLength={simSequence.length}
                isAutoPlay={isAutoPlay}
                simSpeed={simSpeed}
                onStartSim={verifyBaselineAndDeploy}
                onBuildBaseline={handleLoadBaseline}
                onResetSystem={handleSystemReset}
                attackLog={attackLog}
                detectionLog={detectionLog}
                customPort={customPort}
                setCustomPort={setCustomPort}
                customBytes={customBytes}
                setCustomBytes={setCustomBytes}
                customPayload={customPayload}
                setCustomPayload={setCustomPayload}
                customIp={customIp}
                setCustomIp={setCustomIp}
                onInjectCustom={handleInjectCustom}
                onTogglePause={() => setIsAutoPlay(!isAutoPlay)}
                onStopSim={() => {
                  setIsAutoPlay(false);
                  setSimStatus("idle");
                  setSimMessage("✓ Simulation sequence manual terminated");
                }}
                setSimSpeed={setSimSpeed}
              />
            )}

            {/* TAB 3: MODELS VIEW */}
            {activeTab === "MODELS" && (
              <ModelsViewTab
                gmmMean={gmmMean}
                gmmStd={gmmStd}
                anchorMean={anchorMean}
                gmmDrift={gmmDrift}
                lowessSlope={lowessSlope}
                isAnchored={isAnchored}
                activePortsCount={activePortsTouchedCount}
              />
            )}

            {/* TAB 4: METRICS */}
            {activeTab === "METRICS" && (
              <MetricsTab
                logs={logs}
                selectedEntityIp={selectedEntityIp}
                setSelectedEntityIp={setSelectedEntityIp}
              />
            )}

            {/* TAB 5: ALERTS */}
            {activeTab === "ALERTS" && (
              <AlertsTab
                logs={logs}
                onOpenDetail={setSelectedLog}
                blockedIps={blockedIps}
              />
            )}

            {/* TAB 6: DEVICES */}
            {activeTab === "DEVICES" && (
              <DevicesTab />
            )}

          </motion.div>
        </AnimatePresence>

      </main>

      {/* PERSISTENT POPUP OVERLAY FORENSICS MODAL */}
      <ForensicsModal
        isOpen={selectedLog !== null}
        selectedLog={selectedLog}
        logs={logs}
        blockedIps={blockedIps}
        onToggleBlockIp={handleToggleBlockIp}
        onClose={() => setSelectedLog(null)}
      />

      {/* PERSISTENT FOOTER BAR */}
      <footer className="border-t border-[#1F2937]/50 py-6 px-6 bg-[#05080c]/80 backdrop-blur-md text-center font-mono text-[10px] text-slate-500 mt-auto select-text">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <p>© 2026 Drift Watch Security Project • Implementation Testimony Chimberengwa R236592N</p>
          <div className="flex items-center gap-4">
            <span className="text-slate-500">BSc Computer Engineering • Academic Internship Testbed</span>
            <div className="flex gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="text-emerald-400">STATUS_OK</span>
            </div>
          </div>
        </div>
      </footer>

    </div>
  );
}
