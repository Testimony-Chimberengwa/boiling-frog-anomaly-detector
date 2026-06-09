import React, { useState, useMemo } from "react";
import { 
  Search, ShieldAlert, Cpu, Layers, Tag, Radio, Clock, ShieldCheck,
  Terminal, Eye, Radar, Skull, Globe, Zap,
  ChevronUp, ChevronDown, ArrowUpDown, Filter, AlertTriangle, PlayCircle
} from "lucide-react";
import { motion } from "motion/react";
import { LogEntry, ThreatLevel } from "../types";

interface AlertsTabProps {
  logs: LogEntry[];
  onOpenDetail: (log: LogEntry) => void;
  blockedIps: string[];
}

type SortKey = 
  | "timestamp"
  | "srcIp"
  | "dstPort"
  | "attackType"
  | "l1_gmm"
  | "l2_kde"
  | "l3_lowess"
  | "ads"
  | "fusion"
  | "alert";

export default function AlertsTab({ logs, onOpenDetail, blockedIps }: AlertsTabProps) {
  // Filters & Search State
  const [severityFilter, setSeverityFilter] = useState<ThreatLevel | "ALL">("ALL");
  const [searchTerm, setSearchTerm] = useState("");

  // Sorting State
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");

  // Format Helper for byte count or general metrics
  const formatBytes = (n: number) => {
    if (n >= 1048576) return `${(n / 1048576).toFixed(2)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  };

  // Convert raw payload labels into crisp, human-readable attack labels
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
      return { label: "UNKNOWN-PROBE", icon: <ShieldCheck className="w-3 h-3" />, className: "bg-slate-950/40 text-slate-300 border border-slate-500/20" };
    }
    return { label: getAttackType(payloadLabel), icon: <Tag className="w-3 h-3" />, className: "bg-slate-950/30 text-slate-300 border border-slate-500/20" };
  };

  // Compile active alerts (non-monitoring level) data
  const threatLevelsOrder: Record<ThreatLevel, number> = {
    MONITORING: 1,
    LOW: 2,
    MEDIUM: 3,
    HIGH: 4,
  };

  // Filter logs based on search term and selected level
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      const matchSeverity = severityFilter === "ALL" || log.scores.alert === severityFilter;
      
      const attackType = getAttackType(log.payloadLabel);
      const searchString = `${log.srcIp} ${log.dstPort} ${attackType} ${log.payloadLabel}`.toLowerCase();
      const matchSearch = searchString.includes(searchTerm.toLowerCase());

      return matchSeverity && matchSearch;
    });
  }, [logs, severityFilter, searchTerm]);

  // Sort logs based on sortKey and sortDirection
  const sortedLogs = useMemo(() => {
    const sorted = [...filteredLogs];
    sorted.sort((a, b) => {
      let valA: any;
      let valB: any;

      switch (sortKey) {
        case "timestamp":
          // Compare localized times or logical string times
          valA = a.timestamp;
          valB = b.timestamp;
          break;
        case "srcIp":
          valA = a.srcIp;
          valB = b.srcIp;
          break;
        case "dstPort":
          valA = a.dstPort;
          valB = b.dstPort;
          break;
        case "attackType":
          valA = getAttackType(a.payloadLabel);
          valB = getAttackType(b.payloadLabel);
          break;
        case "l1_gmm":
          valA = a.scores.l1_gmm;
          valB = b.scores.l1_gmm;
          break;
        case "l2_kde":
          valA = a.scores.l2_kde;
          valB = b.scores.l2_kde;
          break;
        case "l3_lowess":
          valA = a.scores.l3_lowess;
          valB = b.scores.l3_lowess;
          break;
        case "ads":
          valA = a.scores.ads;
          valB = b.scores.ads;
          break;
        case "fusion":
          valA = a.scores.fusion;
          valB = b.scores.fusion;
          break;
        case "alert":
          valA = threatLevelsOrder[a.scores.alert] || 0;
          valB = threatLevelsOrder[b.scores.alert] || 0;
          break;
        default:
          valA = a.timestamp;
          valB = b.timestamp;
      }

      if (valA < valB) return sortDirection === "asc" ? -1 : 1;
      if (valA > valB) return sortDirection === "asc" ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [filteredLogs, sortKey, sortDirection]);

  // Handle Header Column Sorting triggers
  const requestSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDirection(prev => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDirection("desc"); // Default to newest/highest first
    }
  };

  // Helper component to render sort icons
  const renderSortArrow = (key: SortKey) => {
    if (sortKey !== key) {
      return <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60 hover:opacity-100 transition-opacity" />;
    }
    return sortDirection === "asc" ? (
      <ChevronUp className="w-3.5 h-3.5 text-emerald-400" />
    ) : (
      <ChevronDown className="w-3.5 h-3.5 text-emerald-400" />
    );
  };

  // Compile statistics for the bottom summary strip
  const summaryStats = useMemo(() => {
    let rawAlertsCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    const uniqueThreatIps = new Set<string>();
    const portFrequency: Record<number, number> = {};

    logs.forEach(log => {
      // Accumulate any logs that have non-monitoring alerts
      if (log.scores.alert !== "MONITORING") {
        rawAlertsCount++;
        uniqueThreatIps.add(log.srcIp);
        if (log.scores.alert === "HIGH") highCount++;
        if (log.scores.alert === "MEDIUM") mediumCount++;
      }

      // Track port frequency across overall sessions to determine target priorities
      portFrequency[log.dstPort] = (portFrequency[log.dstPort] || 0) + 1;
    });

    // Find the most targeted port
    let mostTargetedPortValue = "None";
    let maxCount = 0;
    Object.entries(portFrequency).forEach(([portStr, cnt]) => {
      if (cnt > maxCount) {
        maxCount = cnt;
        mostTargetedPortValue = `Port ${portStr} (${cnt} hits)`;
      }
    });

    return {
      totalThreats: rawAlertsCount,
      high: highCount,
      medium: mediumCount,
      uniqueIps: uniqueThreatIps.size,
      topPort: mostTargetedPortValue
    };
  }, [logs]);

  return (
    <div className="space-y-6">
      
      {/* 1. TOP INTERACTIVE FILTER BAR */}
      <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 backdrop-blur-xs flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono">
        
        {/* Severity selection group */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <span className="text-[11px] text-slate-500 uppercase tracking-widest font-bold flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-emerald-400" />
            Severity filtering
          </span>
          
          <div className="flex flex-wrap items-center gap-1.5 bg-[#0b0e14]/65 border border-[#1F2937]/80 p-1 rounded-lg">
            {(["ALL", "MONITORING", "LOW", "MEDIUM", "HIGH"] as const).map(level => {
              const active = severityFilter === level;
              return (
                <button
                  key={level}
                  onClick={() => setSeverityFilter(level)}
                  className={`px-3 py-1 rounded text-[10px] font-bold tracking-wider cursor-pointer transition-colors ${
                    active 
                      ? "bg-slate-800 text-white shadow-sm" 
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {level}
                </button>
              );
            })}
          </div>
        </div>

        {/* Text keyword search inputs & total results badges */}
        <div className="flex items-center gap-3 flex-grow max-w-md">
          <div className="relative w-full">
            <span className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
              <Search className="h-3.5 w-3.5 text-slate-500" />
            </span>
            <input
              type="text"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              placeholder="Search source IP or attack type..."
              className="block w-full pl-9 pr-3 py-1.5 bg-[#0b0e14]/65 border border-[#1F2937]/80 focus:border-emerald-500/50 rounded-lg text-xs text-slate-300 placeholder-slate-500 font-sans focus:outline-none transition-colors"
            />
          </div>

          {/* Alert count metrics badges */}
          <div className="flex items-center gap-1.5 shrink-0 select-none">
            <div className="flex flex-col items-end text-[10px] text-slate-500 leading-tight">
              <span>Matching</span>
              <span>Observed</span>
            </div>
            <div className="px-2 py-1.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-bold rounded-lg text-xs text-center min-w-[3.5rem]">
              {filteredLogs.length}
            </div>
          </div>
        </div>

      </div>

      {/* 2. DONT BE AFRAID OF EMPTY STATE TABLE DISPLAY */}
      <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 flex flex-col">
        {sortedLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-16 text-center border border-dashed border-[#1F2937]/45 rounded-xl font-mono">
            <span className="text-2xl mb-2">🛡️</span>
            <span className="text-[11px] text-slate-500 tracking-wider">░ TELEMETRY QUEUE VACANT ░</span>
            <p className="text-xs text-slate-400 mt-2 max-w-sm font-sans">
              No connections matched the active parameter filters. Change your severity limits, clear your keywords, or deploy live traffic from the <strong>Test Lab</strong>.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-[11px] border-collapse">
              <thead>
                <tr className="border-b border-[#1F2937] text-slate-500 font-bold uppercase select-none">
                  <th onClick={() => requestSort("timestamp")} className="pb-3 pr-2 text-left cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1">
                      Timestamp {renderSortArrow("timestamp")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("srcIp")} className="pb-3 pr-2 text-left cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1">
                      Source IP {renderSortArrow("srcIp")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("dstPort")} className="pb-3 pr-2 text-center cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1 justify-center">
                      Dst Port {renderSortArrow("dstPort")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("attackType")} className="pb-3 pr-2 text-left cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1">
                      Attack Type {renderSortArrow("attackType")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("l1_gmm")} className="pb-3 pr-2 text-right cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1 justify-end">
                      L1 GMM {renderSortArrow("l1_gmm")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("l2_kde")} className="pb-3 pr-2 text-right cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1 justify-end">
                      L2 KDE {renderSortArrow("l2_kde")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("l3_lowess")} className="pb-3 pr-2 text-right cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1 justify-end">
                      L3 Slope {renderSortArrow("l3_lowess")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("ads")} className="pb-3 pr-2 text-right cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1 justify-end">
                      ADS {renderSortArrow("ads")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("fusion")} className="pb-3 pr-2 text-right cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1 justify-end">
                      Composite {renderSortArrow("fusion")}
                    </div>
                  </th>
                  <th onClick={() => requestSort("alert")} className="pb-3 text-center cursor-pointer hover:bg-slate-900/40 p-1 rounded-sm">
                    <div className="flex items-center gap-1 justify-center">
                      Severity {renderSortArrow("alert")}
                    </div>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2937]/30">
                {sortedLogs.map((log) => {
                  const badge = getAttackBadge(log.payloadLabel);
                  const isBlocked = blockedIps.includes(log.srcIp);
                  
                  return (
                    <tr 
                      key={log.id} 
                      onClick={() => onOpenDetail(log)}
                      className={`hover:bg-[#151c27]/75 cursor-pointer transition-colors group relative`}
                    >
                      <td className="py-3 pr-2 text-slate-400 group-hover:text-slate-300 font-mono whitespace-nowrap">
                        {log.timestamp}
                      </td>
                      <td className="py-3 pr-2 font-bold whitespace-nowrap">
                        <span className={isBlocked ? "text-red-400 line-through" : "text-slate-200"}>
                          {log.srcIp}
                        </span>
                        {isBlocked && (
                          <span className="ml-1.5 text-[8px] bg-red-950/40 border border-red-500/20 text-red-500 px-1 py-0.2 rounded font-bold uppercase">
                            BANNED
                          </span>
                        )}
                      </td>
                      <td className="py-3 pr-2 text-center text-slate-400 group-hover:text-slate-300">
                        <span className="font-semibold text-[10px] bg-slate-900 border border-[#1F2937] px-1 rounded text-slate-300">
                          {log.dstPort}
                        </span>
                      </td>
                      <td className="py-3 pr-2 font-sans text-xs text-slate-300 font-medium">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-[10px] font-bold uppercase ${badge.className}`}>
                          {badge.icon}
                          {badge.label}
                        </span>
                      </td>
                      <td className={`py-3 pr-2 text-right font-mono ${log.scores.l1_gmm > 0.5 ? "text-amber-400" : "text-slate-500"}`}>
                        {log.scores.l1_gmm.toFixed(3)}
                      </td>
                      <td className={`py-3 pr-2 text-right font-mono ${log.scores.l2_kde > 0.5 ? "text-amber-400" : "text-slate-500"}`}>
                        {log.scores.l2_kde.toFixed(3)}
                      </td>
                      <td className={`py-3 pr-2 text-right font-mono ${log.scores.l3_lowess > 0.3 ? "text-rose-400" : "text-slate-500"}`}>
                        {log.scores.l3_lowess.toFixed(3)}
                      </td>
                      <td className={`py-3 pr-2 text-right font-mono ${log.scores.ads > 0.5 ? "text-purple-400" : "text-slate-500"}`}>
                        {log.scores.ads.toFixed(3)}
                      </td>
                      <td className="py-3 pr-2 text-right font-bold text-emerald-400 font-mono">
                        {log.scores.fusion.toFixed(4)}
                      </td>
                      <td className="py-3 text-center whitespace-nowrap">
                        <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded border ${
                          log.scores.alert === "HIGH" ? "bg-red-950/40 text-red-400 border-red-500/20" :
                          log.scores.alert === "MEDIUM" ? "bg-amber-950/40 text-amber-400 border-amber-500/20" :
                          log.scores.alert === "LOW" ? "bg-yellow-950/40 text-yellow-400 border-yellow-500/20" :
                          "bg-emerald-950/30 text-emerald-400 border-emerald-500/10"
                        }`}>
                          {log.scores.alert}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 3. UNDER TABLE COMPOSITE METRICS AND SECURITY SUMMARY STRIP */}
      <div className="p-4 rounded-xl border border-[#1F2937]/50 bg-[#111418]/45">
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 font-mono">
          
          {/* Total Alerts metrics */}
          <div className="p-3 bg-[#0b0e14]/40 border border-[#1F2937]/50 rounded-lg flex flex-col justify-between h-16">
            <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-rose-500" />
              Threats Logged
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-slate-100 font-bold text-base">{summaryStats.totalThreats}</span>
              <span className="text-[9px] text-slate-600">Active</span>
            </div>
          </div>

          {/* HIGH indicator */}
          <div className="p-3 bg-red-950/10 border border-red-950/40 rounded-lg flex flex-col justify-between h-16">
            <span className="text-[9px] text-red-400/80 font-bold uppercase tracking-wider flex items-center gap-1">
              <AlertTriangle className="w-3 h-3 text-red-400" />
              HIGH SEVERITY
            </span>
            <span className="text-red-400 font-extrabold text-base">{summaryStats.high}</span>
          </div>

          {/* MEDIUM indicator */}
          <div className="p-3 bg-amber-950/10 border border-amber-950/40 rounded-lg flex flex-col justify-between h-16">
            <span className="text-[9px] text-amber-400/80 font-bold uppercase tracking-wider flex items-center gap-1">
              <AlertTriangle className="w-3 h-3 text-amber-400" />
              MEDIUM SEVERITY
            </span>
            <span className="text-amber-400 font-extrabold text-base">{summaryStats.medium}</span>
          </div>

          {/* Unique Host metrics */}
          <div className="p-3 bg-[#0b0e14]/40 border border-[#1F2937]/50 rounded-lg flex flex-col justify-between h-16">
            <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider flex items-center gap-1">
              <Layers className="w-3 h-3 text-cyan-400" />
              Threat Hosts
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-sky-400 font-bold text-base">{summaryStats.uniqueIps}</span>
              <span className="text-[9px] text-slate-600">IPs</span>
            </div>
          </div>

          {/* Targeted sockets channel */}
          <div className="p-3 bg-[#0b0e14]/40 border border-[#1F2937]/50 rounded-lg flex flex-col justify-between h-16 col-span-2 lg:col-span-1">
            <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider flex items-center gap-1">
              <Radio className="w-3 h-3 text-emerald-400" />
              Top Target
            </span>
            <span className="text-emerald-400 font-semibold text-[11px] truncate">{summaryStats.topPort}</span>
          </div>

        </div>
      </div>

    </div>
  );
}
