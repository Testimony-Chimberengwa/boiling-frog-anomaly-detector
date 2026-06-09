import React from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  AreaChart,
  Area
} from "recharts";
import { LogEntry } from "../types";
import { Activity, Database, AlertCircle, TrendingUp } from "lucide-react";

interface MetricsTabProps {
  logs: LogEntry[];
  selectedEntityIp: string;
  setSelectedEntityIp: (ip: string) => void;
}

export default function MetricsTab({
  logs,
  selectedEntityIp,
  setSelectedEntityIp
}: MetricsTabProps) {
  
  const formatBytes = (n: number) => {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  };

  // 1. Calculate unique IPs for entity trend dropdown selection
  const ipSet = new Set<string>();
  logs.forEach(log => ipSet.add(log.srcIp));
  const uniqueIps = Array.from(ipSet);

  // Default to first available IP if none is selected
  const activeSelectedIp = selectedEntityIp || uniqueIps[0] || "";

  // 2. Prepare rolling observation history data (last 50 observations)
  // Reversing to ensure chronological order (left-to-right)
  const rollingHistoryData = logs
    .slice(0, 50)
    .reverse()
    .map(log => ({
      obs: `#${log.scores.obsCount}`,
      "Composite Fusion": parseFloat(log.scores.fusion.toFixed(4)),
      "L1 GMM (Volume)": parseFloat(log.scores.l1_gmm.toFixed(3)),
      "L2 KDE (Sweeps)": parseFloat(log.scores.l2_kde.toFixed(3)),
      "L3 LOWESS (Slope)": parseFloat(log.scores.l3_lowess.toFixed(3)),
      "ADS Sentinel": parseFloat(log.scores.ads.toFixed(3))
    }));

  // 3. Prepare alert distribution counts
  const alertCounts = {
    MONITORING: 0,
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0
  };
  
  logs.forEach(log => {
    const alert = log.scores.alert;
    if (alert in alertCounts) {
      alertCounts[alert as keyof typeof alertCounts]++;
    }
  });

  const alertDistributionData = [
    { name: "Monitoring", count: alertCounts.MONITORING, fill: "#10B981" },
    { name: "Low Threat", count: alertCounts.LOW, fill: "#F59E0B" },
    { name: "Med Threat", count: alertCounts.MEDIUM, fill: "#EF4444" },
    { name: "High Threat", count: alertCounts.HIGH, fill: "#8B5CF6" }
  ];

  // 4. Prepare selected entity volume trend history
  const entityLogs = logs
    .filter(log => log.srcIp === activeSelectedIp)
    .slice(0, 30)
    .reverse();

  const entityVolumeData = entityLogs.map((log, index) => ({
    connIndex: `#${index + 1}`,
    bytes: log.byteCount,
    displayBytes: formatBytes(log.byteCount),
    port: log.dstPort,
    alert: log.scores.alert
  }));

  const customTooltipStyle = {
    backgroundColor: "#0B0E14",
    border: "1px solid #1F2937",
    color: "#E2E8F0",
    borderRadius: "6px",
    fontFamily: "monospace",
    fontSize: "11px"
  };

  return (
    <div className="space-y-6 py-2">
      
      {/* Tab Header Description */}
      <div className="p-4 rounded-xl bg-[#111418]/60 border border-[#1F2937]/75 backdrop-blur-md flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-sm font-mono font-bold text-emerald-400 tracking-wider uppercase flex items-center gap-2 mb-1">
            <Activity className="w-4 h-4" />
            Performance Indicator Center
          </h2>
          <p className="text-[11px] text-slate-400 max-w-2xl">
            Live telemetry models visualization engine. All metrics compile in real-time from the underlying tapestry log buffer of the reactive NDR kernel.
          </p>
        </div>
        
        {/* Quick IP filter dropdown for Volume Trend Chart */}
        {uniqueIps.length > 0 && (
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-400 text-[11px]">ENTITY HISTORY FOCUS:</span>
            <select
              value={activeSelectedIp}
              onChange={(e) => setSelectedEntityIp(e.target.value)}
              className="px-3 py-1.5 rounded bg-[#0b0e14] border border-[#1F2937] text-white focus:outline-none focus:ring-1 focus:ring-emerald-500 cursor-pointer"
            >
              {uniqueIps.map(ip => (
                <option key={ip} value={ip}>{ip}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      {logs.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-[#1F2937]/50 rounded-xl bg-[#111418]/25">
          <p className="text-sm font-mono text-slate-500 mb-2">░ NO TELEMETRY INGESTED YET ░</p>
          <p className="text-xs text-slate-400 max-w-md">
            The telemetry logging matrices are empty. Deploy a baseline or direct attack scenario under the <strong>TEST LAB</strong> panel to compile chart analytics.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* Chart 1: Composite Score History rolling timeline */}
          <div className="p-5 rounded-xl border border-[#1F2937]/55 bg-[#111418]/30 flex flex-col">
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wide flex items-center gap-1.5 mb-2">
              <TrendingUp className="w-4 h-4 text-emerald-400" />
              Composite Security Fusion Score (Last 50 Obs)
            </h3>
            <p className="text-[10px] text-slate-500 mb-4 leading-relaxed font-mono">
              Fused metric over time. Anomaly scores exceeding 0.35 shift host to alert parameters.
            </p>
            <div className="h-64 w-full mt-auto">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={rollingHistoryData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <defs>
                    <linearGradient id="fusionGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10B981" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="#10B981" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                  <XAxis dataKey="obs" stroke="#475569" fontSize={9} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={9} domain={[0, 1.0]} tickLine={false} />
                  <Tooltip contentStyle={customTooltipStyle} />
                  <Area type="monotone" dataKey="Composite Fusion" stroke="#10B981" strokeWidth={2} fillOpacity={1} fill="url(#fusionGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Chart 2: Individual Sub-layer Scores */}
          <div className="p-5 rounded-xl border border-[#1F2937]/55 bg-[#111418]/30 flex flex-col">
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wide flex items-center gap-1.5 mb-2">
              <Database className="w-4 h-4 text-cyan-400" />
              Tapestry Multi-Layer Sub-Scores Timeline (Last 50 Obs)
            </h3>
            <p className="text-[10px] text-slate-500 mb-4 leading-relaxed font-mono">
              Provides granular visibility to determine which specific sub-module layers triggered during a sequence.
            </p>
            <div className="h-64 w-full mt-auto">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={rollingHistoryData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                  <XAxis dataKey="obs" stroke="#475569" fontSize={9} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={9} domain={[0, 1.0]} tickLine={false} />
                  <Tooltip contentStyle={customTooltipStyle} />
                  <Legend verticalAlign="bottom" height={24} iconSize={8} wrapperStyle={{ fontSize: "9px", fontFamily: "monospace" }} />
                  <Line type="monotone" dataKey="L1 GMM (Volume)" stroke="#34D399" strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} />
                  <Line type="monotone" dataKey="L2 KDE (Sweeps)" stroke="#FBBF24" strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} />
                  <Line type="monotone" dataKey="L3 LOWESS (Slope)" stroke="#F87171" strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} />
                  <Line type="monotone" dataKey="ADS Sentinel" stroke="#C084FC" strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Chart 3: Alert Distribution */}
          <div className="p-5 rounded-xl border border-[#1F2937]/55 bg-[#111418]/30 flex flex-col">
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wide flex items-center gap-1.5 mb-2">
              <AlertCircle className="w-4 h-4 text-emerald-400" />
              Evaluation Severity Distribution Overview
            </h3>
            <p className="text-[10px] text-slate-500 mb-4 leading-relaxed font-mono">
              Breakdown of total threat alerts categorized inside the logging stack.
            </p>
            <div className="h-64 w-full mt-auto">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={alertDistributionData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                  <XAxis dataKey="name" stroke="#475569" fontSize={9} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={9} allowDecimals={false} tickLine={false} />
                  <Tooltip contentStyle={customTooltipStyle} cursor={{ fill: "#1f2937", opacity: 0.2 }} />
                  <Bar dataKey="count" fill="#34D399" radius={[4, 4, 0, 0]} maxBarSize={45}>
                    {alertDistributionData.map((entry, index) => (
                      <rect key={`rect-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Chart 4: Volume Trend per IP */}
          <div className="p-5 rounded-xl border border-[#1F2937]/55 bg-[#111418]/30 flex flex-col">
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wide flex items-center gap-1.5 mb-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              Volume Trend History per Selected Source IP
            </h3>
            <p className="text-[10px] text-slate-500 mb-4 leading-relaxed font-mono">
              Byte counts plotted chronologically for host <strong className="text-slate-300">{activeSelectedIp || "none"}</strong> to review regression gradients.
            </p>
            {entityVolumeData.length === 0 ? (
              <div className="flex flex-col items-center justify-center p-8 text-center bg-[#0b0e14] border border-[#1F2937]/80 rounded h-64">
                <span className="text-[10px] font-mono text-slate-600">░ TELEMETRY HISTORY DRIFT ░</span>
                <span className="text-[10px] text-slate-500 mt-1">No connections archived for IP {activeSelectedIp || "null"}</span>
              </div>
            ) : (
              <div className="h-64 w-full mt-auto">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={entityVolumeData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                    <defs>
                      <linearGradient id="bytesGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.25}/>
                        <stop offset="95%" stopColor="#38BDF8" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                    <XAxis dataKey="connIndex" stroke="#475569" fontSize={9} tickLine={false} />
                    <YAxis 
                      stroke="#475569" 
                      fontSize={9} 
                      tickLine={false}
                      tickFormatter={(v) => {
                        if (v >= 1048576) return `${(v / 1048576).toFixed(0)}M`;
                        if (v >= 1024) return `${(v / 1024).toFixed(0)}K`;
                        return v;
                      }}
                    />
                    <Tooltip 
                      contentStyle={customTooltipStyle} 
                      formatter={(v: any) => [formatBytes(v), "Payload Size"]}
                    />
                    <Area type="monotone" dataKey="bytes" stroke="#38BDF8" strokeWidth={2} fillOpacity={1} fill="url(#bytesGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

        </div>
      )}
    </div>
  );
}
