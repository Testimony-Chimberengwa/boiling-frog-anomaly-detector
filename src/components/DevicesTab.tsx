import React, { useState, useEffect } from "react";
import { 
  Monitor, Cpu, HardDrive, Network, RefreshCw, Terminal, 
  HelpCircle, User, Shield, Info, Activity, Database, CheckCircle
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface DeviceData {
  host: {
    hostname: string;
    platform: string;
    release: string;
    arch: string;
    uptime: number;
    whoami: string;
  };
  cpu: {
    model: string;
    speedMhz: number;
    cores: number;
    loadAvg: number[];
  };
  memory: {
    total: number;
    free: number;
    used: number;
    usagePercent: number;
  };
  processes: {
    pid: number;
    ppid: number;
    user: string;
    cpu: number;
    mem: number;
    name: string;
  }[];
  network: {
    interface: string;
    ip: string;
    mac: string;
    netmask: string;
    type: string;
  }[];
  dns: string[];
}

export default function DevicesTab() {
  const [deviceData, setDeviceData] = useState<DeviceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedDeviceIndex, setSelectedDeviceIndex] = useState<number>(0);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<string>("");

  const fetchTelemetry = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/device/telemetry");
      if (!res.ok) {
        throw new Error(`Telemetry request failed with status: ${res.status}`);
      }
      const data = await res.json();
      setDeviceData(data);
      setLastUpdated(new Date().toLocaleTimeString());
      setError(null);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed to establish a transport websocket with the dynamic telemetry daemon.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  // Poll system details every 4.5 seconds for visual excitement
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (autoRefresh) {
      timer = setInterval(() => {
        fetchTelemetry();
      }, 4500);
    }
    return () => clearInterval(timer);
  }, [autoRefresh]);

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    return `${h}h ${m}m`;
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      
      {/* LEFT COLUMN: DEVICES INDEX PANEL */}
      <div className="lg:col-span-3 flex flex-col gap-4">
        <div className="p-4 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 flex flex-col">
          <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-1.5">
            <Monitor className="w-4 h-4 text-emerald-400" />
            Monitored Devices
          </h3>

          <div className="space-y-2">
            {/* Active Single Host representation (Localhost PC / Docker Container) */}
            <div
              onClick={() => setSelectedDeviceIndex(0)}
              className={`p-3.5 rounded-lg border text-left cursor-pointer transition-all ${
                selectedDeviceIndex === 0
                  ? "bg-slate-900 border-emerald-500/55 text-white"
                  : "bg-transparent border-[#1F2937]/50 hover:border-[#1F2937] text-slate-400 hover:text-slate-200"
              }`}
            >
              <div className="flex justify-between items-start mb-1">
                <span className="font-mono text-xs font-bold text-slate-200">
                  {deviceData?.host.hostname || "localhost"}
                </span>
                <span className="text-[8px] leading-none px-1.5 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-sm uppercase font-bold tracking-widest leading-normal">
                  ONLINE
                </span>
              </div>
              <div className="text-[10px] text-slate-400 font-sans truncate flex items-center gap-1 mt-1.5">
                <User className="w-3 h-3 text-emerald-500" />
                <span>Operator: <strong className="font-mono text-emerald-400">{deviceData?.host.whoami || "whoami"}</strong></span>
              </div>
              <div className="text-[9px] text-slate-500 font-mono mt-1 uppercase">
                IP: {deviceData?.network?.[0]?.ip || "127.0.0.1"} • {deviceData?.host.arch || "x64"}
              </div>
            </div>
            
            {/* Informative placeholder cards */}
            <div className="p-3 border border-dashed border-[#1F2937]/25 rounded-lg opacity-40 select-none">
              <div className="flex justify-between items-center text-[10px] text-slate-500 font-mono">
                <span>[WIFI_AP_BRIDGE]</span>
                <span>OFFLINE</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-[#1F2937]/40 flex flex-col gap-2.5">
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
              <span>Auto Refresh:</span>
              <button 
                onClick={() => setAutoRefresh(!autoRefresh)}
                className={`px-1.5 py-0.5 text-[9px] font-bold rounded cursor-pointer uppercase ${
                  autoRefresh 
                    ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400" 
                    : "bg-slate-900 border border-[#1F2937] text-slate-400"
                }`}
              >
                {autoRefresh ? "ON" : "OFF"}
              </button>
            </div>

            <button
              onClick={fetchTelemetry}
              disabled={loading}
              className="w-full py-2 bg-[#0b0e14] hover:bg-slate-900 border border-[#1F2937]/80 hover:border-emerald-500/40 text-[10px] font-mono font-bold tracking-wider text-slate-300 hover:text-white rounded-lg flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-emerald-400 ${loading ? "animate-spin" : ""}`} />
              RE-POLL METRICS
            </button>

            {lastUpdated && (
              <span className="text-[8px] text-slate-500 text-center font-mono uppercase mt-1">
                Last Polled: {lastUpdated}
              </span>
            )}
          </div>
        </div>

        {/* Security Summary Advisory Frame */}
        <div className="p-4 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 text-left font-mono">
          <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold flex items-center gap-1">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            Environment Info
          </span>
          <p className="text-[11px] text-slate-400 leading-relaxed mt-2 font-sans">
            This module establishes a connection to the local machine's native kernel API. It monitors system loads in real time so operators can evaluate resource consumption or suspicious process anomalies alongside our dynamic NDR detection pipeline.
          </p>
        </div>
      </div>

      {/* RIGHT COLUMN: Telemetry Dashboard deck */}
      <div className="lg:col-span-9 space-y-6">
        
        {loading && !deviceData && (
          <div className="p-16 border border-[#1F2937]/40 rounded-xl bg-[#111418]/25 flex flex-col items-center justify-center font-mono">
            <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin mb-3" />
            <span className="text-xs text-slate-400">CONNECTING TO LOCAL HOST METRICS ENGINE...</span>
          </div>
        )}

        {error && (
          <div className="p-8 border border-red-500/25 rounded-xl bg-red-950/15 font-mono text-center">
            <span className="text-xl">⚠️</span>
            <h4 className="text-red-400 font-bold text-xs uppercase tracking-wider mt-2">Telemetry Gateway Failure</h4>
            <p className="text-slate-400 text-[11px] mt-1.5 max-w-md mx-auto leading-relaxed">
              {error}
            </p>
            <button 
              onClick={fetchTelemetry}
              className="mt-4 px-3 py-1.5 bg-red-950/40 border border-red-500/20 hover:border-red-500/40 text-red-400 text-[10px] font-bold rounded cursor-pointer uppercase transition-colors"
            >
              Retry Connection
            </button>
          </div>
        )}

        {deviceData && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-6"
          >
            {/* 1. HOST SPECIFICATION SUMMARY HEADER */}
            <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/45 relative overflow-hidden flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="absolute top-0 right-0 p-1 bg-emerald-500/10 border-b border-l border-emerald-500/20 rounded-bl text-[8px] text-emerald-400 font-mono font-bold tracking-widest uppercase">
                ACTIVE AUDIT STACK
              </div>

              <div className="space-y-1 font-mono text-left">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider">Device Name / Node Tag</span>
                <h2 className="text-slate-100 font-bold text-base tracking-tight flex items-center gap-1.5">
                  <Monitor className="w-4 h-4 text-emerald-400" />
                  {deviceData.host.hostname}
                </h2>
                <div className="text-[11px] text-slate-400 flex flex-wrap gap-x-4 gap-y-1">
                  <span>OS: <strong className="text-slate-300 font-bold">{deviceData.host.platform} ({deviceData.host.release})</strong></span>
                  <span>Architecture: <strong className="text-slate-300 font-bold">{deviceData.host.arch}</strong></span>
                  <span>Uptime: <strong className="text-slate-300 font-bold">{formatUptime(deviceData.host.uptime)}</strong></span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#0b0e14] border border-[#1F2937] text-left font-mono min-w-[12rem] shrink-0">
                <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider flex items-center gap-1.5 mb-1">
                  <User className="w-3 h-3 text-emerald-400" />
                  WHOAMI Operator
                </span>
                <div className="text-slate-100 text-xs font-bold font-mono">
                  {deviceData.host.whoami}
                </div>
                <div className="text-[9px] text-slate-600 mt-0.5">
                  Secure Host Token Validated
                </div>
              </div>
            </div>

            {/* 2. COMPOSITE RESOURCE ANALYTICS GRID */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* CPU load details */}
              <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 text-left font-mono">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 mb-4">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  Processor Specifications
                </h3>

                <div className="space-y-4">
                  <div>
                    <span className="text-[9px] text-slate-500 uppercase font-bold tracking-wider block">Processor Model</span>
                    <span className="text-[11px] text-slate-200 mt-0.5 block truncate">{deviceData.cpu.model}</span>
                  </div>

                  <div className="grid grid-cols-3 gap-2 py-2 border-y border-[#1F2937]/35 text-center">
                    <div>
                      <span className="text-[8px] text-slate-500 uppercase block font-bold">Cores</span>
                      <strong className="text-slate-200 font-sans text-sm">{deviceData.cpu.cores} CPUS</strong>
                    </div>
                    <div>
                      <span className="text-[8px] text-slate-500 uppercase block font-bold">Base Speed</span>
                      <strong className="text-slate-200 font-mono text-xs">{deviceData.cpu.speedMhz || "N/A"} Mhz</strong>
                    </div>
                    <div>
                      <span className="text-[8px] text-slate-500 uppercase block font-bold">Load Avg</span>
                      <strong className="text-emerald-400 font-mono text-xs">
                        {deviceData.cpu.loadAvg?.length > 0 ? deviceData.cpu.loadAvg[0].toFixed(2) : "0.00"}
                      </strong>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between items-center text-[10px] text-slate-500 mb-1.5 uppercase font-bold">
                      <span>Kernel Load Balance</span>
                      <span className="font-mono text-emerald-400">
                        {deviceData.cpu.loadAvg?.length > 0 ? (Math.min(100, deviceData.cpu.loadAvg[0] * 10)).toFixed(1) : "0.0"}%
                      </span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-950/60 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-1000"
                        style={{ width: `${Math.min(100, deviceData.cpu.loadAvg?.length > 0 ? deviceData.cpu.loadAvg[0] * 12 : 5)}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Memory allocations details */}
              <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 text-left font-mono">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 mb-4">
                  <HardDrive className="w-4 h-4 text-emerald-400" />
                  System Memory Allocation
                </h3>

                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <span className="text-[9px] text-slate-500 uppercase font-bold tracking-wider block">Total Allocated Size</span>
                      <span className="text-xs text-slate-200 font-bold block mt-0.5">{formatBytes(deviceData.memory.total)}</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-slate-500 uppercase font-bold tracking-wider block">Currently Free Heap</span>
                      <span className="text-xs text-slate-200 font-semibold block mt-0.5 text-emerald-400">{formatBytes(deviceData.memory.free)}</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-[#0b0e14]/50 border border-[#1F2937]/45 text-[10px]">
                    <div className="flex justify-between text-slate-400">
                      <span>Used RAM Capacity:</span>
                      <strong className="text-slate-100">{formatBytes(deviceData.memory.used)}</strong>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between items-center text-[10px] text-slate-500 mb-1.5 uppercase font-bold">
                      <span>RAM Utilization Rate</span>
                      <span className="font-mono text-emerald-400">{deviceData.memory.usagePercent}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-950/60 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-emerald-500 to-blue-500 transition-all duration-1000"
                        style={{ width: `${deviceData.memory.usagePercent}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>

            </div>

            {/* 3. DYNAMIC PROCESS TELEMETRY MATRIX TABLE */}
            <div className="p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 text-left">
              <h3 className="text-xs font-mono font-bold text-[#E2E8F0] uppercase tracking-wider mb-4 flex items-center justify-between gap-4">
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  Active Host Processes & Execution Threads
                </span>
                <span className="text-[9px] bg-slate-900 border border-[#1F2937] px-2 py-0.5 rounded text-slate-400 font-mono">
                  {deviceData.processes?.length || 0} Procs Registered
                </span>
              </h3>

              <div className="overflow-x-auto max-h-80 overflow-y-auto scrollbar-thin">
                <table className="w-full text-left font-mono text-[11px]">
                  <thead>
                    <tr className="border-b border-[#1F2937] text-slate-500 font-bold uppercase select-none">
                      <th className="pb-2.5 pl-1.5">PID</th>
                      <th className="pb-2.5">PPID</th>
                      <th className="pb-2.5">User</th>
                      <th className="pb-2.5 text-right pr-4">CPU %</th>
                      <th className="pb-2.5 text-right pr-4">MEM %</th>
                      <th className="pb-2.5 text-left">Process Name</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2937]/25">
                    {deviceData.processes?.map((proc, index) => {
                      const isNode = proc.name.toLowerCase().includes("node") || proc.name.toLowerCase().includes("server");
                      return (
                        <tr key={`${proc.pid}-${index}`} className="hover:bg-slate-900/35 transition-colors">
                          <td className="py-2 pl-1.5 font-semibold text-slate-200">{proc.pid}</td>
                          <td className="py-2 text-slate-500">{proc.ppid}</td>
                          <td className="py-2 text-slate-400">{proc.user}</td>
                          <td className={`py-2 text-right pr-4 font-semibold ${proc.cpu > 1 ? "text-cyan-400" : "text-slate-500"}`}>
                            {proc.cpu.toFixed(1)}%
                          </td>
                          <td className={`py-2 text-right pr-4 font-semibold ${proc.mem > 1 ? "text-purple-400" : "text-slate-500"}`}>
                            {proc.mem.toFixed(1)}%
                          </td>
                          <td className="py-2 text-slate-300">
                            <span className={`px-1 rounded text-[10px] uppercase font-bold mr-1.5 ${
                              isNode 
                                ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400" 
                                : "bg-slate-900 border border-[#1F2937]/50 text-slate-400"
                            }`}>
                              {isNode ? "CORE ENGINE" : "SPAWN"}
                            </span>
                            <span className="font-semibold text-slate-300">{proc.name}</span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* 4. NETWORKING INTERFACES & DNS RESOLVER CARD DECK */}
            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 font-mono text-left">
              
              {/* Interface settings */}
              <div className="md:col-span-8 p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 flex flex-col">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 mb-4">
                  <Network className="w-4 h-4 text-[#C084FC]" />
                  Ethernet Interfaces & Network Sockets
                </h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 grow">
                  {deviceData.network?.length === 0 ? (
                    <div className="col-span-2 flex flex-col items-center justify-center p-8 text-center text-slate-500 text-[10px]">
                      No Physical Interfaces found in the sandbox.
                    </div>
                  ) : (
                    deviceData.network?.map((net, idx) => (
                      <div key={`${net.interface}-${idx}`} className="p-3 bg-[#0b0e14]/50 border border-[#1F2937]/45 rounded-lg space-y-1.5">
                        <div className="flex justify-between items-center text-[10px] font-bold">
                          <span className="text-slate-200">{net.interface}</span>
                          <span className="text-[8px] bg-purple-500/10 border border-purple-500/25 px-1 py-0.2 rounded text-purple-400">
                            {net.type}
                          </span>
                        </div>
                        <div className="text-[10px] space-y-1 text-slate-400">
                          <div>IP: <strong className="text-slate-100">{net.ip}</strong></div>
                          <div>Subnet: <strong className="text-slate-500 font-normal">{net.netmask}</strong></div>
                          <div className="truncate text-[9px] text-slate-500">MAC: {net.mac || "00:00:00:00:00:00"}</div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* DNS settings */}
              <div className="md:col-span-4 p-5 rounded-xl border border-[#1F2937]/50 bg-[#111418]/25 flex flex-col">
                <h3 className="text-xs font-bold text-[#E2E8F0] uppercase tracking-wider flex items-center gap-1.5 mb-4">
                  <Database className="w-4 h-4 text-emerald-400" />
                  Primary DNS Config
                </h3>

                <div className="space-y-3 flex-grow">
                  <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider block">Resolved Nameservers</span>
                  
                  <div className="space-y-2">
                    {deviceData.dns?.map((server, idx) => (
                      <div key={idx} className="p-2.5 bg-[#0b0e14]/50 border border-[#1F2937]/40 rounded text-xs font-bold text-slate-200 flex items-center gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        <span>{server}</span>
                      </div>
                    ))}
                  </div>

                  <div className="p-3 bg-emerald-500/5 border border-emerald-500/10 rounded-lg text-[10px] text-emerald-400/80 leading-normal font-sans mt-auto">
                    Domain Queries are directed and encapsulated through these static nameserver links.
                  </div>
                </div>
              </div>

            </div>

          </motion.div>
        )}

      </div>

    </div>
  );
}
