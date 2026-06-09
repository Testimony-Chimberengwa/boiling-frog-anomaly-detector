/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ConnectionRecord } from "./types";

/**
 * Generate randomized baseline traffic profile that mimics normal enterprise traffic.
 * Total 15 connections with sizes fluctuating between 45KB and 110KB.
 */
export function generateBaselineSequence(): Omit<ConnectionRecord, "id" | "index">[] {
  const normalLabels = [
    { baseSize: 50000, label: "HTTP response body" },
    { baseSize: 75000, label: "API JSON payload" },
    { baseSize: 90000, label: "file download chunk" },
    { baseSize: 60000, label: "form submission" },
    { baseSize: 110000, label: "image asset" },
    { baseSize: 45000, label: "config sync" },
    { baseSize: 80000, label: "log batch" },
    { baseSize: 95000, label: "telemetry upload" },
    { baseSize: 70000, label: "session heartbeat" },
    { baseSize: 55000, label: "auth token refresh" },
    { baseSize: 85000, label: "metrics push" },
    { baseSize: 100000, label: "backup chunk" },
    { baseSize: 65000, label: "event stream" },
    { baseSize: 72000, label: "cache warm" },
    { baseSize: 88000, label: "health check payload" },
  ];

  return normalLabels.map((item, idx) => {
    // Inject small fluctuations of +/- 5000 bytes mimicking build_baseline.py
    const jitter = Math.floor(Math.random() * 10000) - 5000;
    const size = item.baseSize + jitter;
    const port = 5001 + (idx % 10);
    
    // Create random hex payload string for UI visual inspection
    const hex = generateMockHexPayload(size, "BASELINE", idx + 1, item.label);

    return {
      srcIp: "10.0.12.54",
      srcPort: 38200 + idx,
      dstPort: port,
      byteCount: size,
      timestamp: new Date().toLocaleTimeString(),
      payloadLabel: `BASELINE|OBS=${idx + 1}|LABEL=${item.label}`,
      rawPayload: hex,
    };
  });
}

/**
 * Generate Attack 1 sequence: Slow Data Exfiltration.
 * Target: L3 LOWESS Volume Gradient
 * 6 rounds, with sizes skyrocketing: 1MB -> 2MB -> -> 6MB
 */
export function generateExfilSequence(): Omit<ConnectionRecord, "id" | "index">[] {
  const ports = [5003, 5007, 5002, 5009, 5001, 5006];
  return Array.from({ length: 6 }).map((_, i) => {
    const mb = i + 1;
    const size = mb * 1024 * 1024; // MB in bytes
    const port = ports[i];
    
    const hex = generateMockHexPayload(size, "EXFIL", i + 1, "SLOW-EXFIL");

    return {
      srcIp: "192.168.43.88",
      srcPort: 49120 + i,
      dstPort: port,
      byteCount: size,
      timestamp: new Date().toLocaleTimeString(),
      payloadLabel: `EXFIL|ROUND=${i + 1}|SIZE=${mb}MB|RISING-VOLUME|SESSION=0xBF${i.toString(16).toUpperCase()}`,
      rawPayload: hex,
    };
  });
}

/**
 * Generate Attack 2 sequence: Baseline Poisoning.
 * Target: ADS Drift Sentinel & L1 GMM
 * 12 rounds, starting at 64KB and rising by ~5% per round.
 * GMM adapts dynamically to each small increment, but ADS flags the total drift relative to anchor baseline.
 */
export function generatePoisoningSequence(): Omit<ConnectionRecord, "id" | "index">[] {
  const baseKb = 64;
  return Array.from({ length: 12 }).map((_, i) => {
    // Drift goes up by 5% each round: 1.0, 1.05, 1.10, ... 1.55 or similar
    const multiplier = 1 + i * 0.05;
    const size = Math.floor(baseKb * 1024 * multiplier);
    const driftPct = i * 5;
    const port = 5001 + (i % 10);
    
    const hex = generateMockHexPayload(size, "POISON", i + 1, `drift +${driftPct}%`);

    return {
      srcIp: "172.16.5.120",
      srcPort: 41000 + i,
      dstPort: port,
      byteCount: size,
      timestamp: new Date().toLocaleTimeString(),
      payloadLabel: `POISON|ROUND=${i + 1}|DRIFT=+${driftPct}%|SIZE=${Math.floor(size / 1024)}KB`,
      rawPayload: hex,
    };
  });
}

/**
 * Generate Attack 3 sequence: Horizontal Recon Sweep.
 * Target: L2 KDE Density Drift (diversity profile spike)
 * 2 passes across all 10 ports, tiny size of 150 bytes.
 */
export function generateSweepSequence(): Omit<ConnectionRecord, "id" | "index">[] {
  const seq: Omit<ConnectionRecord, "id" | "index">[] = [];
  const ports = Array.from({ length: 10 }).map((_, i) => 5001 + i);

  for (let pass = 1; pass <= 2; pass++) {
    for (let pIdx = 0; pIdx < ports.length; pIdx++) {
      const port = ports[pIdx];
      const size = 150 + Math.floor(Math.random() * 20); // tiny size

      const hex = generateMockHexPayload(size, "RECON", pass, `port ${port} sweep`);

      seq.push({
        srcIp: "10.99.0.7",
        srcPort: 52000 + pass * 100 + pIdx,
        dstPort: port,
        byteCount: size,
        timestamp: new Date().toLocaleTimeString(),
        payloadLabel: `RECON|PASS=${pass}|PORT=${port}|AGENT=APT-SIM|INTENT=PROFILE|SWEEP=HORIZONTAL`,
        rawPayload: hex,
      });
    }
  }

  return seq;
}

/**
 * Helper to build visual cyberpunk hex dump preview representing raw packet data
 */
export function generateMockHexPayload(size: number, type: string, index: number, meta: string): string {
  // Generate beautiful hex dump string representing content
  const headerText = `${type}_OBS_${index}_META[${meta}]_LEN[${size}B]`;
  const textBytes = Array.from(headerText).map(c => c.charCodeAt(0));
  
  const dumpLines: string[] = [];
  
  // Format up to 6 lines for display
  const totalOffset = Math.min(128, size);
  for (let offset = 0; offset < totalOffset; offset += 16) {
    const hexParts: string[] = [];
    const asciiParts: string[] = [];

    for (let i = 0; i < 16; i++) {
      const byteIdx = offset + i;
      if (byteIdx < size) {
        let byte = 0;
        if (byteIdx < textBytes.length) {
          byte = textBytes[byteIdx];
        } else {
          // Fill rest with structured random bytes based on type
          if (type === "BASELINE") byte = 0x30 + (byteIdx % 10); // numerical pattern
          else if (type === "EXFIL") byte = 0x41 + (byteIdx % 26); // alphabetic
          else if (type === "POISON") byte = 0xAB; // solid padding block
          else byte = 0x2E; // dots
        }

        hexParts.push(byte.toString(16).padStart(2, "0").toUpperCase());
        asciiParts.push((byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : ".");
      } else {
        hexParts.push("  ");
        asciiParts.push(" ");
      }
    }

    const hexStr = hexParts.slice(0, 8).join(" ") + "  " + hexParts.slice(8).join(" ");
    const asciiStr = asciiParts.join("");
    const offsetStr = offset.toString(16).padStart(4, "0").toUpperCase();
    
    dumpLines.push(`${offsetStr}  ${hexStr}  |${asciiStr}|`);
  }

  if (size > 128) {
    dumpLines.push(`... [Truncated ${size - 128} bytes of structural bytes]`);
  }

  return dumpLines.join("\n");
}
