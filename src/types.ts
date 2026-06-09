/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface ConnectionRecord {
  id: string;
  srcIp: string;
  srcPort: number;
  dstPort: number;
  byteCount: number;
  timestamp: string;
  payloadLabel: string;
  rawPayload?: string;
  index: number;
}

export type ThreatLevel = "MONITORING" | "LOW" | "MEDIUM" | "HIGH";

export interface HDTScores {
  l1_gmm: number;
  l2_kde: number;
  l3_lowess: number;
  ads: number;
  fusion: number;
  alert: ThreatLevel;
  obsCount: number;
}

export type SimStatus = 
  | "idle" 
  | "initializing"
  | "baseline_ready_to_run"
  | "running_baseline"
  | "baseline_complete"
  | "running_attack_exfil"
  | "running_attack_poison"
  | "running_attack_sweep"
  | "attack_complete";

export interface LogEntry {
  id: string;
  timestamp: string;
  srcIp: string;
  srcPort: number;
  dstPort: number;
  byteCount: number;
  payloadLabel: string;
  scores: HDTScores;
  isCustomManual?: boolean;
  gmmDrift?: number;
}

export interface PortState {
  port: number;
  lastHitTime: number;
  flashType: "normal" | "exfil" | "poison" | "sweep" | null;
  count: number;
}
