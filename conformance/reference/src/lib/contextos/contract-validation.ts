import { types } from "node:util";
import type { ArtifactRef, ControlRef, ProfileSelection } from "./execution-contract-types";

export function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || types.isProxy(value) || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) return false;
  const ownKeys = Reflect.ownKeys(value);
  return ownKeys.length === keys.length && ownKeys.every(key => {
    if (typeof key !== "string" || !keys.includes(key)) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && "value" in descriptor && descriptor.enumerable === true;
  });
}

export function isContractIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512 && [...value].length <= 256;
}
export function isArtifactRef(value: unknown): value is ArtifactRef {
  return hasExactKeys(value, ["artifact_type", "artifact_id", "version", "sha256"])
    && isContractIdentifier(value.artifact_type) && isContractIdentifier(value.artifact_id)
    && isContractIdentifier(value.version) && typeof value.sha256 === "string"
    && /^sha256:[a-f0-9]{64}$/.test(value.sha256);
}
export function isControlRef(value: unknown): value is ControlRef {
  return hasExactKeys(value, ["control_id", "control_version"])
    && isContractIdentifier(value.control_id) && isContractIdentifier(value.control_version);
}
export function isProfileSelection(value: unknown): value is ProfileSelection {
  return hasExactKeys(value, ["profile_id", "profile_version"])
    && isContractIdentifier(value.profile_id) && isContractIdentifier(value.profile_version);
}

/** UTC calendar timestamps; leap-second labels require a separate time-scale adapter. */
export function isContractTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 256) return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= days[month - 1];
}
export function compareContractTimes(left: string, right: string): number | undefined {
  if (!isContractTimestamp(left) || !isContractTimestamp(right)) return undefined;
  const a = left.slice(0, 19), b = right.slice(0, 19);
  if (a !== b) return a < b ? -1 : 1;
  const af = left.length > 20 ? left.slice(20, -1) : "";
  const bf = right.length > 20 ? right.slice(20, -1) : "";
  const length = Math.max(af.length, bf.length);
  const ap = af.padEnd(length, "0"), bp = bf.padEnd(length, "0");
  return ap === bp ? 0 : ap < bp ? -1 : 1;
}
export function isWithinContractInterval(time: string, start: string, end: string): boolean {
  const interval = compareContractTimes(start, end), lower = compareContractTimes(time, start), upper = compareContractTimes(time, end);
  return interval === -1 && lower !== undefined && lower >= 0 && upper === -1;
}

/** Exact whole-second scheduling with the original fractional precision and no ambient clock. */
export function addContractSeconds(time: string, seconds: number): string | undefined {
  if (!isContractTimestamp(time) || !Number.isSafeInteger(seconds) || seconds < 0) return undefined;
  const whole = Date.parse(`${time.slice(0, 19)}Z`);
  const next = BigInt(whole) + BigInt(seconds) * BigInt(1000);
  if (next > BigInt(Date.parse("9999-12-31T23:59:59Z"))) return undefined;
  return `${new Date(Number(next)).toISOString().slice(0, 19)}${time.slice(19, -1)}Z`;
}
