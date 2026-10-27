import fs from "node:fs";
import path from "node:path";
import initialSeed from "@/data/guardian-state.json";
import type { GuardianState } from "./types";

const LOCAL_STATE_PATH = path.join(
  process.cwd(),
  "src/data/guardian-state.json"
);
const TMP_STATE_PATH = "/tmp/vuln-guardian-state.json";

let memoryState: GuardianState | null = null;

export function getGuardianState(): GuardianState {
  if (fs.existsSync(LOCAL_STATE_PATH)) {
    try {
      const raw = fs.readFileSync(LOCAL_STATE_PATH, "utf8");
      const parsed = JSON.parse(raw) as GuardianState;
      if (memoryState && new Date(memoryState.lastGlobalScanAt) > new Date(parsed.lastGlobalScanAt)) {
        return memoryState;
      }
      memoryState = parsed;
      return parsed;
    } catch {
      // Fallback below
    }
  }

  if (fs.existsSync(TMP_STATE_PATH)) {
    try {
      const raw = fs.readFileSync(TMP_STATE_PATH, "utf8");
      memoryState = JSON.parse(raw) as GuardianState;
      return memoryState;
    } catch {
      // Fallback below
    }
  }

  if (memoryState) return memoryState;
  memoryState = structuredClone(initialSeed as unknown as GuardianState);
  return memoryState;
}

export function saveGuardianState(state: GuardianState): void {
  state.lastGlobalScanAt = new Date().toISOString();
  memoryState = state;
  const serialized = JSON.stringify(state, null, 2);

  try {
    fs.writeFileSync(LOCAL_STATE_PATH, serialized, "utf8");
  } catch {
    // Read-only filesystem on Vercel serverless — write to /tmp instead
    try {
      fs.writeFileSync(TMP_STATE_PATH, serialized, "utf8");
    } catch {
      // Ignore if /tmp is unavailable
    }
  }
}
