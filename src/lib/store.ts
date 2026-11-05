import fs from "node:fs";
import path from "node:path";
import initialSeed from "@/data/guardian-state.json";
import { ensureScanHistoryPopulated } from "./scan-history";
import type { GuardianState } from "./types";

const LOCAL_STATE_PATH = path.join(
  process.cwd(),
  "src/data/guardian-state.json"
);
const TMP_STATE_PATH = "/tmp/vuln-guardian-state.json";

let memoryState: GuardianState | null = null;
let lastGithubFetchMs = 0;
const GITHUB_FETCH_TTL_MS = 10_000;

export function getGuardianState(): GuardianState {
  const candidates: GuardianState[] = [];

  if (memoryState) {
    candidates.push(memoryState);
  }

  if (fs.existsSync(TMP_STATE_PATH)) {
    try {
      const raw = fs.readFileSync(TMP_STATE_PATH, "utf8");
      candidates.push(JSON.parse(raw) as GuardianState);
    } catch {
      // Ignore corrupt tmp state
    }
  }

  if (fs.existsSync(LOCAL_STATE_PATH)) {
    try {
      const raw = fs.readFileSync(LOCAL_STATE_PATH, "utf8");
      candidates.push(JSON.parse(raw) as GuardianState);
    } catch {
      // Ignore corrupt local state
    }
  }

  if (candidates.length > 0) {
    candidates.sort(
      (a, b) =>
        new Date(b.lastGlobalScanAt || 0).getTime() -
        new Date(a.lastGlobalScanAt || 0).getTime()
    );
    memoryState = candidates[0];
    ensureScanHistoryPopulated(memoryState);
    return memoryState;
  }

  memoryState = structuredClone(initialSeed as unknown as GuardianState);
  ensureScanHistoryPopulated(memoryState);
  return memoryState;
}

export async function getGuardianStateAsync(
  forceRemote = false
): Promise<GuardianState> {
  const localBest = getGuardianState();
  const now = Date.now();

  if (!forceRemote && now - lastGithubFetchMs < GITHUB_FETCH_TTL_MS) {
    return localBest;
  }

  const remoteState = await fetchStateFromGithubRepo();
  lastGithubFetchMs = now;

  if (remoteState) {
    const remoteTime = new Date(remoteState.lastGlobalScanAt || 0).getTime();
    const localTime = new Date(localBest.lastGlobalScanAt || 0).getTime();
    const remoteHistLen = remoteState.scanHistory?.length || 0;
    const localHistLen = localBest.scanHistory?.length || 0;

    if (remoteTime >= localTime && remoteHistLen >= localHistLen) {
      ensureScanHistoryPopulated(remoteState);
      memoryState = remoteState;
      try {
        fs.writeFileSync(
          TMP_STATE_PATH,
          JSON.stringify(remoteState, null, 2),
          "utf8"
        );
      } catch {
        // Ignore if /tmp is unavailable
      }
      return remoteState;
    }
  }

  return localBest;
}

export async function saveGuardianState(state: GuardianState): Promise<void> {
  state.lastGlobalScanAt = new Date().toISOString();
  ensureScanHistoryPopulated(state);
  memoryState = state;
  lastGithubFetchMs = Date.now();
  const serialized = JSON.stringify(state, null, 2);

  let wroteLocal = false;
  try {
    fs.writeFileSync(LOCAL_STATE_PATH, serialized, "utf8");
    wroteLocal = true;
  } catch {
    // Read-only filesystem on Vercel serverless — write to /tmp
    try {
      fs.writeFileSync(TMP_STATE_PATH, serialized, "utf8");
    } catch {
      // Ignore if /tmp is unavailable
    }
  }

  // Always await GitHub persistence on serverless (or when GITHUB_TOKEN is configured in production)
  if (!wroteLocal || process.env.VERCEL) {
    await persistStateToGithubRepo(serialized);
  }
}

async function fetchStateFromGithubRepo(): Promise<GuardianState | null> {
  const repoSlug =
    process.env.GUARDIAN_STATE_REPO?.trim() || "huseyindol/vuln-guardian";
  const filePath = "src/data/guardian-state.json";
  const token = process.env.GITHUB_TOKEN?.trim();

  try {
    if (token) {
      const apiUrl = `https://api.github.com/repos/${repoSlug}/contents/${filePath}?ref=main`;
      const resp = await fetch(apiUrl, {
        headers: {
          Accept: "application/vnd.github.raw+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "Elly-VulnGuardian-Studio",
          Authorization: `Bearer ${token}`,
        },
        cache: "no-store",
      });
      if (resp.ok) {
        const text = await resp.text();
        return JSON.parse(text) as GuardianState;
      }
    }

    const rawUrl = `https://raw.githubusercontent.com/${repoSlug}/main/${filePath}?t=${Date.now()}`;
    const rawResp = await fetch(rawUrl, { cache: "no-store" });
    if (rawResp.ok) {
      const text = await rawResp.text();
      return JSON.parse(text) as GuardianState;
    }
  } catch {
    // Fallback to local state if GitHub is unreachable
  }
  return null;
}

async function persistStateToGithubRepo(serialized: string): Promise<void> {
  const token = process.env.GITHUB_TOKEN?.trim();
  if (!token) return;
  const repoSlug =
    process.env.GUARDIAN_STATE_REPO?.trim() || "huseyindol/vuln-guardian";
  const filePath = "src/data/guardian-state.json";
  const apiUrl = `https://api.github.com/repos/${repoSlug}/contents/${filePath}`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "Elly-VulnGuardian-Studio",
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };

  try {
    const getResp = await fetch(`${apiUrl}?ref=main`, {
      headers,
      cache: "no-store",
    });
    if (!getResp.ok) return;
    const current = (await getResp.json()) as { sha?: string };
    if (!current.sha) return;

    await fetch(apiUrl, {
      method: "PUT",
      headers,
      body: JSON.stringify({
        message:
          "chore(state): sync guardian-state.json after scan/remediation [skip ci]",
        content: Buffer.from(serialized, "utf8").toString("base64"),
        sha: current.sha,
        branch: "main",
      }),
      cache: "no-store",
    });
  } catch {
    // Best-effort persistence on serverless
  }
}
