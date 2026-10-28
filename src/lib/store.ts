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
    return memoryState;
  }

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
    // Read-only filesystem on Vercel serverless — write to /tmp and sync to GitHub state repo
    try {
      fs.writeFileSync(TMP_STATE_PATH, serialized, "utf8");
    } catch {
      // Ignore if /tmp is unavailable
    }
    void persistStateToGithubRepo(serialized);
  }
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
        message: "chore(state): sync guardian-state.json after scan/remediation [skip ci]",
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
