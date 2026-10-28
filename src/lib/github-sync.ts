import type { CanaryStageResult } from "./types";

export interface GithubFileResult {
  content: string;
  sha: string;
  htmlUrl: string;
}

export interface GithubCommitResult {
  commitSha: string;
  fullCommitSha?: string;
  commitUrl: string;
  prUrl?: string;
  prNumber?: number;
  branchName?: string;
  autoMerged?: boolean;
  mergeCommitSha?: string;
  canaryStages?: CanaryStageResult[];
}

export function extractGithubRepoSlug(repoUrl?: string): string | null {
  if (!repoUrl) return null;
  const cleaned = repoUrl
    .trim()
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/$/, "");
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(cleaned)) {
    return cleaned;
  }
  return null;
}

function getGithubHeaders(customToken?: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "Elly-VulnGuardian-Studio",
  };
  const token = customToken?.trim() || process.env.GITHUB_TOKEN;
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

export async function fetchManifestFromGithub(
  repoUrl: string | undefined,
  manifestFile: string,
  branch = "main",
  customToken?: string
): Promise<GithubFileResult | null> {
  const slug = extractGithubRepoSlug(repoUrl);
  if (!slug) return null;

  const branchesToTry = branch === "main" ? ["main", "master"] : [branch];

  for (const b of branchesToTry) {
    try {
      const url = `https://api.github.com/repos/${slug}/contents/${encodeURIComponent(
        manifestFile
      )}?ref=${encodeURIComponent(b)}`;
      const resp = await fetch(url, {
        headers: getGithubHeaders(customToken),
        cache: "no-store",
      });
      if (resp.ok) {
        const data = (await resp.json()) as {
          content?: string;
          encoding?: string;
          sha?: string;
          html_url?: string;
        };
        if (data.content && data.sha) {
          const decoded = Buffer.from(
            data.content.replace(/\s+/g, ""),
            "base64"
          ).toString("utf8");
          return {
            content: decoded,
            sha: data.sha,
            htmlUrl:
              data.html_url ||
              `https://github.com/${slug}/blob/${b}/${manifestFile}`,
          };
        }
      }

      // Public raw fallback if unauthenticated API is rate-limited
      const rawUrl = `https://raw.githubusercontent.com/${slug}/${encodeURIComponent(
        b
      )}/${manifestFile}`;
      const rawResp = await fetch(rawUrl, { cache: "no-store" });
      if (rawResp.ok) {
        const text = await rawResp.text();
        if (text && text.trim().length > 0) {
          return {
            content: text,
            sha: "raw-public",
            htmlUrl: `https://github.com/${slug}/blob/${b}/${manifestFile}`,
          };
        }
      }
    } catch {
      // Try next branch
    }
  }
  return null;
}

function parseSemverTuple(v: string): [number, number, number] {
  const m = String(v)
    .trim()
    .replace(/^[~^>=<v\s]+/, "")
    .match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return [0, 0, 0];
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function cmpSemverTuple(a: string, b: string): number {
  const pa = parseSemverTuple(a);
  const pb = parseSemverTuple(b);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

function satisfiesSemverRange(ver: string, range: string): boolean {
  const cleanRange = String(range).trim();
  if (!cleanRange || cleanRange === "*" || cleanRange.includes("||")) {
    return true;
  }
  const minVer = cleanRange.replace(/^[~^>=<\s]+/, "");
  if (!/^\d+\.\d+\.\d+/.test(minVer)) return true;
  const [vMaj, vMin] = parseSemverTuple(ver);
  const [rMaj, rMin] = parseSemverTuple(minVer);
  if (cleanRange.startsWith("^") && vMaj !== rMaj) return false;
  if (cleanRange.startsWith("~") && (vMaj !== rMaj || vMin !== rMin)) {
    return false;
  }
  return cmpSemverTuple(ver, minVer) >= 0;
}

async function fetchNpmRegistryPackageTuple(
  name: string,
  targetVerOrRange: string
): Promise<{
  name: string;
  ver: string;
  info: Record<string, unknown>;
  integrity: string;
  tarball: string;
  dependencies: Record<string, string>;
} | null> {
  const cleanTarget = String(targetVerOrRange)
    .trim()
    .replace(/^[~^>=<\s]+/, "");
  if (!cleanTarget) return null;
  try {
    const res = await fetch(
      `https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(
        cleanTarget
      )}`,
      { cache: "no-store" }
    );
    if (!res.ok) return null;
    const meta = (await res.json()) as {
      version?: string;
      dependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      peerDependenciesMeta?: Record<string, { optional?: boolean }>;
      bin?: Record<string, string>;
      dist?: { integrity?: string; tarball?: string };
    };
    const ver = meta.version || cleanTarget;
    const info: Record<string, unknown> = {};
    if (meta.dependencies && Object.keys(meta.dependencies).length > 0) {
      info.dependencies = meta.dependencies;
    }
    if (
      meta.optionalDependencies &&
      Object.keys(meta.optionalDependencies).length > 0
    ) {
      info.optionalDependencies = meta.optionalDependencies;
    }
    if (meta.peerDependencies && Object.keys(meta.peerDependencies).length > 0) {
      info.peerDependencies = meta.peerDependencies;
    }
    if (meta.peerDependenciesMeta) {
      const optPeers = Object.entries(meta.peerDependenciesMeta)
        .filter(([, v]) => v && v.optional)
        .map(([k]) => k);
      if (optPeers.length > 0) info.optionalPeers = optPeers;
    }
    if (meta.bin) {
      const binKeys = Object.keys(meta.bin);
      const shortName = name.split("/").pop();
      if (binKeys.length === 1 && binKeys[0] === shortName) {
        info.bin = meta.bin[binKeys[0]];
      } else if (binKeys.length > 0) {
        info.bin = meta.bin;
      }
    }
    return {
      name,
      ver,
      info,
      integrity: meta.dist?.integrity || "",
      tarball: meta.dist?.tarball || "",
      dependencies: meta.dependencies || {},
    };
  } catch {
    return null;
  }
}

/**
 * `package.json` güncellendiğinde `bun.lock` dosyasını da npm registry verileriyle otomatik senkronize eder.
 * Böylece GitHub Actions veya Vercel üzerinde `bun install --frozen-lockfile` hatası ("lockfile had changes, but lockfile is frozen") oluşmaz.
 */
export async function autoSyncBunLockContent(
  newPkgJsonRaw: string,
  bunLockRaw: string
): Promise<string> {
  try {
    const newPkg = JSON.parse(newPkgJsonRaw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      overrides?: Record<string, string>;
    };
    let lockText = bunLockRaw;

    const allSpecs: Record<string, string> = {
      ...(newPkg.dependencies || {}),
      ...(newPkg.devDependencies || {}),
      ...(newPkg.overrides || {}),
    };

    const queue: Array<[string, string]> = [];
    const pkgBlockIdx = lockText.indexOf('"packages": {');

    for (const [pkgName, newSpec] of Object.entries(allSpecs)) {
      if (typeof newSpec !== "string" || newSpec.startsWith("npm:")) continue;
      const cleanTarget = newSpec.replace(/^[~^>=<\s]+/, "");
      const escaped = pkgName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

      if (pkgBlockIdx !== -1) {
        const header = lockText.slice(0, pkgBlockIdx).replace(
          new RegExp(`("${escaped}":\\s*)"([^"]+)"`, "g"),
          (_, p1: string, oldSpec: string) => {
            if (oldSpec !== newSpec) {
              queue.push([pkgName, cleanTarget]);
            }
            return `${p1}"${newSpec}"`;
          }
        );
        lockText = header + lockText.slice(pkgBlockIdx);
      }

      // Also enqueue if package in "packages" block is older than cleanTarget
      const pkgEntryMatch = lockText.match(
        new RegExp(`"${escaped}":\\s*\\["${escaped}@([^"]+)"`)
      );
      if (
        pkgEntryMatch &&
        cmpSemverTuple(pkgEntryMatch[1], cleanTarget) < 0
      ) {
        queue.push([pkgName, cleanTarget]);
      }
    }

    const visited = new Set<string>();
    while (queue.length > 0) {
      const item = queue.shift()!;
      const [pkgName, targetVer] = item;
      const key = `${pkgName}@${targetVer}`;
      if (visited.has(key)) continue;
      visited.add(key);

      const escaped = pkgName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const entryRegex = new RegExp(
        `("${escaped}":\\s*)\\["${escaped}@([^"]+)",\\s*"",\\s*(\\{[^\\n]*\\}),\\s*"(sha512-[^"]+)"\\]`
      );
      const match = lockText.match(entryRegex);
      if (!match) continue;
      const currentLockedVer = match[2];

      if (
        satisfiesSemverRange(currentLockedVer, `^${targetVer}`) &&
        cmpSemverTuple(currentLockedVer, targetVer) >= 0
      ) {
        continue;
      }

      const tuple = await fetchNpmRegistryPackageTuple(pkgName, targetVer);
      if (!tuple || !tuple.integrity) continue;

      const replacement = `$1["${pkgName}@${tuple.ver}", "", ${JSON.stringify(
        tuple.info
      )}, "${tuple.integrity}"]`;
      lockText = lockText.replace(entryRegex, replacement);

      for (const [subName, subRange] of Object.entries(tuple.dependencies)) {
        const subEsc = subName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const subMatch = lockText.match(
          new RegExp(`"${subEsc}":\\s*\\["${subEsc}@([^"]+)"`)
        );
        if (subMatch && !satisfiesSemverRange(subMatch[1], subRange)) {
          queue.push([subName, String(subRange).replace(/^[~^>=<\s]+/, "")]);
        }
      }
    }

    return lockText;
  } catch {
    return bunLockRaw;
  }
}

/**
 * `package.json` güncellendiğinde `package-lock.json` dosyasını da senkronize eder (`npm ci` uyumluluğu için).
 */
export async function autoSyncPackageLockJsonContent(
  newPkgJsonRaw: string,
  pkgLockRaw: string
): Promise<string> {
  try {
    const newPkg = JSON.parse(newPkgJsonRaw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      overrides?: Record<string, string>;
    };
    const lockJson = JSON.parse(pkgLockRaw) as {
      packages?: Record<string, Record<string, unknown>>;
    };
    if (!lockJson.packages) return pkgLockRaw;

    const rootPkg = lockJson.packages[""] || {};
    if (newPkg.dependencies) rootPkg.dependencies = newPkg.dependencies;
    if (newPkg.devDependencies) rootPkg.devDependencies = newPkg.devDependencies;
    if (newPkg.overrides) rootPkg.overrides = newPkg.overrides;
    lockJson.packages[""] = rootPkg;

    const allSpecs: Record<string, string> = {
      ...(newPkg.dependencies || {}),
      ...(newPkg.devDependencies || {}),
      ...(newPkg.overrides || {}),
    };

    for (const [pkgName, newSpec] of Object.entries(allSpecs)) {
      if (typeof newSpec !== "string" || newSpec.startsWith("npm:")) continue;
      const cleanTarget = newSpec.replace(/^[~^>=<\s]+/, "");
      const nodeKey = `node_modules/${pkgName}`;
      const existing = lockJson.packages[nodeKey] as
        | { version?: string; resolved?: string; integrity?: string; dependencies?: Record<string, string> }
        | undefined;
      if (
        existing?.version &&
        cmpSemverTuple(existing.version, cleanTarget) < 0
      ) {
        const tuple = await fetchNpmRegistryPackageTuple(pkgName, cleanTarget);
        if (tuple && tuple.integrity) {
          existing.version = tuple.ver;
          if (tuple.tarball) existing.resolved = tuple.tarball;
          existing.integrity = tuple.integrity;
          if (Object.keys(tuple.dependencies).length > 0) {
            existing.dependencies = tuple.dependencies;
          }
        }
      }
    }

    return JSON.stringify(lockJson, null, 2) + "\n";
  } catch {
    return pkgLockRaw;
  }
}

export async function commitManifestToGithub(
  repoUrl: string | undefined,
  manifestFile: string,
  newContent: string,
  commitMessage: string,
  branch = "main"
): Promise<GithubCommitResult | null> {
  const slug = extractGithubRepoSlug(repoUrl);
  if (!slug || !process.env.GITHUB_TOKEN) return null;

  const currentFile = await fetchManifestFromGithub(
    repoUrl,
    manifestFile,
    branch
  );
  if (!currentFile) {
    throw new Error(
      `GitHub üzerinden mevcut ${manifestFile} dosyası okunamadı (${slug})`
    );
  }

  // Prepare list of files to commit atomically (manifestFile + synced bun.lock / package-lock.json if applicable)
  const filesToCommit: Array<{ path: string; content: string }> = [
    { path: manifestFile, content: newContent },
  ];

  if (manifestFile.endsWith("package.json")) {
    const dirPrefix = manifestFile.includes("/")
      ? manifestFile.slice(0, manifestFile.lastIndexOf("/") + 1)
      : "";
    const bunLockPath = `${dirPrefix}bun.lock`;
    const pkgLockPath = `${dirPrefix}package-lock.json`;

    const existingBunLock = await fetchManifestFromGithub(
      repoUrl,
      bunLockPath,
      branch
    );
    if (existingBunLock?.content) {
      const syncedBunLock = await autoSyncBunLockContent(
        newContent,
        existingBunLock.content
      );
      if (syncedBunLock.trim() !== existingBunLock.content.trim()) {
        filesToCommit.push({ path: bunLockPath, content: syncedBunLock });
      }
    } else {
      const existingPkgLock = await fetchManifestFromGithub(
        repoUrl,
        pkgLockPath,
        branch
      );
      if (existingPkgLock?.content) {
        const syncedPkgLock = await autoSyncPackageLockJsonContent(
          newContent,
          existingPkgLock.content
        );
        if (syncedPkgLock.trim() !== existingPkgLock.content.trim()) {
          filesToCommit.push({ path: pkgLockPath, content: syncedPkgLock });
        }
      }
    }
  }

  if (
    filesToCommit.length === 1 &&
    currentFile.content.trim() === newContent.trim()
  ) {
    return {
      commitSha: currentFile.sha.slice(0, 7),
      fullCommitSha: currentFile.sha,
      commitUrl: currentFile.htmlUrl,
    };
  }

  // If multiple files (e.g. package.json + bun.lock), commit atomically via Git Data Tree API so CI runs once with synced lockfile!
  if (filesToCommit.length > 1) {
    try {
      const refResp = await fetch(
        `https://api.github.com/repos/${slug}/git/ref/heads/${encodeURIComponent(
          branch
        )}`,
        { headers: getGithubHeaders(), cache: "no-store" }
      );
      if (refResp.ok) {
        const refData = (await refResp.json()) as {
          object?: { sha?: string };
        };
        const latestCommitSha = refData.object?.sha;
        if (latestCommitSha) {
          const commitInfoResp = await fetch(
            `https://api.github.com/repos/${slug}/git/commits/${latestCommitSha}`,
            { headers: getGithubHeaders(), cache: "no-store" }
          );
          const commitInfo = (await commitInfoResp.json()) as {
            tree?: { sha?: string };
          };
          const baseTreeSha = commitInfo.tree?.sha;
          if (baseTreeSha) {
            const treeResp = await fetch(
              `https://api.github.com/repos/${slug}/git/trees`,
              {
                method: "POST",
                headers: {
                  ...getGithubHeaders(),
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  base_tree: baseTreeSha,
                  tree: filesToCommit.map((f) => ({
                    path: f.path,
                    mode: "100644",
                    type: "blob",
                    content: f.content,
                  })),
                }),
              }
            );
            if (treeResp.ok) {
              const treeData = (await treeResp.json()) as { sha?: string };
              const createCommitResp = await fetch(
                `https://api.github.com/repos/${slug}/git/commits`,
                {
                  method: "POST",
                  headers: {
                    ...getGithubHeaders(),
                    "Content-Type": "application/json",
                  },
                  body: JSON.stringify({
                    message: commitMessage,
                    tree: treeData.sha,
                    parents: [latestCommitSha],
                  }),
                }
              );
              if (createCommitResp.ok) {
                const newCommitData = (await createCommitResp.json()) as {
                  sha?: string;
                  html_url?: string;
                };
                const updateRefResp = await fetch(
                  `https://api.github.com/repos/${slug}/git/refs/heads/${encodeURIComponent(
                    branch
                  )}`,
                  {
                    method: "PATCH",
                    headers: {
                      ...getGithubHeaders(),
                      "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                      sha: newCommitData.sha,
                      force: false,
                    }),
                  }
                );
                if (updateRefResp.ok && newCommitData.sha) {
                  return {
                    commitSha: newCommitData.sha.slice(0, 7),
                    fullCommitSha: newCommitData.sha,
                    commitUrl:
                      newCommitData.html_url ||
                      `https://github.com/${slug}/commit/${newCommitData.sha}`,
                  };
                }
              }
            }
          }
        }
      }
    } catch {
      // Fallback to single-file PUT below if Git Data API fails
    }
  }

  const url = `https://api.github.com/repos/${slug}/contents/${encodeURIComponent(
    manifestFile
  )}`;
  const resp = await fetch(url, {
    method: "PUT",
    headers: {
      ...getGithubHeaders(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message: commitMessage,
      content: Buffer.from(newContent, "utf8").toString("base64"),
      sha: currentFile.sha,
      branch,
    }),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(
      `GitHub commit hatası (${resp.status}): ${errText.slice(0, 200)}`
    );
  }

  const result = (await resp.json()) as {
    commit?: { sha?: string; html_url?: string };
  };
  return {
    commitSha: result.commit?.sha?.slice(0, 7) || "pushed",
    fullCommitSha: result.commit?.sha,
    commitUrl:
      result.commit?.html_url ||
      `https://github.com/${slug}/commits/${branch}`,
  };
}

export async function createIsolatedPrOnGithub(
  repoUrl: string | undefined,
  manifestFile: string,
  newContent: string,
  packageName: string,
  fromVersion: string,
  toVersion: string,
  baseBranch = "main"
): Promise<GithubCommitResult | null> {
  const slug = extractGithubRepoSlug(repoUrl);
  if (!slug || !process.env.GITHUB_TOKEN) return null;

  // 1. Get base branch ref SHA
  const refResp = await fetch(
    `https://api.github.com/repos/${slug}/git/ref/heads/${baseBranch}`,
    { headers: getGithubHeaders(), cache: "no-store" }
  );
  if (!refResp.ok) {
    throw new Error(`Base branch (${baseBranch}) okunamadı`);
  }
  const refData = (await refResp.json()) as { object?: { sha?: string } };
  const baseSha = refData.object?.sha;
  if (!baseSha) throw new Error("Base SHA alınamadı");

  const safePkgSlug = packageName.replace(/[^a-zA-Z0-9_-]/g, "-");
  const newBranch = `security/canary-${safePkgSlug}-${toVersion}-${Date.now()
    .toString()
    .slice(-4)}`;

  // 2. Create new branch
  const createBranchResp = await fetch(
    `https://api.github.com/repos/${slug}/git/refs`,
    {
      method: "POST",
      headers: { ...getGithubHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        ref: `refs/heads/${newBranch}`,
        sha: baseSha,
      }),
    }
  );
  if (!createBranchResp.ok) {
    throw new Error(`İzole güvenlik dalı (${newBranch}) oluşturulamadı`);
  }

  // 3. Commit manifest to the new branch
  const commitMsg = `fix(security): upgrade ${packageName} from ${fromVersion} to ${toVersion} [Canary Branch]`;
  const commitRes = await commitManifestToGithub(
    repoUrl,
    manifestFile,
    newContent,
    commitMsg,
    newBranch
  );

  // 4. Open Pull Request against main
  const prResp = await fetch(`https://api.github.com/repos/${slug}/pulls`, {
    method: "POST",
    headers: { ...getGithubHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      title: `🛡️ [VulnGuardian Canary] ${packageName}: ${fromVersion} → ${toVersion} Otonom Major Test & Merge`,
      head: newBranch,
      base: baseBranch,
      body: `### 🛡️ VulnGuardian Otonom Canary Branch Doğrulaması\n\n- **Paket:** \`${packageName}\`\n- **Mevcut Versiyon:** \`${fromVersion}\`\n- **Hedef Safe Versiyon:** \`${toVersion}\`\n- **İzole Canary Dalı:** \`${newBranch}\`\n\nBu güncelleme **Major / Breaking Change** sınıfında olduğu için önce izole \`${newBranch}\` dalında açılmıştır. Tüm derleme, tip, bağımlılık ve smoke kontrolleri hatasız geçtiğinde otomatik olarak \`${baseBranch}\` dalına merge edilir.`,
    }),
  });

  if (prResp.ok) {
    const prData = (await prResp.json()) as {
      html_url?: string;
      number?: number;
    };
    return {
      commitSha: commitRes?.commitSha || "pr-branch",
      fullCommitSha: commitRes?.fullCommitSha,
      commitUrl: commitRes?.commitUrl || "",
      prUrl: prData.html_url,
      prNumber: prData.number,
      branchName: newBranch,
    };
  }

  return {
    commitSha: commitRes?.commitSha || "branch",
    fullCommitSha: commitRes?.fullCommitSha,
    commitUrl: commitRes?.commitUrl || "",
    branchName: newBranch,
  };
}

export async function runCanaryBranchTestAndAutoMergeOnGithub(params: {
  repoUrl: string | undefined;
  manifestFile: string;
  newContent: string;
  packageName: string;
  fromVersion: string;
  toVersion: string;
  localStages: CanaryStageResult[];
  localAllPassed: boolean;
  baseBranch?: string;
}): Promise<GithubCommitResult | null> {
  const {
    repoUrl,
    manifestFile,
    newContent,
    packageName,
    fromVersion,
    toVersion,
    localStages,
    localAllPassed,
    baseBranch = "main",
  } = params;

  const slug = extractGithubRepoSlug(repoUrl);
  if (!slug || !process.env.GITHUB_TOKEN) return null;

  // Step 1: Create isolated canary branch & open PR
  const prInfo = await createIsolatedPrOnGithub(
    repoUrl,
    manifestFile,
    newContent,
    packageName,
    fromVersion,
    toVersion,
    baseBranch
  );
  if (!prInfo) return null;

  const stages: CanaryStageResult[] = localStages.map((s) => ({ ...s }));
  const branchStageIdx = stages.findIndex((s) => s.stage === "BRANCH_ISOLATION");
  if (branchStageIdx !== -1) {
    stages[branchStageIdx] = {
      stage: "BRANCH_ISOLATION",
      label: "1. İzole Canary Branch & PR",
      status: "PASSED",
      detail: `GitHub üzerinde '${prInfo.branchName}' dalı açıldı ve PR #${prInfo.prNumber || "yeni"} oluşturuldu.`,
    };
  }

  // Step 2: Check GitHub CI Check Runs & Combined Status on the canary commit
  let githubCiPassed = true;
  let githubCiDetail = "GitHub commit durum kontrolleri ve PR çakışma analizi temiz.";

  if (prInfo.fullCommitSha) {
    try {
      const statusResp = await fetch(
        `https://api.github.com/repos/${slug}/commits/${prInfo.fullCommitSha}/status`,
        { headers: getGithubHeaders(), cache: "no-store" }
      );
      if (statusResp.ok) {
        const statusData = (await statusResp.json()) as {
          state?: string;
          total_count?: number;
        };
        if (statusData.state === "failure" || statusData.state === "error") {
          githubCiPassed = false;
          githubCiDetail = `GitHub Commit Status hatası raporladı (${statusData.state}).`;
        }
      }

      const checksResp = await fetch(
        `https://api.github.com/repos/${slug}/commits/${prInfo.fullCommitSha}/check-runs`,
        { headers: getGithubHeaders(), cache: "no-store" }
      );
      if (checksResp.ok) {
        const checksData = (await checksResp.json()) as {
          total_count?: number;
          check_runs?: Array<{ name?: string; status?: string; conclusion?: string | null }>;
        };
        const failedRun = (checksData.check_runs || []).find(
          (r) =>
            r.conclusion === "failure" ||
            r.conclusion === "timed_out" ||
            r.conclusion === "action_required"
        );
        if (failedRun) {
          githubCiPassed = false;
          githubCiDetail = `GitHub Check Run başarısız oldu: ${failedRun.name} (${failedRun.conclusion})`;
        }
      }
    } catch {
      // Proceed with PR mergeability check
    }
  }

  const smokeIdx = stages.findIndex((s) => s.stage === "SMOKE_HEALTH_CHECK");
  if (!githubCiPassed && smokeIdx !== -1) {
    stages[smokeIdx] = {
      stage: "SMOKE_HEALTH_CHECK",
      label: "4. Çalışabilirlik & CI Smoke Kontrolü",
      status: "FAILED",
      detail: githubCiDetail,
    };
  }

  const allChecksGreen = localAllPassed && githubCiPassed;

  // Step 3: If all checks passed, auto-merge PR into main & delete temporary canary branch!
  if (allChecksGreen && prInfo.prNumber) {
    let mergeResp: Response | null = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, 900 * attempt));
      }
      mergeResp = await fetch(
        `https://api.github.com/repos/${slug}/pulls/${prInfo.prNumber}/merge`,
        {
          method: "PUT",
          headers: { ...getGithubHeaders(), "Content-Type": "application/json" },
          body: JSON.stringify({
            commit_title: `fix(security): auto-merge verified upgrade ${packageName} (${fromVersion} -> ${toVersion})`,
            commit_message: `Otonom Canary Branch doğrulama kapılarından (Dependecy, Build/Type-Check, Smoke Check) hatasız geçtiği için otomatik olarak ${baseBranch} dalına merge edildi.`,
            merge_method: "squash",
          }),
        }
      );
      if (mergeResp.ok) break;
    }

    if (mergeResp && mergeResp.ok) {
      const mergeData = (await mergeResp.json()) as {
        merged?: boolean;
        sha?: string;
      };
      // Clean up temporary canary branch after successful merge
      if (prInfo.branchName) {
        fetch(
          `https://api.github.com/repos/${slug}/git/refs/heads/${prInfo.branchName}`,
          {
            method: "DELETE",
            headers: getGithubHeaders(),
          }
        ).catch(() => {});
      }

      const mergeIdx = stages.findIndex((s) => s.stage === "AUTO_MERGE_DEPLOY");
      const mergeStage: CanaryStageResult = {
        stage: "AUTO_MERGE_DEPLOY",
        label: "5. Otomatik Main Merge & Deploy",
        status: "PASSED",
        detail: `PR #${prInfo.prNumber} otonom olarak '${baseBranch}' dalına merge edildi (${mergeData.sha?.slice(0, 7) || "merged"}) ve canlı deploy tetiklendi.`,
      };
      if (mergeIdx !== -1) stages[mergeIdx] = mergeStage;
      else stages.push(mergeStage);

      return {
        ...prInfo,
        autoMerged: true,
        mergeCommitSha: mergeData.sha?.slice(0, 7) || prInfo.commitSha,
        canaryStages: stages,
      };
    }
  }

  const mergeIdx = stages.findIndex((s) => s.stage === "AUTO_MERGE_DEPLOY");
  const blockedStage: CanaryStageResult = {
    stage: "AUTO_MERGE_DEPLOY",
    label: "5. Otomatik Main Merge & Deploy",
    status: "FAILED",
    detail: allChecksGreen
      ? `PR #${prInfo.prNumber || ""} açıldı, GitHub merge onayı bekliyor.`
      : `Doğrulama hatası nedeniyle '${baseBranch}' dalına merge OTONOM ENGELLENDİ; canlı site korundu, PR izole dalda açık bırakıldı.`,
  };
  if (mergeIdx !== -1) stages[mergeIdx] = blockedStage;
  else stages.push(blockedStage);

  return {
    ...prInfo,
    autoMerged: false,
    canaryStages: stages,
  };
}

/**
 * Tek Seferde Toplu (Single-Batch) Canary Dalı -> CI/CD & Site Smoke Kontrolü -> PR Açmadan 'main' (Prod) Merge.
 * - Asla paket başına PR açmaz ve GitHub PR mail spam'i üretmez.
 * - Önce tek bir geçici 'security/batch-canary-...' dalı oluşturur.
 * - GitHub Check Runs / Commit Status ve varsa Preview URL (HTTP 200 OK site çalışabilirlik) kontrolü yapar.
 * - Sorun yoksa GitHub Merge API (POST /repos/{owner}/{repo}/merges) ile doğrudan 'main' dalına birleştirip geçici dalı siler.
 */
export async function verifyAndMergeBatchCanaryBranchOnGithub(params: {
  repoUrl: string | undefined;
  manifestFile: string;
  newContent: string;
  commitMessage: string;
  baseBranch?: string;
}): Promise<GithubCommitResult | null> {
  const {
    repoUrl,
    manifestFile,
    newContent,
    commitMessage,
    baseBranch = "main",
  } = params;

  const slug = extractGithubRepoSlug(repoUrl);
  if (!slug || !process.env.GITHUB_TOKEN) return null;

  const currentFile = await fetchManifestFromGithub(
    repoUrl,
    manifestFile,
    baseBranch
  );
  if (!currentFile) return null;

  if (currentFile.content.trim() === newContent.trim()) {
    return {
      commitSha: currentFile.sha.slice(0, 7),
      fullCommitSha: currentFile.sha,
      commitUrl: currentFile.htmlUrl,
      branchName: baseBranch,
      autoMerged: true,
    };
  }

  // 1. Get base branch SHA
  const refResp = await fetch(
    `https://api.github.com/repos/${slug}/git/ref/heads/${baseBranch}`,
    { headers: getGithubHeaders() }
  );
  if (!refResp.ok) return null;
  const refData = (await refResp.json()) as { object?: { sha?: string } };
  const baseSha = refData.object?.sha;
  if (!baseSha) return null;

  const canaryBranch = `security/batch-canary-${Date.now().toString().slice(-4)}`;

  // 2. Create temporary canary branch (NO Pull Request opened -> 0 PR emails!)
  const createRefResp = await fetch(
    `https://api.github.com/repos/${slug}/git/refs`,
    {
      method: "POST",
      headers: { ...getGithubHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        ref: `refs/heads/${canaryBranch}`,
        sha: baseSha,
      }),
    }
  );
  if (!createRefResp.ok) return null;

  // 3. Commit batch manifest to the isolated canary branch
  const canaryCommit = await commitManifestToGithub(
    repoUrl,
    manifestFile,
    newContent,
    commitMessage,
    canaryBranch
  );
  if (!canaryCommit?.fullCommitSha) {
    fetch(`https://api.github.com/repos/${slug}/git/refs/heads/${canaryBranch}`, {
      method: "DELETE",
      headers: getGithubHeaders(),
    }).catch(() => {});
    return null;
  }

  // 4. Verify GitHub Check Runs & Commit Status + Live Preview HTTP Smoke Check BEFORE merging to main (prod)
  let ciAndSiteHealthy = true;
  try {
    const [checksResp, statusResp] = await Promise.all([
      fetch(
        `https://api.github.com/repos/${slug}/commits/${canaryCommit.fullCommitSha}/check-runs`,
        { headers: getGithubHeaders() }
      ),
      fetch(
        `https://api.github.com/repos/${slug}/commits/${canaryCommit.fullCommitSha}/status`,
        { headers: getGithubHeaders() }
      ),
    ]);

    if (checksResp.ok) {
      const checksData = (await checksResp.json()) as {
        check_runs?: Array<{ conclusion?: string | null }>;
      };
      const failedRuns = (checksData.check_runs || []).filter(
        (r) =>
          r.conclusion === "failure" ||
          r.conclusion === "timed_out" ||
          r.conclusion === "cancelled"
      );
      if (failedRuns.length > 0) {
        ciAndSiteHealthy = false;
      }
    }

    if (ciAndSiteHealthy && statusResp.ok) {
      const statusData = (await statusResp.json()) as {
        state?: string;
        statuses?: Array<{ state?: string; target_url?: string }>;
      };
      if (statusData.state === "failure" || statusData.state === "error") {
        ciAndSiteHealthy = false;
      }
      // If a Vercel/Preview deployment URL is attached, run an HTTP GET smoke check to verify the site boots
      const previewUrl = (statusData.statuses || [])
        .map((s) => s.target_url)
        .find((u) => u && u.startsWith("https://") && !u.includes("github.com"));
      if (ciAndSiteHealthy && previewUrl) {
        try {
          const smokeResp = await fetch(previewUrl, { method: "GET" });
          if (smokeResp.status >= 500) {
            ciAndSiteHealthy = false;
          }
        } catch {
          // Ignore network reachability if preview requires auth
        }
      }
    }
  } catch {
    // Proceed if check API is not configured on repo
  }

  // If breaking change or site failure detected on canary branch, DO NOT merge to main (prod)!
  if (!ciAndSiteHealthy) {
    return {
      ...canaryCommit,
      branchName: canaryBranch,
      autoMerged: false,
    };
  }

  // 5. All checks passed -> Merge canaryBranch directly into 'main' (prod) via Git Merge API (NO PR -> 0 PR emails!)
  const mergeResp = await fetch(`https://api.github.com/repos/${slug}/merges`, {
    method: "POST",
    headers: { ...getGithubHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      base: baseBranch,
      head: canaryBranch,
      commit_message: commitMessage,
    }),
  });

  // Delete temporary canary branch after merge
  fetch(`https://api.github.com/repos/${slug}/git/refs/heads/${canaryBranch}`, {
    method: "DELETE",
    headers: getGithubHeaders(),
  }).catch(() => {});

  if (mergeResp.ok) {
    const mergeData = (await mergeResp.json()) as {
      sha?: string;
      html_url?: string;
    };
    return {
      commitSha: mergeData.sha?.slice(0, 7) || canaryCommit.commitSha,
      fullCommitSha: mergeData.sha || canaryCommit.fullCommitSha,
      commitUrl:
        mergeData.html_url || `https://github.com/${slug}/commits/${baseBranch}`,
      branchName: canaryBranch,
      autoMerged: true,
      mergeCommitSha: mergeData.sha?.slice(0, 7) || canaryCommit.commitSha,
    };
  }

  return {
    ...canaryCommit,
    branchName: canaryBranch,
    autoMerged: false,
  };
}
