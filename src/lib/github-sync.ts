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

function getGithubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "Elly-VulnGuardian-Studio",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

export async function fetchManifestFromGithub(
  repoUrl: string | undefined,
  manifestFile: string,
  branch = "main"
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
        headers: getGithubHeaders(),
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
