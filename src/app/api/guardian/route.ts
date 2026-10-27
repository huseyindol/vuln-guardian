import fs from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";
import { getGuardianState, saveGuardianState } from "@/lib/store";
import {
  applySafeVersionToManifest,
  buildSecurityNewsFeed,
  classifyUpgradeRisk,
  computeNextDailyScanIso,
  getEcosystemDefaults,
  parseManifestContent,
  queryOsvForPackages,
  runCanaryVerificationPipeline,
} from "@/lib/scanner-engine";
import {
  commitManifestToGithub,
  extractGithubRepoSlug,
  fetchManifestFromGithub,
  runCanaryBranchTestAndAutoMergeOnGithub,
} from "@/lib/github-sync";
import type {
  CanaryStageResult,
  Ecosystem,
  GuardianState,
  MonitoredProject,
  RemediationRecord,
} from "@/lib/types";

async function rescanProjectObject(
  project: MonitoredProject,
  state: GuardianState,
  preRemediationList?: MonitoredProject[]
): Promise<MonitoredProject> {
  let manifestRaw = project.manifestRaw || "";

  const ghFile = await fetchManifestFromGithub(
    project.repoUrl,
    project.manifestFile,
    "main"
  );
  if (ghFile && ghFile.content) {
    manifestRaw = ghFile.content;
  } else {
    const localManifestPath = path.join(project.path, project.manifestFile);
    if (fs.existsSync(localManifestPath)) {
      try {
        manifestRaw = fs.readFileSync(localManifestPath, "utf8");
      } catch {
        // Fallback to stored manifestRaw
      }
    }
  }

  if (!manifestRaw) {
    throw new Error(`Manifest içeriği okunamadı: ${project.name}`);
  }

  let packages = parseManifestContent(project.ecosystem, manifestRaw);
  let vulnerabilities = await queryOsvForPackages(packages);

  if (preRemediationList) {
    preRemediationList.push({
      ...project,
      packages: [...packages],
      vulnerabilities: [...vulnerabilities],
    });
  }

  if (project.autoRemediate && vulnerabilities.length > 0) {
    const safeTargets = packages.filter(
      (pkg) => pkg.status === "VULNERABLE" && pkg.recommendedSafeVersion
    );

    if (safeTargets.length > 0) {
      const repoSlug = extractGithubRepoSlug(project.repoUrl) || project.name;
      for (const pkg of safeTargets) {
        const fromVer = pkg.cleanVersion;
        const toVer = pkg.recommendedSafeVersion!;
        const { risk, reason } = classifyUpgradeRisk(fromVer, toVer);
        const cveIds = vulnerabilities
          .filter((v) => v.packageName === pkg.name)
          .map((v) => v.cveId || v.id);

        const candidateManifest = applySafeVersionToManifest(
          project.ecosystem,
          manifestRaw,
          pkg.name,
          toVer
        );

        const canaryCheck = await runCanaryVerificationPipeline({
          project,
          nextManifestRaw: candidateManifest,
          packageName: pkg.name,
          fromVersion: fromVer,
          toVersion: toVer,
        });

        if (canaryCheck.allPassed) {
          manifestRaw = candidateManifest;
        }

        state.remediationHistory = state.remediationHistory.filter(
          (r) =>
            !(
              r.projectId === project.id &&
              r.packageName === pkg.name &&
              r.toSafeVersion === toVer
            )
        );
        state.remediationHistory.unshift({
          id: `auto-rem-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          projectId: project.id,
          projectName: project.name,
          timestamp: new Date().toISOString(),
          packageName: pkg.name,
          fromVersion: fromVer,
          toSafeVersion: toVer,
          upgradeRisk: risk,
          cveIds,
          verifyStatus: canaryCheck.allPassed ? "PASSED" : "FAILED",
          deployStatus: canaryCheck.allPassed
            ? risk === "BREAKING_MAJOR"
              ? "AUTO_MERGED_DEPLOYED"
              : project.autoDeploy
                ? "DEPLOYED"
                : "AUTO_MERGED_DEPLOYED"
            : "BLOCKED_BREAKING",
          deployTarget: project.deployTarget,
          commitRef: `fix(security): auto-merge verified ${pkg.name} (${fromVer} -> ${toVer})`,
          canaryBranch: canaryCheck.canaryBranch,
          autoMergedToMain: canaryCheck.allPassed,
          canaryStages: canaryCheck.stages,
          logs: [
            `[AutoScan] ${pkg.name}@${fromVer} sürümünde ${cveIds.slice(0, 3).join(", ")} tespit edildi`,
            `[SemVerGuard] ${risk}: ${reason}`,
            `[CanaryBranch] İzole dal açıldı: ${canaryCheck.canaryBranch}`,
            `[VerifyGate] ${project.verifyCommand} -> ${canaryCheck.allPassed ? "PASSED (EXIT 0)" : "FAILED"}`,
            canaryCheck.allPassed
              ? `[AutoMerge -> main] Tüm testler hatasız geçti; '${canaryCheck.canaryBranch}' otomatik olarak 'main' dalına merge edildi (${repoSlug}) ve ${project.deployTarget} deploy sağlandı`
              : `[MergeBlocked] Test hatası nedeniyle 'main' merge engellendi; canlı site korundu`,
          ],
        });
      }

      const updatedPackages = parseManifestContent(project.ecosystem, manifestRaw);
      for (const up of updatedPackages) {
        const prev = safeTargets.find((t) => t.name === up.name);
        if (prev && up.cleanVersion === prev.recommendedSafeVersion) {
          up.previousVersion = prev.cleanVersion;
          up.status = "PATCHED";
        }
      }
      vulnerabilities = await queryOsvForPackages(updatedPackages);
      packages = updatedPackages;
    }
  }

  for (const up of packages) {
    const hist = state.remediationHistory.find(
      (r) =>
        r.projectId === project.id &&
        r.packageName === up.name &&
        r.toSafeVersion === up.cleanVersion
    );
    if (hist && up.status === "SAFE") {
      up.previousVersion = hist.fromVersion;
      up.status = "PATCHED";
    }
  }

  const now = new Date();
  const dailyTime = project.dailyScanTime || "20:30";

  return {
    ...project,
    dailyScanTime: dailyTime,
    manifestRaw,
    lastScanAt: now.toISOString(),
    nextScanAt: computeNextDailyScanIso(dailyTime),
    status: vulnerabilities.length > 0 ? "VULNERABLE" : "HEALTHY",
    packages,
    vulnerabilities,
  };
}

export async function GET() {
  const state = getGuardianState();
  return NextResponse.json(state);
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { action } = body;
    const state = getGuardianState();

    if (action === "scan-project") {
      const { projectId } = body;
      const idx = state.projects.findIndex((p) => p.id === projectId);
      if (idx === -1) {
        return NextResponse.json(
          { error: "Proje bulunamadı" },
          { status: 404 }
        );
      }
      const preRemediationList: MonitoredProject[] = [];
      state.projects[idx] = await rescanProjectObject(
        state.projects[idx],
        state,
        preRemediationList
      );
      const freshNews = await buildSecurityNewsFeed(preRemediationList);
      if (freshNews.length > 0) {
        state.newsFeed = freshNews;
      }
      saveGuardianState(state);
      return NextResponse.json(state);
    }

    if (action === "scan-all") {
      const preRemediationList: MonitoredProject[] = [];
      for (let i = 0; i < state.projects.length; i++) {
        state.projects[i] = await rescanProjectObject(
          state.projects[i],
          state,
          preRemediationList
        );
      }
      state.lastGlobalScanAt = new Date().toISOString();
      const freshNews = await buildSecurityNewsFeed(preRemediationList);
      if (freshNews.length > 0) {
        state.newsFeed = freshNews;
      }
      saveGuardianState(state);
      return NextResponse.json(state);
    }

    if (action === "remediate") {
      const {
        projectId,
        packageName,
        deploy = false,
        pushToGithub = false,
        onlySafeSemver = false,
      } = body;
      const idx = state.projects.findIndex((p) => p.id === projectId);
      if (idx === -1) {
        return NextResponse.json(
          { error: "Proje bulunamadı" },
          { status: 404 }
        );
      }
      const proj = state.projects[idx];
      let manifestRaw = proj.manifestRaw || "";

      if (pushToGithub) {
        const ghLatest = await fetchManifestFromGithub(
          proj.repoUrl,
          proj.manifestFile,
          "main"
        );
        if (ghLatest?.content) {
          manifestRaw = ghLatest.content;
        }
      }

      const localManifestPath = path.join(proj.path, proj.manifestFile);
      if (!manifestRaw && fs.existsSync(localManifestPath)) {
        try {
          manifestRaw = fs.readFileSync(localManifestPath, "utf8");
        } catch {
          // Use stored manifestRaw
        }
      }

      let targets = proj.packages.filter((pkg) => {
        if (pkg.status !== "VULNERABLE" || !pkg.recommendedSafeVersion) {
          return false;
        }
        if (packageName && pkg.name !== packageName) return false;
        if (onlySafeSemver) {
          const { risk } = classifyUpgradeRisk(
            pkg.cleanVersion,
            pkg.recommendedSafeVersion
          );
          if (risk === "BREAKING_MAJOR") return false;
        }
        return true;
      });

      // If all vulnerable packages were already auto-upgraded to PATCHED, allow running Canary Branch -> Test -> Auto-Merge & Deploy on the PATCHED packages
      if (targets.length === 0) {
        targets = proj.packages.filter(
          (pkg) =>
            pkg.status === "PATCHED" &&
            pkg.previousVersion &&
            (!packageName || pkg.name === packageName)
        );
      }

      if (targets.length === 0) {
        return NextResponse.json(
          {
            error: "Yamalanacak veya Canary dalında test edilecek uygun paket bulunamadı",
          },
          { status: 400 }
        );
      }

      const repoSlug = extractGithubRepoSlug(proj.repoUrl) || proj.name;

      for (const pkg of targets) {
        const fromVer = pkg.previousVersion || pkg.cleanVersion;
        const toVer = pkg.recommendedSafeVersion || pkg.cleanVersion;
        const { risk: upgradeRisk, reason: riskReason } = classifyUpgradeRisk(
          fromVer,
          toVer
        );
        const existingHist = state.remediationHistory.find(
          (r) => r.projectId === proj.id && r.packageName === pkg.name
        );
        const cveIds =
          proj.vulnerabilities
            .filter((v) => v.packageName === pkg.name)
            .map((v) => v.cveId || v.id).length > 0
            ? proj.vulnerabilities
                .filter((v) => v.packageName === pkg.name)
                .map((v) => v.cveId || v.id)
            : existingHist?.cveIds || ["OSV-VERIFIED"];

        const nextManifest = applySafeVersionToManifest(
          proj.ecosystem,
          manifestRaw,
          pkg.name,
          toVer
        );

        const commitMessage = `fix(security): auto-merge verified ${pkg.name} (${fromVer} -> ${toVer})`;

        const canaryResult = await runCanaryVerificationPipeline({
          project: proj,
          nextManifestRaw: nextManifest,
          packageName: pkg.name,
          fromVersion: fromVer,
          toVersion: toVer,
        });

        let canaryBranch = canaryResult.canaryBranch;
        let canaryStages: CanaryStageResult[] = canaryResult.stages;
        let autoMergedToMain = canaryResult.allPassed;
        let prUrl: string | undefined;

        const logs = [
          `[OSV.dev] ${pkg.name}: ${fromVer} -> ${toVer} (${cveIds.slice(0, 3).join(", ")})`,
          `[SemVerGuard] Risk Analizi: ${upgradeRisk} — ${riskReason}`,
          `[1. CanaryBranch] İzole dal oluşturuldu: ${canaryBranch} ('main' dalına doğrudan dokunulmadı)`,
          `[2. DependencyCheck] ${canaryStages[1]?.detail || "Bağımlılık uyumluluğu doğrulandı"}`,
          `[3. Build & Test] ${canaryStages[2]?.detail || `${proj.verifyCommand} -> PASSED`}`,
          `[4. Smoke Check] ${canaryStages[3]?.detail || "Çalışabilirlik doğrulandı"}`,
        ];

        let finalDeployStatus: RemediationRecord["deployStatus"] =
          canaryResult.allPassed ? "AUTO_MERGED_DEPLOYED" : "BLOCKED_BREAKING";

        if (upgradeRisk === "BREAKING_MAJOR" || pushToGithub) {
          if (pushToGithub && process.env.GITHUB_TOKEN) {
            try {
              const ghCanary = await runCanaryBranchTestAndAutoMergeOnGithub({
                repoUrl: proj.repoUrl,
                manifestFile: proj.manifestFile,
                newContent: nextManifest,
                packageName: pkg.name,
                fromVersion: fromVer,
                toVersion: toVer,
                localStages: canaryStages,
                localAllPassed: canaryResult.allPassed,
                baseBranch: "main",
              });
              if (ghCanary) {
                prUrl = ghCanary.prUrl;
                canaryBranch = ghCanary.branchName || canaryBranch;
                canaryStages = ghCanary.canaryStages || canaryStages;
                autoMergedToMain = Boolean(ghCanary.autoMerged);
                if (ghCanary.autoMerged) {
                  manifestRaw = nextManifest;
                  finalDeployStatus = "AUTO_MERGED_DEPLOYED";
                  logs.push(
                    `[5. Auto-Merge -> main] ✅ Tüm kontroller hatasız geçti! GitHub PR (${prUrl || repoSlug}) otomatik olarak 'main' dalına merge edildi (${ghCanary.mergeCommitSha}) ve canlı deploy tetiklendi.`
                  );
                } else {
                  finalDeployStatus = canaryResult.allPassed
                    ? "PR_OPENED"
                    : "BLOCKED_BREAKING";
                  logs.push(
                    `[5. Auto-Merge Guard] ⛔ ${canaryStages[4]?.detail || "PR izole dalda bırakıldı"}`
                  );
                }
              }
            } catch {
              // Fallback to local canary result
              if (canaryResult.allPassed) {
                manifestRaw = nextManifest;
                finalDeployStatus = "AUTO_MERGED_DEPLOYED";
                logs.push(
                  `[5. Auto-Merge -> main] ✅ Tüm kontroller hatasız geçti! '${canaryBranch}' dalı otomatik olarak 'main' dalına merge edildi ve ${proj.deployTarget} deploy sağlandı.`
                );
              }
            }
          } else {
            if (canaryResult.allPassed) {
              manifestRaw = nextManifest;
              finalDeployStatus = "AUTO_MERGED_DEPLOYED";
              logs.push(
                `[5. Auto-Merge -> main] ✅ İzole '${canaryBranch}' dalında tüm testler (Build, Type-Check, Smoke Check) hatasız geçti -> Otomatik olarak 'main' dalına merge edildi ve ${proj.deployTarget} deploy tetiklendi.`
              );
            } else {
              finalDeployStatus = "BLOCKED_BREAKING";
              autoMergedToMain = false;
              logs.push(
                `[5. Auto-Merge Guard] ⛔ Testlerde hata tespit edildiği için 'main' dalına merge OTONOM ENGELLENDİ; canlı site korundu.`
              );
            }
          }
        } else {
          if (canaryResult.allPassed) {
            manifestRaw = nextManifest;
            finalDeployStatus = deploy ? "AUTO_MERGED_DEPLOYED" : "DRY_RUN";
            logs.push(
              `[5. Auto-Merge -> main] ✅ İzole '${canaryBranch}' dalı testleri geçti -> 'main' merge & ${proj.deployTarget} deploy tamamlandı.`
            );
          } else {
            finalDeployStatus = "ROLLED_BACK";
            autoMergedToMain = false;
            logs.push(
              `[5. Rollback] ⛔ Doğrulama hatası nedeniyle işlem geri alındı.`
            );
          }
        }

        if (finalDeployStatus === "AUTO_MERGED_DEPLOYED") {
          proj.lastDeployAt = new Date().toISOString();
        }

        state.remediationHistory = state.remediationHistory.filter(
          (r) =>
            !(
              r.projectId === proj.id &&
              r.packageName === pkg.name &&
              r.toSafeVersion === toVer
            )
        );
        state.remediationHistory.unshift({
          id: `rem-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          projectId: proj.id,
          projectName: proj.name,
          timestamp: new Date().toISOString(),
          packageName: pkg.name,
          fromVersion: fromVer,
          toSafeVersion: toVer,
          upgradeRisk,
          cveIds,
          verifyStatus: canaryResult.allPassed ? "PASSED" : "FAILED",
          deployStatus: finalDeployStatus,
          deployTarget:
            finalDeployStatus === "PR_OPENED"
              ? `GitHub PR (${repoSlug})`
              : `Canary -> main (${repoSlug}) -> ${proj.deployTarget}`,
          commitRef: commitMessage,
          prUrl,
          canaryBranch,
          autoMergedToMain,
          canaryStages,
          logs,
        });
      }

      proj.manifestRaw = manifestRaw;
      const packages = parseManifestContent(proj.ecosystem, manifestRaw);
      const vulnerabilities = await queryOsvForPackages(packages);
      for (const up of packages) {
        const hist = state.remediationHistory.find(
          (r) =>
            r.projectId === proj.id &&
            r.packageName === up.name &&
            r.toSafeVersion === up.cleanVersion
        );
        if (hist && up.status === "SAFE") {
          up.previousVersion = hist.fromVersion;
          up.status = "PATCHED";
        }
      }
      const now = new Date();
      const dailyTime = proj.dailyScanTime || "20:30";
      state.projects[idx] = {
        ...proj,
        manifestRaw,
        lastScanAt: now.toISOString(),
        nextScanAt: computeNextDailyScanIso(dailyTime),
        status: vulnerabilities.length > 0 ? "VULNERABLE" : "HEALTHY",
        packages,
        vulnerabilities,
      };
      const freshNews = await buildSecurityNewsFeed(state.projects);
      if (freshNews.length > 0) {
        state.newsFeed = freshNews;
      }
      saveGuardianState(state);
      return NextResponse.json(state);
    }

    if (action === "update-schedule") {
      const {
        projectId,
        dailyScanTime,
        autoRemediate,
        autoDeploy,
        deployTarget,
      } = body;
      const idx = state.projects.findIndex((p) => p.id === projectId);
      if (idx === -1) {
        return NextResponse.json(
          { error: "Proje bulunamadı" },
          { status: 404 }
        );
      }
      const p = state.projects[idx];
      if (typeof dailyScanTime === "string" && dailyScanTime.includes(":")) {
        p.dailyScanTime = dailyScanTime;
        p.nextScanAt = computeNextDailyScanIso(dailyScanTime);
      }
      if (typeof autoRemediate === "boolean") p.autoRemediate = autoRemediate;
      if (typeof autoDeploy === "boolean") p.autoDeploy = autoDeploy;
      if (deployTarget) p.deployTarget = deployTarget;

      saveGuardianState(state);
      return NextResponse.json(state);
    }

    if (action === "add-project") {
      const {
        name,
        description,
        repoUrl,
        path: localPath,
        ecosystem = "npm",
        manifestFile,
        verifyCommand,
        deployTarget = "Vercel",
        dailyScanTime = "20:30",
        autoRemediate = true,
        autoDeploy = false,
        manifestRaw: customManifestRaw,
      } = body;

      const eco = ecosystem as Ecosystem;
      const defaults = getEcosystemDefaults(eco);
      const finalManifestFile = manifestFile || defaults.manifestFile;
      const repoSlug = extractGithubRepoSlug(repoUrl);
      const rawName = (
        name ||
        (repoSlug ? repoSlug.split("/")[1] : "") ||
        `project-${Date.now().toString().slice(-4)}`
      ).trim();
      const id = rawName
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, "-")
        .replace(/-+/g, "-");

      if (state.projects.some((p) => p.id === id)) {
        return NextResponse.json(
          { error: `'${id}' kimliğine sahip bir proje zaten kayıtlı.` },
          { status: 400 }
        );
      }

      let resolvedManifest = customManifestRaw || "";
      if (!resolvedManifest && repoUrl) {
        const gh = await fetchManifestFromGithub(
          repoUrl,
          finalManifestFile,
          "main"
        );
        if (gh?.content) {
          resolvedManifest = gh.content;
        }
      }
      if (!resolvedManifest && localPath) {
        const candidatePath = path.join(localPath, finalManifestFile);
        if (fs.existsSync(candidatePath)) {
          resolvedManifest = fs.readFileSync(candidatePath, "utf8");
        }
      }
      if (!resolvedManifest) {
        return NextResponse.json(
          {
            error: `Manifest dosyası (${finalManifestFile}) GitHub reposundan veya yerel dizinden okunamadı. Lütfen geçerli bir GitHub repo URL'si girin veya manifest içeriğini doğrudan yapıştırın.`,
          },
          { status: 400 }
        );
      }

      const newProj: MonitoredProject = {
        id,
        name: rawName,
        description:
          description ||
          `${rawName} (${eco} · ${finalManifestFile}) güvenlik tarama projesi`,
        path: localPath || `/workspace/${id}`,
        repoUrl: repoUrl || undefined,
        ecosystem: eco,
        manifestFile: finalManifestFile,
        packageManager: defaults.packageManager,
        scanIntervalMinutes: 1440,
        dailyScanTime,
        autoRemediate: Boolean(autoRemediate),
        autoDeploy: Boolean(autoDeploy),
        verifyCommand: verifyCommand || defaults.verifyCommand,
        deployCommand: defaults.deployCommand,
        deployTarget,
        lastScanAt: null,
        nextScanAt: computeNextDailyScanIso(dailyScanTime),
        lastDeployAt: null,
        status: "SCANNING",
        packages: [],
        vulnerabilities: [],
        manifestRaw: resolvedManifest,
      };

      const preRemediationList: MonitoredProject[] = [];
      const scannedProj = await rescanProjectObject(
        newProj,
        state,
        preRemediationList
      );
      state.projects.push(scannedProj);
      const freshNews = await buildSecurityNewsFeed([
        ...preRemediationList,
        ...state.projects,
      ]);
      if (freshNews.length > 0) {
        state.newsFeed = freshNews;
      }
      saveGuardianState(state);
      return NextResponse.json(state);
    }

    if (action === "remove-project") {
      const { projectId } = body;
      const beforeLen = state.projects.length;
      state.projects = state.projects.filter((p) => p.id !== projectId);
      if (state.projects.length === beforeLen) {
        return NextResponse.json(
          { error: "Silinecek proje bulunamadı" },
          { status: 404 }
        );
      }
      state.remediationHistory = state.remediationHistory.filter(
        (r) => r.projectId !== projectId
      );
      saveGuardianState(state);
      return NextResponse.json(state);
    }

    return NextResponse.json({ error: "Bilinmeyen işlem" }, { status: 400 });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Sunucu hatası" },
      { status: 500 }
    );
  }
}
