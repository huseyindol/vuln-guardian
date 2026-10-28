"use client";

import React, { useState, useRef, useMemo, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Clock,
  Package,
  Rocket,
  Terminal,
  Newspaper,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Search,
  ArrowRight,
  Activity,
  Code2,
  FileCode2,
  Smartphone,
  Eye,
  ChevronDown,
  ChevronUp,
  X,
  CalendarClock,
  Plus,
  Trash2,
} from "lucide-react";
import type {
  Ecosystem,
  GuardianState,
  MonitoredProject,
  Severity,
  VulnerabilityItem,
} from "@/lib/types";

interface Props {
  initialState: GuardianState;
}

interface LanguageGroupMeta {
  ecosystem: Ecosystem;
  langTitle: string;
  runtimeLabel: string;
  manifestLabel: string;
  defaultVerify: string;
  accentBorder: string;
  accentBadge: string;
  accentText: string;
}

const LANGUAGE_GROUPS: LanguageGroupMeta[] = [
  {
    ecosystem: "npm",
    langTitle: "TypeScript / Node.js",
    runtimeLabel: "Bun · npm · Next.js",
    manifestLabel: "package.json",
    defaultVerify: "bun run lint && bun run type-check && bun run build",
    accentBorder: "border-sky-500/50",
    accentBadge: "bg-sky-500/15 text-sky-300 border-sky-500/30",
    accentText: "text-sky-400",
  },
  {
    ecosystem: "Maven",
    langTitle: "Java / Spring Boot",
    runtimeLabel: "JVM · Maven",
    manifestLabel: "pom.xml",
    defaultVerify: "./mvnw -q -DskipTests compile",
    accentBorder: "border-amber-500/50",
    accentBadge: "bg-amber-500/15 text-amber-300 border-amber-500/30",
    accentText: "text-amber-400",
  },
  {
    ecosystem: "Pub",
    langTitle: "Dart / Flutter",
    runtimeLabel: "Flutter SDK · Pub",
    manifestLabel: "pubspec.yaml",
    defaultVerify: "flutter analyze --no-fatal-infos && flutter test",
    accentBorder: "border-teal-500/50",
    accentBadge: "bg-teal-500/15 text-teal-300 border-teal-500/30",
    accentText: "text-teal-400",
  },
  {
    ecosystem: "PyPI",
    langTitle: "Python / PyPI",
    runtimeLabel: "Python · pip / uv",
    manifestLabel: "requirements.txt",
    defaultVerify: "pytest -q",
    accentBorder: "border-emerald-500/50",
    accentBadge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    accentText: "text-emerald-400",
  },
  {
    ecosystem: "Go",
    langTitle: "Go Modules",
    runtimeLabel: "Go Toolchain",
    manifestLabel: "go.mod",
    defaultVerify: "go test ./...",
    accentBorder: "border-cyan-500/50",
    accentBadge: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
    accentText: "text-cyan-400",
  },
  {
    ecosystem: "crates.io",
    langTitle: "Rust / Cargo",
    runtimeLabel: "Rust · crates.io",
    manifestLabel: "Cargo.toml",
    defaultVerify: "cargo check && cargo test",
    accentBorder: "border-orange-500/50",
    accentBadge: "bg-orange-500/15 text-orange-300 border-orange-500/30",
    accentText: "text-orange-400",
  },
];

function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "Henüz taranmadı";
  try {
    const d = new Date(iso);
    return d.toLocaleString("tr-TR", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function severityBadgeStyle(sev: Severity): string {
  switch (sev) {
    case "CRITICAL":
      return "bg-[#d83a26]/20 text-[#ff6b57] border-[#d83a26]/50";
    case "HIGH":
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    case "MEDIUM":
      return "bg-sky-500/15 text-sky-300 border-sky-500/40";
    case "LOW":
    default:
      return "bg-zinc-500/15 text-zinc-300 border-zinc-500/40";
  }
}

function buildManifestDiffPreview(
  ecosystem: Ecosystem,
  pkgName: string,
  oldVer: string,
  safeVer: string | null
): string {
  const target = safeVer || "GÜNCEL_SAFE_SÜRÜM";
  if (ecosystem === "Maven") {
    const [groupId, artifactId] = pkgName.includes(":")
      ? pkgName.split(":")
      : ["org.example", pkgName];
    return `<dependency>
  <groupId>${groupId}</groupId>
  <artifactId>${artifactId}</artifactId>
- <version>${oldVer}</version>
+ <version>${target}</version>
</dependency>`;
  }
  if (ecosystem === "Pub") {
    return `dependencies:
-  ${pkgName}: ^${oldVer}
+  ${pkgName}: ^${target}`;
  }
  return `"dependencies / overrides": {
-  "${pkgName}": "^${oldVer}",
+  "${pkgName}": "^${target}"
}`;
}

export default function GuardianDashboard({ initialState }: Props) {
  const [state, setState] = useState<GuardianState>(initialState);
  const [selectedLang, setSelectedLang] = useState<"ALL" | Ecosystem>("ALL");
  const [selectedProjectId, setSelectedProjectId] = useState<string>(
    initialState.projects[0]?.id || "elly-admin"
  );
  const [activeTab, setActiveTab] = useState<
    "vulns" | "packages" | "news" | "logs"
  >("vulns");
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [bannerMessage, setBannerMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  // Expanded vulnerability cards set (by default expand the first 3 so details are immediately visible!)
  const [expandedVulnKeys, setExpandedVulnKeys] = useState<
    Record<string, boolean>
  >({});

  // Modal dialog for full vulnerability inspection (from either Vulns tab or Packages table)
  const detailDialogRef = useRef<HTMLDialogElement | null>(null);
  const [inspectedVulns, setInspectedVulns] = useState<VulnerabilityItem[]>([]);
  const [inspectedPkgName, setInspectedPkgName] = useState<string>("");

  // Modal dialog for adding any GitHub repository or local project
  const addProjectDialogRef = useRef<HTMLDialogElement | null>(null);
  const [newProjEco, setNewProjEco] = useState<Ecosystem>("npm");
  const [newProjRepoUrl, setNewProjRepoUrl] = useState<string>("");
  const [newProjName, setNewProjName] = useState<string>("");
  const [newProjDesc, setNewProjDesc] = useState<string>("");
  const [newProjPath, setNewProjPath] = useState<string>("");
  const [newProjManifestFile, setNewProjManifestFile] =
    useState<string>("package.json");
  const [newProjVerifyCmd, setNewProjVerifyCmd] = useState<string>(
    "bun run lint && bun run type-check && bun run build"
  );
  const [newProjDeployTarget, setNewProjDeployTarget] = useState<
    MonitoredProject["deployTarget"]
  >("Vercel");
  const [newProjDailyTime, setNewProjDailyTime] = useState<string>("20:30");
  const [newProjManifestRaw, setNewProjManifestRaw] = useState<string>("");

  // Filters
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState<string>("ALL");
  const [vulnSearch, setVulnSearch] = useState<string>("");
  const [pkgSearch, setPkgSearch] = useState<string>("");
  const [pkgStatusFilter, setPkgStatusFilter] = useState<
    "ALL" | "VULNERABLE" | "SAFE"
  >("ALL");
  const [pkgSectionFilter, setPkgSectionFilter] = useState<string>("ALL");

  const visibleProjects = useMemo(() => {
    if (selectedLang === "ALL") return state.projects;
    return state.projects.filter((p) => p.ecosystem === selectedLang);
  }, [state.projects, selectedLang]);

  const selectedProject: MonitoredProject = useMemo(() => {
    const inVisible = visibleProjects.find((p) => p.id === selectedProjectId);
    if (inVisible) return inVisible;
    return visibleProjects[0] || state.projects[0];
  }, [visibleProjects, state.projects, selectedProjectId]);

  const languageStats = useMemo(() => {
    return LANGUAGE_GROUPS.filter(
      (lg) =>
        ["npm", "Maven", "Pub"].includes(lg.ecosystem) ||
        state.projects.some((p) => p.ecosystem === lg.ecosystem)
    ).map((lg) => {
      const projs = state.projects.filter((p) => p.ecosystem === lg.ecosystem);
      const pkgCount = projs.reduce((acc, p) => acc + p.packages.length, 0);
      const vulnCount = projs.reduce(
        (acc, p) => acc + p.vulnerabilities.length,
        0
      );
      const critCount = projs.reduce(
        (acc, p) =>
          acc +
          p.vulnerabilities.filter((v) => v.severity === "CRITICAL").length,
        0
      );
      return {
        ...lg,
        projects: projs,
        pkgCount,
        vulnCount,
        critCount,
      };
    });
  }, [state.projects]);

  const filteredVulns = useMemo(() => {
    if (!selectedProject) return [];
    return selectedProject.vulnerabilities.filter((v) => {
      if (vulnSeverityFilter !== "ALL" && v.severity !== vulnSeverityFilter) {
        return false;
      }
      if (vulnSearch.trim()) {
        const q = vulnSearch.toLowerCase();
        return (
          v.packageName.toLowerCase().includes(q) ||
          v.id.toLowerCase().includes(q) ||
          (v.cveId && v.cveId.toLowerCase().includes(q)) ||
          v.summary.toLowerCase().includes(q) ||
          v.details.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [selectedProject, vulnSeverityFilter, vulnSearch]);

  const filteredPackages = useMemo(() => {
    if (!selectedProject) return [];
    return selectedProject.packages.filter((pkg) => {
      if (pkgStatusFilter === "VULNERABLE" && pkg.status !== "VULNERABLE") {
        return false;
      }
      if (pkgStatusFilter === "SAFE" && pkg.status !== "SAFE") {
        return false;
      }
      if (pkgSectionFilter !== "ALL" && pkg.section !== pkgSectionFilter) {
        return false;
      }
      if (pkgSearch.trim()) {
        const q = pkgSearch.toLowerCase();
        return (
          pkg.name.toLowerCase().includes(q) ||
          pkg.cleanVersion.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [selectedProject, pkgStatusFilter, pkgSectionFilter, pkgSearch]);

  const filteredNews = useMemo(() => {
    if (selectedLang === "ALL") return state.newsFeed;
    return state.newsFeed.filter((n) => n.ecosystem === selectedLang);
  }, [state.newsFeed, selectedLang]);

  const remediationCandidatesCount = useMemo(() => {
    if (!selectedProject) return 0;
    return selectedProject.packages.filter(
      (pkg) =>
        pkg.status === "VULNERABLE" &&
        pkg.recommendedSafeVersion &&
        pkg.upgradeRisk !== "BREAKING_MAJOR"
    ).length;
  }, [selectedProject]);

  const breakingMajorCount = useMemo(() => {
    if (!selectedProject) return 0;
    return selectedProject.packages.filter(
      (pkg) =>
        pkg.status === "VULNERABLE" &&
        pkg.recommendedSafeVersion &&
        pkg.upgradeRisk === "BREAKING_MAJOR"
    ).length;
  }, [selectedProject]);

  function openVulnerabilityDetailModal(
    vulns: VulnerabilityItem[],
    pkgTitle: string
  ) {
    setInspectedVulns(vulns);
    setInspectedPkgName(pkgTitle);
    detailDialogRef.current?.showModal();
  }

  function toggleVulnExpand(key: string, defaultOpen: boolean) {
    setExpandedVulnKeys((prev) => {
      const current = prev[key] !== undefined ? prev[key] : defaultOpen;
      return { ...prev, [key]: !current };
    });
  }

  async function callApi(
    payload: Record<string, unknown>,
    loadingKey: string,
    successText?: string
  ) {
    setLoadingAction(loadingKey);
    setBannerMessage(null);
    try {
      const resp = await fetch("/api/guardian", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || "İşlem başarısız oldu");
      }
      setState(data);
      if (successText) {
        setBannerMessage({ type: "success", text: successText });
      }
      return data as GuardianState;
    } catch (err) {
      setBannerMessage({
        type: "error",
        text:
          err instanceof Error ? err.message : "Beklenmeyen bir hata oluştu",
      });
      return null;
    } finally {
      setLoadingAction(null);
    }
  }

  const currentLangMeta =
    LANGUAGE_GROUPS.find((l) => l.ecosystem === selectedProject?.ecosystem) ||
    LANGUAGE_GROUPS[0];

  // Auto-watch for 20:30 scheduled scan and periodic state sync
  useEffect(() => {
    const timer = setInterval(async () => {
      try {
        const nextIso = state.projects[0]?.nextScanAt;
        if (nextIso && Date.now() >= new Date(nextIso).getTime()) {
          const cronResp = await fetch("/api/cron/scan", { cache: "no-store" });
          if (cronResp.ok) {
            const cronData = await cronResp.json();
            if (cronData.state) {
              setState(cronData.state);
              setBannerMessage({
                type: "success",
                text: "⏰ Saat 20:30 Otomatik Günlük Tarama çalıştı — GitHub ve OSV.dev üzerinden tüm Elly zafiyetleri güncellendi!",
              });
              return;
            }
          }
        }
        const r = await fetch("/api/guardian", { cache: "no-store" });
        if (r.ok) {
          const fresh = (await r.json()) as GuardianState;
          if (fresh.lastGlobalScanAt !== state.lastGlobalScanAt) {
            setState(fresh);
          }
        }
      } catch {
        // Ignore transient network poll error
      }
    }, 15000);
    return () => clearInterval(timer);
  }, [state.lastGlobalScanAt, state.projects]);

  return (
    <div className="min-h-screen flex flex-col bg-[#0b0c0e] text-[#f3f4f6]">
      {/* Top Header */}
      <header className="sticky top-0 z-30 border-b border-[#232730] bg-[#0b0c0e]/95 backdrop-blur-md">
        <div className="max-w-[1580px] mx-auto px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-lg bg-[#d83a26] flex items-center justify-center text-white font-bold shadow-sm">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <h1 className="text-lg font-bold tracking-tight text-white">
                  VulnGuardian — Autonomous Security & Deploy Studio
                </h1>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 text-[11px] font-mono font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 rounded">
                  <CalendarClock className="w-3.5 h-3.5" />
                  Otonom Tarama: Her Akşam 20:30
                </span>
              </div>
              <p className="text-xs text-[#9ca3af]">
                Çok Dilli Zafiyet Analizi (TypeScript · Java · Flutter · Python · Go · Rust), Canary Branch Test & Otomatik Main Merge
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#121418] border border-[#232730] text-xs font-mono text-zinc-300">
              <Clock className="w-3.5 h-3.5 text-[#d83a26]" />
              <span>Son Tarama: {formatDateTime(state.lastGlobalScanAt)}</span>
            </div>

            <button
              type="button"
              onClick={() => addProjectDialogRef.current?.showModal()}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-md border border-emerald-500/40 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 transition cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              Yeni Proje / GitHub Repo Ekle
            </button>

            <button
              type="button"
              onClick={() =>
                callApi(
                  { action: "scan-all" },
                  "scan-all",
                  "Kayıtlı tüm projeler canlı OSV.dev veritabanına karşı tarandı ve Safe-Version güncellemeleri doğrulandı."
                )
              }
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-md bg-[#d83a26] hover:bg-[#c0301d] text-white transition disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${
                  loadingAction === "scan-all" ? "animate-spin" : ""
                }`}
              />
              {loadingAction === "scan-all"
                ? "Projeler Taranıyor..."
                : "Tüm Projeleri Şimdi Tara"}
            </button>
          </div>
        </div>
      </header>

      {/* Feedback Banner */}
      {bannerMessage && (
        <div
          className={`border-b px-4 sm:px-6 py-2.5 text-xs font-medium flex items-center justify-between ${
            bannerMessage.type === "success"
              ? "bg-emerald-950/60 border-emerald-500/30 text-emerald-300"
              : "bg-red-950/60 border-[#d83a26]/40 text-red-300"
          }`}
        >
          <div className="max-w-[1580px] mx-auto w-full flex items-center justify-between gap-4">
            <span className="flex items-center gap-2">
              {bannerMessage.type === "success" ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              )}
              {bannerMessage.text}
            </span>
            <button
              type="button"
              onClick={() => setBannerMessage(null)}
              className="text-xs opacity-75 hover:opacity-100 cursor-pointer"
            >
              Kapat
            </button>
          </div>
        </div>
      )}

      {/* Main Content Container */}
      <main className="max-w-[1580px] w-full mx-auto px-4 sm:px-6 py-6 flex-1 flex flex-col gap-6">
        {/* LANGUAGE / STACK & PROJECT SELECTOR CARDS (Üst Birleşik Alan) */}
        <section aria-label="Proje Dillerine Göre Ayrım">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-[#9ca3af]">
              Proje Dillerine & Ekosistemlerine Göre Ayrım (İncelemek İçin Proje Seçin)
            </h2>
            <div className="flex flex-wrap items-center gap-3">
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md border border-[#232730] bg-[#121418] text-[11px] font-mono text-zinc-300">
                <CalendarClock className="w-3.5 h-3.5 text-emerald-400" />
                <span>
                  Otonom Tarama: <strong className="text-emerald-400">Her Akşam 20:30</strong> (Cron: 30 20 * * * TSİ)
                </span>
                <span className="text-zinc-600">·</span>
                <span>
                  Sonraki:{" "}
                  <span className="text-emerald-400">
                    {formatDateTime(selectedProject?.nextScanAt)}
                  </span>
                </span>
              </div>
              {selectedLang !== "ALL" && (
                <button
                  type="button"
                  onClick={() => setSelectedLang("ALL")}
                  className="text-xs font-mono text-[#ff6b57] hover:underline cursor-pointer"
                >
                  Tüm Dilleri Göster (Sıfırla)
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {languageStats.map((lg) => {
              const isSelectedLang = selectedLang === lg.ecosystem;
              return (
                <div
                  key={lg.ecosystem}
                  onClick={() => {
                    const nextLang =
                      selectedLang === lg.ecosystem ? "ALL" : lg.ecosystem;
                    setSelectedLang(nextLang);
                    if (lg.projects[0]) {
                      setSelectedProjectId(lg.projects[0].id);
                    }
                  }}
                  className={`p-4 rounded-xl border transition cursor-pointer flex flex-col justify-between ${
                    isSelectedLang
                      ? `${lg.accentBorder} bg-[#171b24] shadow-md`
                      : "border-[#232730] bg-[#121418] hover:border-[#323846]"
                  }`}
                >
                  <div>
                    <div className="flex items-start justify-between gap-2 pb-2.5 border-b border-[#232730]">
                      <div>
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-mono font-bold rounded border ${lg.accentBadge}`}
                        >
                          {lg.ecosystem === "npm" && (
                            <Code2 className="w-3.5 h-3.5" />
                          )}
                          {lg.ecosystem === "Maven" && (
                            <FileCode2 className="w-3.5 h-3.5" />
                          )}
                          {lg.ecosystem === "Pub" && (
                            <Smartphone className="w-3.5 h-3.5" />
                          )}
                          {lg.langTitle}
                        </span>
                        <span className="block text-[11px] font-mono text-zinc-400 mt-1">
                          {lg.runtimeLabel} · {lg.manifestLabel}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-[#1b1f27] text-zinc-300 border border-[#2c313d]">
                          {lg.projects.length} repo
                        </span>
                      </div>
                    </div>

                    {/* Enriched Project Cards inside this language */}
                    <div
                      className={`mt-3 grid gap-2.5 ${
                        lg.projects.length > 1
                          ? "grid-cols-1 sm:grid-cols-2"
                          : "grid-cols-1"
                      }`}
                    >
                      {lg.projects.map((p) => {
                        const isSelected = selectedProject?.id === p.id;
                        const vulnCount = p.vulnerabilities.length;
                        return (
                          <button
                            key={p.id}
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedLang(lg.ecosystem);
                              setSelectedProjectId(p.id);
                            }}
                            className={`w-full text-left p-2.5 rounded-lg border transition cursor-pointer flex flex-col justify-between ${
                              isSelected
                                ? "border-[#d83a26] bg-[#191d26] shadow-sm ring-1 ring-[#d83a26]/40"
                                : "border-[#232730] bg-[#0b0c0e] hover:border-[#323846]"
                            }`}
                          >
                            <div>
                              <div className="flex items-center justify-between gap-1.5">
                                <span className="font-bold text-xs font-mono text-white truncate">
                                  {p.name}
                                </span>
                                {vulnCount > 0 ? (
                                  <span className="shrink-0 px-1.5 py-0.5 text-[10px] font-mono font-bold rounded bg-[#d83a26]/20 text-[#ff6b57] border border-[#d83a26]/40">
                                    {vulnCount} Zafiyet
                                  </span>
                                ) : (
                                  <span className="shrink-0 px-1.5 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                                    Güvenli
                                  </span>
                                )}
                              </div>
                              <p className="text-[11px] text-[#9ca3af] line-clamp-1 mt-1">
                                {p.description}
                              </p>
                            </div>

                            <div className="mt-2 pt-1.5 border-t border-[#232730]/80 flex items-center justify-between text-[10px] text-zinc-400 font-mono">
                              <span className="text-emerald-400">
                                ⏰ Her Akşam {p.dailyScanTime || "20:30"}
                              </span>
                              <span>{p.packages.length} paket</span>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  <div className="mt-3.5 pt-2.5 border-t border-[#232730] flex items-center justify-between text-xs font-mono">
                    <span className="text-zinc-400">
                      {lg.projects.length} Proje · {lg.pkgCount} Paket
                    </span>
                    {lg.vulnCount > 0 ? (
                      <span className="text-[#ff6b57] font-bold">
                        {lg.vulnCount} Aktif Zafiyet{" "}
                        {lg.critCount > 0 ? `(${lg.critCount} CRIT)` : ""}
                      </span>
                    ) : (
                      <span className="text-emerald-400 font-bold">
                        0 Zafiyet (Güvenli)
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Full-Width Selected Project Inspector */}
        <div className="w-full">
          <section className="w-full flex flex-col gap-5">
            {selectedProject && (
              <>
                {/* Selected Project Header Card */}
                <div className="p-5 rounded-xl border border-[#232730] bg-[#121418]">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <div className="flex flex-wrap items-center gap-2.5">
                        <span
                          className={`px-2.5 py-0.5 text-xs font-mono font-bold rounded border ${currentLangMeta.accentBadge}`}
                        >
                          {currentLangMeta.langTitle}
                        </span>
                        <h2 className="text-xl font-bold text-white">
                          {selectedProject.name}
                        </h2>
                        <span className="px-2 py-0.5 text-xs font-mono rounded bg-[#232730] text-zinc-200">
                          {selectedProject.manifestFile}
                        </span>
                        <span className="px-2 py-0.5 text-xs font-mono rounded border border-[#323846] text-zinc-300">
                          Deploy: {selectedProject.deployTarget}
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs text-[#9ca3af]">
                        {selectedProject.description}
                      </p>
                      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-zinc-400">
                        <span>Dizin: {selectedProject.path}</span>
                        <span>
                          Doğrulama:{" "}
                          <code className="text-zinc-200">
                            {selectedProject.verifyCommand}
                          </code>
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2.5">
                      <button
                        type="button"
                        onClick={() =>
                          callApi(
                            {
                              action: "scan-project",
                              projectId: selectedProject.id,
                            },
                            `scan-${selectedProject.id}`,
                            `${selectedProject.name} (${currentLangMeta.langTitle}) projesi canlı OSV.dev üzerinden yeniden tarandı.`
                          )
                        }
                        disabled={loadingAction !== null}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-md border border-[#323846] bg-[#181b22] hover:bg-[#222630] text-white transition disabled:opacity-50 cursor-pointer"
                      >
                        <RefreshCw
                          className={`w-3.5 h-3.5 ${
                            loadingAction === `scan-${selectedProject.id}`
                              ? "animate-spin"
                              : ""
                          }`}
                        />
                        {selectedProject.name} Şimdi Tara
                      </button>

                      <button
                        type="button"
                        onClick={() =>
                          callApi(
                            {
                              action: "remediate",
                              projectId: selectedProject.id,
                              deploy: true,
                              pushToGithub: false,
                              onlySafeSemver: true,
                            },
                            `remediate-stage-${selectedProject.id}`,
                            `${selectedProject.name} içindeki kırılma riski olmayan (${remediationCandidatesCount} Patch/Minor) paket Safe Versiyona hazırlandı. (${breakingMajorCount} Major güncelleme güvenlik kilidiyle korundu)`
                          )
                        }
                        disabled={
                          loadingAction !== null ||
                          remediationCandidatesCount === 0
                        }
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-md border border-emerald-500/40 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 transition disabled:opacity-40 cursor-pointer"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Uyumlu Olanları Hazırla ({remediationCandidatesCount} Patch/Minor)
                      </button>

                      <button
                        type="button"
                        onClick={() =>
                          callApi(
                            {
                              action: "remediate",
                              projectId: selectedProject.id,
                              deploy: true,
                              pushToGithub: true,
                              onlySafeSemver: false,
                            },
                            `remediate-all-${selectedProject.id}`,
                            `${selectedProject.name}: Tüm zafiyetli paketler (Major dahil) güvenli versiyonlarına çekildi, breaking-change ve site çalışabilirlik kontrolleri tamamlandı ve ayrı PR açılmadan tek seferde 'main' dalına gönderilip deploy tetiklendi!`
                          )
                        }
                        disabled={loadingAction !== null}
                        className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-md bg-emerald-600 hover:bg-emerald-500 text-white transition disabled:opacity-40 cursor-pointer"
                      >
                        <Rocket className="w-3.5 h-3.5" />
                        {loadingAction ===
                        `remediate-all-${selectedProject.id}`
                          ? "Toplu Doğrulama & Gönderim Çalışıyor..."
                          : `Tümünü Safe Versiyona Çek, Doğrula & Tekte Gönder`}
                      </button>

                      {state.projects.length > 1 && (
                        <button
                          type="button"
                          title="Projeyi İzlemeden Kaldır"
                          onClick={async () => {
                            const removedName = selectedProject.name;
                            const nextState = await callApi(
                              {
                                action: "remove-project",
                                projectId: selectedProject.id,
                              },
                              `remove-${selectedProject.id}`,
                              `${removedName} projesi izleme listesinden kaldırıldı.`
                            );
                            if (nextState?.projects[0]) {
                              setSelectedProjectId(nextState.projects[0].id);
                            }
                          }}
                          disabled={loadingAction !== null}
                          className="inline-flex items-center gap-1 px-2.5 py-2 text-xs font-medium rounded-md border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 text-red-300 transition disabled:opacity-40 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Autonomous Canary Branch -> Test -> Auto-Merge Pipeline Banner */}
                  <div className="mt-4 p-3.5 rounded-lg border border-emerald-500/30 bg-[#0b0c0e] flex flex-col gap-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                        <ShieldCheck className="w-4 h-4" />
                        Otonom Canary Branch → 4 Aşamalı Test Kapısı → Otomatik Main Merge & Deploy Sistemi Aktif
                      </span>
                      <span className="text-[11px] font-mono text-zinc-400">
                        Hata Yoksa: Otomatik <code>main</code> Merge + Deploy · Hata Varsa: Otomatik Rollback & PR Kilidi
                      </span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-[11px] font-mono">
                      <div className="p-2 rounded bg-[#121418] border border-[#232730] text-zinc-200">
                        <span className="text-emerald-400 font-bold block">1. İzole Canary Dalı</span>
                        <code>security/canary-*</code> açılır, <code>main</code> korunur
                      </div>
                      <div className="p-2 rounded bg-[#121418] border border-[#232730] text-zinc-200">
                        <span className="text-emerald-400 font-bold block">2. Peer & Manifest</span>
                        SemVer ve bağımlılık ağacı çakışma testi
                      </div>
                      <div className="p-2 rounded bg-[#121418] border border-[#232730] text-zinc-200">
                        <span className="text-emerald-400 font-bold block">3. Build & Type-Check</span>
                        <code>{selectedProject.verifyCommand}</code>
                      </div>
                      <div className="p-2 rounded bg-[#121418] border border-[#232730] text-zinc-200">
                        <span className="text-emerald-400 font-bold block">4. Smoke & OSV Kontrolü</span>
                        Canlı OSV 0-zafiyet ve sağlık kontrolü
                      </div>
                      <div className="p-2 rounded bg-[#121418] border border-emerald-500/40 text-emerald-300">
                        <span className="font-bold block">5. Auto-Merge & Deploy</span>
                        Hatasızsa <code>main</code> merge + {selectedProject.deployTarget}
                      </div>
                    </div>
                  </div>

                  {/* Schedule Bar */}
                  <div className="mt-4 pt-4 border-t border-[#232730] grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 text-xs">
                    <div className="p-2.5 rounded bg-[#0b0c0e] border border-[#232730] flex items-center justify-between">
                      <div>
                        <span className="block text-[11px] text-[#9ca3af]">
                          Günlük Tarama Saati (TSİ)
                        </span>
                        <input
                          type="time"
                          aria-label="Günlük Tarama Saati"
                          value={selectedProject.dailyScanTime || "20:30"}
                          onChange={(e) =>
                            callApi(
                              {
                                action: "update-schedule",
                                projectId: selectedProject.id,
                                dailyScanTime: e.target.value,
                              },
                              "update-schedule",
                              `${selectedProject.name} günlük tarama saati Her Akşam ${e.target.value} olarak güncellendi.`
                            )
                          }
                          className="mt-1 bg-transparent font-mono font-bold text-emerald-400 focus:outline-none cursor-pointer"
                        />
                      </div>
                      <CalendarClock className="w-4 h-4 text-emerald-400" />
                    </div>

                    <div className="p-2.5 rounded bg-[#0b0c0e] border border-[#232730] flex flex-col justify-center">
                      <span className="text-[11px] text-[#9ca3af]">
                        Sonraki Otomatik Tarama (20:30)
                      </span>
                      <div className="mt-1 font-mono font-semibold text-emerald-400">
                        {formatDateTime(selectedProject.nextScanAt)}
                      </div>
                    </div>

                    <div className="p-2.5 rounded bg-[#0b0c0e] border border-[#232730] flex items-center justify-between">
                      <div>
                        <span className="block text-[11px] text-[#9ca3af]">
                          Otonom Safe-Version Yama
                        </span>
                        <span className="mt-1 block font-mono font-semibold text-white">
                          {selectedProject.autoRemediate ? "AKTİF" : "MANUEL"}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          callApi(
                            {
                              action: "update-schedule",
                              projectId: selectedProject.id,
                              autoRemediate: !selectedProject.autoRemediate,
                            },
                            "toggle-remediate"
                          )
                        }
                        className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold transition cursor-pointer ${
                          selectedProject.autoRemediate
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                            : "bg-zinc-800 text-zinc-400 border border-zinc-700"
                        }`}
                      >
                        {selectedProject.autoRemediate ? "AÇIK" : "KAPALI"}
                      </button>
                    </div>

                    <div className="p-2.5 rounded bg-[#0b0c0e] border border-[#232730] flex items-center justify-between">
                      <div>
                        <span className="block text-[11px] text-[#9ca3af]">
                          Yama Sonrası Oto-Deploy
                        </span>
                        <span className="mt-1 block font-mono font-semibold text-white">
                          {selectedProject.autoDeploy
                            ? `AKTİF (${selectedProject.deployTarget})`
                            : "ONAY BEKLER"}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          callApi(
                            {
                              action: "update-schedule",
                              projectId: selectedProject.id,
                              autoDeploy: !selectedProject.autoDeploy,
                            },
                            "toggle-deploy"
                          )
                        }
                        className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold transition cursor-pointer ${
                          selectedProject.autoDeploy
                            ? "bg-[#d83a26]/25 text-[#ff6b57] border border-[#d83a26]/50"
                            : "bg-zinc-800 text-zinc-400 border border-zinc-700"
                        }`}
                      >
                        {selectedProject.autoDeploy ? "AÇIK" : "KAPALI"}
                      </button>
                    </div>
                  </div>
                </div>

                {/* Navigation Tabs */}
                <div className="border-b border-[#232730] flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setActiveTab("vulns")}
                    className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition flex items-center gap-2 cursor-pointer ${
                      activeTab === "vulns"
                        ? "border-[#d83a26] text-white"
                        : "border-transparent text-[#9ca3af] hover:text-white"
                    }`}
                  >
                    <ShieldAlert className="w-4 h-4" />
                    Zafiyet Listesi & Tam Teknik Detaylar
                    <span className="px-1.5 py-0.5 text-[11px] font-mono rounded bg-[#232730] text-white">
                      {selectedProject.vulnerabilities.length}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab("packages")}
                    className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition flex items-center gap-2 cursor-pointer ${
                      activeTab === "packages"
                        ? "border-[#d83a26] text-white"
                        : "border-transparent text-[#9ca3af] hover:text-white"
                    }`}
                  >
                    <Package className="w-4 h-4" />
                    Projedeki Paketler & Versiyonlar ({selectedProject.manifestFile})
                    <span className="px-1.5 py-0.5 text-[11px] font-mono rounded bg-[#232730] text-white">
                      {selectedProject.packages.length}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab("news")}
                    className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition flex items-center gap-2 cursor-pointer ${
                      activeTab === "news"
                        ? "border-[#d83a26] text-white"
                        : "border-transparent text-[#9ca3af] hover:text-white"
                    }`}
                  >
                    <Newspaper className="w-4 h-4" />
                    Zafiyet Haberleri ({selectedLang === "ALL" ? "Tüm Diller" : currentLangMeta.langTitle})
                    <span className="px-1.5 py-0.5 text-[11px] font-mono rounded bg-[#232730] text-white">
                      {filteredNews.length}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab("logs")}
                    className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition flex items-center gap-2 cursor-pointer ${
                      activeTab === "logs"
                        ? "border-[#d83a26] text-white"
                        : "border-transparent text-[#9ca3af] hover:text-white"
                    }`}
                  >
                    <Activity className="w-4 h-4" />
                    Yama & Deploy Geçmişi
                    <span className="px-1.5 py-0.5 text-[11px] font-mono rounded bg-[#232730] text-white">
                      {state.remediationHistory.length}
                    </span>
                  </button>
                </div>

                {/* TAB 1: VULNERABILITIES WITH FULL EXPANDABLE DETAILS & DIFF */}
                {activeTab === "vulns" && (
                  <div className="flex flex-col gap-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="relative flex-1 min-w-[240px]">
                        <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          value={vulnSearch}
                          onChange={(e) => setVulnSearch(e.target.value)}
                          placeholder="CVE kodu, GHSA ID, paket adı (örn. next, dompurify, jsoup, pgjdbc) veya teknik detay ara..."
                          className="w-full pl-9 pr-3 py-2 text-xs rounded-md bg-[#121418] border border-[#232730] text-white placeholder:text-zinc-500 focus:outline-none focus:border-[#d83a26]"
                        />
                      </div>

                      <div className="flex items-center gap-1.5 text-xs">
                        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(
                          (sev) => (
                            <button
                              key={sev}
                              type="button"
                              onClick={() => setVulnSeverityFilter(sev)}
                              className={`px-2.5 py-1.5 rounded font-mono text-[11px] font-semibold transition cursor-pointer ${
                                vulnSeverityFilter === sev
                                  ? "bg-[#d83a26] text-white"
                                  : "bg-[#121418] border border-[#232730] text-zinc-400 hover:text-white"
                              }`}
                            >
                              {sev === "ALL" ? "Tümü" : sev}
                            </button>
                          )
                        )}
                      </div>
                    </div>

                    {filteredVulns.length === 0 ? (
                      <div className="flex flex-col gap-4">
                        <div className="p-8 rounded-xl border border-emerald-500/30 bg-[#121418] text-center">
                          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
                          <h3 className="mt-3 text-base font-bold text-white">
                            {selectedProject.vulnerabilities.length === 0
                              ? `${selectedProject.name} (${currentLangMeta.langTitle}) Tüm Paketler Safe Versiyonda ve Güvenli!`
                              : "Filtreyle Eşleşen Zafiyet Bulunamadı"}
                          </h3>
                          <p className="mt-1 text-xs text-[#9ca3af] max-w-lg mx-auto">
                            Otonom tarama sırasında tespit edilen zafiyetli paketler SemVer Breaking-Change kontrolünden geçirilerek en yakın güvenli (Safe) sürümlerine yükseltildi.
                          </p>
                        </div>

                        {/* Show recently auto-patched packages for this project right here! */}
                        {state.remediationHistory.filter(
                          (r) => r.projectId === selectedProject.id
                        ).length > 0 && (
                          <div className="flex flex-col gap-3">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 px-1">
                              ✅ {selectedProject.name} — Otonom Safe Versiyona Çekilen Paketler & Kapatılan Zafiyetler
                            </h4>
                            {state.remediationHistory
                              .filter((r) => r.projectId === selectedProject.id)
                              .map((rec) => (
                                <div
                                  key={rec.id}
                                  className="p-4 rounded-xl border border-emerald-500/30 bg-[#121418] flex flex-col gap-2.5"
                                >
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                                        ✓ SAFE VERSİYONA ÇEKİLDİ ({rec.upgradeRisk || "SAFE_PATCH"})
                                      </span>
                                      {rec.canaryBranch && (
                                        <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
                                          🌿 {rec.canaryBranch} → {rec.autoMergedToMain ? "main (AUTO-MERGED)" : "PR AÇIK"}
                                        </span>
                                      )}
                                      <span className="font-mono text-sm font-bold text-white">
                                        {rec.packageName}
                                      </span>
                                      <span className="px-2 py-0.5 text-xs font-mono rounded bg-red-500/15 text-red-300 line-through">
                                        {rec.fromVersion}
                                      </span>
                                      <ArrowRight className="w-3.5 h-3.5 text-zinc-400" />
                                      <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                                        {rec.toSafeVersion}
                                      </span>
                                    </div>
                                    <span className="text-xs font-mono text-zinc-400">
                                      {formatDateTime(rec.timestamp)}
                                    </span>
                                  </div>
                                  <div className="text-xs font-mono text-zinc-300">
                                    Kapatılan Zafiyetler (CVE / GHSA):{" "}
                                    <span className="text-[#ff6b57] font-semibold">
                                      {rec.cveIds.join(", ")}
                                    </span>
                                  </div>
                                  {rec.canaryStages && rec.canaryStages.length > 0 && (
                                    <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 pt-1">
                                      {rec.canaryStages.map((st) => (
                                        <div
                                          key={st.stage}
                                          className={`p-2 rounded border text-[11px] font-mono ${
                                            st.status === "PASSED"
                                              ? "bg-emerald-950/30 border-emerald-500/30 text-emerald-200"
                                              : "bg-red-950/30 border-red-500/40 text-red-200"
                                          }`}
                                        >
                                          <div className="font-bold flex items-center justify-between">
                                            <span>{st.label}</span>
                                            <span>{st.status === "PASSED" ? "✓" : "✕"}</span>
                                          </div>
                                          <p className="mt-1 text-[10px] text-zinc-300 leading-snug">
                                            {st.detail}
                                          </p>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                  <pre className="p-2.5 rounded bg-[#0b0c0e] border border-[#232730] text-[11px] font-mono text-emerald-300/90 overflow-x-auto">
                                    {rec.logs.join("\n")}
                                  </pre>
                                </div>
                              ))}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="flex flex-col gap-4">
                        {filteredVulns.map((v, idx) => {
                          const vulnKey = `${v.id}-${v.packageName}`;
                          const defaultOpen = idx < 3;
                          const isOpen =
                            expandedVulnKeys[vulnKey] !== undefined
                              ? expandedVulnKeys[vulnKey]
                              : defaultOpen;

                          return (
                            <div
                              key={vulnKey}
                              className="rounded-xl border border-[#282d39] bg-[#121418] overflow-hidden flex flex-col"
                            >
                              {/* Card Top Bar */}
                              <div className="p-4 flex flex-wrap items-start justify-between gap-3 bg-[#151820] border-b border-[#232730]">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span
                                    className={`px-2.5 py-0.5 text-xs font-mono font-bold rounded border ${severityBadgeStyle(
                                      v.severity
                                    )}`}
                                  >
                                    {v.severity} · CVSS {v.cvssScore.toFixed(1)}
                                  </span>

                                  <span className="font-mono text-xs font-bold text-white bg-[#0b0c0e] px-2.5 py-0.5 rounded border border-[#2c313d]">
                                    {v.cveId || v.id}
                                  </span>

                                  {v.cveId && v.id !== v.cveId && (
                                    <span className="font-mono text-xs text-zinc-300 bg-[#1b1f27] px-2 py-0.5 rounded">
                                      GHSA: {v.id}
                                    </span>
                                  )}

                                  {v.cweIds &&
                                    v.cweIds.map((cwe) => (
                                      <span
                                        key={cwe}
                                        className="font-mono text-[11px] text-amber-300 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded"
                                      >
                                        {cwe}
                                      </span>
                                    ))}

                                  <span
                                    className={`px-2 py-0.5 text-[11px] font-mono rounded border ${currentLangMeta.accentBadge}`}
                                  >
                                    {v.ecosystem} · {v.dependencySection}
                                  </span>

                                  {v.upgradeRisk === "SAFE_PATCH" && (
                                    <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                                      🟢 SAFE PATCH (Kırılma Yok)
                                    </span>
                                  )}
                                  {v.upgradeRisk === "MINOR_VERIFY" && (
                                    <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
                                      🟡 MINOR (SemVer Uyumlu)
                                    </span>
                                  )}
                                  {v.upgradeRisk === "BREAKING_MAJOR" && (
                                    <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-red-500/20 text-red-300 border border-red-500/50">
                                      ⛔ MAJOR BREAKING (Main Push Kilitli)
                                    </span>
                                  )}
                                </div>

                                <div className="flex flex-wrap items-center gap-2">
                                  <button
                                    type="button"
                                    onClick={() =>
                                      openVulnerabilityDetailModal(
                                        [v],
                                        `${v.packageName} (${v.cveId || v.id})`
                                      )
                                    }
                                    className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded border border-[#323846] bg-[#0b0c0e] hover:bg-[#1c2029] text-zinc-200 cursor-pointer"
                                  >
                                    <Eye className="w-3.5 h-3.5 text-sky-400" />
                                    Tam Rapor Penceresi
                                  </button>

                                  {v.fixedVersion &&
                                    (v.upgradeRisk === "BREAKING_MAJOR" ? (
                                      <button
                                        type="button"
                                        onClick={() =>
                                          callApi(
                                            {
                                              action: "remediate",
                                              projectId: selectedProject.id,
                                              packageName: v.packageName,
                                              deploy: false,
                                              pushToGithub: true,
                                            },
                                            `rem-pr-${selectedProject.id}-${v.packageName}`,
                                            `${v.packageName} (${v.installedVersion} -> ${v.fixedVersion}) Major güncellemesi için main dalına dokunulmadan izole GitHub Pull Request açıldı!`
                                          )
                                        }
                                        disabled={loadingAction !== null}
                                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded border border-amber-500/50 bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 transition disabled:opacity-50 cursor-pointer"
                                        title="Major sürüm geçişi siteyi kırabileceği için doğrudan main dalına basılmaz; izole PR açılır."
                                      >
                                        <AlertTriangle className="w-3.5 h-3.5" />
                                        {loadingAction ===
                                        `rem-pr-${selectedProject.id}-${v.packageName}`
                                          ? "İzole PR Açılıyor..."
                                          : `İzole PR Aç (${v.fixedVersion} · Major Guard)`}
                                      </button>
                                    ) : (
                                      <>
                                        <button
                                          type="button"
                                          onClick={() =>
                                            callApi(
                                              {
                                                action: "remediate",
                                                projectId: selectedProject.id,
                                                packageName: v.packageName,
                                                deploy: true,
                                                pushToGithub: false,
                                              },
                                              `rem-stage-${selectedProject.id}-${v.packageName}`,
                                              `${v.packageName} paketi ${v.installedVersion} -> ${v.fixedVersion} safe versiyonuna hazırlandı.`
                                            )
                                          }
                                          disabled={loadingAction !== null}
                                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold rounded border border-emerald-500/40 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 transition disabled:opacity-50 cursor-pointer"
                                        >
                                          Hazırla ({v.fixedVersion})
                                        </button>
                                        <button
                                          type="button"
                                          onClick={() =>
                                            callApi(
                                              {
                                                action: "remediate",
                                                projectId: selectedProject.id,
                                                packageName: v.packageName,
                                                deploy: true,
                                                pushToGithub: true,
                                              },
                                              `rem-${selectedProject.id}-${v.packageName}`,
                                              `${v.packageName} paketi ${v.installedVersion} -> ${v.fixedVersion} safe versiyonuna çekildi ve GitHub'a pushlanarak sunucu deploy tetiklendi!`
                                            )
                                          }
                                          disabled={loadingAction !== null}
                                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-emerald-600 hover:bg-emerald-500 text-white transition disabled:opacity-50 cursor-pointer"
                                        >
                                          <Rocket className="w-3.5 h-3.5" />
                                          {loadingAction ===
                                          `rem-${selectedProject.id}-${v.packageName}`
                                            ? "GitHub'a Pushlanıyor..."
                                            : `Safe Versiyona Çek & GitHub'a Pushla`}
                                        </button>
                                      </>
                                    ))}
                                </div>
                              </div>

                              {/* Title & Version Transition Strip */}
                              <div className="p-4 flex flex-col gap-3">
                                <div className="flex flex-wrap items-start justify-between gap-2">
                                  <h3 className="text-base font-bold text-white">
                                    {v.summary}
                                  </h3>
                                  <button
                                    type="button"
                                    onClick={() =>
                                      toggleVulnExpand(vulnKey, defaultOpen)
                                    }
                                    className="inline-flex items-center gap-1 text-xs font-mono text-sky-400 hover:underline cursor-pointer shrink-0"
                                  >
                                    {isOpen ? (
                                      <>
                                        Detayı Gizle{" "}
                                        <ChevronUp className="w-3.5 h-3.5" />
                                      </>
                                    ) : (
                                      <>
                                        Zafiyet Detayını Göster{" "}
                                        <ChevronDown className="w-3.5 h-3.5" />
                                      </>
                                    )}
                                  </button>
                                </div>

                                {/* Package & Version Comparison */}
                                <div className="p-3 rounded-lg bg-[#0b0c0e] border border-[#232730] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
                                  <div>
                                    <span className="text-zinc-400 block text-[11px]">
                                      Etkilenen Paket
                                    </span>
                                    <span className="text-white font-bold">
                                      {v.packageName}
                                    </span>
                                  </div>
                                  <div>
                                    <span className="text-zinc-400 block text-[11px]">
                                      Zafiyetli Versiyon Aralığı
                                    </span>
                                    <span className="text-amber-300">
                                      {v.affectedRangeText ||
                                        `<= ${v.installedVersion}`}
                                    </span>
                                  </div>
                                  <div>
                                    <span className="text-zinc-400 block text-[11px]">
                                      Projedeki Mevcut Versiyon
                                    </span>
                                    <span className="text-red-400 font-bold">
                                      {v.installedVersion}
                                    </span>
                                  </div>
                                  <div>
                                    <span className="text-zinc-400 block text-[11px]">
                                      Önerilen Safe (Yamalı) Versiyon
                                    </span>
                                    <span className="text-emerald-400 font-bold">
                                      {v.fixedVersion || "İnceleniyor"}
                                    </span>
                                  </div>
                                </div>

                                {/* SemVer Breaking-Change Risk Banner */}
                                {v.upgradeRiskReason && (
                                  <div
                                    className={`px-3 py-2 rounded text-xs font-mono border ${
                                      v.upgradeRisk === "BREAKING_MAJOR"
                                        ? "bg-red-950/40 border-red-500/40 text-red-200"
                                        : v.upgradeRisk === "MINOR_VERIFY"
                                          ? "bg-sky-950/30 border-sky-500/30 text-sky-200"
                                          : "bg-emerald-950/30 border-emerald-500/30 text-emerald-200"
                                    }`}
                                  >
                                    🛡️ {v.upgradeRiskReason}
                                  </div>
                                )}

                                {/* EXPANDED TECHNICAL DETAILS & MANIFEST DIFF */}
                                {isOpen && (
                                  <div className="mt-1 flex flex-col gap-3 pt-3 border-t border-[#232730]">
                                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                                      {/* Full Technical Advisory Text */}
                                      <div className="lg:col-span-2 p-3.5 rounded-lg bg-[#0b0c0e] border border-[#232730]">
                                        <div className="flex items-center justify-between mb-2">
                                          <span className="text-xs font-bold uppercase tracking-wider text-zinc-300">
                                            Zafiyetin Teknik Detayı & Etki Analizi (OSV / GHSA)
                                          </span>
                                          {v.cvssVector && (
                                            <span className="text-[11px] font-mono text-zinc-400">
                                              {v.cvssVector}
                                            </span>
                                          )}
                                        </div>
                                        <div className="text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap font-sans max-h-[320px] overflow-y-auto pr-2">
                                          {v.details || v.summary}
                                        </div>
                                      </div>

                                      {/* Manifest Patch Preview + References */}
                                      <div className="p-3.5 rounded-lg bg-[#0b0c0e] border border-[#232730] flex flex-col justify-between gap-3">
                                        <div>
                                          <span className="text-xs font-bold uppercase tracking-wider text-zinc-300 block mb-2">
                                            Otomatik Yama Önizlemesi ({selectedProject.manifestFile})
                                          </span>
                                          <pre className="p-2.5 rounded bg-[#121418] border border-[#232730] text-[11px] font-mono text-emerald-300 overflow-x-auto">
                                            {buildManifestDiffPreview(
                                              v.ecosystem,
                                              v.packageName,
                                              v.installedVersion,
                                              v.fixedVersion
                                            )}
                                          </pre>
                                        </div>

                                        <div>
                                          <span className="text-[11px] font-bold uppercase tracking-wider text-zinc-400 block mb-1.5">
                                            Resmi Bülten & Kaynak Bağlantıları
                                          </span>
                                          <div className="flex flex-col gap-1">
                                            <a
                                              href={`https://osv.dev/vulnerability/${v.id}`}
                                              target="_blank"
                                              rel="noreferrer"
                                              className="text-xs font-mono text-sky-400 hover:underline flex items-center gap-1 truncate"
                                            >
                                              <ExternalLink className="w-3 h-3 shrink-0" />
                                              https://osv.dev/vulnerability/{v.id}
                                            </a>
                                            {v.references.slice(0, 3).map((refUrl) => (
                                              <a
                                                key={refUrl}
                                                href={refUrl}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="text-xs font-mono text-zinc-400 hover:text-white hover:underline flex items-center gap-1 truncate"
                                              >
                                                <ExternalLink className="w-3 h-3 shrink-0" />
                                                {refUrl}
                                              </a>
                                            ))}
                                          </div>
                                        </div>
                                      </div>
                                    </div>

                                    <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-zinc-400">
                                      <span>
                                        Alias Kayıtları:{" "}
                                        {v.aliases.length > 0
                                          ? v.aliases.join(", ")
                                          : v.id}
                                      </span>
                                      <span>
                                        Yayınlanma:{" "}
                                        {formatDateTime(v.publishedAt)} · Son
                                        Güncelleme:{" "}
                                        {formatDateTime(v.modifiedAt)}
                                      </span>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}

                {/* TAB 2: PACKAGES & VERSIONS INVENTORY (responsive-table) */}
                {activeTab === "packages" && (
                  <div className="flex flex-col gap-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="relative flex-1 min-w-[240px]">
                        <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          value={pkgSearch}
                          onChange={(e) => setPkgSearch(e.target.value)}
                          placeholder="Paket adı veya versiyon ara (örn. next, jsoup, postgresql, 16.3.8)..."
                          className="w-full pl-9 pr-3 py-2 text-xs rounded-md bg-[#121418] border border-[#232730] text-white placeholder:text-zinc-500 focus:outline-none focus:border-[#d83a26]"
                        />
                      </div>

                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <select
                          aria-label="Kategori Filtresi"
                          value={pkgSectionFilter}
                          onChange={(e) => setPkgSectionFilter(e.target.value)}
                          className="px-3 py-1.5 rounded bg-[#121418] border border-[#232730] text-zinc-300 font-mono text-xs"
                        >
                          <option value="ALL">Tüm Kategoriler</option>
                          <option value="dependencies">dependencies</option>
                          <option value="devDependencies">devDependencies</option>
                          <option value="overrides">overrides</option>
                          <option value="maven">maven (pom.xml)</option>
                          <option value="pubspec">pubspec.yaml</option>
                        </select>

                        {(["ALL", "VULNERABLE", "SAFE"] as const).map((st) => (
                          <button
                            key={st}
                            type="button"
                            onClick={() => setPkgStatusFilter(st)}
                            className={`px-2.5 py-1.5 rounded font-mono text-[11px] font-semibold transition cursor-pointer ${
                              pkgStatusFilter === st
                                ? "bg-[#d83a26] text-white"
                                : "bg-[#121418] border border-[#232730] text-zinc-400 hover:text-white"
                            }`}
                          >
                            {st === "ALL"
                              ? "Tümü"
                              : st === "VULNERABLE"
                                ? "Zafiyetli"
                                : "Güvenli"}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div
                      tabIndex={0}
                      role="region"
                      aria-labelledby="project-packages-caption"
                      className="table-wrapper"
                    >
                      <table>
                        <caption
                          id="project-packages-caption"
                          className="sr-only"
                        >
                          {selectedProject.name} projesi paket ve versiyon listesi
                        </caption>
                        <thead>
                          <tr>
                            <th scope="col">Paket Adı</th>
                            <th scope="col">Kategori</th>
                            <th scope="col">Mevcut Versiyon</th>
                            <th scope="col">Önerilen Safe Versiyon</th>
                            <th scope="col">Zafiyet & Detay</th>
                            <th scope="col">Aksiyon</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredPackages.map((pkg) => {
                            const pkgVulns =
                              selectedProject.vulnerabilities.filter(
                                (v) => v.packageName === pkg.name
                              );
                            return (
                              <tr key={`${pkg.section}:${pkg.name}`}>
                                <th scope="row" className="font-mono text-xs">
                                  {pkg.name}
                                </th>
                                <td className="font-mono text-xs text-zinc-400">
                                  {pkg.section}
                                </td>
                                <td className="font-mono text-xs">
                                  {pkg.previousVersion && (
                                    <>
                                      <span className="px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 line-through mr-1.5">
                                        {pkg.previousVersion}
                                      </span>
                                      <span className="text-zinc-500 mr-1.5">→</span>
                                    </>
                                  )}
                                  <span
                                    className={`px-2 py-0.5 rounded ${
                                      pkg.status === "VULNERABLE"
                                        ? "bg-red-500/15 text-red-300 border border-red-500/30"
                                        : pkg.previousVersion
                                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold"
                                          : "bg-[#1b1f27] text-zinc-200"
                                    }`}
                                  >
                                    {pkg.cleanVersion}
                                  </span>
                                  {pkg.rawSpec !== pkg.cleanVersion && (
                                    <span className="ml-1.5 text-[11px] text-zinc-400">
                                      ({pkg.rawSpec})
                                    </span>
                                  )}
                                </td>
                                <td className="font-mono text-xs">
                                  {pkg.recommendedSafeVersion ? (
                                    <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold">
                                      {pkg.recommendedSafeVersion}
                                    </span>
                                  ) : (
                                    <span className="text-zinc-400">—</span>
                                  )}
                                </td>
                                <td>
                                  {pkg.status === "VULNERABLE" ? (
                                    <button
                                      type="button"
                                      onClick={() =>
                                        openVulnerabilityDetailModal(
                                          pkgVulns,
                                          `${pkg.name}@${pkg.cleanVersion}`
                                        )
                                      }
                                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono font-bold rounded bg-[#d83a26]/20 text-[#ff6b57] border border-[#d83a26]/40 hover:bg-[#d83a26]/30 cursor-pointer"
                                    >
                                      <Eye className="w-3 h-3" />
                                      {pkg.vulnerabilityCount} Zafiyet Detayını Gör
                                    </button>
                                  ) : (
                                    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono font-semibold rounded bg-emerald-500/15 text-emerald-400">
                                      Güvenli
                                    </span>
                                  )}
                                </td>
                                <td>
                                  {pkg.status === "VULNERABLE" &&
                                  pkg.recommendedSafeVersion ? (
                                    <button
                                      type="button"
                                      onClick={() =>
                                        callApi(
                                          {
                                            action: "remediate",
                                            projectId: selectedProject.id,
                                            packageName: pkg.name,
                                            deploy: true,
                                          },
                                          `pkg-rem-${pkg.name}`,
                                          `${pkg.name} paketi ${pkg.recommendedSafeVersion} safe versiyonuna yükseltildi!`
                                        )
                                      }
                                      disabled={loadingAction !== null}
                                      className="px-2.5 py-1 text-xs font-semibold rounded bg-emerald-600 hover:bg-emerald-500 text-white transition cursor-pointer"
                                    >
                                      Safe Versiyona Çek
                                    </button>
                                  ) : (
                                    <span className="text-xs text-zinc-400 font-mono">
                                      Doğrulandı
                                    </span>
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* TAB 3: LIVE VULNERABILITY NEWS & ADVISORIES */}
                {activeTab === "news" && (
                  <div className="flex flex-col gap-3">
                    <div className="p-3.5 rounded-lg border border-[#232730] bg-[#121418] flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs text-[#9ca3af]">
                        Elly Studio projelerinin kullandığı dillerle eşleşen canlı OSV.dev & GitHub Security Advisory bültenleri:
                      </div>
                      <div className="flex items-center gap-1.5 text-xs font-mono">
                        {(["ALL", "npm", "Maven", "Pub"] as const).map((ec) => (
                          <button
                            key={ec}
                            type="button"
                            onClick={() => setSelectedLang(ec)}
                            className={`px-2.5 py-1 rounded cursor-pointer ${
                              selectedLang === ec
                                ? "bg-[#d83a26] text-white font-bold"
                                : "bg-[#0b0c0e] border border-[#232730] text-zinc-400"
                            }`}
                          >
                            {ec === "ALL"
                              ? "Tüm Diller"
                              : ec === "npm"
                                ? "TypeScript (npm)"
                                : ec === "Maven"
                                  ? "Java (Maven)"
                                  : "Flutter (Pub)"}
                          </button>
                        ))}
                      </div>
                    </div>

                    {filteredNews.map((item) => (
                      <article
                        key={item.id}
                        className="p-4 rounded-xl border border-[#232730] bg-[#121418] hover:border-[#323846] transition flex flex-col gap-3"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`px-2 py-0.5 text-[11px] font-mono font-bold rounded border ${severityBadgeStyle(
                                item.severity
                              )}`}
                            >
                              {item.severity} · CVSS {item.cvssScore.toFixed(1)}
                            </span>
                            <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-[#0b0c0e] text-white border border-[#2c313d]">
                              {item.cveId || item.id}
                            </span>
                            <span className="px-2 py-0.5 text-xs font-mono rounded bg-[#232730] text-zinc-200">
                              {item.ecosystem} · {item.affectedPackage}
                            </span>
                          </div>

                          <div className="flex items-center gap-2 text-xs font-mono">
                            <span className="text-red-300">
                              Zafiyetli: {item.vulnerableRange}
                            </span>
                            <ArrowRight className="w-3.5 h-3.5 text-zinc-500" />
                            <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold">
                              Safe: {item.safeVersion}
                            </span>
                            <a
                              href={item.url}
                              target="_blank"
                              rel="noreferrer"
                              className="p-1.5 rounded border border-[#2c313d] bg-[#181b22] hover:bg-[#222630] text-zinc-300"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          </div>
                        </div>

                        <h3 className="text-sm font-bold text-white">
                          {item.title}
                        </h3>
                        <div className="p-3 rounded bg-[#0b0c0e] border border-[#232730] text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap max-h-40 overflow-y-auto">
                          {item.details || item.summary}
                        </div>

                        <div className="pt-2 border-t border-[#232730]/80 flex flex-wrap items-center justify-between gap-2 text-xs">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="text-zinc-400">
                              Etkilenen Elly Projeleri:
                            </span>
                            {item.impactedProjectIds.map((pid) => (
                              <button
                                key={pid}
                                type="button"
                                onClick={() => {
                                  setSelectedProjectId(pid);
                                  setActiveTab("vulns");
                                }}
                                className="px-2 py-0.5 text-[11px] font-mono font-semibold rounded bg-[#d83a26]/20 text-[#ff6b57] border border-[#d83a26]/40 hover:bg-[#d83a26]/30 cursor-pointer"
                              >
                                {pid} (Detay & Yama →)
                              </button>
                            ))}
                          </div>
                          <span className="text-zinc-400 font-mono">
                            Kaynak: {item.source} ·{" "}
                            {formatDateTime(item.publishedAt)}
                          </span>
                        </div>
                      </article>
                    ))}
                  </div>
                )}

                {/* TAB 4: REMEDIATION LOGS */}
                {activeTab === "logs" && (
                  <div className="flex flex-col gap-4">
                    <div className="p-4 rounded-xl border border-[#232730] bg-[#121418] flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-bold text-white flex items-center gap-2">
                          <Terminal className="w-4 h-4 text-[#d83a26]" />
                          Elly Studio Otonom Safe-Version Yama & Deploy Kayıtları
                        </h3>
                        <p className="text-xs text-[#9ca3af] mt-0.5">
                          Uygulanan her safe-version yükseltmesi, doğrulama testi ve deploy çıktısı aşağıda kayıtlıdır.
                        </p>
                      </div>
                    </div>

                    {state.remediationHistory.map((rec) => (
                      <div
                        key={rec.id}
                        className="p-4 rounded-xl border border-[#232730] bg-[#121418] flex flex-col gap-3"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                              {rec.deployStatus}
                            </span>
                            {rec.canaryBranch && (
                              <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
                                🌿 {rec.canaryBranch} → {rec.autoMergedToMain ? "main (AUTO-MERGED)" : "PR AÇIK"}
                              </span>
                            )}
                            <span className="font-semibold text-sm text-white">
                              {rec.projectName}
                            </span>
                            <span className="font-mono text-xs text-zinc-300">
                              {rec.packageName}: {rec.fromVersion} →{" "}
                              <strong className="text-emerald-400">
                                {rec.toSafeVersion}
                              </strong>
                            </span>
                          </div>
                          <span className="text-xs font-mono text-zinc-400">
                            {formatDateTime(rec.timestamp)} · Hedef:{" "}
                            {rec.deployTarget}
                          </span>
                        </div>

                        <div className="text-xs font-mono text-zinc-400">
                          Commit:{" "}
                          <code className="text-zinc-200">{rec.commitRef}</code>{" "}
                          | Kapatılan CVE:{" "}
                          <span className="text-[#ff6b57]">
                            {rec.cveIds.slice(0, 6).join(", ")}
                          </span>
                        </div>

                        {rec.canaryStages && rec.canaryStages.length > 0 && (
                          <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
                            {rec.canaryStages.map((st) => (
                              <div
                                key={st.stage}
                                className={`p-2 rounded border text-[11px] font-mono ${
                                  st.status === "PASSED"
                                    ? "bg-emerald-950/30 border-emerald-500/30 text-emerald-200"
                                    : "bg-red-950/30 border-red-500/40 text-red-200"
                                }`}
                              >
                                <div className="font-bold flex items-center justify-between">
                                  <span>{st.label}</span>
                                  <span>{st.status === "PASSED" ? "✓" : "✕"}</span>
                                </div>
                                <p className="mt-1 text-[10px] text-zinc-300 leading-snug">
                                  {st.detail}
                                </p>
                              </div>
                            ))}
                          </div>
                        )}

                        <pre className="p-3 rounded bg-[#0b0c0e] border border-[#232730] text-[11px] font-mono text-emerald-300/90 overflow-x-auto">
                          {rec.logs.join("\n")}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </section>
        </div>
      </main>

      {/* Native Modal Dialog for Full Vulnerability Details (Modern Web Guidance: prevent-page-scroll-under-modal-dialog) */}
      <dialog
        ref={detailDialogRef}
        className="m-auto w-full max-w-3xl rounded-xl border border-[#323846] bg-[#121418] text-[#f3f4f6] p-0 shadow-2xl"
      >
        <div className="p-6 flex flex-col gap-4 max-h-[85vh] overflow-y-auto">
          <div className="flex items-center justify-between border-b border-[#232730] pb-3">
            <div>
              <h2 className="text-base font-bold text-white">
                Zafiyet Teknik Raporu: {inspectedPkgName}
              </h2>
              <p className="text-xs text-[#9ca3af]">
                OSV.dev, GitHub Security Advisories (GHSA) ve NVD CVE tam kapsamlı zafiyet analizi
              </p>
            </div>
            <button
              type="button"
              onClick={() => detailDialogRef.current?.close()}
              className="p-1.5 rounded hover:bg-[#232730] text-zinc-400 hover:text-white cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex flex-col gap-4">
            {inspectedVulns.map((v) => (
              <div
                key={v.id}
                className="p-4 rounded-lg border border-[#282d39] bg-[#0b0c0e] flex flex-col gap-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`px-2 py-0.5 text-xs font-mono font-bold rounded border ${severityBadgeStyle(
                        v.severity
                      )}`}
                    >
                      {v.severity} · CVSS {v.cvssScore.toFixed(1)}
                    </span>
                    <span className="font-mono text-xs font-bold text-white">
                      {v.cveId || v.id}
                    </span>
                    {v.cweIds?.map((cwe) => (
                      <span
                        key={cwe}
                        className="px-2 py-0.5 text-[11px] font-mono rounded bg-amber-500/15 text-amber-300"
                      >
                        {cwe}
                      </span>
                    ))}
                  </div>

                  {v.fixedVersion && (
                    <button
                      type="button"
                      onClick={async () => {
                        await callApi(
                          {
                            action: "remediate",
                            projectId: selectedProject.id,
                            packageName: v.packageName,
                            deploy: true,
                          },
                          `modal-rem-${v.packageName}`,
                          `${v.packageName} paketi ${v.fixedVersion} safe versiyonuna çekildi!`
                        );
                        detailDialogRef.current?.close();
                      }}
                      className="px-3 py-1.5 text-xs font-semibold rounded bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer"
                    >
                      Safe Versiyona Çek ({v.fixedVersion}) & Deploy
                    </button>
                  )}
                </div>

                <h3 className="text-sm font-bold text-white">{v.summary}</h3>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 p-2.5 rounded bg-[#121418] border border-[#232730] text-xs font-mono">
                  <div>
                    <span className="text-zinc-400 block text-[10px]">
                      Etkilenen Aralık
                    </span>
                    <span className="text-amber-300">
                      {v.affectedRangeText || `<= ${v.installedVersion}`}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-400 block text-[10px]">
                      Mevcut Versiyon
                    </span>
                    <span className="text-red-400 font-bold">
                      {v.installedVersion}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-400 block text-[10px]">
                      Safe Versiyon
                    </span>
                    <span className="text-emerald-400 font-bold">
                      {v.fixedVersion || "İnceleniyor"}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-zinc-200 leading-relaxed whitespace-pre-wrap font-sans p-3 rounded bg-[#121418] border border-[#232730]">
                  {v.details || v.summary}
                </div>

                <div>
                  <span className="text-[11px] font-bold uppercase tracking-wider text-zinc-400 block mb-1">
                    Manifest Yama Önizlemesi
                  </span>
                  <pre className="p-2.5 rounded bg-[#121418] border border-[#232730] text-[11px] font-mono text-emerald-300 overflow-x-auto">
                    {buildManifestDiffPreview(
                      v.ecosystem,
                      v.packageName,
                      v.installedVersion,
                      v.fixedVersion
                    )}
                  </pre>
                </div>

                <div className="flex flex-wrap gap-2 pt-2 border-t border-[#232730] text-xs font-mono">
                  {v.references.map((url) => (
                    <a
                      key={url}
                      href={url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-sky-400 hover:underline flex items-center gap-1"
                    >
                      <ExternalLink className="w-3 h-3" />
                      {url}
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </dialog>

      {/* Native Modal Dialog for Adding Any GitHub Repository or Local Project */}
      <dialog
        ref={addProjectDialogRef}
        className="m-auto w-full max-w-2xl rounded-xl border border-[#323846] bg-[#121418] text-[#f3f4f6] p-0 shadow-2xl"
      >
        <div className="p-6 flex flex-col gap-4 max-h-[85vh] overflow-y-auto">
          <div className="flex items-center justify-between border-b border-[#232730] pb-3">
            <div>
              <h2 className="text-base font-bold text-white">
                + Yeni Proje veya GitHub Reposu Ekle
              </h2>
              <p className="text-xs text-[#9ca3af]">
                Herhangi bir GitHub reposunu veya yerel projeyi (TypeScript/Node.js, Java/Maven, Flutter/Pub, Python/PyPI, Go, Rust) otonom taramaya ekleyin
              </p>
            </div>
            <button
              type="button"
              onClick={() => addProjectDialogRef.current?.close()}
              className="p-1.5 rounded hover:bg-[#232730] text-zinc-400 hover:text-white cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="sm:col-span-2">
              <label className="block font-semibold text-zinc-200 mb-1">
                1. Proje Dili / Ekosistem Seçin
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {LANGUAGE_GROUPS.map((lg) => (
                  <button
                    key={lg.ecosystem}
                    type="button"
                    onClick={() => {
                      setNewProjEco(lg.ecosystem);
                      setNewProjManifestFile(lg.manifestLabel);
                      setNewProjVerifyCmd(lg.defaultVerify);
                    }}
                    className={`p-2.5 rounded-lg border text-left font-mono transition cursor-pointer ${
                      newProjEco === lg.ecosystem
                        ? `${lg.accentBorder} bg-[#1b202b] text-white`
                        : "border-[#232730] bg-[#0b0c0e] text-zinc-400 hover:text-white"
                    }`}
                  >
                    <span className="font-bold block text-xs">
                      {lg.langTitle}
                    </span>
                    <span className="text-[10px] text-zinc-400">
                      {lg.manifestLabel}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            <div className="sm:col-span-2">
              <label className="block font-semibold text-zinc-200 mb-1">
                2. GitHub Repo URL&apos;si (Public veya GITHUB_TOKEN ile Private)
              </label>
              <input
                type="url"
                value={newProjRepoUrl}
                onChange={(e) => {
                  const val = e.target.value;
                  setNewProjRepoUrl(val);
                  const slug = val
                    .replace(/^https?:\/\/github\.com\//i, "")
                    .replace(/\.git$/i, "")
                    .replace(/\/$/, "");
                  if (!newProjName && slug.includes("/")) {
                    setNewProjName(slug.split("/")[1] || "");
                  }
                }}
                placeholder="https://github.com/kullanici/proje-adi"
                className="w-full px-3 py-2 rounded bg-[#0b0c0e] border border-[#2c313d] text-white font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block font-semibold text-zinc-200 mb-1">
                Proje Adı
              </label>
              <input
                type="text"
                value={newProjName}
                onChange={(e) => setNewProjName(e.target.value)}
                placeholder="örn. api-service"
                className="w-full px-3 py-2 rounded bg-[#0b0c0e] border border-[#2c313d] text-white font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block font-semibold text-zinc-200 mb-1">
                Manifest Dosyası Adı
              </label>
              <input
                type="text"
                value={newProjManifestFile}
                onChange={(e) => setNewProjManifestFile(e.target.value)}
                placeholder="package.json / pom.xml / requirements.txt"
                className="w-full px-3 py-2 rounded bg-[#0b0c0e] border border-[#2c313d] text-white font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block font-semibold text-zinc-200 mb-1">
                Canary Test / Doğrulama Komutu
              </label>
              <input
                type="text"
                value={newProjVerifyCmd}
                onChange={(e) => setNewProjVerifyCmd(e.target.value)}
                className="w-full px-3 py-2 rounded bg-[#0b0c0e] border border-[#2c313d] text-white font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block font-semibold text-zinc-200 mb-1">
                Günlük Tarama Saati & Deploy Hedefi
              </label>
              <div className="flex gap-2">
                <input
                  type="time"
                  value={newProjDailyTime}
                  onChange={(e) => setNewProjDailyTime(e.target.value)}
                  className="px-2.5 py-2 rounded bg-[#0b0c0e] border border-[#2c313d] text-emerald-400 font-mono text-xs"
                />
                <select
                  value={newProjDeployTarget}
                  onChange={(e) =>
                    setNewProjDeployTarget(
                      e.target.value as MonitoredProject["deployTarget"]
                    )
                  }
                  className="flex-1 px-2.5 py-2 rounded bg-[#0b0c0e] border border-[#2c313d] text-white font-mono text-xs"
                >
                  <option value="Vercel">Vercel</option>
                  <option value="Kubernetes / Server">Kubernetes / Server</option>
                  <option value="GitHub Actions">GitHub Actions</option>
                  <option value="Local / Dry-Run">Local / Dry-Run</option>
                </select>
              </div>
            </div>

            <div className="sm:col-span-2">
              <label className="block font-semibold text-zinc-200 mb-1">
                Yerel Dizin Yolu (İsteğe Bağlı) veya Açıklama
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <input
                  type="text"
                  value={newProjPath}
                  onChange={(e) => setNewProjPath(e.target.value)}
                  placeholder="/path/to/local/repo (İsteğe bağlı)"
                  className="w-full px-3 py-2 rounded bg-[#0b0c0e] border border-[#2c313d] text-white font-mono text-xs"
                />
                <input
                  type="text"
                  value={newProjDesc}
                  onChange={(e) => setNewProjDesc(e.target.value)}
                  placeholder="Proje açıklaması (İsteğe bağlı)"
                  className="w-full px-3 py-2 rounded bg-[#0b0c0e] border border-[#2c313d] text-white text-xs"
                />
              </div>
            </div>

            <div className="sm:col-span-2">
              <label className="block font-semibold text-zinc-200 mb-1">
                Manifest İçeriğini Doğrudan Yapıştır (İsteğe Bağlı — GitHub URL yoksa)
              </label>
              <textarea
                rows={4}
                value={newProjManifestRaw}
                onChange={(e) => setNewProjManifestRaw(e.target.value)}
                placeholder="GitHub URL girdiyseniz otomatik çekilir; dilerseniz package.json / pom.xml / requirements.txt içeriğini buraya doğrudan yapıştırabilirsiniz..."
                className="w-full p-2.5 rounded bg-[#0b0c0e] border border-[#2c313d] text-zinc-200 font-mono text-[11px] focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#232730]">
            <button
              type="button"
              onClick={() => addProjectDialogRef.current?.close()}
              className="px-3.5 py-2 text-xs font-medium rounded border border-[#323846] text-zinc-300 hover:text-white cursor-pointer"
            >
              İptal
            </button>
            <button
              type="button"
              disabled={loadingAction === "add-project"}
              onClick={async () => {
                const updated = await callApi(
                  {
                    action: "add-project",
                    name: newProjName,
                    description: newProjDesc,
                    repoUrl: newProjRepoUrl,
                    path: newProjPath,
                    ecosystem: newProjEco,
                    manifestFile: newProjManifestFile,
                    verifyCommand: newProjVerifyCmd,
                    deployTarget: newProjDeployTarget,
                    dailyScanTime: newProjDailyTime,
                    autoRemediate: true,
                    manifestRaw: newProjManifestRaw || undefined,
                  },
                  "add-project",
                  `Yeni proje (${newProjName || newProjRepoUrl}) eklendi, OSV.dev üzerinden tarandı ve Safe-Version analizi tamamlandı!`
                );
                if (updated) {
                  const lastAdded =
                    updated.projects[updated.projects.length - 1];
                  if (lastAdded) {
                    setSelectedLang("ALL");
                    setSelectedProjectId(lastAdded.id);
                  }
                  setNewProjRepoUrl("");
                  setNewProjName("");
                  setNewProjDesc("");
                  setNewProjPath("");
                  setNewProjManifestRaw("");
                  addProjectDialogRef.current?.close();
                }
              }}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded bg-emerald-600 hover:bg-emerald-500 text-white transition disabled:opacity-50 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              {loadingAction === "add-project"
                ? "Taranıyor ve Ekleniyor..."
                : "Projeyi Ekle, OSV.dev İle Tara & Koruma Altına Al"}
            </button>
          </div>
        </div>
      </dialog>
    </div>
  );
}
