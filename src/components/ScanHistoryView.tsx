"use client";

import React, { useState, useMemo, useEffect, useRef } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  CalendarClock,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ArrowLeft,
  ExternalLink,
  Search,
  FileText,
  Wrench,
  Lock,
  Unlock,
  LogOut,
  Plus,
  Sparkles,
  Layers,
  Package,
} from "lucide-react";
import type {
  GuardianState,
  ScanHistoryEntry,
  ScanOutcomeStatus,
  Severity,
} from "@/lib/types";

interface Props {
  initialState: GuardianState;
}

const KNOWN_CVE_META: Record<
  string,
  { severity: Severity; cvss: number; url?: string; title?: string }
> = {
  "GHSA-2464-fhr4-w9xw": {
    severity: "CRITICAL",
    cvss: 9.4,
    url: "https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw",
    title: "Next.js Unauthenticated RCE in Image Optimization API",
  },
  "GHSA-673q-mjm6-r5xr": {
    severity: "CRITICAL",
    cvss: 9.4,
    url: "https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr",
    title: "Next.js Server Actions / Middleware Authorization Bypass",
  },
  "CVE-2026-94482": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/vercel/next.js/security/advisories/GHSA-p3m5-59mp-jv5r",
    title: "Next.js Cache Poisoning / SSRF Vulnerability",
  },
  "CVE-2026-116804": {
    severity: "CRITICAL",
    cvss: 9.4,
    url: "https://github.com/cure53/DOMPurify/security/advisories/GHSA-cg2g-xh64-v4q7",
    title: "DOMPurify SAFE_FOR_TEMPLATES Shadow Root Bypass",
  },
  "CVE-2026-116803": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/cure53/DOMPurify/security/advisories/GHSA-mrv2-3pqr-j5jr",
    title: "DOMPurify mXSS Sanitization Bypass",
  },
  "CVE-2026-116802": {
    severity: "HIGH",
    cvss: 7.8,
    url: "https://nvd.nist.gov/vuln/detail/CVE-2026-116802",
    title: "DOMPurify DOM Clobbering Bypass",
  },
  "GHSA-mmhx-hmjr-r674": {
    severity: "HIGH",
    cvss: 7.5,
    url: "https://github.com/advisories/GHSA-mmhx-hmjr-r674",
    title: "DOMPurify Mutation XSS Vulnerability",
  },
  "CVE-2026-112948": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://nvd.nist.gov/vuln/detail/CVE-2026-112948",
    title: "@vitest/ui Arbitrary File Read / WebSocket Origin Bypass",
  },
  "CVE-2026-102990": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/patrickjuchli/basic-ftp/security/advisories/GHSA-c475-qrg2-pj4r",
    title: "basic-ftp Path Traversal / Command Injection",
  },
  "CVE-2026-112942": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/vitejs/launch-editor/security/advisories/GHSA-587h-7wmj-h5pm",
    title: "Vite launch-editor OS Command Injection Bypass",
  },
  "CVE-2023-54404": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://nvd.nist.gov/vuln/detail/CVE-2023-54404",
    title: "Zod Uncontrolled Resource Consumption (DoS)",
  },
  "CVE-2026-33671": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/micromatch/picomatch/security/advisories/GHSA-c2c7-rcm5-vvqj",
    title: "picomatch ReDoS via extglob quantifiers",
  },
  "CVE-2026-4800": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/lodash/lodash/security/advisories/GHSA-r5fr-rjxr-66jc",
    title: "lodash Prototype Pollution",
  },
  "CVE-2026-4926": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/pillarjs/path-to-regexp/security/advisories/GHSA-j3q9-mxjg-w52f",
    title: "path-to-regexp Catastrophic Backtracking ReDoS",
  },
  "CVE-2026-114111": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/lovell/sharp/security/advisories/GHSA-wq5f-xc86-pv6w",
    title: "sharp Heap Buffer Overflow in Image Processing",
  },
  "CVE-2026-67213": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://nvd.nist.gov/vuln/detail/CVE-2026-67213",
    title: "nanoid Predictable PRNG Seed / Collision Issue",
  },
  "CVE-2026-33228": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/WebReflection/flatted/security/advisories/GHSA-rf6f-7fwh-wjgh",
    title: "flatted Prototype Pollution / DoS",
  },
  "CVE-2026-111181": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/expressjs/body-parser/security/advisories/GHSA-27r3-jxmh-p828",
    title: "body-parser Asymmetric Payload DoS",
  },
  "CVE-2026-110816": {
    severity: "HIGH",
    cvss: 7.5,
    url: "https://nvd.nist.gov/vuln/detail/CVE-2026-110816",
    title: "qs Deep Object Nesting Denial of Service",
  },
  "CVE-2026-75140": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://nvd.nist.gov/vuln/detail/CVE-2026-75140",
    title: "org.jsoup:jsoup HTML Parser XSS / DoS",
  },
  "CVE-2026-42198": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-98qh-xjc8-98pq",
    title: "PostgreSQL JDBC Driver SQL Injection",
  },
  "CVE-2025-49146": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-hq9p-pm7w-8p54",
    title: "PostgreSQL JDBC Authentication Channel Binding Bypass",
  },
  "CVE-2026-54291": {
    severity: "HIGH",
    cvss: 8.1,
    url: "https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-j92g-9f8w-j867",
    title: "PostgreSQL JDBC Driver Protocol Stream Injection",
  },
  "CVE-2025-48924": {
    severity: "HIGH",
    cvss: 7.5,
    url: "https://nvd.nist.gov/vuln/detail/CVE-2025-48924",
    title: "Apache Commons Lang3 Uncontrolled Recursion",
  },
};

function buildAdvisoryUrl(code: string): string {
  if (code.startsWith("GHSA-")) {
    return `https://github.com/advisories/${encodeURIComponent(code)}`;
  }
  if (code.startsWith("CVE-")) {
    return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(code)}`;
  }
  return `https://osv.dev/vulnerability/${encodeURIComponent(code)}`;
}

function formatFullTurkishDay(dateKeyOrIso: string): string {
  try {
    const d = dateKeyOrIso.length === 10
      ? new Date(`${dateKeyOrIso}T12:00:00+03:00`)
      : new Date(dateKeyOrIso);
    return d.toLocaleDateString("tr-TR", {
      weekday: "long",
      day: "numeric",
      month: "long",
      year: "numeric",
      timeZone: "Europe/Istanbul",
    });
  } catch {
    return dateKeyOrIso;
  }
}

function formatTimeOnly(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString("tr-TR", {
      hour: "2-digit",
      minute: "2-digit",
      timeZone: "Europe/Istanbul",
    });
  } catch {
    return iso;
  }
}

function formatRelativeDayLabel(iso: string): string {
  try {
    const now = new Date();
    const target = new Date(iso);
    const diffMs = now.getTime() - target.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 2) return "Az önce tarandı";
    if (diffMins < 60) return `${diffMins} dakika önce`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `Bugün · ${diffHours} saat önce`;
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays === 1) return "Dün tarandı";
    return `${diffDays} gün önce`;
  } catch {
    return "";
  }
}

function CveLinkChip({ code, state }: { code: string; state: GuardianState }) {
  if (
    code === "PEER-LOCKSTEP-SYNC" ||
    code === "PEER-SYNC" ||
    code === "GITHUB-SYNC" ||
    code === "OSV-VERIFIED"
  ) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
        🔗 {code}
      </span>
    );
  }

  const newsMatch = state.newsFeed.find(
    (n) => n.cveId === code || n.id === code
  );
  const meta = KNOWN_CVE_META[code];
  const severity: Severity =
    newsMatch?.severity || meta?.severity || "HIGH";
  const cvss = newsMatch?.cvssScore || meta?.cvss || 7.8;
  const url = newsMatch?.url || meta?.url || buildAdvisoryUrl(code);
  const sevLabel =
    severity === "CRITICAL"
      ? "KRİTİK"
      : severity === "HIGH"
        ? "YÜKSEK"
        : severity === "MEDIUM"
          ? "ORTA"
          : "DÜŞÜK";

  const colorStyle =
    severity === "CRITICAL"
      ? "bg-[#d83a26]/20 text-[#ff6b57] border-[#d83a26]/50"
      : severity === "HIGH"
        ? "bg-amber-500/15 text-amber-300 border-amber-500/40"
        : "bg-sky-500/15 text-sky-300 border-sky-500/40";

  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      title={`${meta?.title || code} · Resmi güvenlik bültenini yeni sekmede aç`}
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-mono rounded border transition hover:brightness-125 ${colorStyle}`}
    >
      <span className="font-bold underline decoration-current/40 underline-offset-2">
        {code}
      </span>
      <span className="px-1 py-0.2 text-[9px] font-bold rounded bg-black/35 uppercase">
        {sevLabel} · {cvss.toFixed(1)}
      </span>
      <ExternalLink className="w-2.5 h-2.5 opacity-80 shrink-0" aria-hidden="true" />
    </a>
  );
}

export default function ScanHistoryView({ initialState }: Props) {
  const [state, setState] = useState<GuardianState>(initialState);
  const [outcomeFilter, setOutcomeFilter] = useState<"ALL" | ScanOutcomeStatus>(
    "ALL"
  );
  const [projectFilter, setProjectFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [loadingScan, setLoadingScan] = useState<boolean>(false);
  const [banner, setBanner] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  // Admin auth state & modal
  const authDialogRef = useRef<HTMLDialogElement | null>(null);
  const noteDialogRef = useRef<HTMLDialogElement | null>(null);
  const [authState, setAuthState] = useState<{
    authenticated: boolean;
    user: string | null;
    ownerHint: string;
  }>({
    authenticated: false,
    user: null,
    ownerHint: "@huseyindol",
  });
  const [authTab, setAuthTab] = useState<"github" | "password">("github");
  const [loginGithubToken, setLoginGithubToken] = useState<string>("");
  const [loginPassword, setLoginPassword] = useState<string>("");
  const [authLoading, setAuthLoading] = useState<boolean>(false);
  const [authError, setAuthError] = useState<string | null>(null);

  // Daily note editor state
  const [editingEntryId, setEditingEntryId] = useState<string>("");
  const [editingNoteText, setEditingNoteText] = useState<string>("");
  const [savingNote, setSavingNote] = useState<boolean>(false);

  useEffect(() => {
    fetch("/api/auth", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) {
          setAuthState({
            authenticated: Boolean(d.authenticated),
            user: d.user || null,
            ownerHint: d.ownerHint || "@huseyindol",
          });
        }
      })
      .catch(() => {});
  }, []);

  // Auto-watch for overdue 20:30 scheduled scan and periodic state sync on /history
  useEffect(() => {
    let cancelled = false;
    async function checkAndSyncScheduledScan() {
      try {
        const nextIso = state.projects[0]?.nextScanAt;
        if (nextIso && Date.now() >= new Date(nextIso).getTime()) {
          const cronResp = await fetch("/api/cron/scan", { cache: "no-store" });
          if (cronResp.ok) {
            const cronData = await cronResp.json();
            if (!cancelled && cronData.state) {
              setState(cronData.state);
              setBanner({
                type: "success",
                text: "⏰ Saat 20:30 Otomatik Günlük Tarama çalıştı — yeni günlük tarama raporu geçmişe eklendi.",
              });
              return;
            }
          }
        }
        const r = await fetch("/api/guardian", { cache: "no-store" });
        if (r.ok) {
          const fresh = (await r.json()) as GuardianState;
          if (!cancelled && fresh.lastGlobalScanAt !== state.lastGlobalScanAt) {
            setState(fresh);
          }
        }
      } catch {
        // Ignore transient network error
      }
    }

    void checkAndSyncScheduledScan();
    const timer = setInterval(checkAndSyncScheduledScan, 20000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [state.lastGlobalScanAt, state.projects]);

  const scanHistory: ScanHistoryEntry[] = useMemo(() => {
    return state.scanHistory || [];
  }, [state.scanHistory]);

  const latestScan: ScanHistoryEntry | null = scanHistory[0] || null;

  const filteredEntries = useMemo(() => {
    return scanHistory.filter((entry) => {
      if (outcomeFilter !== "ALL" && entry.outcome !== outcomeFilter) {
        return false;
      }
      if (projectFilter !== "ALL") {
        const hasProj =
          entry.projectSummaries.some((p) => p.projectId === projectFilter) ||
          entry.findings.some((f) => f.projectId === projectFilter) ||
          entry.fixes.some((f) => f.projectId === projectFilter);
        if (!hasProj) return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const inTitle =
          entry.verdictTitle.toLowerCase().includes(q) ||
          entry.dailyNote.toLowerCase().includes(q) ||
          entry.triggerLabel.toLowerCase().includes(q) ||
          entry.dateKey.toLowerCase().includes(q);
        const inNotes = entry.notes.some((n) => n.toLowerCase().includes(q));
        const inFindings = entry.findings.some(
          (f) =>
            f.packageName.toLowerCase().includes(q) ||
            f.projectName.toLowerCase().includes(q) ||
            f.cveIds.some((c) => c.toLowerCase().includes(q))
        );
        const inFixes = entry.fixes.some(
          (f) =>
            f.packageName.toLowerCase().includes(q) ||
            f.projectName.toLowerCase().includes(q) ||
            f.cveIds.some((c) => c.toLowerCase().includes(q))
        );
        return inTitle || inNotes || inFindings || inFixes;
      }
      return true;
    });
  }, [scanHistory, outcomeFilter, projectFilter, searchQuery]);

  // Group filtered entries by dateKey (YYYY-MM-DD)
  const groupedByDay = useMemo(() => {
    const map = new Map<string, ScanHistoryEntry[]>();
    for (const entry of filteredEntries) {
      const key = entry.dateKey || entry.timestamp.slice(0, 10);
      const list = map.get(key) || [];
      list.push(entry);
      map.set(key, list);
    }
    return Array.from(map.entries()).map(([dateKey, entries]) => {
      const totalDetected = entries.reduce(
        (acc, e) => acc + e.detectedVulnCount,
        0
      );
      const totalFixed = entries.reduce(
        (acc, e) => acc + e.fixedPackageCount,
        0
      );
      const totalRemaining = entries[0]?.remainingVulnCount || 0;
      return {
        dateKey,
        dayTitle: formatFullTurkishDay(dateKey),
        entries,
        totalDetected,
        totalFixed,
        totalRemaining,
        primaryNote: entries[0]?.dailyNote || "",
      };
    });
  }, [filteredEntries]);

  const totalHistoricalFixes = useMemo(
    () => scanHistory.reduce((acc, e) => acc + e.fixedPackageCount, 0),
    [scanHistory]
  );

  const totalHistoricalCvesDetected = useMemo(
    () => scanHistory.reduce((acc, e) => acc + e.detectedVulnCount, 0),
    [scanHistory]
  );

  async function handleRunFullScan() {
    if (!authState.authenticated) {
      setAuthError(null);
      authDialogRef.current?.showModal();
      return;
    }
    setLoadingScan(true);
    setBanner(null);
    try {
      const resp = await fetch("/api/guardian", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "scan-all" }),
      });
      const data = await resp.json();
      if (resp.status === 401 || data.requiresAuth) {
        authDialogRef.current?.showModal();
        return;
      }
      if (!resp.ok) {
        throw new Error(data.error || "Tarama başlatılamadı");
      }
      setState(data);
      setBanner({
        type: "success",
        text: "✅ Tüm projeler canlı OSV.dev veritabanına karşı tarandı ve yeni tarama raporu geçmişe eklendi.",
      });
    } catch (err) {
      setBanner({
        type: "error",
        text: err instanceof Error ? err.message : "Tarama hatası oluştu",
      });
    } finally {
      setLoadingScan(false);
    }
  }

  async function handleSaveDailyNote(e: React.FormEvent) {
    e.preventDefault();
    if (!editingNoteText.trim()) return;
    setSavingNote(true);
    try {
      const resp = await fetch("/api/guardian", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "add-daily-note",
          entryId: editingEntryId,
          noteText: editingNoteText,
        }),
      });
      const data = await resp.json();
      if (resp.ok) {
        setState(data);
        noteDialogRef.current?.close();
        setBanner({
          type: "success",
          text: "📝 Günlük tarama notu kaydedildi.",
        });
      }
    } finally {
      setSavingNote(false);
    }
  }

  async function handleLoginSubmit(e: React.FormEvent) {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError(null);
    try {
      const resp = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "login",
          method: authTab,
          githubToken: authTab === "github" ? loginGithubToken : undefined,
          password: authTab === "password" ? loginPassword : undefined,
        }),
      });
      const data = await resp.json();
      if (!resp.ok || !data.authenticated) {
        setAuthError(data.error || "Giriş başarısız.");
        return;
      }
      setAuthState({
        authenticated: true,
        user: data.user,
        ownerHint: authState.ownerHint,
      });
      setLoginGithubToken("");
      setLoginPassword("");
      authDialogRef.current?.close();
      setBanner({
        type: "success",
        text: `🔓 Yönetici girişi başarılı (${data.user}).`,
      });
    } catch {
      setAuthError("Sunucu bağlantı hatası.");
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogout() {
    await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "logout" }),
    });
    setAuthState((prev) => ({ ...prev, authenticated: false, user: null }));
  }

  return (
    <div className="min-h-screen flex flex-col bg-[#0b0c0e] text-[#f3f4f6]">
      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-[#232730] bg-[#0b0c0e]/95 backdrop-blur-md">
        <div className="max-w-[1580px] mx-auto px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#2c313d] bg-[#14171d] hover:bg-[#1c2029] text-xs font-semibold text-zinc-200 transition"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-[#ff6b57]" aria-hidden="true" />
              Ana Komut Merkezine Dön
            </Link>
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-lg bg-[#d83a26] flex items-center justify-center text-white font-bold">
                <CalendarClock className="w-5 h-5" aria-hidden="true" />
              </div>
              <div>
                <h1 className="text-base sm:text-lg font-bold tracking-tight text-white">
                  Tarama Geçmişi & Günlük Güvenlik Notları
                </h1>
                <p className="text-xs text-[#9ca3af]">
                  En son hangi gün tarandı, taramada neler çıktı ve hangi paketler düzeltildi — Günlük Seyir Defteri
                </p>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {authState.authenticated ? (
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md border border-emerald-500/40 bg-emerald-500/15 text-emerald-300 text-xs font-mono">
                <Unlock className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                <span>{authState.user}</span>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="ml-1 inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-950/80 hover:bg-red-950/80 text-zinc-200 border border-emerald-500/30 transition cursor-pointer"
                >
                  <LogOut className="w-3 h-3" aria-hidden="true" />
                  Çıkış
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => authDialogRef.current?.showModal()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md border border-amber-500/40 bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 transition cursor-pointer"
              >
                <Lock className="w-3.5 h-3.5" aria-hidden="true" />
                Yönetici Girişi Yap
              </button>
            )}

            <button
              type="button"
              onClick={handleRunFullScan}
              disabled={loadingScan}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-md bg-[#d83a26] hover:bg-[#c0301d] text-white transition disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${loadingScan ? "animate-spin" : ""}`}
                aria-hidden="true"
              />
              {loadingScan
                ? "Projeler Taranıyor..."
                : "Şimdi Yeni Tarama Başlat"}
            </button>
          </div>
        </div>
      </header>

      {banner && (
        <div
          className={`border-b px-4 sm:px-6 py-2.5 text-xs font-medium ${
            banner.type === "success"
              ? "bg-emerald-950/60 border-emerald-500/30 text-emerald-300"
              : "bg-red-950/60 border-[#d83a26]/40 text-red-300"
          }`}
        >
          <div className="max-w-[1580px] mx-auto flex items-center justify-between gap-4">
            <span>{banner.text}</span>
            <button
              type="button"
              onClick={() => setBanner(null)}
              className="text-xs underline cursor-pointer"
            >
              Kapat
            </button>
          </div>
        </div>
      )}

      <main className="max-w-[1580px] w-full mx-auto px-4 sm:px-6 py-6 flex-1 flex flex-col gap-6">
        {/* HERO VERDICT CARD: En Son Hangi Gün Tarandı & Sorun Var mıydı? */}
        {latestScan && (
          <section
            aria-label="Son Tarama Özeti ve Karar Kartı"
            className={`p-5 sm:p-6 rounded-2xl border shadow-lg ${
              latestScan.outcome === "CLEAN_NO_ISSUES"
                ? "border-emerald-500/40 bg-gradient-to-br from-emerald-950/35 via-[#121418] to-[#121418]"
                : latestScan.outcome === "ISSUES_FOUND_AND_FIXED"
                  ? "border-sky-500/40 bg-gradient-to-br from-sky-950/35 via-[#121418] to-[#121418]"
                  : "border-[#d83a26]/50 bg-gradient-to-br from-red-950/40 via-[#121418] to-[#121418]"
            }`}
          >
            <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-[#232730]">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2.5 py-0.5 text-[11px] font-mono font-bold uppercase tracking-wider rounded bg-white/10 text-white">
                    SON TARAMA DURUM ÖZETİ
                  </span>
                  <span className="px-2.5 py-0.5 text-xs font-mono font-semibold rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                    {formatRelativeDayLabel(latestScan.timestamp)}
                  </span>
                  <span className="text-xs font-mono text-zinc-400">
                    ({latestScan.triggerLabel})
                  </span>
                </div>

                <h2 className="text-xl sm:text-2xl font-extrabold text-white flex flex-wrap items-center gap-2.5">
                  <span>
                    En Son Tarama:{" "}
                    <span className="text-emerald-400">
                      {formatFullTurkishDay(latestScan.timestamp)}
                    </span>{" "}
                    · Saat {formatTimeOnly(latestScan.timestamp)}
                  </span>
                </h2>
              </div>

              {/* Big unmistakable answer to: "Sorun var mıydı yok muydu?" */}
              <div
                className={`px-4 py-2.5 rounded-xl border flex items-center gap-2.5 font-mono text-xs sm:text-sm font-bold ${
                  latestScan.outcome === "CLEAN_NO_ISSUES"
                    ? "border-emerald-500/50 bg-emerald-500/20 text-emerald-300"
                    : latestScan.outcome === "ISSUES_FOUND_AND_FIXED"
                      ? "border-sky-500/50 bg-sky-500/20 text-sky-200"
                      : "border-[#d83a26]/60 bg-[#d83a26]/20 text-[#ff6b57]"
                }`}
              >
                {latestScan.outcome === "CLEAN_NO_ISSUES" ? (
                  <>
                    <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" aria-hidden="true" />
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-emerald-300/80">
                        SON TARAMADA SORUN VAR MIYDI?
                      </div>
                      <div className="text-sm font-extrabold text-white">
                        HAYIR — SORUN YOK (0 Zafiyet Çıktı)
                      </div>
                    </div>
                  </>
                ) : latestScan.outcome === "ISSUES_FOUND_AND_FIXED" ? (
                  <>
                    <CheckCircle2 className="w-5 h-5 text-sky-400 shrink-0" aria-hidden="true" />
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-sky-300/80">
                        SON TARAMADA SORUN VAR MIYDI?
                      </div>
                      <div className="text-sm font-extrabold text-white">
                        EVET ({latestScan.detectedVulnCount} Bulgu) → TÜMÜ OTOMATİK DÜZELTİLDİ (Kalan: 0)
                      </div>
                    </div>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-5 h-5 text-[#ff6b57] shrink-0" aria-hidden="true" />
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-red-300/80">
                        SON TARAMADA SORUN VAR MIYDI?
                      </div>
                      <div className="text-sm font-extrabold text-white">
                        EVET — {latestScan.remainingVulnCount} AÇIK ZAFİYET MEVCUT
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* 4 Key Telemetry KPIs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 mt-4">
              <div className="p-3.5 rounded-xl border border-[#232730] bg-[#0b0c0e]/90">
                <span className="text-[11px] font-mono uppercase text-zinc-400">
                  1. Son Tarama Kapsamı
                </span>
                <div className="mt-1 text-base font-bold text-white font-mono">
                  {latestScan.scannedProjectsCount} Proje ·{" "}
                  {latestScan.totalPackagesScanned} Paket
                </div>
                <p className="mt-0.5 text-[11px] text-zinc-400">
                  Canlı OSV.dev & GitHub Advisory sorgusu
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-[#232730] bg-[#0b0c0e]/90">
                <span className="text-[11px] font-mono uppercase text-zinc-400">
                  2. Son Taramada Çıkan Sorun
                </span>
                <div
                  className={`mt-1 text-base font-bold font-mono ${
                    latestScan.detectedVulnCount === 0
                      ? "text-emerald-400"
                      : "text-amber-300"
                  }`}
                >
                  {latestScan.detectedVulnCount === 0
                    ? "0 Sorun (Tertemiz)"
                    : `${latestScan.detectedVulnCount} CVE / Bulgu (${latestScan.detectedPackageCount} Paket)`}
                </div>
                <p className="mt-0.5 text-[11px] text-zinc-400">
                  {latestScan.detectedVulnCount === 0
                    ? "Hiçbir pakette yeni zafiyet çıkmadı"
                    : "Eski sürümlerde tespit edilen kayıtlar"}
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-[#232730] bg-[#0b0c0e]/90">
                <span className="text-[11px] font-mono uppercase text-zinc-400">
                  3. Son Taramada Neler Düzeldi?
                </span>
                <div className="mt-1 text-base font-bold text-sky-300 font-mono">
                  {latestScan.fixedPackageCount > 0
                    ? `${latestScan.fixedPackageCount} Paket Yamalandı`
                    : "Yama Gerekmedi (Tüm Paketler Güncel)"}
                </div>
                <p className="mt-0.5 text-[11px] text-zinc-400">
                  Toplam geçmişte {totalHistoricalFixes} paket ({totalHistoricalCvesDetected} CVE) düzeltildi
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-[#232730] bg-[#0b0c0e]/90">
                <span className="text-[11px] font-mono uppercase text-zinc-400">
                  4. Şu Anki Canlı Durum
                </span>
                <div
                  className={`mt-1 text-base font-bold font-mono ${
                    latestScan.remainingVulnCount === 0
                      ? "text-emerald-400"
                      : "text-[#ff6b57]"
                  }`}
                >
                  {latestScan.remainingVulnCount === 0
                    ? "0 Açık Zafiyet (Güvenli)"
                    : `${latestScan.remainingVulnCount} Açık Zafiyet Var`}
                </div>
                <p className="mt-0.5 text-[11px] text-zinc-400">
                  Sonraki otonom tarama: Her Akşam 20:30
                </p>
              </div>
            </div>

            {/* Latest Daily Note & Per-Project Quick Status */}
            <div className="mt-4 pt-3.5 border-t border-[#232730] flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="text-xs text-zinc-200 flex items-start gap-2">
                <FileText className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />
                <div>
                  <strong className="text-white">Son Günlük Not:</strong>{" "}
                  {latestScan.dailyNote}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                {latestScan.projectSummaries.map((ps) => (
                  <span
                    key={ps.projectId}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono border ${
                      ps.status === "CLEAN"
                        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                        : ps.status === "FIXED"
                          ? "border-sky-500/30 bg-sky-500/10 text-sky-300"
                          : "border-[#d83a26]/40 bg-[#d83a26]/15 text-[#ff6b57]"
                    }`}
                  >
                    <span className="font-bold">{ps.projectName}:</span>
                    {ps.status === "CLEAN"
                      ? "Sorun Yok"
                      : ps.status === "FIXED"
                        ? `${ps.fixedPackageCount} Paket Düzeldi`
                        : `${ps.remainingVulnCount} Sorun`}
                  </span>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* SEARCH & FILTER BAR (<search> landmark per Modern Web Guidance) */}
        <search
          aria-label="Tarama Geçmişi ve Günlük Not Filtreleri"
          className="p-4 rounded-xl border border-[#232730] bg-[#121418] flex flex-col lg:flex-row lg:items-center justify-between gap-3.5"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-mono text-zinc-400 mr-1">
              Sonuca Göre:
            </span>
            {[
              { id: "ALL", label: `Tümü (${scanHistory.length})` },
              {
                id: "CLEAN_NO_ISSUES",
                label: `🟢 Sorun Çıkmayanlar (${
                  scanHistory.filter((e) => e.outcome === "CLEAN_NO_ISSUES")
                    .length
                })`,
              },
              {
                id: "ISSUES_FOUND_AND_FIXED",
                label: `🛠️ Sorun Çıkıp Düzeltilenler (${
                  scanHistory.filter(
                    (e) => e.outcome === "ISSUES_FOUND_AND_FIXED"
                  ).length
                })`,
              },
              {
                id: "ISSUES_REMAINING",
                label: `🔴 Açık Sorun Kalanlar (${
                  scanHistory.filter((e) => e.outcome === "ISSUES_REMAINING")
                    .length
                })`,
              },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() =>
                  setOutcomeFilter(tab.id as "ALL" | ScanOutcomeStatus)
                }
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border transition cursor-pointer ${
                  outcomeFilter === tab.id
                    ? "border-[#d83a26] bg-[#d83a26]/20 text-white"
                    : "border-[#2c313d] bg-[#0b0c0e] text-zinc-300 hover:border-zinc-500"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <select
              aria-label="Projeye göre filtrele"
              value={projectFilter}
              onChange={(e) => setProjectFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg text-xs font-mono bg-[#0b0c0e] border border-[#2c313d] text-zinc-200"
            >
              <option value="ALL">Tüm Projeler ({state.projects.length})</option>
              {state.projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.ecosystem})
                </option>
              ))}
            </select>

            <div className="relative min-w-[240px]">
              <Search
                className="w-3.5 h-3.5 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2"
                aria-hidden="true"
              />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Paket, CVE kodu veya günlük not ara..."
                className="w-full pl-8 pr-3 py-1.5 rounded-lg text-xs font-mono bg-[#0b0c0e] border border-[#2c313d] text-white placeholder:text-zinc-500"
              />
            </div>
          </div>
        </search>

        {/* DAILY SCAN JOURNAL TIMELINE */}
        <section
          aria-label="Günlük Tarama Geçmişi Zaman Çizelgesi"
          className="space-y-6"
        >
          {groupedByDay.length === 0 ? (
            <div className="p-8 rounded-xl border border-[#232730] bg-[#121418] text-center text-sm text-zinc-400">
              Seçilen filtreye uygun tarama geçmişi kaydı bulunamadı.
            </div>
          ) : (
            groupedByDay.map((dayGroup, dayIdx) => (
              <article
                key={dayGroup.dateKey}
                className="rounded-2xl border border-[#232730] bg-[#121418] overflow-hidden shadow-md"
              >
                {/* Day Header Banner */}
                <div className="px-5 py-4 bg-[#161922] border-b border-[#232730] flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="px-2.5 py-1 rounded-md bg-[#d83a26]/20 border border-[#d83a26]/40 text-[#ff6b57] text-xs font-mono font-bold">
                      {dayGroup.dateKey}
                    </span>
                    <h2 className="text-base sm:text-lg font-bold text-white">
                      {dayGroup.dayTitle}
                    </h2>
                    {dayIdx === 0 && (
                      <span className="px-2 py-0.5 text-[11px] font-mono font-semibold rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                        En Güncel Tarama Günü
                      </span>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                    <span className="px-2.5 py-1 rounded bg-[#0b0c0e] border border-[#2c313d] text-zinc-300">
                      {dayGroup.entries.length} Tarama Kaydı
                    </span>
                    {dayGroup.totalDetected === 0 && dayGroup.totalFixed === 0 ? (
                      <span className="px-2.5 py-1 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-bold">
                        🟢 Sorun Çıkmadı (0 Zafiyet)
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 rounded bg-sky-500/15 border border-sky-500/30 text-sky-300 font-bold">
                        🛠️ {dayGroup.totalDetected} Bulgu Tespit Edildi ·{" "}
                        {dayGroup.totalFixed} Paket Düzeltildi
                      </span>
                    )}
                  </div>
                </div>

                {/* Daily Note Callout Box */}
                <div className="px-5 py-3.5 bg-[#0e1015] border-b border-[#232730] flex flex-wrap items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5 max-w-4xl">
                    <Sparkles
                      className="w-4 h-4 text-amber-400 shrink-0 mt-0.5"
                      aria-hidden="true"
                    />
                    <div className="text-xs text-zinc-200 leading-relaxed">
                      <span className="font-bold text-amber-300 uppercase font-mono mr-1.5">
                        Günlük Güvenlik Notu:
                      </span>
                      {dayGroup.primaryNote}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      if (!authState.authenticated) {
                        authDialogRef.current?.showModal();
                        return;
                      }
                      const firstEntry = dayGroup.entries[0];
                      if (firstEntry) {
                        setEditingEntryId(firstEntry.id);
                        setEditingNoteText(firstEntry.dailyNote);
                        noteDialogRef.current?.showModal();
                      }
                    }}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[#2c313d] bg-[#161922] hover:bg-[#1f2430] text-[11px] font-mono text-zinc-300 transition cursor-pointer shrink-0"
                  >
                    <Plus className="w-3 h-3 text-emerald-400" aria-hidden="true" />
                    Günlük Notu Düzenle
                  </button>
                </div>

                {/* Individual Scan Runs of that Day */}
                <div className="p-4 sm:p-5 space-y-4">
                  {dayGroup.entries.map((entry, entryIdx) => {
                    const isDefaultOpen = dayIdx === 0 && entryIdx === 0;
                    return (
                      <details
                        key={entry.id}
                        open={isDefaultOpen}
                        className="group rounded-xl border border-[#262b36] bg-[#0b0c0e] overflow-hidden"
                      >
                        <summary className="px-4 py-3.5 cursor-pointer select-none hover:bg-[#141821] transition flex flex-wrap items-center justify-between gap-3 list-none">
                          <div className="flex flex-wrap items-center gap-2.5">
                            <span className="px-2.5 py-1 rounded bg-[#171b24] border border-[#2c313d] text-xs font-mono font-bold text-white">
                              ⏰ Saat {formatTimeOnly(entry.timestamp)}
                            </span>

                            {entry.outcome === "CLEAN_NO_ISSUES" ? (
                              <span className="px-2.5 py-1 rounded-md bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-mono font-bold">
                                🟢 SORUN YOK — 0 ZAFİYET
                              </span>
                            ) : entry.outcome === "ISSUES_FOUND_AND_FIXED" ? (
                              <span className="px-2.5 py-1 rounded-md bg-sky-500/15 border border-sky-500/40 text-sky-300 text-xs font-mono font-bold">
                                🛠️ {entry.detectedVulnCount} SORUN ÇIKTI →{" "}
                                {entry.fixedPackageCount} PAKET DÜZELTİLDİ (Kalan: 0)
                              </span>
                            ) : (
                              <span className="px-2.5 py-1 rounded-md bg-[#d83a26]/20 border border-[#d83a26]/50 text-[#ff6b57] text-xs font-mono font-bold">
                                🔴 {entry.remainingVulnCount} AÇIK ZAFİYET
                              </span>
                            )}

                            <span className="text-xs sm:text-sm font-bold text-white">
                              {entry.triggerLabel}
                            </span>
                          </div>

                          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-zinc-400">
                            <span>
                              {entry.scannedProjectsCount} Proje ·{" "}
                              {entry.totalPackagesScanned} Paket
                            </span>
                            <span className="px-2 py-0.5 rounded bg-[#181c24] text-zinc-300 group-open:bg-[#d83a26]/20 group-open:text-[#ff6b57]">
                              Detayları Göster / Gizle ▾
                            </span>
                          </div>
                        </summary>

                        <div className="p-4 sm:p-5 border-t border-[#232730] space-y-5 bg-[#0e1015]">
                          {/* 1. Per-Project Scan Status Grid */}
                          <div>
                            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400 mb-2.5 flex items-center gap-1.5">
                              <Layers className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
                              1. Bu Taramada Kontrol Edilen Projeler ({entry.projectSummaries.length})
                            </h3>
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                              {entry.projectSummaries.map((ps) => (
                                <div
                                  key={ps.projectId}
                                  className={`p-3 rounded-lg border ${
                                    ps.status === "CLEAN"
                                      ? "border-emerald-500/25 bg-emerald-950/15"
                                      : ps.status === "FIXED"
                                        ? "border-sky-500/30 bg-sky-950/15"
                                        : "border-[#d83a26]/40 bg-red-950/20"
                                  }`}
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <span className="font-mono font-bold text-xs text-white">
                                      {ps.projectName}
                                    </span>
                                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/40 text-zinc-300">
                                      {ps.ecosystem} · {ps.totalPackages} paket
                                    </span>
                                  </div>
                                  <div className="mt-2 text-xs font-mono">
                                    {ps.status === "CLEAN" ? (
                                      <span className="text-emerald-400 font-semibold">
                                        ✓ Sorun Çıkmadı (0 Zafiyet)
                                      </span>
                                    ) : ps.status === "FIXED" ? (
                                      <span className="text-sky-300 font-semibold">
                                        🛠️ {ps.detectedVulnCount} Bulgu →{" "}
                                        {ps.fixedPackageCount} Paket Yamalandı
                                      </span>
                                    ) : (
                                      <span className="text-[#ff6b57] font-semibold">
                                        ⚠️ {ps.remainingVulnCount} Açık Zafiyet
                                      </span>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* 2. Taramada Neler Çıktı? (Findings) & 3. Taramada Neler Düzeldi? (Fixes) */}
                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            {/* Column A: Taramada Neler Çıktı? */}
                            <div className="p-4 rounded-xl border border-[#232730] bg-[#121418]">
                              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-amber-300 mb-3 flex items-center gap-1.5">
                                <ShieldAlert className="w-4 h-4 text-amber-400" aria-hidden="true" />
                                2. Taramada Neler Çıktı? ({entry.findings.length}{" "}
                                Paket / {entry.detectedVulnCount} CVE Bulgusu)
                              </h3>

                              {entry.findings.length === 0 ? (
                                <div className="p-4 rounded-lg border border-emerald-500/30 bg-emerald-950/20 text-xs text-emerald-300 flex items-center gap-2.5">
                                  <CheckCircle2
                                    className="w-4 h-4 text-emerald-400 shrink-0"
                                    aria-hidden="true"
                                  />
                                  <span>
                                    Bu taramada incelenen{" "}
                                    <strong>
                                      {entry.scannedProjectsCount} proje ve{" "}
                                      {entry.totalPackagesScanned} paketin
                                    </strong>{" "}
                                    hiçbirinde yeni güvenlik zafiyeti (CVE/GHSA)
                                    veya kırık bağımlılık tespit edilmedi.
                                  </span>
                                </div>
                              ) : (
                                <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
                                  {entry.findings.map((f, i) => (
                                    <div
                                      key={`${f.projectId}-${f.packageName}-${i}`}
                                      className="p-2.5 rounded-lg border border-[#262b36] bg-[#0b0c0e] flex flex-col gap-1.5"
                                    >
                                      <div className="flex flex-wrap items-center justify-between gap-2">
                                        <div className="flex items-center gap-2 text-xs font-mono">
                                          <span className="px-1.5 py-0.5 rounded bg-[#1b1f27] text-zinc-300 border border-[#2c313d]">
                                            {f.projectName}
                                          </span>
                                          <span className="font-bold text-white">
                                            {f.packageName}
                                          </span>
                                          <span className="text-red-400">
                                            @{f.installedVersion}
                                          </span>
                                        </div>
                                        {f.fixedInThisRun && (
                                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                                            ✓ Aynı Taramada Yamalandı
                                          </span>
                                        )}
                                      </div>

                                      <div className="flex flex-wrap items-center gap-1.5">
                                        {f.cveIds.map((cve) => (
                                          <CveLinkChip
                                            key={cve}
                                            code={cve}
                                            state={state}
                                          />
                                        ))}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>

                            {/* Column B: Taramada Neler Düzeldi? */}
                            <div className="p-4 rounded-xl border border-[#232730] bg-[#121418]">
                              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 mb-3 flex items-center gap-1.5">
                                <Wrench className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                                3. Taramada Neler Düzeldi? ({entry.fixes.length}{" "}
                                Paket Güvenli Sürüme Çekildi)
                              </h3>

                              {entry.fixes.length === 0 ? (
                                <div className="p-4 rounded-lg border border-[#262b36] bg-[#0b0c0e] text-xs text-zinc-300 flex items-center gap-2.5">
                                  <Package
                                    className="w-4 h-4 text-emerald-400 shrink-0"
                                    aria-hidden="true"
                                  />
                                  <span>
                                    Tüm paketler zaten güvenli (`SAFE` /{" "}
                                    `PATCHED`) sürümde olduğu için ek sürüm
                                    yükseltmesine veya yamaya ihtiyaç duyulmadı.
                                  </span>
                                </div>
                              ) : (
                                <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
                                  {entry.fixes.map((fx, i) => (
                                    <div
                                      key={`${fx.projectId}-${fx.packageName}-${i}`}
                                      className="p-2.5 rounded-lg border border-emerald-500/25 bg-[#0b0c0e] flex flex-col gap-1.5"
                                    >
                                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                                        <div className="flex flex-wrap items-center gap-2">
                                          <span className="px-1.5 py-0.5 rounded bg-[#1b1f27] text-zinc-300 border border-[#2c313d]">
                                            {fx.projectName}
                                          </span>
                                          <span className="font-bold text-white">
                                            {fx.packageName}
                                          </span>
                                          <span className="text-zinc-400 line-through">
                                            {fx.fromVersion}
                                          </span>
                                          <span className="text-emerald-400 font-bold">
                                            → {fx.toSafeVersion}
                                          </span>
                                        </div>

                                        {fx.commitUrl ? (
                                          <a
                                            href={fx.commitUrl}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-[10px] hover:underline"
                                          >
                                            Commit Gör
                                            <ExternalLink
                                              className="w-2.5 h-2.5"
                                              aria-hidden="true"
                                            />
                                          </a>
                                        ) : (
                                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300">
                                            {fx.deployStatus}
                                          </span>
                                        )}
                                      </div>

                                      {fx.commitRef && (
                                        <div className="text-[11px] font-mono text-zinc-400 truncate">
                                          Commit: {fx.commitRef}
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>

                          {/* 4. Tarama Seyir Notları (Notes List) */}
                          <div className="p-4 rounded-xl border border-[#232730] bg-[#121418]">
                            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300 mb-2.5 flex items-center gap-1.5">
                              <FileText className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
                              4. Tarama Günlük Kayıt Notları
                            </h3>
                            <ul className="space-y-1.5 text-xs text-zinc-300 font-mono">
                              {entry.notes.map((n, idx) => (
                                <li
                                  key={idx}
                                  className="flex items-start gap-2 leading-relaxed"
                                >
                                  <span className="text-[#ff6b57] font-bold">
                                    •
                                  </span>
                                  <span>{n}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </details>
                    );
                  })}
                </div>
              </article>
            ))
          )}
        </section>
      </main>

      {/* Daily Note Edit Modal */}
      <dialog
        ref={noteDialogRef}
        className="m-auto w-full max-w-lg rounded-2xl border border-[#2c313d] bg-[#121418] text-white p-6 shadow-2xl backdrop:bg-black/75"
      >
        <form onSubmit={handleSaveDailyNote} className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold">
              📝 Günlük Tarama Notunu Düzenle
            </h2>
            <button
              type="button"
              onClick={() => noteDialogRef.current?.close()}
              className="text-xs text-zinc-400 hover:text-white cursor-pointer"
            >
              Kapat
            </button>
          </div>
          <p className="text-xs text-zinc-400">
            Bu güne ait tarama özetine özel güvenlik notu veya açıklama
            ekleyebilirsiniz.
          </p>
          <textarea
            rows={4}
            value={editingNoteText}
            onChange={(e) => setEditingNoteText(e.target.value)}
            className="w-full p-3 rounded-lg bg-[#0b0c0e] border border-[#2c313d] text-xs text-white font-mono"
            placeholder="Günlük tarama notunuz..."
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => noteDialogRef.current?.close()}
              className="px-3.5 py-2 rounded-lg border border-[#2c313d] text-xs text-zinc-300 cursor-pointer"
            >
              İptal
            </button>
            <button
              type="submit"
              disabled={savingNote}
              className="px-4 py-2 rounded-lg bg-[#d83a26] hover:bg-[#c0301d] text-xs font-semibold text-white cursor-pointer"
            >
              {savingNote ? "Kaydediliyor..." : "Notu Kaydet"}
            </button>
          </div>
        </form>
      </dialog>

      {/* Admin Login Modal */}
      <dialog
        ref={authDialogRef}
        className="m-auto w-full max-w-md rounded-2xl border border-[#2c313d] bg-[#121418] text-white p-6 shadow-2xl backdrop:bg-black/75"
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold flex items-center gap-2">
              <Lock className="w-4 h-4 text-amber-400" aria-hidden="true" />
              Yönetici Doğrulaması Gerekiyor
            </h2>
            <button
              type="button"
              onClick={() => authDialogRef.current?.close()}
              className="text-xs text-zinc-400 hover:text-white cursor-pointer"
            >
              Kapat
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2 p-1 rounded-lg bg-[#0b0c0e] border border-[#232730]">
            <button
              type="button"
              onClick={() => setAuthTab("github")}
              className={`py-1.5 text-xs font-semibold rounded-md cursor-pointer ${
                authTab === "github"
                  ? "bg-[#d83a26] text-white"
                  : "text-zinc-400"
              }`}
            >
              GitHub Token ile Giriş
            </button>
            <button
              type="button"
              onClick={() => setAuthTab("password")}
              className={`py-1.5 text-xs font-semibold rounded-md cursor-pointer ${
                authTab === "password"
                  ? "bg-[#d83a26] text-white"
                  : "text-zinc-400"
              }`}
            >
              Kurulum Şifresi
            </button>
          </div>

          {authError && (
            <div className="p-2.5 rounded-lg bg-red-950/60 border border-[#d83a26]/40 text-xs text-red-300">
              {authError}
            </div>
          )}

          <form onSubmit={handleLoginSubmit} className="space-y-3">
            {authTab === "github" ? (
              <div>
                <label className="block text-xs text-zinc-300 mb-1">
                  GitHub Personal Access Token ({authState.ownerHint}):
                </label>
                <input
                  type="password"
                  name="github-token"
                  autoComplete="current-password"
                  value={loginGithubToken}
                  onChange={(e) => setLoginGithubToken(e.target.value)}
                  placeholder="ghp_... veya github_pat_..."
                  className="w-full px-3 py-2 rounded-lg bg-[#0b0c0e] border border-[#2c313d] text-xs font-mono text-white"
                />
              </div>
            ) : (
              <div>
                <label className="block text-xs text-zinc-300 mb-1">
                  Kurulum Yönetici Şifresi (`GUARDIAN_ADMIN_PASSWORD`):
                </label>
                <input
                  type="password"
                  name="admin-password"
                  autoComplete="current-password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="Yönetici şifreniz..."
                  className="w-full px-3 py-2 rounded-lg bg-[#0b0c0e] border border-[#2c313d] text-xs font-mono text-white"
                />
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => authDialogRef.current?.close()}
                className="px-3.5 py-2 rounded-lg border border-[#2c313d] text-xs text-zinc-300 cursor-pointer"
              >
                Vazgeç
              </button>
              <button
                type="submit"
                disabled={authLoading}
                className="px-4 py-2 rounded-lg bg-[#d83a26] hover:bg-[#c0301d] text-xs font-semibold text-white cursor-pointer"
              >
                {authLoading ? "Doğrulanıyor..." : "Giriş Yap"}
              </button>
            </div>
          </form>
        </div>
      </dialog>
    </div>
  );
}
