export type Ecosystem = "npm" | "Maven" | "Pub" | "PyPI" | "Go" | "crates.io";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type UpgradeRisk = "SAFE_PATCH" | "MINOR_VERIFY" | "BREAKING_MAJOR" | "MANUAL_ONLY";

export type DependencySection =
  | "dependencies"
  | "devDependencies"
  | "overrides"
  | "maven"
  | "pubspec"
  | "pypi"
  | "gomod"
  | "cargo";

export interface VulnerabilityItem {
  id: string;
  cveId: string | null;
  aliases: string[];
  packageName: string;
  ecosystem: Ecosystem;
  installedVersion: string;
  introducedVersion?: string | null;
  fixedVersion: string | null;
  upgradeRisk: UpgradeRisk;
  upgradeRiskReason: string;
  affectedRangeText?: string;
  cweIds?: string[];
  cvssVector?: string | null;
  severity: Severity;
  cvssScore: number;
  summary: string;
  details: string;
  publishedAt: string;
  modifiedAt?: string;
  references: string[];
  isDirect: boolean;
  dependencySection: DependencySection;
}

export interface PackageDependency {
  name: string;
  rawSpec: string;
  cleanVersion: string;
  section: DependencySection;
  ecosystem: Ecosystem;
  status: "SAFE" | "VULNERABLE" | "PATCHED";
  vulnerabilityCount: number;
  recommendedSafeVersion: string | null;
  upgradeRisk?: UpgradeRisk;
  upgradeRiskReason?: string;
  previousVersion?: string;
}

export interface CanaryStageResult {
  stage:
    | "BRANCH_ISOLATION"
    | "DEPENDENCY_COMPAT"
    | "BUILD_AND_TEST"
    | "SMOKE_HEALTH_CHECK"
    | "AUTO_MERGE_DEPLOY";
  label: string;
  status: "PASSED" | "FAILED" | "SKIPPED";
  detail: string;
}

export interface RemediationRecord {
  id: string;
  projectId: string;
  projectName: string;
  timestamp: string;
  packageName: string;
  fromVersion: string;
  toSafeVersion: string;
  upgradeRisk?: UpgradeRisk;
  cveIds: string[];
  verifyStatus: "PASSED" | "FAILED" | "SKIPPED";
  deployStatus:
    | "DEPLOYED"
    | "AUTO_MERGED_DEPLOYED"
    | "PR_OPENED"
    | "DRY_RUN"
    | "ROLLED_BACK"
    | "BLOCKED_BREAKING";
  deployTarget: string;
  commitRef: string;
  prUrl?: string;
  canaryBranch?: string;
  autoMergedToMain?: boolean;
  canaryStages?: CanaryStageResult[];
  logs: string[];
}

export interface SecurityNewsItem {
  id: string;
  cveId: string | null;
  title: string;
  summary: string;
  details?: string;
  ecosystem: Ecosystem | "General";
  affectedPackage: string;
  vulnerableRange: string;
  safeVersion: string;
  severity: Severity;
  cvssScore: number;
  publishedAt: string;
  source: "OSV.dev" | "GitHub Advisory" | "CISA KEV";
  url: string;
  impactedProjectIds: string[];
}

export interface MonitoredProject {
  id: string;
  name: string;
  description: string;
  path: string;
  repoUrl?: string;
  ecosystem: Ecosystem;
  manifestFile: string;
  packageManager: "bun" | "npm" | "maven" | "flutter" | "pip" | "go" | "cargo";
  scanIntervalMinutes: number;
  dailyScanTime: string;
  autoRemediate: boolean;
  autoDeploy: boolean;
  verifyCommand: string;
  deployCommand: string;
  deployTarget:
    | "Vercel"
    | "Kubernetes / Server"
    | "GitHub Actions"
    | "Local / Dry-Run";
  lastScanAt: string | null;
  nextScanAt: string | null;
  lastDeployAt: string | null;
  status: "HEALTHY" | "VULNERABLE" | "SCANNING" | "DEPLOYING" | "ERROR";
  packages: PackageDependency[];
  vulnerabilities: VulnerabilityItem[];
  manifestRaw?: string;
}

export interface GuardianState {
  version: string;
  lastGlobalScanAt: string;
  schedulerActive: boolean;
  dailyScheduleCron: string;
  dailyScheduleLabel: string;
  hostingMode: "HYBRID_VERCEL_EDGE";
  projects: MonitoredProject[];
  newsFeed: SecurityNewsItem[];
  remediationHistory: RemediationRecord[];
}
