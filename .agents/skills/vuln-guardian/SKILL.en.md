---
name: vuln-guardian
description: >-
  Autonomous vulnerability intelligence, scheduled multi-project dependency scanner,
  single-batch safe-version auto-remediation, pre-prod breaking-change verifier, and
  continuous deployment skill. Use this skill whenever the user wants to scan projects
  for CVEs/GHSA vulnerabilities, read security advisory news, upgrade vulnerable packages
  to safe patched versions in a single batch, verify breaking changes and site health,
  or deploy patched projects.
---

# VulnGuardian — Vulnerability Intelligence, Single-Batch Safe-Version Patcher & Auto-Deploy Skill (English)

> **Language:** [🇬🇧 English](./SKILL.en.md) · [🇹🇷 Türkçe](./SKILL.md)

This skill scans project dependency manifests (`package.json`, `pom.xml`, `pubspec.yaml`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`) against live **Google OSV.dev**, **GitHub Security Advisories (GHSA)**, and **NVD/CVE** feeds, upgrades all vulnerable packages (including Patch, Minor, and Major versions) to their **minimum safe (`fixed`) versions in a single batch**, runs a **4-stage Pre-Prod Breaking-Change & Site Health Verification pipeline**, and merges verified upgrades into `main` in one shot.

## Architecture & Command Center

- **CLI & Automation Engine:** [scan-cli.mjs](./scripts/scan-cli.mjs)
- **Ecosystem Remediation & Batch Canary Playbook (EN):** [remediation-playbook.en.md](./references/remediation-playbook.en.md)
- **State & Telemetry Store:** `src/data/guardian-state.json` (synchronized with the Next.js 16 Web Dashboard)

---

## Step-by-Step Agent Runbook

### 1. List Monitored Projects & Schedules

```bash
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs list
```

Add a new GitHub repository or local project to monitoring:

```bash
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs add \
  --name "project-name" \
  --repo "https://github.com/owner/repo" \
  --ecosystem "npm" \
  --manifest "package.json"
```

### 2. Read Live Vulnerability Advisories & News (`news`)

```bash
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs news
```

### 3. Run Live OSV.dev Dependency Scan (`scan`)

```bash
# Scan all monitored projects
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs scan

# Scan a single project
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs scan --project <project-id>
```

### 4. Single-Batch Safe-Version Upgrade, Breaking-Change Verification & Deploy (`remediate`)

```bash
# Upgrade all vulnerable packages in a project, verify breaking changes, and deploy in a single batch
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs remediate \
  --project <project-id> \
  --apply \
  --deploy
```

**Single-Batch & Pre-Prod Verification Rules:**
- **Never Open Per-Package PRs:** Regardless of how many vulnerable packages exist in a project (`SAFE_PATCH`, `MINOR_VERIFY`, and `BREAKING_MAJOR`), all of them are first upgraded together in a single manifest.
- **4-Stage Pre-Prod Breaking-Change & Site Health Gate:**
  1. **Dependency & Peer Compatibility (`DEPENDENCY_COMPAT`):** Validates manifest syntax and peer-group major version alignment (`react` ↔ `react-dom`, `next` ↔ `eslint-config-next`).
  2. **Build, Type-Check & Test (`BUILD_AND_TEST`):** Runs the project's `verifyCommand` and verifies GitHub Check Runs (`/commits/{sha}/check-runs`) on the isolated `security/batch-canary` branch.
  3. **Live Site Smoke Check & Zero-CVE Check (`SMOKE_HEALTH_CHECK`):** Confirms `0` remaining CVEs on OSV.dev and verifies the preview deployment responds with `HTTP 200 OK` (no `5xx` errors).
  4. **Single-Batch Prod (`main`) Merge & Deploy (`AUTO_MERGE_DEPLOY`):** Merges all verified packages into `main` in **one single batch operation** (`POST /repos/{owner}/{repo}/merges`) without opening Pull Requests or triggering PR email spam, then triggers production deployment.
