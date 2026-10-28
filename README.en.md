<div align="center">

**[🇬🇧 English](./README.en.md)** · **[🇹🇷 Türkçe](./README.md)**

[![GitHub Release](https://img.shields.io/github/v/release/huseyindol/vuln-guardian?style=flat-square&color=10b981)](https://github.com/huseyindol/vuln-guardian/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Agent Skill](https://img.shields.io/badge/Agent_Skill-Antigravity_%26_Claude_Code-f97316?style=flat-square)](./.agents/skills/vuln-guardian/SKILL.en.md)
[![OSV.dev Live](https://img.shields.io/badge/Advisory_Engine-Google_OSV.dev_%2B_GHSA-ef4444?style=flat-square)](https://osv.dev)
[![Next.js 16](https://img.shields.io/badge/Dashboard-Next.js_16-black?style=flat-square)](https://nextjs.org)

</div>

# 🛡️ VulnGuardian — Autonomous Vulnerability Intelligence, Single-Batch Safe-Version Patcher & Deploy Skill

**VulnGuardian** is an open-source **AI Agent Skill (`Google Antigravity` & `Claude Code`)** and **Self-Hosted Web Command Center (Next.js 16)** that scans multi-language software projects (`TypeScript/Node.js`, `Java/Spring Boot`, `Flutter/Dart`, `Python/PyPI`, `Go`, `Rust/Cargo`) against live **Google OSV.dev**, **GitHub Security Advisories (GHSA)**, and **NVD/CVE** databases.

It upgrades **all vulnerable packages at once (including Patch, Minor, and Major versions) into a single batch**, verifies **Breaking-Changes and Live Site Health** on an isolated staging branch before touching production (`main`), and merges all verified upgrades into `main` in **one single operation without spamming per-package Pull Request emails**.

> **Self-Hosted & Personal Setup:** Every developer or team clones this repository (`huseyindol/vuln-guardian`), installs the skill globally into their AI coding agent via `bun run skill:install`, and runs the Command Center either **locally (`localhost:3400`)** or on **their own Vercel / cloud server** using their own `GITHUB_TOKEN`.

---

## ✨ Key Features

1. **6 Languages & Ecosystems Supported (Multi-Manifest Parser):**
   - **TypeScript / JavaScript (`npm` / `Bun`):** `package.json` (`dependencies`, `devDependencies`, `overrides`)
   - **Java / Kotlin (`Maven`):** `pom.xml` (`<parent>`, `<dependencies>`, Spring Boot BOM resolution)
   - **Dart / Flutter (`Pub`):** `pubspec.yaml` (`dependencies`, `dev_dependencies`)
   - **Python (`PyPI`):** `requirements.txt` & `pyproject.toml`
   - **Go (`Go Modules`):** `go.mod`
   - **Rust (`crates.io`):** `Cargo.toml`
2. **Single-Batch Safe-Version Upgrade, Pre-Prod Breaking-Change Verification & Zero-Spam `main` Merge:**
   - **1. Batch Preparation & Isolated Canary Branch (`BRANCH_ISOLATION`):** Never opens separate PRs per package! All vulnerable packages in a project (`SAFE_PATCH`, `MINOR_VERIFY`, and `BREAKING_MAJOR`) are upgraded together in a single manifest and committed once to a temporary `security/batch-canary` branch without touching `main` *(no PR is opened, producing zero GitHub email spam)*.
   - **2. Breaking-Change & Peer Compatibility Gate (`DEPENDENCY_COMPAT`):** Validates manifest syntax and peer-group major version alignment (`react` ↔ `react-dom`, `next` ↔ `eslint-config-next`, etc.). If a specific package introduces a breaking conflict, only that package is excluded while healthy upgrades proceed.
   - **3. Build, Type-Check & Lint Gate (`BUILD_AND_TEST`):** Runs the project's `verifyCommand` and verifies GitHub Check Runs (`/commits/{sha}/check-runs`) and Commit Status (`/commits/{sha}/status`).
   - **4. Live Site Smoke Check (`HTTP 200 OK`) & OSV Zero-CVE Verification (`SMOKE_HEALTH_CHECK`):** Queries live `api.osv.dev` to confirm `0` remaining vulnerabilities on the upgraded versions and performs an HTTP `GET` smoke test against the preview deployment URL to ensure the site boots without `5xx` errors.
   - **5. Single-Shot `main` (Prod) Merge & Deploy (`AUTO_MERGE_DEPLOY`):** Once all gates pass, merges `security/batch-canary` directly into `main` via GitHub's Branch Merge API (`POST /repos/{owner}/{repo}/merges`), deletes the temporary branch, and triggers production deployment. If any check fails, the merge into `main` is automatically blocked to protect production.
3. **Web Command Center (Dashboard) & Interactive Repository Onboarding:**
   - Add any public or private GitHub repository (`https://github.com/owner/repo`) and an optional per-repo `GitHub Token` in seconds via the **"+ Add Project / GitHub Repo"** modal.
4. **Portable AI Agent Skill (`Antigravity` & `Claude Code`):**
   - Packaged using the standard `.agents/skills/vuln-guardian/SKILL.md` specification ([English Skill Doc](./.agents/skills/vuln-guardian/SKILL.en.md) · [English Playbook](./.agents/skills/vuln-guardian/references/remediation-playbook.en.md)).

---

## 🚀 Quick Start

### 1. Clone the Repository & Install Dependencies

```bash
git clone https://github.com/huseyindol/vuln-guardian.git
cd vuln-guardian
bun install
```

### 2. Install the Agent Skill Globally (Antigravity & Claude Code)

```bash
bun run skill:install
```

This automatically links `~/.gemini/config/skills/vuln-guardian` (Google Antigravity) and `~/.claude/skills/vuln-guardian` (Claude Code).

### 3. Run Locally or Deploy to Your Own Vercel Account

```bash
cp .env.example .env.local
# Set GITHUB_TOKEN, GITHUB_OWNER, and/or GUARDIAN_ADMIN_PASSWORD
bun run dev
```

> **🔒 Read-Only Community Mode & Admin Login:** The Web Command Center opens in **Read-Only** mode by default so visitors can explore ecosystems and CVE reports without triggering real GitHub/deployment mutations. Mutating actions require signing in via the **Admin Login Modal** using either **GitHub (`GITHUB_OWNER` token verification)** or the setup password (**`GUARDIAN_ADMIN_PASSWORD`**).

Open `http://localhost:3400` in your browser, or deploy directly to your own Vercel account:

```bash
bunx --yes vercel@latest --prod
```

A daily autonomous scan and batch-remediation cron job (`/api/cron/scan`) is pre-configured in [`vercel.json`](./vercel.json) for **20:30 TRT (`30 17 * * *` UTC)**.

---

## 💻 CLI Usage

```bash
# List monitored projects and daily scan schedules
bun run guardian:list

# Scan all monitored projects against live OSV.dev and apply batch Safe-Version upgrades
bun run guardian:scan

# Add and scan any GitHub repository
bun run guardian:add -- --name my-api --repo https://github.com/owner/repo --ecosystem npm --manifest package.json

# Auto-discover all projects in a directory (package.json, pom.xml, pubspec.yaml, requirements.txt, go.mod, Cargo.toml)
bun run guardian:discover -- --dir /path/to/projects

# Remove a project from monitoring
bun run guardian:remove -- --project my-api

# Fetch live security advisories & CVE news feed
bun run guardian:news
```
