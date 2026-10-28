# VulnGuardian — Single-Batch Safe-Version Remediation & Pre-Prod Verification Playbook (English)

> **Language:** [🇬🇧 English](./remediation-playbook.en.md) · [🇹🇷 Türkçe](./remediation-playbook.md)

This reference playbook defines the rules for upgrading vulnerable dependencies to safe (`fixed`) versions across 6 ecosystems, overriding transitive dependencies, and executing the **Single-Batch Pre-Prod Breaking-Change & Site Health Verification** pipeline before merging into `main`.

## 1. Ecosystem-Specific Safe-Version Rules

### A. Node.js / Bun / npm (`package.json`)
- **Direct Dependencies (`dependencies` / `devDependencies`):**
  - Preserves the existing range prefix (`^` or `~`) while bumping to `fixedVersion`.
- **Transitive Dependencies (`overrides` / `resolutions`):**
  - Pins `"<pkg>": "^<fixedVersion>"` inside the `"overrides"` block in `package.json`.
- **Verification:**
  - Runs `bun run lint && bun run type-check && bun run test:ci` (or `npm test`).

### B. Java / Spring Boot (`pom.xml`)
- **Explicit `<version>` Dependencies:**
  - Updates the `<version>` tag directly to `fixedVersion`.
- **Parent POM / Spring Boot BOM Dependencies:**
  - Upgrades the `<parent>` Spring Boot version or pins the transitive artifact explicitly inside `<dependencies>`.
- **Verification:**
  - Runs `./mvnw -q -DskipTests compile`.

### C. Flutter / Dart (`pubspec.yaml`), Python (`requirements.txt` / `pyproject.toml`), Go (`go.mod`), Rust (`Cargo.toml`)
- Updates the version constraint to the minimum patched version reported by OSV.dev and runs the ecosystem's verification gate (`flutter analyze`, `pytest`, `go vet && go test ./...`, `cargo check && cargo test`).

---

## 2. Single-Batch Safe-Version, Pre-Prod Breaking-Change Check & Auto-Merge (Including Major Upgrades)

Regardless of how many vulnerable packages are found in a project (**never open separate PRs per package**), all `SAFE_PATCH`, `MINOR_VERIFY`, and `BREAKING_MAJOR` upgrades are combined and verified in a single batch:

1. **Stage 1 — Batch Preparation & Isolated Canary Branch (`BRANCH_ISOLATION`):**
   - All vulnerable packages in the project are upgraded to their recommended safe versions in a single manifest and committed once to an isolated `security/batch-canary` branch on GitHub (without opening a PR, avoiding email spam).
2. **Stage 2 — Peer-Dependency & Breaking-Change Check (`DEPENDENCY_COMPAT`):**
   - Validates manifest syntax and peer-dependency major version alignment (`react` ↔ `react-dom`, `next` ↔ `eslint-config-next`).
3. **Stage 3 — Build, Type-Check & CI Check Runs (`BUILD_AND_TEST`):**
   - Runs `verifyCommand` and verifies GitHub Check Runs (`/commits/{sha}/check-runs`) and Commit Status (`/commits/{sha}/status`) on the canary commit.
4. **Stage 4 — Live Site Smoke Check (`HTTP 200 OK`) & OSV Zero-CVE Check (`SMOKE_HEALTH_CHECK`):**
   - Confirms 0 remaining CVEs on OSV.dev and sends an HTTP `GET` request to the preview deployment URL (`target_url`) to ensure the site opens without `5xx` errors.
5. **Stage 5 — Single-Shot `main` (Prod) Merge & Deploy (`AUTO_MERGE_DEPLOY`):**
   - **All Passed:** Merges `security/batch-canary` directly into `main` via `POST /repos/{owner}/{repo}/merges`, deletes the temporary canary branch, and triggers production deployment (`AUTO_MERGED_DEPLOYED`).
   - **Breaking Change / Failure Detected:** Blocks the merge into `main` (`BLOCKED_BREAKING`), keeping the live production site 100% safe.
