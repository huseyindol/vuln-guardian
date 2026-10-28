<div align="center">

**[🇹🇷 Türkçe](./README.md)** · **[🇬🇧 English](./README.en.md)**

[![GitHub Release](https://img.shields.io/github/v/release/huseyindol/vuln-guardian?style=flat-square&color=10b981)](https://github.com/huseyindol/vuln-guardian/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Agent Skill](https://img.shields.io/badge/Agent_Skill-Antigravity_%26_Claude_Code-f97316?style=flat-square)](./.agents/skills/vuln-guardian/SKILL.md)
[![OSV.dev Live](https://img.shields.io/badge/Advisory_Engine-Google_OSV.dev_%2B_GHSA-ef4444?style=flat-square)](https://osv.dev)
[![Next.js 16](https://img.shields.io/badge/Dashboard-Next.js_16-black?style=flat-square)](https://nextjs.org)

</div>

# 🛡️ VulnGuardian — Autonomous Vulnerability Intelligence, Single-Batch Safe-Version Patcher & Deploy Skill

**VulnGuardian**, çok dilli yazılım projelerinizin (`TypeScript/Node.js`, `Java/Spring Boot`, `Flutter/Dart`, `Python/PyPI`, `Go`, `Rust/Cargo`) bağımlılıklarını canlı **Google OSV.dev**, **GitHub Security Advisories (GHSA)** ve **NVD/CVE** veritabanlarına karşı tarayan; zafiyetli paketlerin **tamamını (Patch, Minor ve Major dahil) tek seferde güvenli (`Safe`) versiyona çeken**, prod (`main`) ortamına göndermeden önce **Breaking-Change ve Site Çalışabilirlik kontrollerini** çalıştıran ve **PR mail spam'i üretmeden tek seferde `main` dalına birleştirip deploy eden** açık kaynaklı bir **AI Agent Skill (`Antigravity` & `Claude Code`)** ve **Self-Hosted Web Komut Merkezidir (Next.js 16)**.

> **Nasıl Çalışır (Self-Hosted & Kişisel Kurulum):** Her geliştirici veya ekip bu repoyu (`huseyindol/vuln-guardian`) kendi ortamına klonlar, `bun run skill:install` ile skill'i kendi AI ajanına kurar ve kontrol panelini **kendi yerel makinesinde (`localhost:3400`)** veya **kendi Vercel / sunucu hesabında** kendi `GITHUB_TOKEN` anahtarıyla yayınlar.

---

## ✨ Temel Özellikler

1. **6 Dil & Ekosistem Desteği (Çoklu Manifest Ayrıştırıcı):**
   - **TypeScript / JavaScript (`npm` / `Bun`):** `package.json` (`dependencies`, `devDependencies`, `overrides`)
   - **Java / Kotlin (`Maven`):** `pom.xml` (`<parent>`, `<dependencies>`, Spring Boot BOM çözümleme)
   - **Dart / Flutter (`Pub`):** `pubspec.yaml` (`dependencies`, `dev_dependencies`)
   - **Python (`PyPI`):** `requirements.txt` & `pyproject.toml`
   - **Go (`Go Modules`):** `go.mod`
   - **Rust (`crates.io`):** `Cargo.toml`
2. **Tek Seferde Toplu (Single-Batch) Safe-Version, Breaking-Change Kontrolü & Prod (`main`) Merge:**
   - **1. Toplu Hazırlık & İzole Test Dalı (`BRANCH_ISOLATION`):** Her paket için ayrı PR açılmaz! Projedeki tüm zafiyetli paketler (`SAFE_PATCH`, `MINOR_VERIFY` ve `BREAKING_MAJOR` dahil) tek manifest üzerinde güvenli sürümlerine çekilir ve canlı `main` dalına dokunulmadan geçici `security/batch-canary` dalına tek commit olarak gönderilir *(PR açılmadığı için GitHub bildirim maili üretmez)*.
   - **2. Breaking-Change & Peer Uyumluluk Kontrolü (`DEPENDENCY_COMPAT`):** Manifest sözdizimi ve birbirine bağlı ekosistem paketlerinin (`react` ↔ `react-dom`, `next` ↔ `eslint-config-next` vb.) major sürüm uyumluluğu doğrulanır.
   - **3. Derleme, Type-Check & Lint Test Kapısı (`BUILD_AND_TEST`):** Projenin doğrulama komutu (`verifyCommand`) ve GitHub Check Runs (`/commits/{sha}/check-runs`) kontrol edilir.
   - **4. Site Çalışabilirlik (Preview HTTP 200 OK) & OSV Sıfır-Zafiyet Kontrolü (`SMOKE_HEALTH_CHECK`):** Güncellenen versiyonlarda OSV.dev üzerinde 0 aktif zafiyet kaldığı ve Preview URL'sinin `500` hatası vermeden açıldığı doğrulanır.
   - **5. Tek Seferde `main` (Prod) Merge & Deploy (`AUTO_MERGE_DEPLOY`):** Tüm kontroller hatasızsa GitHub Branch Merge API (`POST /repos/{owner}/{repo}/merges`) ile geçici dal **PR açılmadan tek seferde `main` dalına birleştirilir**, geçici dal silinir ve canlı deploy tetiklenir. Hata varsa `main` dalına birleştirme otomatik engellenir; canlı site korunur.
3. **Web Komut Merkezi (Dashboard) & İnteraktif Proje Ekleme:**
   - Arayüzdeki **"+ Yeni Proje / GitHub Repo Ekle"** penceresinden herhangi bir public veya private GitHub reposunu (`https://github.com/kullanici/proje`) ve isteğe bağlı özel `GitHub Token`'ını saniyeler içinde taramaya dahil edebilirsiniz.
4. **Taşınabilir AI Agent Skill (`Antigravity` & `Claude Code`):**
   - `.agents/skills/vuln-guardian/SKILL.md` standardıyla paketlenmiştir; tek komutla global olarak tüm projelerinizde aktifleşir.

---

## 🚀 Hızlı Kurulum

### 1. Repoyu Klonlayın ve Bağımlılıkları Kurun

```bash
git clone https://github.com/huseyindol/vuln-guardian.git
cd vuln-guardian
bun install
```

### 2. Agent Skill'i Global Olarak Kurun (Antigravity & Claude Code)

```bash
bun run skill:install
```

Bu komut `~/.gemini/config/skills/vuln-guardian` ve `~/.claude/skills/vuln-guardian` sembolik bağlantılarını otomatik oluşturur.

### 3. Web Komut Merkezini Başlatın veya Vercel'e Yayınlayın

```bash
cp .env.example .env.local
# Private GitHub repoları ve otonom batch-canary doğrulama + main merge için GITHUB_TOKEN ekleyin
bun run dev
```

Yerelde test için `http://localhost:3400` adresini açabilir veya doğrudan kendi Vercel hesabınıza yayınlayabilirsiniz:

```bash
bunx --yes vercel@latest --prod
```

Projede [`vercel.json`](./vercel.json) içinde her akşam saat **20:30 (TSİ)** (`30 17 * * *` UTC) için otomatik tarama ve toplu iyileştirme zamanlayıcısı (`/api/cron/scan`) hazır tanımlıdır.

---

## 💻 CLI Kullanımı

```bash
# Kayıtlı projeleri ve tarama zamanlayıcısını listele
bun run guardian:list

# Tüm kayıtlı projeleri canlı OSV.dev ile tara ve toplu Safe-Version yamasını uygula
bun run guardian:scan

# Herhangi bir GitHub reposunu ekle ve tara
bun run guardian:add -- --name my-api --repo https://github.com/owner/repo --ecosystem npm --manifest package.json

# Bir klasördeki tüm projeleri (package.json, pom.xml, pubspec.yaml, requirements.txt, go.mod, Cargo.toml) otomatik keşfet
bun run guardian:discover -- --dir /path/to/projects

# Projeyi listeden kaldır
bun run guardian:remove -- --project my-api

# Güncel zafiyet bültenlerini (OSV.dev / GHSA / CVE) listele
bun run guardian:news
```
