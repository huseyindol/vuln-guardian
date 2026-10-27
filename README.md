# 🛡️ VulnGuardian — Autonomous Vulnerability Intelligence, Canary Auto-Merge & Deploy Studio

**VulnGuardian**, çok dilli yazılım projelerinizin (`TypeScript/Node.js`, `Java/Spring Boot`, `Flutter/Dart`, `Python/PyPI`, `Go`, `Rust/Cargo`) bağımlılıklarını canlı **Google OSV.dev**, **GitHub Security Advisories (GHSA)** ve **NVD/CVE** veritabanlarına karşı tarayan, zafiyetli paketleri **kırılma yaratmayan en yakın güvenli (`Safe`) versiyona** yükselten ve **5 Aşamalı Otonom Canary Branch → Test → Otomatik `main` Merge & Deploy** hattıyla yayınlayan açık kaynaklı bir **Agent Skill** ve **Self-Hosted Web Komut Merkezidir (Next.js 16)**.

> **Nasıl Çalışır (Self-Hosted & Kişisel Kurulum):** Her geliştirici veya ekip bu repoyu kendi bilgisayarına klonlar, `bun run skill:install` ile skill'i kendi AI ajanına kurar ve kontrol panelini **kendi yerel makinesinde (`localhost:3400`)** veya **kendi Vercel / sunucu hesabında** kendi `GITHUB_TOKEN` anahtarıyla yayınlar.

---

## ✨ Temel Özellikler

1. **6 Dil & Ekosistem Desteği (Çoklu Manifest Ayrıştırıcı):**
   - **TypeScript / JavaScript (`npm` / `Bun`):** `package.json` (`dependencies`, `devDependencies`, `overrides`)
   - **Java / Kotlin (`Maven`):** `pom.xml` (`<parent>`, `<dependencies>`, Spring Boot BOM çözümleme)
   - **Dart / Flutter (`Pub`):** `pubspec.yaml` (`dependencies`, `dev_dependencies`)
   - **Python (`PyPI`):** `requirements.txt` & `pyproject.toml`
   - **Go (`Go Modules`):** `go.mod`
   - **Rust (`crates.io`):** `Cargo.toml`
2. **SemVer Breaking-Change Koruması & 5 Aşamalı Otonom Canary Auto-Merge:**
   - **1. İzole Canary Dalı (`BRANCH_ISOLATION`):** Canlı `main` dalına doğrudan dokunulmaz; `security/canary-<paket>-<versiyon>` dalı ve PR açılır.
   - **2. Bağımlılık & Peer Uyumluluk Kontrolü (`DEPENDENCY_COMPAT`):** Manifest sözdizimi ve çalışma ortamı uyumluluğu doğrulanır.
   - **3. Derleme, Type-Check & Lint Test Kapısı (`BUILD_AND_TEST`):** Projenin doğrulama komutu (`verifyCommand`) çalıştırılır.
   - **4. Çalışabilirlik & OSV Zero-CVE Smoke Kontrolü (`SMOKE_HEALTH_CHECK`):** Hedef sürümde 0 aktif zafiyet kaldığı ve GitHub CI Check-Run durumlarının yeşil olduğu doğrulanır.
   - **5. Otomatik `main` Merge & Deploy (`AUTO_MERGE_DEPLOY`):** Tüm testler hatasızsa PR otomatik olarak `main` dalına merge edilir ve deploy tetiklenir; en ufak bir hata varsa `main` merge engellenir ve canlı site korunur.
3. **Web Komut Merkezi (Dashboard) & İnteraktif Proje Ekleme:**
   - Arayüzdeki **"+ Yeni Proje / GitHub Repo Ekle"** penceresinden herhangi bir public/private GitHub reposunu (`https://github.com/kullanici/proje`) veya yerel dizini saniyeler içinde taramaya dahil edebilirsiniz.
4. **Taşınabilir AI Agent Skill (`Antigravity` & `Claude Code`):**
   - `.agents/skills/vuln-guardian/SKILL.md` standardıyla paketlenmiştir; tek komutla global olarak tüm projelerinizde aktifleşir.

---

## 🚀 Hızlı Kurulum

### 1. Repoyu Klonlayın ve Bağımlılıkları Kurun

```bash
git clone https://github.com/huseyindol/skill_studio.git
cd skill_studio
bun install
```

### 2. Agent Skill'i Global Olarak Kurun (Antigravity & Claude Code)

```bash
bun run skill:install
```

Bu komut `~/.gemini/config/skills/vuln-guardian` ve `~/.claude/skills/vuln-guardian` sembolik bağlantılarını otomatik oluşturur.

### 3. Web Komut Merkezini Başlatın

```bash
cp .env.example .env.local
# İsteğe bağlı: Private GitHub repoları ve otomatik PR/Merge için GITHUB_TOKEN ekleyin
bun run dev
```

Tarayıcınızda `http://localhost:3400` adresini açın.

---

## 💻 CLI Kullanımı

```bash
# Kayıtlı projeleri ve tarama zamanlayıcısını listele
bun run guardian:list

# Tüm kayıtlı projeleri canlı OSV.dev ile tara ve Safe-Version yamasını uygula
bun run guardian:scan

# Herhangi bir GitHub reposunu veya yerel projeyi ekle ve tara
bun run guardian:add -- --name my-api --repo https://github.com/owner/repo --ecosystem npm --manifest package.json

# Bir klasördeki tüm projeleri (package.json, pom.xml, pubspec.yaml, requirements.txt, go.mod, Cargo.toml) otomatik keşfet
bun run guardian:discover -- --dir /path/to/projects

# Projeyi listeden kaldır
bun run guardian:remove -- --project my-api

# Güncel zafiyet bültenlerini (OSV.dev / GHSA / CVE) listele
bun run guardian:news
```

---

## ☁️ Vercel Üzerinde Yayınlama

Projede [`vercel.json`](./vercel.json) içinde günlük otomatik tarama zamanlayıcısı (`/api/cron/scan`) hazır tanımlıdır:

```bash
bunx vercel@latest deploy --prod
```

GitHub üzerinde otomatik dal açma, PR oluşturma ve test sonrası `main` merge işlemleri için Vercel proje ayarlarına `GITHUB_TOKEN` ortam değişkenini eklemeniz yeterlidir.
