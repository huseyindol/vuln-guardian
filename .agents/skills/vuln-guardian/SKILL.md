---
name: vuln-guardian
description: >-
  Autonomous vulnerability intelligence, scheduled multi-project dependency scanner,
  safe-version auto-remediation, and continuous deployment skill. Use this skill whenever
  the user wants to scan projects for CVEs/GHSA vulnerabilities, read security advisory news,
  automatically bump vulnerable packages to safe patched versions, run pre-deploy verification,
  deploy patched projects, or manage periodic vulnerability scanning schedules.
---

# VulnGuardian — Vulnerability Intelligence, Safe-Version Patcher & Auto-Deploy Skill

Bu skill, kayıtlı projelerin bağımlılık ağaçlarını (`package.json`, `pom.xml`, `pubspec.yaml`, `requirements.txt`, `go.mod`) belirli aralıklarla tarar, güncel zafiyet haberlerini (OSV.dev, GitHub Security Advisories, CISA KEV, CVE/NVD) okur, zafiyetli paket versiyonlarını **en yakın güvenli (safe/fixed) versiyona** çeker, doğrulama testlerini çalıştırır ve otomatik deploy çıkar.

## Mimari & Komut Merkezi

- **CLI & Otomasyon Motoru:** [scan-cli.mjs](./scripts/scan-cli.mjs)
- **Ekosistem Yama & Rollback Rehberi:** [remediation-playbook.md](./references/remediation-playbook.md)
- **Durum & Telemetri Kaynağı:** `src/data/guardian-state.json` (Web Dashboard ile gerçek zamanlı senkronize)

---

## Adım Adım İş Akışı (Agent Runbook)

### 1. Kayıtlı Projeleri ve Tarama Aralıklarını Listele

Taramaya alınan projeleri, tarama periyotlarını (`intervalMinutes`), son tarama zamanlarını ve aktif zafiyet sayılarını görmek için:

```bash
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs list
```

Yeni bir projeyi periyodik taramaya eklemek veya tarama aralığını güncellemek için:

```bash
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs add \
  --name "proje-adi" \
  --path "/mutlak/proje/yolu" \
  --interval 60 \
  --deploy "vercel --prod --yes" \
  --auto-remediate true
```

### 2. Güncel Zafiyet Haberlerini (Vulnerability Advisories & News) Oku

Projelerin kullandığı ekosistemlerle (`npm`, `Maven`, `Pub`, `PyPI`, `Go`) eşleşen son CVE/GHSA bültenlerini ve CISA KEV haberlerini çekmek için:

```bash
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs news
```

### 3. Bağımlılık ve Zafiyet Taraması Çalıştır (`scan`)

Tüm kayıtlı projeleri veya belirli bir projeyi canlı OSV.dev veritabanına karşı taramak için:

```bash
# Tüm projeleri tara
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs scan

# Tek bir projeyi tara
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs scan --project <project-id>
```

Bu komut:
1. Projenin manifest dosyasından (`package.json`, `pom.xml`, `pubspec.yaml` vb.) tüm doğrudan ve override paketlerini ve tam versiyonlarını çıkarır.
2. `https://api.osv.dev/v1/querybatch` ve `/v1/vulns/{id}` üzerinden aktif CVE/GHSA kayıtlarını sorgular.
3. Her zafiyet için `affected[].ranges[].events[].fixed` verisinden ve paket kayıt defterinden (`registry.npmjs.org`, Maven Central, `pub.dev`) **Safe Version (`fixedVersion`)** bilgisini hesaplar.
4. Sonuçları `src/data/guardian-state.json` dosyasına yazar.

### 4. Safe Versiyona Çek, Doğrula ve Deploy Çık (`remediate`)

Zafiyet tespit edilen bir projede paketleri güvenli versiyona yükseltmek, doğrulama komutunu çalıştırmak ve deploy çıkmak için:

```bash
# Belirli bir projedeki tüm zafiyetli paketleri safe versiyona çek ve deploy et
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs remediate \
  --project <project-id> \
  --apply \
  --deploy

# Yalnızca tek bir paketi safe versiyona çek
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs remediate \
  --project <project-id> \
  --pkg <paket-adi> \
  --apply \
  --deploy
```

**Güvenlik & Doğrulama Kuralları:**
- Manifest güncellendikten sonra projenin doğrulama komutu (`verifyCommand`: örn. `bun run type-check`, `./mvnw -q -DskipTests compile`, `flutter analyze`) çalıştırılır.
- Doğrulama başarısız olursa manifest otomatik olarak yedekten geri yüklenir (`rollback`) ve deploy durdurulur; kırık kod asla prod ortamına çıkmaz.
- Doğrulama başarılıysa `fix(security): upgrade <pkg> from <old> to <safe> (<CVE>)` commit'i oluşturulur ve `deployCommand` tetiklenir.

### 5. Periyodik Arka Plan Tarayıcısı (Scheduled Daemon & Cron)

Belirlenen tarama aralıklarına (`15dk`, `1 saat`, `6 saat`, `12 saat`, `24 saat`) göre projeleri otomatik taramak ve `autoRemediate: true` olan projeleri otonom yamayıp deploy etmek için:

```bash
# Sürekli çalışan zamanlayıcı daemon
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs daemon

# Tek seferlik "vakti gelen (due) projeleri tara" kontrolü (Cron / /schedule uyumlu)
node .agents/skills/vuln-guardian/scripts/scan-cli.mjs tick
```
