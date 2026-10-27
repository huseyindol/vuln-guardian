# Skill Studio — VulnGuardian Autonomous Security & Deploy Orchestrator

Bu çalışma alanı, projelerin güvenlik zafiyeti haberlerini (OSV.dev, GitHub Security Advisories, CISA KEV, CVE/NVD) okuyan, zafiyetli paket versiyonlarını **en yakın güvenli (`safe`) versiyona** çekip doğrulama sonrası **otomatik deploy** çıkan genel **`vuln-guardian`** skill'ini ve **Web Komut Merkezini (Dashboard)** barındırır.

## Bileşenler

| Bileşen | Konum | Açıklama |
|---|---|---|
| **Antigravity & Claude Skill** | `.agents/skills/vuln-guardian/SKILL.md` | Agent'ların tüm projelerde zafiyet taraması, bülten okuma, safe-version yamalama ve deploy için kullandığı genel skill (`~/.gemini/config/skills/vuln-guardian` olarak global tanımlıdır). |
| **CLI & Zamanlayıcı Daemon** | `.agents/skills/vuln-guardian/scripts/scan-cli.mjs` | `npm/Bun`, `Maven (pom.xml)` ve `Flutter/Dart (pubspec.yaml)` manifestlerini ayrıştıran, canlı `api.osv.dev` sorgusu yapan, safe-version yamalayan ve periyodik tarama yapan CLI motoru. |
| **Yama & Rollback Rehberi** | `.agents/skills/vuln-guardian/references/remediation-playbook.md` | Ekosistem bazlı yama, `overrides` / BOM pinleme ve doğrulama (`verifyCommand`) başarısızlığında otomatik rollback kuralları. |
| **Web Dashboard & API** | `src/app/` & `src/components/GuardianDashboard.tsx` | Taramaya alınan projeleri, tarama aralıklarını, paket/versiyon envanterini, aktif zafiyetleri ve canlı güvenlik haberlerini gösteren Next.js 16 kontrol paneli. |

## Hızlı Komutlar

```bash
# Kayıtlı projeleri ve tarama periyotlarını listele
bun run guardian:list

# Tüm projeleri canlı OSV.dev veritabanına karşı tara
bun run guardian:scan

# Güncel zafiyet bültenlerini ve haberlerini oku
bun run guardian:news

# Belirli bir projede zafiyetli paketleri safe versiyona çek, doğrula ve deploy çık
bun run guardian:remediate -- --project payment-gateway-demo --apply --deploy

# Arka plan periyodik tarama daemon'ını başlat
bun run guardian:daemon
```
