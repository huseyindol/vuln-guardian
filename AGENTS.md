# VulnGuardian — Autonomous Vulnerability Intelligence & Single-Batch Safe-Version Skill

Bu depo (`huseyindol/vuln-guardian`), çok dilli yazılım projelerinin güvenlik zafiyeti bültenlerini (OSV.dev, GitHub Security Advisories, CISA KEV, CVE/NVD) okuyan, zafiyetli paketlerin tamamını (Patch, Minor ve Major dahil) **en yakın güvenli (`safe`) versiyona** çekip **prod (`main`) öncesi Breaking-Change & Site Çalışabilirlik kontrolünden** geçirdikten sonra **PR açmadan tek seferde (`single-batch`) `main` dalına birleştirip deploy** çıkan genel **`vuln-guardian`** skill'ini ve **Next.js 16 Web Komut Merkezini** barındırır.

## Bileşenler

| Bileşen | Konum | Açıklama |
|---|---|---|
| **Antigravity & Claude Skill** | `.agents/skills/vuln-guardian/SKILL.md` | Agent'ların tüm projelerde zafiyet taraması, bülten okuma, toplu safe-version yamalama, breaking-change kontrolü ve deploy için kullandığı genel skill (`~/.gemini/config/skills/vuln-guardian` ve `~/.claude/skills/vuln-guardian`). |
| **CLI & Otomasyon Motoru** | `.agents/skills/vuln-guardian/scripts/scan-cli.mjs` | 6 ekosistemi (`npm/Bun`, `Maven`, `Pub`, `PyPI`, `Go`, `crates.io`) ayrıştıran, canlı `api.osv.dev` sorgusu yapan ve toplu safe-version yamalayan CLI motoru. |
| **Yama & Breaking-Change Rehberi** | `.agents/skills/vuln-guardian/references/remediation-playbook.md` | Ekosistem bazlı yama, `overrides` / BOM pinleme, izole `security/batch-canary` doğrulaması ve tek seferde `main` merge kuralları. |
| **Web Komut Merkezi & API** | `src/app/` & `src/components/GuardianDashboard.tsx` | Taramaya alınan projeleri, 20:30 günlük otonom tarama zamanlayıcısını, paket/versiyon envanterini, aktif zafiyetleri ve canlı güvenlik haberlerini gösteren Next.js 16 kontrol paneli. |

## Hızlı Komutlar

```bash
# Global skill bağlantılarını kur (Antigravity & Claude Code)
bun run skill:install

# Kayıtlı projeleri ve tarama saatlerini listele
bun run guardian:list

# Tüm projeleri canlı OSV.dev veritabanına karşı tara ve toplu Safe-Version uygula
bun run guardian:scan

# Güncel zafiyet bültenlerini ve haberlerini oku
bun run guardian:news

# Belirli bir projede tüm zafiyetli paketleri safe versiyona çek, doğrula ve tek seferde gönder
bun run guardian:remediate -- --project elly-admin --apply --deploy
```
