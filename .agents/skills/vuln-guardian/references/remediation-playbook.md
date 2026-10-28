# VulnGuardian — Safe-Version Remediation & Deployment Playbook

> **Dil / Language:** [🇹🇷 Türkçe](./remediation-playbook.md) · [🇬🇧 English](./remediation-playbook.en.md)

Bu referans dokümanı, farklı ekosistemlerde zafiyetli paketlerin güvenli (`safe`) versiyonlara çekilmesi, geçişli (transitive) bağımlılıkların ezilmesi ve güvenli deploy kurallarını tanımlar.

## 1. Ekosistem Bazlı Safe-Version Güncelleme Kuralları

### A. Node.js / Bun / npm (`package.json`)
- **Doğrudan Bağımlılıklar (`dependencies` / `devDependencies`):**
  - Mevcut aralık öneki (`^` veya `~`) korunarak veya tam güvenli versiyon (`x.y.z`) yazılarak güncellenir.
  - Eğer `fixedVersion` mevcut versiyonla aynı major sürümdeyse (`semver` minor/patch), doğrudan yükseltilir.
- **Kardeş (Lockstep Peer) Paket Ailesi Senkronizasyonu (`NPM_LOCKSTEP_PEER_FAMILIES`):**
  - Birlikte aynı versiyonda yürümesi zorunlu olan paket ailelerinden (`vitest` / `@vitest/ui` / `@vitest/coverage-v8`, `react` / `react-dom`, `@angular/*`) herhangi biri güncellendiğinde, `package.json` içindeki diğer aile üyeleri de otomatik olarak aynı hedef versiyona yükseltilir (`incorrect peer dependency` hatasını önler).
- **Geçişli Bağımlılıklar (`overrides` / `resolutions`):**
  - Zafiyet bir alt paketten geliyorsa `package.json` içindeki `"overrides"` bloğuna `"<pkg>": "^<fixedVersion>"` eklenir veya güncellenir.
- **Zorunlu Lockfile (`bun.lock` / `package-lock.json`) Atomik Senkronizasyonu:**
  - `package.json` güncellendiğinde CI/CD ortamlarında `bun install --frozen-lockfile` veya `npm ci` komutlarının `error: lockfile had changes, but lockfile is frozen` hatasıyla patlamaması için `bun.lock` (`workspaces[""]`, `overrides`, `packages` tuple'ları + `registry.npmjs.org` integrity/alt-bağımlılık ağacı) ve `package-lock.json` dosyaları otomatik senkronize edilir ve GitHub Git Data Tree API üzerinden `package.json` ile **tek bir atomik commit** içinde gönderilir.
- **Doğrulama:**
  - `bun install --frozen-lockfile` (veya `npm ci`) ardından `bun run type-check` veya `npm test` çalıştırılır.

### B. Java / Spring Boot (`pom.xml`)
- **Açık Versiyonlu Bağımlılıklar (`<version>`):**
  - İlgili `<dependency>` bloğundaki `<version>` etiketi doğrudan `fixedVersion` ile güncellenir.
- **Parent POM'dan Miras Alınan Bağımlılıklar (`spring-boot-starter-*`):**
  - Eğer zafiyet Spring Boot starter'larından veya alt kütüphanelerinden (örn. `commons-lang3`, `jsoup`, `jackson-databind`) kaynaklanıyorsa:
    1. Üst `<parent>` versiyonu güvenli Spring Boot sürümüne çekilir, VEYA
    2. `pom.xml` içine ilgili alt kütüphane açık `<version>` ile pinlenir (örn. `CVE-2025-48924` için `commons-lang3` `3.20.0` pinlemesi).
- **Doğrulama:**
  - `./mvnw -q -DskipTests compile` çalıştırılır.

### C. Flutter / Dart (`pubspec.yaml`)
- `dependencies` veya `dev_dependencies` altındaki paket `^<fixedVersion>` olarak güncellenir.
- Alt bağımlılık çakışması varsa `dependency_overrides:` bloğuna eklenir.
- **Doğrulama:**
  - `flutter pub get && flutter analyze --no-fatal-infos` çalıştırılır.

---

## 2. Tek Seferde Toplu (Single-Batch) Safe-Version, Breaking-Change Kontrolü & Otomatik Deploy (Patch, Minor ve Major Dahil)

Bir projede kaç adet zafiyetli paket tespit edilirse edilsin (**her paket için ayrı PR açılmaz**); Patch, Minor ve Major (`BREAKING_MAJOR`) güncellemelerin tamamı tek bir toplu akışta doğrulanıp gönderilir:

1. **Aşama 1 — Tüm Zafiyetli Paketlerin Güvenli Versiyona Çekilmesi (`BATCH_PREPARATION`):**
   - Projedeki tüm zafiyetli paketler (`SAFE_PATCH`, `MINOR_VERIFY` ve `BREAKING_MAJOR` dahil) tek bir manifest (`package.json`, `pom.xml`, `pubspec.yaml` vb.) üzerinde önerilen güvenli (`safe`) versiyonlarına çekilir.
2. **Aşama 2 — Bağımlılık & Peer Uyumluluk Kontrolü (`DEPENDENCY_COMPAT`):**
   - Manifest sözdizimi ve peer-dependency / framework uyumluluğu doğrulanır.
3. **Aşama 3 — Breaking-Change, Derleme, Type-Check & Lint Kapısı (`BUILD_AND_TEST`):**
   - Projenin `verifyCommand` komutu (`bun run lint && bun run type-check && bun run test:ci`, `./mvnw -q -DskipTests compile`, `flutter analyze && flutter test`) çalıştırılarak özellikle Major sürüm geçişlerinde herhangi bir breaking-change olup olmadığı ve sitenin hatasız derlendiği kontrol edilir.
4. **Aşama 4 — Çalışabilirlik & OSV Zero-CVE Smoke Kontrolü (`SMOKE_HEALTH_CHECK`):**
   - Hedef versiyonlarda OSV.dev üzerinde 0 aktif zafiyet kaldığı ve uygulamanın çalışabilir (smoke check) durumda olduğu doğrulanır.
5. **Aşama 5 — Tek Seferde Toplu Gönderim & Deploy (`AUTO_MERGE_DEPLOY`):**
   - **Hata Yoksa (`ALL PASSED`):** Doğrulamadan geçen tüm paketler (Major güncellemeler dahil) **tek bir toplu commit (`fix(security): batch upgrade verified packages`)** ile `main` dalına gönderilir ve canlı deploy (`AUTO_MERGED_DEPLOYED`) tek seferde tetiklenir.
   - **Breaking-Change Varsa (`FAILED`):** Sitenin çalışmasını veya derlemeyi bozan paket toplu gönderimden otomatik olarak çıkarılır (`BLOCKED_BREAKING`), canlı site korunur; diğer sağlam paketler güvenle gönderilir.
