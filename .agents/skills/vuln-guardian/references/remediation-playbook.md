# VulnGuardian — Safe-Version Remediation & Deployment Playbook

Bu referans dokümanı, farklı ekosistemlerde zafiyetli paketlerin güvenli (`safe`) versiyonlara çekilmesi, geçişli (transitive) bağımlılıkların ezilmesi ve güvenli deploy kurallarını tanımlar.

## 1. Ekosistem Bazlı Safe-Version Güncelleme Kuralları

### A. Node.js / Bun / npm (`package.json`)
- **Doğrudan Bağımlılıklar (`dependencies` / `devDependencies`):**
  - Mevcut aralık öneki (`^` veya `~`) korunarak veya tam güvenli versiyon (`x.y.z`) yazılarak güncellenir.
  - Eğer `fixedVersion` mevcut versiyonla aynı major sürümdeyse (`semver` minor/patch), doğrudan yükseltilir.
- **Geçişli Bağımlılıklar (`overrides` / `resolutions`):**
  - Zafiyet bir alt paketten geliyorsa `package.json` içindeki `"overrides"` bloğuna `"<pkg>": "^<fixedVersion>"` eklenir veya güncellenir.
- **Doğrulama:**
  - `bun install` (veya `npm install --package-lock-only`) ardından `bun run type-check` veya `npm test` çalıştırılır.

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

## 2. Otonom Canary Branch → 4 Aşamalı Doğrulama Kapısı → Otomatik `main` Merge & Deploy (Major Güncellemeler)

Major (`BREAKING_MAJOR`) veya yüksek riskli paket güncellemelerinde canlı `main` dalını asla doğrudan riske atmadan tamamen otonom doğrulama ve birleştirme akışı uygulanır:

1. **Aşama 1 — İzole Canary Dalı & PR (`BRANCH_ISOLATION`):**
   - `main` dalından `security/canary-<paket>-<hedefVersiyon>` adında izole bir dal oluşturulur ve manifest güncellemesi bu dala commitlenerek PR açılır.
2. **Aşama 2 — Bağımlılık & Peer Uyumluluk Kontrolü (`DEPENDENCY_COMPAT`):**
   - `package.json` / `pom.xml` / `pubspec.yaml` sözdizimi ve peer-dependency / framework uyumluluğu doğrulanır.
3. **Aşama 3 — Derleme, Type-Check & Lint Kapısı (`BUILD_AND_TEST`):**
   - Projenin `verifyCommand` komutu (`bun run lint && bun run type-check && bun run test:ci`, `./mvnw -q -DskipTests compile`, `flutter analyze && flutter test`) ve GitHub Check Suites çalıştırılır.
4. **Aşama 4 — Çalışabilirlik & OSV Zero-CVE Smoke Kontrolü (`SMOKE_HEALTH_CHECK`):**
   - Hedef versiyonda (`<paket>@<hedefVersiyon>`) OSV.dev üzerinde 0 aktif zafiyet kaldığı, GitHub Commit Status/Check Runs kontrollerinin yeşil olduğu ve derleme çıktısının hatasız üretildiği doğrulanır.
5. **Aşama 5 — Otomatik `main` Merge & Deploy VEYA Rollback (`AUTO_MERGE_DEPLOY`):**
   - **Hata Yoksa (`ALL PASSED`):** GitHub Pull Request Merge API (`PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge`, `merge_method: "squash"`) çağrılarak izole canary dalı **otomatik olarak `main` dalına merge edilir**, geçici canary dalı silinir ve canlı deploy (`AUTO_MERGED_DEPLOYED`) tetiklenir.
   - **En Ufak Bir Hata Varsa (`FAILED`):** `main` dalına merge **otomatik olarak engellenir** (`BLOCKED_BREAKING` / `ROLLED_BACK`), canlı site korunur ve izole dal/PR hata raporuyla birlikte açık bırakılır.
