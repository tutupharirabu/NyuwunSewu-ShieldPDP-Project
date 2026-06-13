# Design — PDP-03 Breach Automation: Auto-trigger, SLA Monitor & Frontend

**Date:** 2026-06-13
**Status:** Approved (pending spec review)
**Topic:** Mengotomatiskan alur breach notification Pasal 46 UU PDP — deteksi otomatis setelah scan, pemantauan SLA 3×24 jam, dan UI untuk melihat/menghasilkan surat notifikasi.

---

## 1. Latar Belakang & Tujuan

`BreachNotificationService` (`app/services/breach_notification.py`) sudah lengkap dan teruji (20 test): deteksi breach, klasifikasi, generate surat Pasal 46, hitung SLA 72 jam, kirim Telegram. API-nya juga lengkap (6 endpoint di `app/api/compliance.py`). DB model `BreachNotification` (`app/models/agent.py`) sudah ada.

**Tiga gap yang ditutup spec ini:**

1. **Tidak auto-trigger** — `detect_breach` hanya dipanggil manual via API; tidak otomatis setelah scan selesai.
2. **SLA monitoring pasif** — `check_sla_compliance` hanya dihitung saat endpoint dipanggil; tidak ada proses yang proaktif memantau jam 72 jam berjalan.
3. **Tidak ada frontend** — nol referensi breach di `frontend/`; surat notifikasi tidak bisa dilihat/di-generate dari UI.

**Tujuan:** scan selesai → breach terdeteksi & tercatat otomatis (jam SLA jalan) → tim dapat Telegram alert → scheduler mengingatkan berjenjang sampai dinotifikasi → operator bisa lihat, salin, dan unduh surat dari UI.

---

## 2. Keputusan Desain (hasil brainstorming)

| Keputusan | Pilihan |
|---|---|
| Tingkat otomasi auto-trigger | **Opsi A** — assess + create record (mulai jam SLA) otomatis; pengiriman **surat resmi tetap manual**. |
| Notifikasi otomatis | **Telegram alert internal** ke tim (`build_telegram_message`), **bukan** surat resmi ke otoritas/pengguna. |
| Mekanisme scheduler | **asyncio background task** di FastAPI `lifespan`. Tanpa APScheduler/Celery (YAGNI). |
| Ambang reminder SLA | **48 / 24 / 6 / 1 jam** tersisa, lalu **overdue**. Sekali per ambang (anti-spam). |
| Penerima surat (Pasal 46 ayat 1) | **DUA varian**: (A) ke otoritas pengawas, (B) ke subjek data/pengguna. |
| Nama otoritas pengawas | **Configurable** via setting. Default **Kementerian Komunikasi dan Digital (Komdigi)** — karena Lembaga PDP belum sepenuhnya beroperasi per 2026. |
| Frontend create/assess manual | **Di luar scope** — auto-trigger sudah menggantikannya. FE hanya list/lihat/notify/dismiss. |

### Catatan domain (penting untuk akurasi)
- **Target** = sistem yang di-scan; **tidak pernah** menerima surat.
- **Pengendali Data Pribadi** (perusahaan pemilik target) = **pengirim** surat.
- **Penerima** = **subjek data (pengguna)** + **otoritas pengawas** (saat ini Kemkomdigi).
- Yang dideteksi adalah **kerentanan yang berpotensi breach**, jadi surat bersifat **draft kesiapan kepatuhan**, dikirim resmi hanya bila breach nyata terjadi.

---

## 3. Fitur 1 — Auto-assess Breach Setelah Scan

### 3.1 Refactor (anti-duplikasi)
Logika "findings → `detect_breach` → buat `BreachNotification` → generate surat" saat ini inline di endpoint `POST /compliance/breach-create`. Ekstrak menjadi fungsi reusable:

```python
# app/services/breach_notification.py (atau orchestrator tipis baru)
@classmethod
async def persist_breach(
    cls,
    session: AsyncSession,
    organization_id: str,
    finding_dicts: list[dict],
    org_name: str = "",
    contact_info: str = "",
) -> BreachNotification | None:
    """Assess findings; jika wajib lapor, buat record BreachNotification (mulai
    jam SLA), generate kedua varian surat, commit, dan kembalikan record.
    Kembalikan None bila bukan breach wajib-lapor."""
```

Endpoint `breach-create` diubah memakai `persist_breach` (satu sumber kebenaran).

### 3.2 Hook di scan_service
Di `app/services/scan_service.py`, setelah scan menjadi `COMPLETED` (sekitar baris 287–288, setelah commit & sebelum/sesudah `_dispatch_webhooks`):

1. Muat semua `Finding` milik scan (`Finding.scan_id == scan.id`) → ubah ke dict (`id, finding_type, severity, title, evidence_summary, compliance`).
2. Panggil `persist_breach(self.session, scan.organization_id, finding_dicts, org_name)`.
3. Jika record dikembalikan (≠ None): kirim **Telegram alert internal** via `build_telegram_message` + `send_telegram_notification`; catat channel ke `notification_channels`.
4. **Seluruh blok dibungkus `try/except`** dengan logging — kegagalan assess/Telegram **tidak boleh menggagalkan scan**.

Hanya berjalan pada jalur `COMPLETED` (bukan `FAILED`/`STOPPED`).

### 3.3 org_name
Diambil dari `Organization` via `scan.organization_id` (query ringan), sama seperti yang dilakukan endpoint `breach-create` saat ini.

---

## 4. Fitur 2 — SLA Monitor (asyncio)

### 4.1 Modul baru `app/services/sla_monitor.py`

**Fungsi murni (mudah di-test, tanpa DB/waktu):**
```python
def due_sla_alerts(
    hours_remaining: float,
    is_overdue: bool,
    already_sent: list[str],
    thresholds: list[int],
) -> list[str]:
    """Kembalikan label ambang yang BARU harus dialertkan.
    - Untuk tiap threshold T (mis. 48,24,6,1): jika hours_remaining <= T
      dan "T" belum ada di already_sent → ikutkan.
    - Jika is_overdue dan "overdue" belum terkirim → ikutkan "overdue".
    Tidak menyertakan yang sudah pernah dikirim (anti-spam)."""
```

**Loop scheduler:**
```python
async def run_sla_monitor(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            await _tick()
        except Exception:
            logger.exception("SLA monitor tick failed")  # loop tak pernah mati
        await _wait(interval, stop_event)  # bisa di-interrupt saat shutdown
```

**`_tick()`** (satu sesi DB per tick):
1. Query `BreachNotification` dengan `status NOT IN ("notified", "dismissed")`.
2. Untuk tiap record: `sla = check_sla_compliance(detected_at)` → `hours_remaining`, `is_overdue`.
3. `new = due_sla_alerts(hours_remaining, is_overdue, record.sla_alerts_sent, thresholds)`.
4. Untuk tiap label di `new`: kirim Telegram reminder (template ringkas dengan sisa jam / status overdue); append label ke `record.sla_alerts_sent`.
5. Jika `is_overdue` dan `record.status != "overdue"`: set `record.status = "overdue"`.
6. Commit perubahan.

### 4.2 Perubahan DB
Tambah kolom ke `BreachNotification` (`app/models/agent.py`):
```python
sla_alerts_sent: Mapped[list[str]] = mapped_column(
    JSON, default=list, nullable=False,
    comment="SLA alert thresholds already sent: e.g. ['48','24','overdue']")
```
**Satu migrasi Alembic** menambah kolom ini.

> Kolom ke-2 untuk varian surat subjek data dibahas di §5.2 dan dimasukkan ke migrasi yang sama.

### 4.3 Wiring di `main.py`
Di dalam `lifespan`: jika `settings.enable_sla_monitor`, buat `stop_event = asyncio.Event()` dan `task = asyncio.create_task(run_sla_monitor(stop_event))` sebelum `yield`; pada shutdown (`finally`) set `stop_event.set()` lalu `await task` (dengan timeout/guard). Berjalan satu instance per proses aplikasi.

### 4.4 Config baru (`app/core/config.py`)
```python
enable_sla_monitor: bool = True
sla_monitor_interval_seconds: int = 900            # 15 menit
sla_alert_thresholds: list[int] = [48, 24, 6, 1]   # jam tersisa
pdp_authority_name: str = "Kementerian Komunikasi dan Digital (Komdigi)"
```

---

## 5. Fitur 3 — Frontend Breach Notification

Stack FE: React 18 + Vite + TypeScript + Tailwind + Radix + lucide-react. Tanpa dependensi baru.

### 5.1 API client (`frontend/src/lib/api.ts`)
Tambah method untuk endpoint yang sudah ada:
- `breaches()` → `GET /compliance/breaches`
- `breach(id)` → `GET /compliance/breach/{id}` (termasuk kedua varian surat)
- `breachNotify(id, { channels, contact_info })` → `POST /compliance/breach-notify`
- `breachDismiss(id, reason)` → `POST /compliance/breach-dismiss`

`breach-assess`/`breach-create` **tidak** diekspos ke FE (auto-trigger menggantikan).

### 5.2 Dua varian surat (backend)
`generate_notification_text()` diperluas / dipasangkan dengan generator varian subjek data:
- **Varian A — otoritas pengawas**: ganti baris hardcode `"Kepada Yth. Badan Pelindungan Data Pribadi"` menjadi `f"Kepada Yth. {settings.pdp_authority_name}"`. Tetap formal/regulator. Disimpan di kolom `notification_text` (existing).
- **Varian B — subjek data/pengguna**: surat baru, bahasa awam, memuat **langkah konkret** (ganti password, blokir kartu, waspada penipuan) + jenis data terdampak. Disimpan di kolom baru:
  ```python
  notification_text_subject: Mapped[str | None] = mapped_column(Text, nullable=True)
  ```
  Ditambahkan ke migrasi Alembic yang sama (§4.2). `persist_breach` mengisi kedua kolom saat record dibuat. Detail endpoint mengembalikan keduanya.

### 5.3 Komponen `BreachNotificationsPanel` (di `compliance.tsx`)
Diletakkan dekat `BreachReadinessImpl` (baris ~770). Fungsi:
- **Daftar breach**: severity badge + **countdown SLA** dari `hours_remaining`/`sla_deadline` (warna berubah <24j & <6j; label `OVERDUE` merah saat lewat) + status.
- **Detail** (ikuti pola `RegulatoryDrawer` yang sudah ada di file ini): tampilkan **kedua varian surat** dengan toggle (Otoritas / Subjek Data), masing-masing tombol **Copy** & **Download .txt**.
- **Aksi**: "Tandai sudah dinotifikasi" (`breachNotify`) dan "Dismiss" dengan input alasan (`breachDismiss`).

### 5.4 Tanpa dialog blocking
Konfirmasi Dismiss dibuat **inline** (bukan `window.confirm`/alert) agar tidak memblokir.

---

## 6. Error Handling
- **Auto-trigger**: `try/except` menyeluruh; kegagalan tidak menggagalkan scan; semua error di-log.
- **SLA monitor**: tiap tick `try/except`; loop tidak pernah mati; Telegram gagal hanya di-log.
- **Telegram tanpa konfigurasi**: `send_telegram_notification` sudah mengembalikan `{success: False, ...}` secara graceful — tidak ada exception.
- **FE**: error fetch ditampilkan inline; aksi non-blocking.

---

## 7. Testing

### Backend (pytest)
- **`due_sla_alerts`** (unit, murni): berbagai `hours_remaining` vs `thresholds`; menghormati `already_sent`; transisi `overdue`; tidak mengirim ulang.
- **`persist_breach`**: findings PII critical → record dibuat + kedua varian surat terisi; findings non-notifiable → `None`.
- **Auto-trigger**: scan completed dengan finding PII critical → ada `BreachNotification`; tanpa finding wajib-lapor → tidak ada. (Integrasi alur scan bila praktis.)
- **Varian surat**: surat otoritas memuat `pdp_authority_name` dari setting; surat subjek data memuat imbauan tindakan.
- **Regresi**: 20 test `test_breach_notification.py` tetap hijau setelah refactor; endpoint `breach-create` tetap berfungsi.

### Frontend
- Tidak ada test runner di `package.json` saat ini → verifikasi via **`tsc` + `vite build` hijau** dan cek render manual. Tidak menambah framework test baru (di luar scope).

---

## 8. Ringkasan File Terdampak
- `app/services/breach_notification.py` — `persist_breach`, dua varian surat, pakai `pdp_authority_name`.
- `app/services/sla_monitor.py` — **baru**: `due_sla_alerts` + `run_sla_monitor`.
- `app/services/scan_service.py` — hook auto-trigger pada COMPLETED.
- `app/api/compliance.py` — `breach-create` pakai `persist_breach`; detail kembalikan kedua varian.
- `app/models/agent.py` — kolom `sla_alerts_sent`, `notification_text_subject`.
- `app/core/config.py` — 4 setting baru.
- `app/main.py` — start/stop SLA monitor di `lifespan`.
- `alembic/versions/*` — **satu** migrasi (dua kolom baru).
- `frontend/src/lib/api.ts` — 4 method breach.
- `frontend/src/pages/compliance.tsx` — `BreachNotificationsPanel` + detail dua varian.

---

## 9. Di Luar Scope (YAGNI)
- Tombol create/assess manual di FE.
- Pengiriman surat resmi otomatis ke otoritas/pengguna (tetap keputusan manusia).
- Channel email/SMS (hanya Telegram + dashboard).
- Framework test FE baru.
- APScheduler/Celery-beat untuk scheduler.
