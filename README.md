# N8N-WAZUH-KIBANA
Integration N8N as SOAR, WAZUH as SIEM & KIBANA For Geo Enrichment Mapping

---

## 📋 Daftar Isi
- [Tentang Project](#tentang-project)
- [Arsitektur](#arsitektur)
- [⚠️ PENTING: Prasyarat Wajib](#️-penting-prasyarat-wajib)
- [Fitur](#fitur)
- [Struktur Repositori](#struktur-repositori)

---

## Tentang Project

Project ini mengintegrasikan:
- **N8N** sebagai platform SOAR (Security Orchestration, Automation and Response)
- **Wazuh** sebagai SIEM (Security Information and Event Management)
- **Kibana** untuk Geo Enrichment Mapping dan visualisasi

---

## Arsitektur

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Wazuh Agent   │────▶│  Wazuh Manager  │────▶│      N8N        │
│   (Endpoint)    │     │   (SIEM)        │     │    (SOAR)       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │     Kibana      │
                                                │ (Visualization) │
                                                └─────────────────┘
```

---

## ⚠️ PENTING: Prasyarat Wajib

> **🚨 SEBELUM MENGIKUTI TUTORIAL APAPUN DI REPOSITORI INI, ANDA WAJIB MEMBUAT SCRIPT `custom-n8n` TERLEBIH DAHULU!**

Script `custom-n8n` adalah **custom integration Wazuh** yang berfungsi untuk mengirim alert dalam format JSON ke webhook N8N menggunakan metode HTTP POST. Tanpa script ini, integrasi Wazuh-N8N **TIDAK AKAN BERFUNGSI**.

### Langkah-langkah Membuat Script custom-n8n:

**1. Buat file script di direktori integrations Wazuh:**
```bash
sudo nano /var/ossec/integrations/custom-n8n
```

**2. Salin dan paste seluruh kode berikut:**
```python
#!/var/ossec/framework/python/bin/python3
import json
import os
import re
import ssl
import sys
import time
import urllib.request

LOG_FILE = "/var/ossec/logs/integrations.log"

def log(line: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{ts} custom-n8n: {line}\n")

def find_alert_file(args):
    # Wazuh selalu mengirim path file alert JSON sebagai salah satu argumen awal.
    for a in args[1:]:
        if a and os.path.isfile(a):
            return a
    return None

def find_hook_url(args):
    # Cari argumen yang mirip URL http(s)
    for a in args:
        if a and re.match(r"^https?://", a):
            return a
    return None

def find_api_key(args):
    # API key bisa datang dari <api_key> atau argumen tambahan.
    # Jika tidak ada, coba environment var.
    for a in args:
        if a and len(a) >= 16 and not a.startswith("/") and not a.startswith("http"):
            # heuristik sederhana: string panjang, bukan path, bukan url
            return a
    return os.environ.get("N8N_API_KEY", "")

def main():
    args = sys.argv
    debug = ("debug" in args)

    try:
        alert_file = find_alert_file(args)
        hook_url = find_hook_url(args)
        api_key  = find_api_key(args)

        if debug:
            log(f"ARGS={args}")

        if not alert_file:
            log("ERROR: alert file not found in args")
            sys.exit(2)
        if not hook_url:
            log("ERROR: hook_url not found in args")
            sys.exit(3)

        # Load alert JSON
        with open(alert_file, "r") as f:
            alert = json.load(f)

        # Kirim apa adanya (biar n8n yang proses)
        payload = json.dumps(alert).encode("utf-8")

        req = urllib.request.Request(
            hook_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "wazuh-custom-n8n",
                "X-Api-Key": api_key
            },
            method="POST"
        )

        # Jika kamu pakai TLS self-signed di n8n, ini akan mengabaikan verifikasi.
        # Kalau sertifikat valid, aman juga.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            status = resp.getcode()
            body = resp.read(200).decode("utf-8", errors="ignore")
            log(f"POST {hook_url} status={status} resp={body[:200]}")

        sys.exit(0)

    except Exception as e:
        log(f"ERROR: exception={repr(e)}")
        sys.exit(10)

if __name__ == "__main__":
    main()
```

**3. Simpan file dan set permission yang benar:**
```bash
sudo chmod 750 /var/ossec/integrations/custom-n8n
sudo chown root:wazuh /var/ossec/integrations/custom-n8n
```

**4. Verifikasi file sudah terbuat dengan benar:**
```bash
ls -la /var/ossec/integrations/custom-n8n
```

### Penjelasan Fungsi Script:

| Fungsi | Deskripsi |
|--------|-----------|
| `log()` | Mencatat log ke `/var/ossec/logs/integrations.log` |
| `find_alert_file()` | Mencari file alert JSON dari argumen Wazuh |
| `find_hook_url()` | Mengekstrak URL webhook N8N dari argumen |
| `find_api_key()` | Mencari API key (opsional) untuk autentikasi |
| `main()` | Fungsi utama yang membaca alert dan mengirim via HTTP POST |

### Catatan Penting:
- Script ini menggunakan Python dari Wazuh framework (`/var/ossec/framework/python/bin/python3`)
- SSL verification dinonaktifkan untuk mendukung self-signed certificate
- Log tersimpan di `/var/ossec/logs/integrations.log` untuk debugging
- Timeout request adalah 10 detik

---

## Fitur

### 🔴 SSH Brute Force Detection
Mendeteksi serangan brute force SSH dan mengirim alert ke N8N untuk response otomatis.
- **Direktori:** `🔴 Wazuh Alert - SSH Brute Force/`
- **Tutorial:** Lihat `Tutor Node SSH Alert.txt`

### ✅ Malicious File Detection  
Mendeteksi file berbahaya menggunakan File Integrity Monitoring (FIM) dan integrasi VirusTotal.
- **Direktori:** `✅ Wazuh Alert - Malicious File Detection/`
- **Tutorial:** Lihat `Tutor Node File Alert.txt`

---

## Struktur Repositori

```
N8N-WAZUH-KIBANA/
├── README.md                                    # Dokumentasi utama
├── custom-n8n                                   # Script integrasi Wazuh-N8N
├── 🔴 Wazuh Alert - SSH Brute Force/
│   └── Tutor Node SSH Alert.txt                 # Tutorial SSH alert
└── ✅ Wazuh Alert - Malicious File Detection/
    ├── Tutor Node File Alert.txt                # Tutorial file detection
```

---

## 📝 Alur Kerja

1. **Wazuh Agent** mendeteksi event (SSH brute force, file baru, dll.)
2. **Wazuh Manager** memproses alert berdasarkan rules
3. **Script custom-n8n** mengirim alert ke webhook N8N dalam format JSON
4. **N8N** melakukan automasi response (enrichment, notification, blocking, dll.)
5. **Kibana** menampilkan visualisasi dan geo mapping

---

## 🤝 Kontribusi

Silakan buat pull request atau issue jika menemukan bug atau ingin menambahkan fitur baru.

---

## 📄 Lisensi

MIT License - silakan gunakan dan modifikasi sesuai kebutuhan.
