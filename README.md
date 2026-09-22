# ArcGIS Enterprise Hardening Utility v2

Milestone 1 membangun fondasi koneksi dan target discovery. Aplikasi lama tidak diperlukan untuk menjalankan milestone ini.

## Kemampuan

- Mode ArcGIS Enterprise: Portal URL + administrator credential.
- Discovery semua federated server melalui Portal Administrator API.
- Pertukaran Portal token menjadi server-token per federated site.
- Mode standalone ArcGIS Server menggunakan Primary Site Administrator.
- Status koneksi per target, sehingga satu server yang gagal tidak membatalkan hasil target lain.
- Password tidak disimpan dan dikosongkan setelah proses koneksi.

## Instalasi Windows

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Menjalankan

```powershell
python app.py
```

## ArcGIS Enterprise

1. Pilih `ArcGIS Enterprise`.
2. Isi URL Portal, misalnya `https://host/portal`.
3. Isi akun administrator Portal.
4. Klik `Connect & Discover`.
5. Portal dan semua federated server akan ditampilkan.

## Standalone ArcGIS Server

1. Pilih `ArcGIS Server (standalone / non-federated)`.
2. Isi URL server, misalnya `https://host/server`.
3. Isi Primary Site Administrator.
4. Klik `Connect Standalone Server`.

## Pengujian

```powershell
python -m pytest -q
```

## Batas milestone

Milestone ini belum mencakup Analyze, Preview, Apply, Verify, Rollback, report, OAuth browser login, ataupun penyimpanan credential.
