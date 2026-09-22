PORTAL VERSION FIX
==================

Perbaikan ini menghapus mapping hard-coded yang salah (2025.1 -> Enterprise 11.4).
Versi Portal sekarang diprioritaskan dari endpoint /sharing/rest/portals/self.
Untuk Tata Ruang Jakarta, hasil yang diharapkan adalah 11.5.

Cara pakai:
1. Ekstrak folder Portal_Version_Fix langsung ke root project.
2. Klik kanan apply_patch.ps1, lalu Run with PowerShell.
3. Jalankan kembali aplikasi.

Script otomatis membuat backup sebelum mengganti file dan menjalankan syntax check jika Python aktif.
