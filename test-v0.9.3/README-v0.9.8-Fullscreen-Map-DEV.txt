TITIPUUY v0.9.8 — MITRA FULLSCREEN MAP (DEV)

Isi paket:
- index.html: frontend dengan tampilan peta Mitra fullscreen.
- worker.js: salinan source Worker yang tersedia pada arsip/proyek saat penyusunan paket.
- aset gambar dan ikon dari baseline v0.9.7.

PERUBAHAN FRONTEND:
1. Tampilan Mitra menggunakan peta fullscreen pada layar ponsel.
2. Header status Mitra dan kontrol peta dibuat mengambang.
3. Ringkasan GPS dan statistik ditempatkan sebagai overlay.
4. Area status operasional dibuat seperti bottom sheet.
5. API frontend diarahkan ke DEV:
   https://nitipuuy-api-dev.refidhenaldi126.workers.dev

PENTING — WORKER:
Source worker.js yang tersedia untuk paket ini memiliki konstanta VERSION = "0.8.5".
Pengguna menyampaikan Worker yang sedang terpasang di DEV adalah 0.8.0.
Karena kedua versi ini tidak cocok, worker.js disertakan agar tidak perlu mencari file terpisah,
tetapi JANGAN deploy worker.js ini ke Cloudflare sebelum versi dan konfigurasi DEV diverifikasi.
Jangan pernah menimpa Worker produksi.
Periksa binding dan secrets melalui Cloudflare Dashboard; jangan menaruh secret di file ini.

CATATAN:
Paket ini merupakan build awal UI v0.9.8 DEV. Fitur backend dan alur pesanan tidak sengaja
diubah. Uji login, status online/offline, GPS, daftar pesanan, chat, dan pergantian mode
sebelum digunakan lebih lanjut.
