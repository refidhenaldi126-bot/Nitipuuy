TITIPUUY v0.9.8 — PRODUCTION CANDIDATE (BELUM DEPLOY)

Tujuan
- Kandidat rilis untuk mengalihkan frontend v0.9.8 ke Worker produksi.
- Tidak ada perubahan desain UI, ukuran marker, atau logika GPS dalam tahap pengalihan ini.

TEMUAN AUDIT PENTING
1. Frontend sumber v0.9.8 masih memakai Worker DEV pada NITIPUUY_API.
2. Worker produksi yang sumbernya tersedia di percakapan adalah v0.8.0.
3. Frontend v0.9.8 memanggil endpoint POST /orders/{key}/cancel.
4. Worker v0.8.0 belum memiliki endpoint pembatalan tersebut.
5. Worker v0.8.5 di arsip v0.9.8 menambahkan endpoint pembatalan dan beberapa perubahan perilaku pesanan, tetapi belum boleh dianggap identik/aman dengan Worker produksi yang sedang aktif.

STATUS
- File frontend disiapkan untuk Worker produksi: https://nitipuuy-api.refidhenaldi126.workers.dev
- Worker v0.8.5 disertakan untuk audit/deployment staging, bukan instruksi deploy langsung.
- Jangan menimpa Worker produksi v0.8.0 sebelum pengujian staging dan pemeriksaan variabel/secret selesai.
- Jangan upload worker.js ke GitHub Pages sebagai file yang dijalankan browser; Worker harus dideploy melalui Cloudflare Workers.

URUTAN RILIS YANG AMAN
A. Backup source frontend GitHub produksi dan source Worker aktif.
B. Deploy Worker v0.8.5 ke Worker staging terpisah (bukan production) dengan variabel dan secret yang sama secara aman.
C. Tes: login, status Mitra, role, online/offline, buat pesanan, daftar pesanan Pembeli, papan Mitra, klaim, update status, chat, pembatalan pesanan.
D. Jika lulus, deploy Worker teruji ke production.
E. Upload frontend v0.9.8 ke GitHub Pages production.
F. Uji ulang melalui domain GitHub Pages production.

VARIABEL/SECRET YANG HARUS DIVERIFIKASI DI CLOUDFLARE
- FIREBASE_PROJECT_ID
- FIREBASE_DATABASE_URL
- FIREBASE_SERVICE_ACCOUNT_JSON (secret)
Jangan menyalin atau membagikan nilai secret di chat/screenshot.

CATATAN KOMPATIBILITAS
Worker v0.8.5 memiliki perubahan tambahan selain pembatalan pesanan: dukungan koordinat pickup/delivery, preview tujuan yang dibulatkan untuk privasi sebelum klaim, penutupan otomatis pesanan yang belum mendapat Mitra setelah 15 menit, dan pemulihan slot Mitra yang stale. Perubahan ini perlu dites karena memengaruhi alur pesanan.
