TITIPUUY v0.9.1 — RIDER NAVIGATION

Pembaruan:
- Mengganti ikon motor sementara dengan foto maskot pengendara Titipuuy.
- GPS Mitra menggunakan watchPosition agar posisi marker diperbarui otomatis ketika perangkat bergerak.
- Tombol "Lokasi saya" memusatkan peta ke posisi GPS terakhir.
- Arah marker mengikuti heading GPS jika perangkat/browser menyediakannya.
- Menampilkan status GPS dan estimasi akurasi.

Yang dipertahankan:
- worker.js disalin byte-for-byte dari paket v0.9.0 (Worker v0.8.0).
- Alur autentikasi, pesanan, Online/Offline, dan chat tidak diubah secara sengaja.

CARA DEPLOY:
1. Ekstrak ZIP.
2. Unggah/ganti index.html dan file titipuuy-rider-mascot.jpg di root repositori GitHub Pages.
3. Pertahankan aset ikon/manifest yang ada; paket ini juga menyertakannya.
4. Jangan deploy worker.js; Worker v0.8.0 tetap berjalan seperti sebelumnya.
5. Uji di HP melalui HTTPS dan izinkan akses lokasi.

CATATAN:
- GPS watchPosition memperbarui marker selama halaman Beranda Mitra terbuka dan browser mengizinkan lokasi.
- Heading hanya tersedia pada perangkat/browser tertentu; jika tidak tersedia, maskot tetap tampil tanpa rotasi.
- Rute jemput–antar, garis rute, dan navigasi turn-by-turn belum dibuat pada versi ini. Itu memerlukan koordinat pesanan yang valid dan tahap integrasi rute berikutnya.
- Akurasi GPS bergantung pada perangkat, sinyal, izin, dan kondisi lingkungan.
