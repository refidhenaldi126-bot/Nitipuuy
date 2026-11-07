TITIPUUY v0.9.3 — ROUTE FOUNDATION + MITRA ROUTE PREVIEW

STATUS
- Build pengembangan / development, belum untuk produksi.
- Baseline pengembangan: Titipuuy v0.9.2 Transparent Mascot.
- Worker di paket ini mendukung pickupPoint, address.point, serta deliveryPreviewPoint yang dikaburkan untuk papan pesanan.

FITUR YANG TERSEDIA PADA BUILD INI
1. Pembeli dapat menentukan titik toko/cabang pada peta.
2. Pembeli dapat menentukan titik alamat pengantaran pada peta.
3. Koordinat ikut dikirim saat pesanan dibuat.
4. Mitra dapat membuka pratinjau rute dari kartu pesanan.
5. Peta pratinjau menampilkan posisi GPS Mitra, toko, dan tujuan; rute jalan dihitung melalui OSRM.
6. Jarak dan estimasi waktu untuk Mitra→Toko, Toko→Pembeli, dan total ditampilkan.
7. Setelah pesanan diterima, data alamat privat tersedia bagi Mitra yang ditugaskan. Setelah status berubah menjadi Dalam perjalanan, peta otomatis menampilkan fase menuju pembeli.
8. Chat dan alur pesanan lama tetap dipertahankan.

PRIVASI
- Pada penawaran yang belum diterima, Worker hanya mengirim deliveryPreviewPoint yang dibulatkan ke tiga angka desimal (perkiraan sekitar 100 meter, bergantung lokasi).
- Nama, telepon, dan alamat lengkap tidak dikirim ke papan penawaran.
- Setelah claim berhasil, endpoint Mitra mengembalikan data pesanan privat untuk Mitra yang ditugaskan.

PENGUJIAN
- Sintaks seluruh inline JavaScript pada index.html telah diperiksa dengan node --check.
- Sintaks worker.js telah diperiksa dengan node --check.
- Ini belum menggantikan pengujian browser/perangkat nyata, Firebase, izin GPS, serta pengujian dua akun (Pembeli dan Mitra).
- OSRM public demo dan OpenStreetMap/Nominatim memiliki kebijakan penggunaan dan batas layanan. Estimasi bukan lalu lintas real-time.

PENTING
JANGAN deploy ke GitHub Pages produksi atau Cloudflare Worker produksi dulu.
Uji di salinan lokal / branch development. Simpan v0.9.2 dan Worker produksi v0.8.0 sebagai baseline stabil.
