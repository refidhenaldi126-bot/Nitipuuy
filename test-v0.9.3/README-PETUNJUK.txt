TITIPUUY v0.9.3 — ROUTE FOUNDATION (FRONTEND DEVELOPMENT BUILD)

Dibangun dari baseline v0.9.2 Transparent Mascot.

PERUBAHAN:
1. Checkout kini menyediakan pemilihan titik toko/cabang melalui pencarian lokasi dan peta.
2. Pembeli dapat memilih titik alamat tujuan pada peta.
3. Koordinat tujuan disimpan pada alamat lokal perangkat.
4. Saat membuat pesanan, frontend mengirim pickupPoint dan address.point ke Worker.
5. Worker v0.8.0 bawaan baseline sudah memiliki dukungan koordinat opsional, validasi koordinat, penyimpanan koordinat privat, dan deliveryPreviewPoint perkiraan pada orderBoard.

PENTING:
- Ini build pengembangan tahap fondasi, BELUM implementasi penuh navigasi Mitra.
- Belum ada routing OSRM, visualisasi tiga titik di dashboard Mitra, maupun perpindahan rute otomatis.
- Jangan deploy sebagai produksi sebelum uji browser, Firebase, Worker, dan alur pesanan.
- Pertahankan Worker produksi yang sedang berjalan. worker.js dalam paket ini adalah salinan Worker v0.8.0 dari baseline; tidak perlu diganti jika produksi sudah memakai versi tersebut.
- Pencarian lokasi menggunakan layanan publik Nominatim/OpenStreetMap dan peta Leaflet/OSM; memerlukan internet.
- Untuk lokasi toko, cari nama toko beserta kecamatan/kota, lalu ketuk peta tepat di cabang yang dimaksud. Jangan mengandalkan hasil pertama tanpa memeriksa pin.

UJI COBA:
1. Deploy hanya pada salinan/staging GitHub Pages, bukan mengganti produksi.
2. Login sebagai Pembeli.
3. Tambahkan barang ke keranjang dan lanjut checkout.
4. Pilih lokasi toko/cabang di peta.
5. Pilih alamat tersimpan dan tentukan titik alamatnya, atau buat alamat baru lalu tentukan titik rumah.
6. Buat pesanan dan periksa respons Worker serta data order.
7. Pastikan pickupPoint dan address.point tersimpan.

Jika ada error, simpan screenshot Console browser dan respons Network untuk endpoint POST /orders.
