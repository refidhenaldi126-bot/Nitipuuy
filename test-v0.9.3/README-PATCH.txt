TITIPUUY v0.9.3 — ROUTE FOUNDATION (BACKEND PATCH)

Isi paket:
- worker.js: Worker API dengan dukungan koordinat pickupPoint dan deliveryPoint.

Perubahan:
1. Endpoint POST /orders menerima pickupPoint: {lat,lng} dan address.point: {lat,lng} (atau deliveryPoint).
2. Koordinat divalidasi pada server.
3. Koordinat presisi disimpan pada order privat (orders dan ordersByBuyer).
4. orderBoard untuk Mitra yang belum menerima pesanan hanya memuat pickupPoint dan deliveryPreviewPoint yang dibulatkan 3 desimal (sekitar 100 meter, bergantung lokasi). Nama penerima, nomor telepon, alamat teks, dan titik rumah presisi tidak dibuka sebelum pesanan diterima.
5. Setelah Mitra menerima pesanan, GET /mitra/orders mengembalikan data privat pesanan milik Mitra sehingga koordinat tujuan presisi tersedia.
6. Permintaan dari frontend lama tetap kompatibel: koordinat bersifat opsional.

PENTING:
- Ini patch backend/fondasi, bukan rilis frontend lengkap.
- Jangan mengganti Worker produksi sebelum frontend yang mengirim koordinat dan pengujian end-to-end siap.
- Worker tetap menggunakan konfigurasi environment dan Firebase yang sudah ada; jangan menimpa secrets/vars.
- Uji pada environment staging terlebih dahulu.

Validasi sintaks: node --check worker.js (lulus).
