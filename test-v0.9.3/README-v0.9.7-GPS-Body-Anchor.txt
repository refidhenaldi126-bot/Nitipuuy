Titipuuy v0.9.7 — GPS Body Anchor & Compact Mascot

Perubahan dari v0.9.6:
1. Titik koordinat marker dipindahkan dari bagian bawah/roda belakang ke area tengah badan motor (sekitar tas/box pengantaran), sehingga lingkaran akurasi GPS tidak tampak berada di belakang motor.
2. Ukuran maskot diperkecil dari 60px menjadi 52px (sekitar 13%) agar peta lebih mudah dibaca.
3. Titik rotasi maskot diselaraskan dengan titik koordinat badan motor agar rotasi kompas tetap berpusat dan tidak terasa mengayun.

Tidak ada perubahan pada Firebase, Worker/API, autentikasi, pesanan, chat, atau aturan GPS/kompas v0.9.6.

PENGUJIAN:
- Ekstrak ZIP.
- Jalankan index.html melalui Live Server atau GitHub Pages.
- Izinkan lokasi dan sensor arah di HP.
- Periksa lingkaran akurasi GPS: pusatnya seharusnya berada di area tengah badan/box motor, bukan roda belakang.
- Pastikan ukuran maskot lebih kecil dan rotasi tetap mengikuti arah perangkat saat bergerak.

Catatan: perubahan ini menggeser titik anchor visual marker; tidak mengubah koordinat GPS perangkat yang diterima browser.
