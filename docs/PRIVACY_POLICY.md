# Kebijakan Privasi — ARGENT DEFENDER

**Prinsip: local-first, privacy by design.**

1. **Pemrosesan lokal.** Seluruh pemindaian, dekripsi backup, analisis APK/IPA, deteksi anomali AI dan pembuatan laporan berjalan di Mac Anda. Tidak ada APK, backup, berkas, atau data pribadi yang diunggah.
2. **Aksi online hanya atas perintah Anda:** pembaruan threat intelligence (abuse.ch), penelusuran redirect URL, dan AI cloud. AI cloud nonaktif secara default; bila diaktifkan, hanya judul & bukti temuan (bukan berkas) yang dikirim.
3. **Kredensial.** Kata sandi backup iPhone dipakai sekali melalui stdin dan **tidak pernah disimpan**. Kunci API dan seed kriptografi pasca-kuantum disimpan di macOS Keychain (*WhenUnlockedThisDeviceOnly*). Hasil dekripsi sementara ditulis ke folder 0700 dan dihapus setelah analisis.
4. **Persetujuan.** Setiap pemeriksaan perangkat memerlukan konfirmasi bahwa Anda pemilik perangkat atau memiliki izin/kewenangan sah, dan bahwa pengguna perangkat mengetahuinya.
5. **Tanpa pemantauan tersembunyi.** Tidak ada intersepsi jaringan diam-diam, tidak ada pemantauan komunikasi atau transaksi keuangan, tidak ada perubahan konfigurasi perangkat, tidak ada penghapusan aplikasi otomatis, tidak ada root/jailbreak.
6. **Pesan.** Analisis tautan SMS/iMessage bersifat opt-in; hanya URL yang dipertahankan, isi pesan tidak disimpan maupun dilaporkan.
7. **Penyimpanan.** Basis data lokal `~/Library/Application Support/ArgentDefender/argent.db` (izin 0600) berisi riwayat pemindaian, indikator, dan catatan forensik. Hapus folder tersebut untuk menghapus semua data.
8. **Audit.** Tindakan penting dicatat dalam log audit berantai-hash yang dapat diverifikasi (Settings › Audit log).
