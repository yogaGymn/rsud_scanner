  _____   _____ _    _ _____    __  __              _ ______ _   _          _   _  _____ 
 |  __ \ / ____| |  | |  __ \  |  \/  |   /\       | |  ____| \ | |   /\   | \ | |/ ____|
 | |__) | (___ | |  | | |  | | | \  / |  /  \      | | |__  |  \| |  /  \  |  \| | |  __ 
 |  _  / \___ \| |  | | |  | | | |\/| | / /\ \ _   | |  __| | . ` | / /\ \ | . ` | | |_ |
 | | \ \ ____) | |__| | |__| | | |  | |/ ____ \ |__| | |____| |\  |/ ____ \| |\  | |__| |
 |_|  \_\_____/ \____/|_____/  |_|  |_/_/    \_\____/|______|_| \_/_/    \_\_| \_| \_____|

                 Tools Security Directory & Data Breach — rsud_scanner
                              Author: @YogaGymn


📌 Ringkasan

rsud_scanner adalah alat CLI sederhana untuk security testing:

🔎 Scan Directory → Menggabungkan target yang Anda masukkan dengan daftar path dari directoary.txt.

🔐 Data Breach → Mengecek daftar endpoint dari databreach.txt terhadap daftar situs bawaan.

Output ditampilkan realtime dengan warna menarik, lalu diakhiri dengan tabel hasil valid yang rapi.

⚠️ Gunakan hanya pada sistem yang Anda miliki izin eksplisit untuk diuji.


⚙️ Instalasi

   *Windows*
   # clone repo
git clone https://github.com/username/rsud_scanner.git
cd rsud_scanner

# buat virtualenv (opsional)
python -m venv .venv
.\.venv\Scripts\activate

# install dependency
pip install -r requirements.txt


*Linux*
# clone repo
git clone https://github.com/username/rsud_scanner.git
cd rsud_scanner

# buat virtualenv (opsional)
python3 -m venv .venv
source .venv/bin/activate

# install dependency
pip install -r requirements.txt

▶️ Cara Penggunaan

Jalankan: python rsud_scanner.py

⚖️ Disclaimer

Gunakan hanya untuk tujuan pembelajaran & pengujian keamanan dengan izin resmi.

Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.

👤 Author

@YogaGymn
