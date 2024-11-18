from flask import Flask, request, render_template, redirect, url_for
import requests

app = Flask(__name__)

# Landing Page
@app.route('/')
def landing():
    return render_template('landing.html')

# Halaman Pendaftaran (Register)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Ambil data dari form input
        full_name = request.form['full_name']
        credit_card = request.form['credit_card']
        cvv = request.form['cvv']
        expiration_year = request.form['expiration_year']
        key = request.form['key']
        
        # Gabungkan data dan kirim ke server untuk enkripsi
        data = {
            'full_name': full_name,
            'credit_card': credit_card,
            'cvv': cvv,
            'expiration_year': expiration_year,
            'key': key
        }
        
        # Kirim data ke server untuk dienkripsi
        response = requests.post('http://127.0.0.1:5001/encrypt', data=data)
        
        # Redirect ke halaman sukses setelah pendaftaran selesai
        return redirect(url_for('success'))
    
    return render_template('client.html')

# Halaman Sukses setelah Pendaftaran
@app.route('/success')
def success():
    return render_template('success.html')

# Halaman Login untuk Retrieve Data
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        full_name = request.form['full_name']
        key = request.form['key']
        
        # Kirim permintaan ke server untuk mendekripsi data
        data = {'full_name': full_name, 'key': key}
        response = requests.post('http://127.0.0.1:5001/decrypt', data=data)
        
        # Jika pengguna tidak ditemukan, tampilkan pesan kesalahan
        if response.status_code == 404:
            return render_template('retrieve.html', error="User not found")
        
        # Jika kunci salah, tampilkan pesan kesalahan
        if response.status_code == 403:
            return render_template('retrieve.html', error="Invalid key, please try again")
        
        # Dapatkan hasil dekripsi dan tampilkan
        decrypted_data = response.json()
        return render_template('retrieve.html', credit_card=decrypted_data['credit_card'], cvv=decrypted_data['cvv'], expiration_year=decrypted_data['expiration_year'])
    
    return render_template('retrieve.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
