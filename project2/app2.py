import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash, session
import rsa  # Ini adalah library enkripsi Anda sendiri

app = Flask(__name__)
app.secret_key = 'your_secret_key'

KEYS_DIRECTORY = 'data/keys'
NOTES_DIRECTORY = 'data/notes'
CREDS_FILE = 'data/creds.txt'

def save_user_keys(username, private_key, public_key):
    user_dir = os.path.join(KEYS_DIRECTORY, username.lower())
    os.makedirs(user_dir, exist_ok=True)
    with open(os.path.join(user_dir, 'private_key.pem'), 'w') as f:
        f.write(f"{private_key[0]},{private_key[1]}")
    with open(os.path.join(user_dir, 'public_key.pem'), 'w') as f:
        f.write(f"{public_key[0]},{public_key[1]}")

def load_user_keys(username):
    user_dir = os.path.join(KEYS_DIRECTORY, username.lower())
    try:
        with open(os.path.join(user_dir, 'private_key.pem'), 'r') as f:
            d, n = map(int, f.read().split(','))
        with open(os.path.join(user_dir, 'public_key.pem'), 'r') as f:
            e, n = map(int, f.read().split(','))
        return (d, n), (e, n)
    except FileNotFoundError:
        return None, None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def save_user_credentials(username, hashed_password):
    with open(CREDS_FILE, 'a') as f:
        f.write(f"{username},{hashed_password}\n")

def check_credentials(username, password):
    if os.path.exists(CREDS_FILE):
        with open(CREDS_FILE, 'r') as f:
            for line in f:
                stored_username, stored_hashed_password = line.strip().split(',')
                if stored_username == username and stored_hashed_password == hash_password(password):
                    return True
    return False

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        if check_credentials(username, request.form['password']):
            session['username'] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.", "error")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("You need to login first.", "error")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        private_key, public_key = load_user_keys(username)
        if not private_key or not public_key:
            hashed_password = hash_password(password)
            private_key, public_key = rsa.generate_rsa_keys()  # Library RSA Anda sendiri
            save_user_keys(username, private_key, public_key)
            save_user_credentials(username, hashed_password)
            flash(f"User {username} registered successfully!", "success")
            return redirect(url_for('login'))
        flash(f"User {username} already exists!", "error")
    return render_template('register.html')

@app.route('/buat_catatan', methods=['GET', 'POST'])
def buat_catatan():
    if 'username' not in session:
        flash("You need to login first.", "error")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = session['username']
        judul = request.form['judul']
        content = request.form['content']
        
        _, public_key = load_user_keys(username)
        if public_key:
            encrypted_note = rsa.encrypt_message(public_key, content)  # Enkripsi menggunakan library Anda
            save_note(username, judul, encrypted_note)
            flash("Note saved successfully!", "success")
        else:
            flash("Public key not found!", "error")
    
    return render_template('buat_catatan.html')

@app.route('/inbox')
def inbox():
    if 'username' not in session:
        flash("You need to login first.", "error")
        return redirect(url_for('login'))
    
    username = session['username']
    private_key, _ = load_user_keys(username)
    if private_key:
        notes = load_notes(username)
        user_notes = [{'judul': note['judul'], 'content': rsa.decrypt_message(private_key, note['content'])} for note in notes]
        return render_template('inbox.html', username=username, notes=user_notes)
    flash("User not found!", "error")
    return redirect(url_for('login'))

def save_note(username, judul, encrypted_note):
    user_notes_file = os.path.join(NOTES_DIRECTORY, f"{username}_notes.txt")
    os.makedirs(NOTES_DIRECTORY, exist_ok=True)
    with open(user_notes_file, 'a') as f:
        f.write(f"{judul},{encrypted_note}\n")

def load_notes(username):
    user_notes_file = os.path.join(NOTES_DIRECTORY, f"{username}_notes.txt")
    notes = []
    if os.path.exists(user_notes_file):
        with open(user_notes_file, 'r') as f:
            for line in f.readlines():
                judul, encrypted_note = line.strip().split(',', 1)
                notes.append({'judul': judul, 'content': encrypted_note})
    return notes

if __name__ == '__main__':
    os.makedirs(KEYS_DIRECTORY, exist_ok=True)
    app.run(debug=True, port=5005)
