import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash, session
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

app = Flask(__name__)
app.secret_key = 'your_secret_key'

KEYS_DIRECTORY = 'data/keys'
NOTES_DIRECTORY = 'data/notes'
CREDS_FILE = 'data/creds.txt'

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_user_keys(username, private_key, public_key):
    username = username.lower()
    user_dir = os.path.join(KEYS_DIRECTORY, username)
    
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    
    private_key_file = os.path.join(user_dir, 'private_key.pem')
    with open(private_key_file, 'wb') as f:
        f.write(private_key)
    
    public_key_file = os.path.join(user_dir, 'public_key.pem')
    with open(public_key_file, 'wb') as f:
        f.write(public_key)

def load_user_keys(username):
    username = username.lower()
    user_dir = os.path.join(KEYS_DIRECTORY, username)
    private_key_file = os.path.join(user_dir, 'private_key.pem')
    public_key_file = os.path.join(user_dir, 'public_key.pem')
    
    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        with open(private_key_file, 'rb') as f:
            private_key = f.read()
        with open(public_key_file, 'rb') as f:
            public_key = f.read()
        return private_key, public_key
    else:
        return None, None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def save_user_credentials(username, hashed_password):
    with open(CREDS_FILE, 'a') as f:
        f.write(f"{username},{hashed_password}\n")

def check_credentials(username, password):
    hashed_input_password = hash_password(password)
    if os.path.exists(CREDS_FILE):
        with open(CREDS_FILE, 'r') as f:
            for line in f.readlines():
                stored_username, stored_hashed_password = line.strip().split(',')
                if stored_username == username and stored_hashed_password == hashed_input_password:
                    return True
    return False

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        
        if check_credentials(username, password):
            session['username'] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password. Please try again.", "error")
            return redirect(url_for('login'))

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
        
        if private_key is None or public_key is None:
            hashed_password = hash_password(password)
            private_key, public_key = generate_rsa_keys()
            save_user_keys(username, private_key, public_key)
            save_user_credentials(username, hashed_password)
            
            flash(f"User {username} registered successfully!", "success")
            return redirect(url_for('login'))
        else:
            flash(f"User {username} already exists!", "error")
            return redirect(url_for('register'))
    
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
            encrypted_note = encrypt_message(public_key, content)
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
    if private_key is None:
        flash("User not found!", "error")
        return redirect(url_for('login'))
    
    notes = load_notes(username)

    print(notes)

    user_notes = []
    
    for note in notes:
        decrypted_note = decrypt_message(private_key, note['content'])
        user_notes.append({
            'judul': note['judul'],
            'content': decrypted_note
        })

    return render_template('inbox.html', username=username, notes=user_notes)

def encrypt_message(public_key_str, message):
    public_key = RSA.import_key(public_key_str)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
    return b64encode(encrypted_message).decode('utf-8')

def decrypt_message(private_key_str, encrypted_message):
    private_key = RSA.import_key(private_key_str)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(b64decode(encrypted_message))
    return decrypted_message.decode('utf-8')

def save_note(username, judul, encrypted_note):
    username = username.lower()
    user_notes_file = os.path.join(NOTES_DIRECTORY, f"{username}_notes.txt")
    
    with open(user_notes_file, 'a') as f:
        f.write(f"{judul},{encrypted_note}\n")

def load_notes(username):
    username = username.lower()
    user_notes_file = os.path.join(NOTES_DIRECTORY, f"{username}_notes.txt")
    notes = []
    
    if os.path.exists(user_notes_file):
        with open(user_notes_file, 'r') as f:
            for line in f.readlines():
                judul, encrypted_note = line.strip().split(',', 1)
                notes.append({
                    'judul': judul,
                    'content': encrypted_note
                })
    return notes

if __name__ == '__main__':
    os.makedirs(KEYS_DIRECTORY, exist_ok=True)
    os.makedirs(NOTES_DIRECTORY, exist_ok=True)
    app.run(debug=True, port=5005)
