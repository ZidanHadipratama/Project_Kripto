from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import DES, AES
import base64
import hashlib
import os

app = Flask(__name__)

def generate_16_char_key(key):
    hashed_key = hashlib.sha256(key.encode('utf-8')).hexdigest()
    return hashed_key[:16]

def encrypt_data(data, key):
    des_key = key[:8]
    aes_key = generate_16_char_key(key)
    des_cipher = DES.new(des_key.encode('utf-8'), DES.MODE_ECB)
    padded_data = data + (8 - len(data) % 8) * ' '
    des_encrypted = des_cipher.encrypt(padded_data.encode('utf-8'))
    aes_cipher = AES.new(aes_key.encode('utf-8'), AES.MODE_ECB)
    aes_encrypted = aes_cipher.encrypt(des_encrypted.ljust(16, b' '))
    return base64.b64encode(aes_encrypted).decode('utf-8')

def decrypt_data(encrypted_data, key):
    des_key = key[:8]
    aes_key = generate_16_char_key(key)
    try:
        aes_cipher = AES.new(aes_key.encode('utf-8'), AES.MODE_ECB)
        aes_decrypted = aes_cipher.decrypt(base64.b64decode(encrypted_data))
        des_cipher = DES.new(des_key.encode('utf-8'), DES.MODE_ECB)
        des_decrypted = des_cipher.decrypt(aes_decrypted).decode('utf-8').strip()
        return des_decrypted.strip()
    except Exception as e:
        return None

def save_to_file(username, encrypted_data):
    with open("penting.txt", "a") as file:
        file.write(f"{username},{encrypted_data}\n")

def read_all_data_from_file():
    if os.path.exists("penting.txt"):
        with open("penting.txt", "r") as file:
            data = [line.strip().split(',') for line in file.readlines()]
        return data
    return []

def read_from_file(username):
    if os.path.exists("penting.txt"):
        with open("penting.txt", "r") as file:
            for line in file:
                saved_username, saved_encrypted_data = line.strip().split(',')
                if saved_username == username:
                    return saved_encrypted_data
    return None

@app.route('/encrypt', methods=['POST'])
def encrypt():
    full_name = request.form['full_name']
    credit_card = request.form['credit_card']
    cvv = request.form['cvv']
    expiration_year = request.form['expiration_year']
    key = request.form['key']
    payment_data = f"Card: {credit_card}, CVV: {cvv}, Expiry: {expiration_year}"
    encrypted_data = encrypt_data(payment_data, key)
    save_to_file(full_name, encrypted_data)
    return encrypted_data

@app.route('/decrypt', methods=['POST'])
def decrypt():
    full_name = request.form['full_name']
    key = request.form['key']
    encrypted_data = read_from_file(full_name)
    if not encrypted_data:
        return "User not found", 404
    decrypted_data = decrypt_data(encrypted_data, key)
    if not decrypted_data:
        return "Invalid key", 403
    parts = decrypted_data.split(", ")
    credit_card = parts[0].split(": ")[1]
    cvv = parts[1].split(": ")[1]
    expiration_year = parts[2].split(": ")[1]
    return jsonify({
        'credit_card': credit_card,
        'cvv': cvv,
        'expiration_year': expiration_year
    })

@app.route('/')
def users():
    user_data = read_all_data_from_file()
    return render_template('server.html', user_data=user_data)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
