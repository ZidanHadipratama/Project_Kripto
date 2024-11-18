import os
import base64

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_rsa_keys(bits=512):
    from random import getrandbits
    from sympy import nextprime

    e = 65537
    p = nextprime(getrandbits(bits // 2))
    q = nextprime(getrandbits(bits // 2))
    n = p * q
    phi = (p - 1) * (q - 1)
    while gcd(e, phi) != 1:
        e = nextprime(e)
    d = modinv(e, phi)
    
    private_key = (d, n)
    public_key = (e, n)
    return private_key, public_key

def encrypt_message(public_key, message):
    e, n = public_key
    message_int = int.from_bytes(message.encode('utf-8'), 'big')
    encrypted_message_int = pow(message_int, e, n)
    encrypted_message = base64.b64encode(encrypted_message_int.to_bytes((encrypted_message_int.bit_length() + 7) // 8, 'big')).decode('utf-8')
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    d, n = private_key
    encrypted_message_int = int.from_bytes(base64.b64decode(encrypted_message), 'big')
    decrypted_message_int = pow(encrypted_message_int, d, n)
    decrypted_message = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, 'big').decode('utf-8')
    return decrypted_message
