from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result


# Extended Euclidean Algorithm
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    return x % m


def RSA_Key(bits):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)

    return {"public": (e, n), "private": (d, n)}


def rsa_encrypt(message, e, n):
    return modular_exponentiation(message, e, n)


def rsa_decrypt(ciphertext, d, n):
    return modular_exponentiation(ciphertext, d, n)


def aes_encrypt(key, message, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(message, 16))


def aes_decrypt(key, ciphertext, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16)


iv = get_random_bytes(16)

rsa_keys = RSA_Key(1024)
e, n = rsa_keys["public"]
d = rsa_keys["private"][0]

# Bob generates a symmetric key 's' and sends encrypted to Alice
s = getPrime(128)
c = rsa_encrypt(s, e, n)

# Mallory intercepts and modifies the ciphertext
c_prime = 1

# Alice decrypts the modified ciphertext to get 's_prime'
s_prime = rsa_decrypt(c_prime, d, n)

# Alice derives key k = SHA256(s')
k = SHA256.new(str(s_prime).encode()).hexdigest()[:16].encode()

# Alice uses AES to encrypt a message
message = b"Hi Bob!"
c0 = aes_encrypt(k, message, iv)

# Mallory knows that s_prime must be 1
k_stolen = SHA256.new(str(1).encode()).hexdigest()[:16].encode()

# Mallory can decrypt the message
decrypted_message = aes_decrypt(k_stolen, c0, iv)
print(f"Decrypted message by Mallory: {decrypted_message.decode()}")
