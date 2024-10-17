from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result


def get_shared_key(public, private, q):
    s = modular_exponentiation(public, private, q)  # shared key
    hash_output = SHA256.new(str(s).encode()).hexdigest()
    key = hash_output[:16]  # 16 byte for hashed shared key
    return key


def MITM_alpha_attack(tampered_a):

    Xa = 6 # Alice private key
    Xb = 15 # Bob private key

    Ya = modular_exponentiation(tampered_a, Xa, q) # Alice public key
    Yb = modular_exponentiation(tampered_a, Xb, q) # Bob public key

    iv = get_random_bytes(16)

    # Bob sending message to Alice
    bob_message = "Hi Alice!"
    bob_message_16bit = pad(bob_message.encode("utf-8"), 16)
    bob_shared_key = get_shared_key(Ya, Xb, q)
    bob_cipher = AES.new(bob_shared_key.encode(), AES.MODE_CBC, iv)
    bob_encrypted_message = bob_cipher.encrypt(bob_message_16bit)

    # Alice reading message from Bob
    alice_message = "Hi Bob!"
    alice_message_16bit = pad(alice_message.encode("utf-8"), 16)
    alice_shared_key = get_shared_key(Yb, Xa, q)
    alice_cipher = AES.new(alice_shared_key.encode(), AES.MODE_CBC, iv)
    alice_encrypted_message = alice_cipher.encrypt(alice_message_16bit)

    # Mallory decrypting Bob and Alice's message
    if tampered_a == 1:
        s = 1 # since 1 ^ x % q = 1
        hash_output = SHA256.new(str(s).encode()).hexdigest()
        stolen_key = hash_output[:16]  # 16 byte for hashed shared key
    elif tampered_a == q:
        s = 0 # since q ^ x % q = 0
        hash_output = SHA256.new(str(s).encode()).hexdigest()
        stolen_key = hash_output[:16]  # 16 byte for hashed shared key
    else:
        s = modular_exponentiation(q - 1, Xa, q)
        hash_output = SHA256.new(str(s).encode()).hexdigest()
        stolen_key = hash_output[:16]  # 16 byte for hashed shared key

    mallory_cipher = AES.new(stolen_key.encode(), AES.MODE_CBC, iv)
    bob_decrypted_message = unpad(mallory_cipher.decrypt(bob_encrypted_message), 16)
    mallory_cipher = AES.new(stolen_key.encode(), AES.MODE_CBC, iv)
    alice_decrypted_message = unpad(mallory_cipher.decrypt(alice_encrypted_message), 16)

    print(f"Bob sends: {bob_message}")
    print(f"Alice sends: {alice_message}")

    print(f"Mallory decrypted Bob's message: {bob_decrypted_message}")
    print(f"Mallory decrypted Alice's message: {alice_decrypted_message}")

q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371

print("Tampered alpha with 1")
MITM_alpha_attack(1)
print()

print("Tampered alpha with q")
MITM_alpha_attack(q)
print()

print("Tampered alpha with q-1")
MITM_alpha_attack(q-1)
print()



