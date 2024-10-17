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


def validate_shared_key_equal():
    s = modular_exponentiation(Yb, Xa, q)  # shared key
    Sb = modular_exponentiation(Ya, Xb, q)
    print(f"Shared key are equal: {s == Sb}\nSa={s}\nSb={Sb}\n")


def get_shared_key(public, private, q):
    s = modular_exponentiation(public, private, q)  # shared key
    hash_output = SHA256.new(str(s).encode()).hexdigest()
    key = hash_output[:16]  # 16 byte for hashed shared key
    return key


q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
a = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

Xa = 6 # Alice private key
Xb = 15 # Bob private key

Ya = modular_exponentiation(a, Xa, q) # Alice public key
Yb = modular_exponentiation(a, Xb, q) # Bob public key

iv = get_random_bytes(16)

# Bob sending message to Alice
message = "Hi Alice!"
message_16bit = pad(message.encode("utf-8"), 16)
bob_shared_key = get_shared_key(Ya, Xb, q)
bob_cipher = AES.new(bob_shared_key.encode(), AES.MODE_CBC, iv)
encrypted_message = bob_cipher.encrypt(message_16bit)

# Alice reading message from Bob
alice_shared_key = get_shared_key(Yb, Xa, q)
alice_cipher = AES.new(alice_shared_key.encode(), AES.MODE_CBC, iv)
decrypted_message = unpad(alice_cipher.decrypt(encrypted_message), 16)

print(f"Bob sends: {message}")
print(f"Alice reads: {decrypted_message}")
