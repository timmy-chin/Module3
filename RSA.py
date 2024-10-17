from Crypto.Util.number import getPrime

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


def string_to_hex_to_int(s):
    hex_value = s.encode('utf-8').hex()
    int_value = int(hex_value, 16)
    return int_value


def int_to_hex_to_string(num):
    hex_value = hex(num)[2:]
    bytes_value = bytes.fromhex(hex_value)
    original_string = bytes_value.decode('utf-8')
    return original_string


def RSA_Key(bits):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)

    return {"public": (e, n), "private": (d, n)}


def encrypt(message, key):
    int_message = string_to_hex_to_int(message)
    e = key["public"][0]
    n = key["public"][1]
    c = modular_exponentiation(int_message, e, n)
    return c


def decrypt(message, key):
    d = key["private"][0]
    n = key["private"][1]
    m = modular_exponentiation(message, d, n)
    return int_to_hex_to_string(m)

rsa_key = RSA_Key(256)
message = "Hello World"
encrypted = encrypt(message, rsa_key)
decrypted = decrypt(encrypted, rsa_key)

print(f"Message: {message}")
print(f"Encrypted Message: {encrypted}")
print(f"Decrypted Message: {decrypted}")





