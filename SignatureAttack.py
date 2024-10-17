from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

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

# RSA signature
def sign(message, d, n):
    m = bytes_to_long(message)
    return modular_exponentiation(m, d, n)

# RSA signature verification
def verify(message, signature, e, n):
    m = bytes_to_long(message)
    s = modular_exponentiation(signature, e, n)
    return s == m

def signature_malleability_attack():
    rsa_keys = RSA_Key(1024)
    e, n = rsa_keys["public"]
    d = rsa_keys["private"][0]

    # Messages to be signed
    m1 = b"Message One"
    m2 = b"Message Two"

    # Sign the messages
    sigma1 = sign(m1, d, n)
    sigma2 = sign(m2, d, n)

    print(f"Original Message 1: {m1.decode()}, Signature 1: {sigma1}")
    print(f"Original Message 2: {m2.decode()}, Signature 2: {sigma2}")

    # Create the new message m3
    m3 = (bytes_to_long(m1) * bytes_to_long(m2)) % n

    # Create the forged signature for m3
    sigma3 = (sigma1 * sigma2) % n
    print(f"Forged Signature for Message 3: {sigma3}")

    # Verify the forged signature
    if verify(long_to_bytes(m3), sigma3, e, n):
        print("The forged signature is valid for Message 3!")
    else:
        print("The forged signature is NOT valid for Message 3.")

signature_malleability_attack()
