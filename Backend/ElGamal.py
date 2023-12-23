import random


def square_and_multiply(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent //= 2
        base = (base * base) % modulus

    return result


def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def is_primitive_root(g, p):
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    def multiplicative_order(a, m):
        for k in range(1, m):
            if square_and_multiply(a, k, m) == 1:
                return k
        return None

    if gcd(g, p) != 1:
        return False  # g and p should be relatively prime

    phi_p = p - 1
    order_g = multiplicative_order(g, p)

    return order_g == phi_p


def generate_gamal_prime(bits=10):
    while True:
        candidate = random.getrandbits(bits)
        if candidate % 2 == 0:
            candidate += 1  # Make it odd
        if is_prime(candidate) and candidate > 150:
            return candidate


def generate_gamal_primitive_root(p):
    while True:
        g = random.randint(2, p - 1)
        if is_primitive_root(g, p):
            return g


def generate_keypair_gamal(p, g):
    private_key = random.randint(2, p - 2)
    public_key = square_and_multiply(g, private_key, p)
    return private_key, public_key


def elgamal_encrypt(plain_text, public_key, p, g):
    encrypted_text = []
    for char in plain_text:
        k = random.randint(2, p - 2)
        c1 = square_and_multiply(g, k, p)
        s = pow(public_key, k, p)
        c2 = (ord(char) * s) % p
        encrypted_text.append((c1, c2))
    return encrypted_text


def elgamal_decrypt(encrypted_text, private_key, p):
    decrypted_message = ""
    for c1, c2 in encrypted_text:
        s = pow(c1, private_key, p)
        s_inv = pow(s, -1, p)  # Modular multiplicative inverse
        char = chr((c2 * s_inv) % p)
        decrypted_message += char
    return decrypted_message
