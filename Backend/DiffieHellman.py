import random


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


def generate_prime(bits=10):
    """Generate a random prime number with a specified number of bits."""
    while True:
        candidate = random.getrandbits(bits)
        if candidate % 2 == 0:
            candidate += 1  # Make it odd
        if is_prime(candidate):
            return candidate


def is_primitive_root(g, p):
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    def multiplicative_order(a, m):
        for k in range(1, m):
            if pow(a, k, m) == 1:
                return k
        return None

    if gcd(g, p) != 1:
        return False  # g and p should be relatively prime

    phi_p = p - 1
    order_g = multiplicative_order(g, p)

    return order_g == phi_p


def square_and_multiply(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent //= 2
        base = (base * base) % modulus

    return result


def generate_key_pair_diffie(p, g):
    private = random.randint(2, p - 2)  # private key for sender
    public = square_and_multiply(g, private, p)
    return public, private


def diffie_hellman_key_exchange():
    # Step 1: Key Generation
    p = generate_prime()
    g = random.randint(2, p - 1)
    while not is_primitive_root(g, p):
        g = random.randint(2, p - 1)

    return p, g


def generate_session_key_diffie(APr, BPu, prime):
    return square_and_multiply(BPu, APr, prime)
