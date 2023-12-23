import time
import random


def calculateN(PQ):
    return PQ[0] * PQ[1]


def calculatefiN(PQ):
    return (PQ[0] - 1) * (PQ[1] - 1)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, fi):
    fi0, x0, x1 = fi, 0, 1
    while e > 1:
        q = e // fi
        fi, e = e % fi, fi
        x0, x1 = x1 - q * x0, x0
    return x1 + fi0 if x1 < 0 else x1


def GeneratePQ(n):
    PQ = []
    while True:
        prime_candidate = PrimeCandidateFilter1(n)
        if not RabinMillerTest(prime_candidate):
            continue
        else:
            PQ.append(prime_candidate)
            if len(PQ) == 2 and PQ[0] != PQ[1]:
                return PQ


def generate_keypair_rsa(PQsize=1024):
    PQ = GeneratePQ(PQsize)
    n = calculateN(PQ)
    phi = calculatefiN(PQ)

    # Choose public key 'e'
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # Compute private key 'd'
    d = mod_inverse(e, phi)

    return (n, e), (n, d)


def RandomNBits(n):
    return random.randrange(2 ** (n - 1) + 1, 2**n - 1)


def FirstPrimeNumbers():
    firstPrimeNumbers = []
    i = 2
    while len(firstPrimeNumbers) < 100:
        is_prime = True
        for j in range(2, int(i**0.5) + 1):
            if i % j == 0:
                is_prime = False
                break

        if is_prime or i == 2:
            firstPrimeNumbers.append(i)
        i += 1

    return firstPrimeNumbers


def PrimeCandidateFilter1(n):
    firstPrimes = FirstPrimeNumbers()
    while True:
        randomNumb = RandomNBits(n)
        for divisor in firstPrimes:
            if randomNumb % divisor == 0 and divisor**2 <= randomNumb:
                break
        else:
            return randomNumb


n = 1024
primeCandidate = PrimeCandidateFilter1(n)


def RabinMillerTest(primeCandidate):
    maxDivisionsByTwo = 0
    ec = primeCandidate - 1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert 2**maxDivisionsByTwo * ec == primeCandidate - 1

    def trialComposite(round_tester):
        if pow(round_tester, ec, primeCandidate) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, primeCandidate) == primeCandidate - 1:
                return False
        return True

    # Set number of trials here
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, primeCandidate)
        if trialComposite(round_tester):
            return False
    return True


def rsa_encrypt(message, public_key):
    n, e = public_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message


def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    decrypted_message = "".join([chr(pow(char, d, n)) for char in ciphertext])
    return decrypted_message
