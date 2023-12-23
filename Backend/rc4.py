import random
import string


def RandomKey(keySize=1024):
    return "".join(
        random.choices(string.ascii_uppercase + string.ascii_lowercase, k=keySize)
    )


# Create State Vector
def CreateStateVector(lenS=256):
    S = [i for i in range(lenS)]
    return S


# Create Temporary Vector
def CreateTemporaryVector(key, lenS=256):
    temp = [key[i % len(key)] for i in range(lenS)]
    return temp


# Initial permutation on S vector
def InitialPermutation(S, T, lenS=256):
    j = 0
    S = list(S)
    T = list(T)
    for i in range(lenS):
        j = (j + S[i] + T[i]) % lenS
        S[i], S[j] = S[j], S[i]
    return S


# Test S, T values and permutation on S vector
def Test(key=[1, 2, 3, 6], lenS=8):
    S = CreateStateVector(lenS)
    T = CreateTemporaryVector(key, lenS)
    return InitialPermutation(S, T, lenS)


def rc4_decrypt(ciphertxt, key, lenS=256):
    IP = Test(lenS=256)
    i = j = 0
    plaintxt = []
    for indx, item in enumerate(ciphertxt):
        i = (i + 1) % lenS
        j = (j + IP[i]) % lenS
        IP[i], IP[j] = IP[j], IP[i]
        t = (IP[i] + IP[j]) % lenS
        k = IP[t]
        plaintxt_char = k ^ item
        plaintxt.append(chr(plaintxt_char))
    return "".join(plaintxt)


def rc4_encrypt(plaintxt, key, lenS=256):
    IP = Test(lenS=256)
    i = j = indx = 0
    ciphertxt = []
    for indx, char in enumerate(plaintxt):
        i = (i + 1) % lenS
        j = (j + IP[i]) % lenS
        IP[i], IP[j] = IP[j], IP[i]
        t = (IP[i] + IP[j]) % lenS
        k = IP[t]
        cipher = k ^ ord(char)
        ciphertxt.append(cipher)
    return ciphertxt
