import numpy as np


class AES:
    _VALID_KEY_SIZES = (128, 192, 256)
    _POSSIBLE_NUMBER_OF_ROUNDS = {128: 10, 192: 12, 256: 14}
    _NUMBER_OF_SUBKEY_WORDS = {128: 4, 192: 6, 256: 8}
    _BLOCK_SIZE = 16
    _SUBKEY_CONSTANTS = {
        128: np.array(
            [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36],
            dtype=np.uint32,
        ),
        192: np.array(
            [
                0x01,
                0x02,
                0x04,
                0x08,
                0x10,
                0x20,
                0x40,
                0x80,
                0x1B,
                0x36,
                0x6C,
                0xD8,
                0xAB,
                0x4D,
                0x9A,
            ],
            dtype=np.uint32,
        ),
        256: np.array(
            [
                0x01,
                0x02,
                0x04,
                0x08,
                0x10,
                0x20,
                0x40,
                0x80,
                0x1B,
                0x36,
                0x6C,
                0xD8,
                0xAB,
                0x4D,
                0x9A,
                0x2F,
                0x5E,
                0xBC,
                0x63,
                0xC6,
                0x97,
                0x35,
                0x6A,
                0xD4,
                0xB3,
                0x7D,
                0xFA,
                0xEF,
                0xC5,
            ],
            dtype=np.uint32,
        ),
    }

    CT = 0

    def __init__(self, key_size=128, text=None, key=None, mode="encrypt"):
        self.mode = mode
        self._key_size = self._validate_key_size(key_size)
        if mode == "encrypt":
            self._text = self._validate_text(text) if text else None
        else:
            self._text = text

        self._key = self._validate_key(key) if key else None

        self.subkeys = []

        self._sbox = np.array(
            [
                [
                    0x63,
                    0x7C,
                    0x77,
                    0x7B,
                    0xF2,
                    0x6B,
                    0x6F,
                    0xC5,
                    0x30,
                    0x01,
                    0x67,
                    0x2B,
                    0xFE,
                    0xD7,
                    0xAB,
                    0x76,
                ],
                [
                    0xCA,
                    0x82,
                    0xC9,
                    0x7D,
                    0xFA,
                    0x59,
                    0x47,
                    0xF0,
                    0xAD,
                    0xD4,
                    0xA2,
                    0xAF,
                    0x9C,
                    0xA4,
                    0x72,
                    0xC0,
                ],
                [
                    0xB7,
                    0xFD,
                    0x93,
                    0x26,
                    0x36,
                    0x3F,
                    0xF7,
                    0xCC,
                    0x34,
                    0xA5,
                    0xE5,
                    0xF1,
                    0x71,
                    0xD8,
                    0x31,
                    0x15,
                ],
                [
                    0x04,
                    0xC7,
                    0x23,
                    0xC3,
                    0x18,
                    0x96,
                    0x05,
                    0x9A,
                    0x07,
                    0x12,
                    0x80,
                    0xE2,
                    0xEB,
                    0x27,
                    0xB2,
                    0x75,
                ],
                [
                    0x09,
                    0x83,
                    0x2C,
                    0x1A,
                    0x1B,
                    0x6E,
                    0x5A,
                    0xA0,
                    0x52,
                    0x3B,
                    0xD6,
                    0xB3,
                    0x29,
                    0xE3,
                    0x2F,
                    0x84,
                ],
                [
                    0x53,
                    0xD1,
                    0x00,
                    0xED,
                    0x20,
                    0xFC,
                    0xB1,
                    0x5B,
                    0x6A,
                    0xCB,
                    0xBE,
                    0x39,
                    0x4A,
                    0x4C,
                    0x58,
                    0xCF,
                ],
                [
                    0xD0,
                    0xEF,
                    0xAA,
                    0xFB,
                    0x43,
                    0x4D,
                    0x33,
                    0x85,
                    0x45,
                    0xF9,
                    0x02,
                    0x7F,
                    0x50,
                    0x3C,
                    0x9F,
                    0xA8,
                ],
                [
                    0x51,
                    0xA3,
                    0x40,
                    0x8F,
                    0x92,
                    0x9D,
                    0x38,
                    0xF5,
                    0xBC,
                    0xB6,
                    0xDA,
                    0x21,
                    0x10,
                    0xFF,
                    0xF3,
                    0xD2,
                ],
                [
                    0xCD,
                    0x0C,
                    0x13,
                    0xEC,
                    0x5F,
                    0x97,
                    0x44,
                    0x17,
                    0xC4,
                    0xA7,
                    0x7E,
                    0x3D,
                    0x64,
                    0x5D,
                    0x19,
                    0x73,
                ],
                [
                    0x60,
                    0x81,
                    0x4F,
                    0xDC,
                    0x22,
                    0x2A,
                    0x90,
                    0x88,
                    0x46,
                    0xEE,
                    0xB8,
                    0x14,
                    0xDE,
                    0x5E,
                    0x0B,
                    0xDB,
                ],
                [
                    0xE0,
                    0x32,
                    0x3A,
                    0x0A,
                    0x49,
                    0x06,
                    0x24,
                    0x5C,
                    0xC2,
                    0xD3,
                    0xAC,
                    0x62,
                    0x91,
                    0x95,
                    0xE4,
                    0x79,
                ],
                [
                    0xE7,
                    0xC8,
                    0x37,
                    0x6D,
                    0x8D,
                    0xD5,
                    0x4E,
                    0xA9,
                    0x6C,
                    0x56,
                    0xF4,
                    0xEA,
                    0x65,
                    0x7A,
                    0xAE,
                    0x08,
                ],
                [
                    0xBA,
                    0x78,
                    0x25,
                    0x2E,
                    0x1C,
                    0xA6,
                    0xB4,
                    0xC6,
                    0xE8,
                    0xDD,
                    0x74,
                    0x1F,
                    0x4B,
                    0xBD,
                    0x8B,
                    0x8A,
                ],
                [
                    0x70,
                    0x3E,
                    0xB5,
                    0x66,
                    0x48,
                    0x03,
                    0xF6,
                    0x0E,
                    0x61,
                    0x35,
                    0x57,
                    0xB9,
                    0x86,
                    0xC1,
                    0x1D,
                    0x9E,
                ],
                [
                    0xE1,
                    0xF8,
                    0x98,
                    0x11,
                    0x69,
                    0xD9,
                    0x8E,
                    0x94,
                    0x9B,
                    0x1E,
                    0x87,
                    0xE9,
                    0xCE,
                    0x55,
                    0x28,
                    0xDF,
                ],
                [
                    0x8C,
                    0xA1,
                    0x89,
                    0x0D,
                    0xBF,
                    0xE6,
                    0x42,
                    0x68,
                    0x41,
                    0x99,
                    0x2D,
                    0x0F,
                    0xB0,
                    0x54,
                    0xBB,
                    0x16,
                ],
            ],
            dtype=np.uint32,
        )

        self._inv_sbox = np.array(
            [
                [
                    0x52,
                    0x09,
                    0x6A,
                    0xD5,
                    0x30,
                    0x36,
                    0xA5,
                    0x38,
                    0xBF,
                    0x40,
                    0xA3,
                    0x9E,
                    0x81,
                    0xF3,
                    0xD7,
                    0xFB,
                ],
                [
                    0x7C,
                    0xE3,
                    0x39,
                    0x82,
                    0x9B,
                    0x2F,
                    0xFF,
                    0x87,
                    0x34,
                    0x8E,
                    0x43,
                    0x44,
                    0xC4,
                    0xDE,
                    0xE9,
                    0xCB,
                ],
                [
                    0x54,
                    0x7B,
                    0x94,
                    0x32,
                    0xA6,
                    0xC2,
                    0x23,
                    0x3D,
                    0xEE,
                    0x4C,
                    0x95,
                    0x0B,
                    0x42,
                    0xFA,
                    0xC3,
                    0x4E,
                ],
                [
                    0x08,
                    0x2E,
                    0xA1,
                    0x66,
                    0x28,
                    0xD9,
                    0x24,
                    0xB2,
                    0x76,
                    0x5B,
                    0xA2,
                    0x49,
                    0x6D,
                    0x8B,
                    0xD1,
                    0x25,
                ],
                [
                    0x72,
                    0xF8,
                    0xF6,
                    0x64,
                    0x86,
                    0x68,
                    0x98,
                    0x16,
                    0xD4,
                    0xA4,
                    0x5C,
                    0xCC,
                    0x5D,
                    0x65,
                    0xB6,
                    0x92,
                ],
                [
                    0x6C,
                    0x70,
                    0x48,
                    0x50,
                    0xFD,
                    0xED,
                    0xB9,
                    0xDA,
                    0x5E,
                    0x15,
                    0x46,
                    0x57,
                    0xA7,
                    0x8D,
                    0x9D,
                    0x84,
                ],
                [
                    0x90,
                    0xD8,
                    0xAB,
                    0x00,
                    0x8C,
                    0xBC,
                    0xD3,
                    0x0A,
                    0xF7,
                    0xE4,
                    0x58,
                    0x05,
                    0xB8,
                    0xB3,
                    0x45,
                    0x06,
                ],
                [
                    0xD0,
                    0x2C,
                    0x1E,
                    0x8F,
                    0xCA,
                    0x3F,
                    0x0F,
                    0x02,
                    0xC1,
                    0xAF,
                    0xBD,
                    0x03,
                    0x01,
                    0x13,
                    0x8A,
                    0x6B,
                ],
                [
                    0x3A,
                    0x91,
                    0x11,
                    0x41,
                    0x4F,
                    0x67,
                    0xDC,
                    0xEA,
                    0x97,
                    0xF2,
                    0xCF,
                    0xCE,
                    0xF0,
                    0xB4,
                    0xE6,
                    0x73,
                ],
                [
                    0x96,
                    0xAC,
                    0x74,
                    0x22,
                    0xE7,
                    0xAD,
                    0x35,
                    0x85,
                    0xE2,
                    0xF9,
                    0x37,
                    0xE8,
                    0x1C,
                    0x75,
                    0xDF,
                    0x6E,
                ],
                [
                    0x47,
                    0xF1,
                    0x1A,
                    0x71,
                    0x1D,
                    0x29,
                    0xC5,
                    0x89,
                    0x6F,
                    0xB7,
                    0x62,
                    0x0E,
                    0xAA,
                    0x18,
                    0xBE,
                    0x1B,
                ],
                [
                    0xFC,
                    0x56,
                    0x3E,
                    0x4B,
                    0xC6,
                    0xD2,
                    0x79,
                    0x20,
                    0x9A,
                    0xDB,
                    0xC0,
                    0xFE,
                    0x78,
                    0xCD,
                    0x5A,
                    0xF4,
                ],
                [
                    0x1F,
                    0xDD,
                    0xA8,
                    0x33,
                    0x88,
                    0x07,
                    0xC7,
                    0x31,
                    0xB1,
                    0x12,
                    0x10,
                    0x59,
                    0x27,
                    0x80,
                    0xEC,
                    0x5F,
                ],
                [
                    0x60,
                    0x51,
                    0x7F,
                    0xA9,
                    0x19,
                    0xB5,
                    0x4A,
                    0x0D,
                    0x2D,
                    0xE5,
                    0x7A,
                    0x9F,
                    0x93,
                    0xC9,
                    0x9C,
                    0xEF,
                ],
                [
                    0xA0,
                    0xE0,
                    0x3B,
                    0x4D,
                    0xAE,
                    0x2A,
                    0xF5,
                    0xB0,
                    0xC8,
                    0xEB,
                    0xBB,
                    0x3C,
                    0x83,
                    0x53,
                    0x99,
                    0x61,
                ],
                [
                    0x17,
                    0x2B,
                    0x04,
                    0x7E,
                    0xBA,
                    0x77,
                    0xD6,
                    0x26,
                    0xE1,
                    0x69,
                    0x14,
                    0x63,
                    0x55,
                    0x21,
                    0x0C,
                    0x7D,
                ],
            ],
            dtype=np.uint32,
        )

    def encrypt(self):
        if self._text is None or self._key is None:
            raise ValueError("Text and key must be initialized before encryption.")
        self._NUMBER_OF_ROUNDS = self._POSSIBLE_NUMBER_OF_ROUNDS[self._key_size]
        self._SUBKEY_CONSTANT = self._SUBKEY_CONSTANTS[self._key_size]
        self._generate_subkeys()

        if self._key_size == 256:
            subkey_first_half, subkey_second_half = np.split(
                self.subkeys[0].flatten(), 2
            )
            initial_transformation = (
                np.bitwise_xor(self._text.flatten(), subkey_first_half)
                ^ subkey_second_half
            )
        else:
            initial_transformation = np.bitwise_xor(
                self._text.flatten(), self.subkeys[0].flatten()
            )

        initial_transformation = initial_transformation.reshape(4, 4)
        cipher_text = initial_transformation

        for i in range(self._NUMBER_OF_ROUNDS):
            is_last = False if i < self._NUMBER_OF_ROUNDS - 1 else True
            cipher_text = self.round_func(
                plain_text=cipher_text, subkey=self.subkeys[i + 1], is_last=is_last
            )
            self.CT += 1
        # cipher_text = ''.join([chr(item) for item in cipher_text.flatten()])
        # last_round_key = ''.join([chr(item) for item in self.subkeys[-1].flatten()])

        return cipher_text.flatten()

    def add_round_key(self, text, subkey, isLast=False):
        subkey = subkey if self.mode == "encrypt" or isLast else self.mix_cols(subkey)
        result = []
        if self._key_size == 256:
            subkey_first_half, subkey_second_half = np.split(subkey.flatten(), 2)
            result = (
                np.bitwise_xor(text.flatten(), subkey_first_half) ^ subkey_second_half
            )
        else:
            result = np.bitwise_xor(text.flatten(), subkey.flatten())
        return result.reshape(4, 4)

    def substitute_bytes(self, matrix):
        sbox = self._sbox if self.mode == "encrypt" else self._inv_sbox

        for i, row in enumerate(matrix):
            for j, col in enumerate(row):
                bits = np.binary_repr(col, width=8)
                row_lookup = int(bits[:4], 2)
                col_lookup = int(bits[4:], 2)

                matrix[i][j] = sbox[row_lookup][col_lookup]
        return matrix

    def shift_rows(self, matrix):
        direction = -1 if self.mode == "encrypt" else 1
        matrix = np.transpose(matrix)
        matrix[1, :] = np.roll(matrix[1, :], 1 * direction)
        matrix[2, :] = np.roll(matrix[2, :], 2 * direction)
        matrix[3, :] = np.roll(matrix[3, :], 3 * direction)
        matrix = np.transpose(matrix)
        return matrix

    def mix_cols(self, matrix):
        num_columns = matrix.shape[1]

        result = np.zeros_like(matrix, dtype=np.uint8)

        for col in range(num_columns):
            result[:, col] = self.mix_column(matrix[:, col])

        return result

    def mix_column(self, column):
        matrix = (
            np.array(
                [
                    [0x02, 0x03, 0x01, 0x01],
                    [0x01, 0x02, 0x03, 0x01],
                    [0x01, 0x01, 0x02, 0x03],
                    [0x03, 0x01, 0x01, 0x02],
                ],
                dtype=np.uint8,
            )
            if self.mode == "encrypt"
            else np.array(
                [
                    [0x0E, 0x0B, 0x0D, 0x09],
                    [0x09, 0x0E, 0x0B, 0x0D],
                    [0x0D, 0x09, 0x0E, 0x0B],
                    [0x0B, 0x0D, 0x09, 0x0E],
                ],
                dtype=np.uint8,
            )
        )

        result = np.zeros_like(column, dtype=np.uint8)

        for i in range(4):
            result[i] = (
                self.galois_mult(matrix[i, 0], column[0])
                ^ self.galois_mult(matrix[i, 1], column[1])
                ^ self.galois_mult(matrix[i, 2], column[2])
                ^ self.galois_mult(matrix[i, 3], column[3])
            )

        return result

    def galois_mult(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B
            b >>= 1
        return p

    def round_func(self, plain_text, subkey, is_last=False):
        sub_bytes = self.substitute_bytes(plain_text)
        shift_rows = self.shift_rows(sub_bytes)
        last_permutation = self.mix_cols(shift_rows) if not is_last else shift_rows
        round_result = self.add_round_key(last_permutation, subkey, is_last)

        return round_result

    def _validate_key_size(self, key_size):
        if key_size not in self._VALID_KEY_SIZES:
            raise ValueError("Invalid key size. Please use 128, 192, or 256.")
        return key_size

    def _validate_text(self, text):
        if self.mode == "decrypt":
            return text
        text = text[: min(len(text), self._BLOCK_SIZE)]
        text_len = len(bytes(text, "UTF-8"))
        if text_len < self._BLOCK_SIZE:
            text = text + " " * (self._BLOCK_SIZE - text_len)

        return np.frombuffer(bytes(text, "UTF-8"), dtype=np.uint8)

    def _validate_key(self, key):
        if key is None:
            raise ValueError(
                f"Invalid key size. Please enter a key size of {self._key_size}"
            )
        elif len(key) * 8 != self._key_size:
            key = key * (self._key_size // len(key))

        return np.frombuffer(bytes(key, "UTF-8"), dtype=np.uint8)

    def set_text(self, text):
        self._text = self._validate_text(text)

    def set_key(self, key):
        self._key = self._validate_key(key)

    def g_func(self, w, round_number):
        constant_array = np.zeros(len(w), dtype=np.uint32)
        constant_array[0] = self._SUBKEY_CONSTANT[round_number]
        new_w = np.zeros(len(w), dtype=np.uint32)
        w = np.roll(w, -1)
        sbox = self._sbox
        for i, bit in enumerate(w):
            w_bits = np.binary_repr(bit, width=8)
            row = int(w_bits[:4], 2)
            col = int(w_bits[4:], 2)
            new_w[i] = sbox[row][col]

        xor = np.bitwise_xor(new_w, constant_array)
        return xor

    def _generate_subkeys(self):
        # Generate subkeys manually for my AES code
        key_size_in_words = self._NUMBER_OF_SUBKEY_WORDS[self._key_size]
        sub_keys = np.zeros(
            (self._NUMBER_OF_ROUNDS + 1, key_size_in_words, 4), dtype=np.uint32
        )

        for i in range(key_size_in_words):
            sub_keys[0][i] = self._key[4 * (i) : 4 * (i + 1)]

        for i in range(self._NUMBER_OF_ROUNDS):
            last_word = sub_keys[i][-1]
            xor_word = self.g_func(last_word, round_number=i)
            new_word = np.zeros(key_size_in_words * 4, dtype=np.uint32)
            ct = 0
            for n, word in enumerate(sub_keys[i]):
                for z, w in enumerate(word):
                    new_word[ct] = np.bitwise_xor(xor_word[z], w)
                    ct += 1
                xor_word = new_word[4 * n : (4 * n) + 4]
            new_word = new_word.reshape((key_size_in_words, 4))

            sub_keys[i + 1][:] = new_word

        self.subkeys = sub_keys if self.mode == "encrypt" else np.flip(sub_keys, axis=0)

    @property
    def text(self):
        return self._text

    @property
    def key(self):
        return self._key


# key128 = "sss"
# plain_text = "sssasa"
# print(len(key128))
# print(int("20", base=16))
# print("########### ENCRYPT ###########")
# my_aes = AES(128, text=plain_text, key=key128, mode="encrypt")
# cipher_text = my_aes.encrypt()
# print("CIPHER TEXT:", [hex(c)[2:] for c in cipher_text])
# print("CIPHER TEXT_LEN:", len(cipher_text))

# print("########### DECRYPT ###########")
# my_aes_decrypt = AES(128, text=cipher_text, key=key128, mode="decrypt")
# plain_text = my_aes_decrypt.encrypt()

# print("PLAIN TEXT:")
# print("PLAIN TEXT:", "".join(chr(p) for p in plain_text))
# print("PLAIN TEXT_LEN:", len(plain_text))
