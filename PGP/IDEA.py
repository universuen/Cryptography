def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def mod_inv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def _mul(x, y):
    assert 0 <= x <= 0xFFFF
    assert 0 <= y <= 0xFFFF

    if x == 0:
        x = 0x10000
    if y == 0:
        y = 0x10000

    r = (x * y) % 0x10001

    if r == 0x10000:
        r = 0

    assert 0 <= r <= 0xFFFF
    return r


def _KA_layer(x1, x2, x3, x4, round_keys):
    assert 0 <= x1 <= 0xFFFF
    assert 0 <= x2 <= 0xFFFF
    assert 0 <= x3 <= 0xFFFF
    assert 0 <= x4 <= 0xFFFF

    z1, z2, z3, z4 = round_keys[0:4]
    assert 0 <= z1 <= 0xFFFF
    assert 0 <= z2 <= 0xFFFF
    assert 0 <= z3 <= 0xFFFF
    assert 0 <= z4 <= 0xFFFF

    y1 = _mul(x1, z1)
    y2 = (x2 + z2) % 0x10000
    y3 = (x3 + z3) % 0x10000
    y4 = _mul(x4, z4)

    return y1, y2, y3, y4


def _MA_layer(y1, y2, y3, y4, round_keys):
    assert 0 <= y1 <= 0xFFFF
    assert 0 <= y2 <= 0xFFFF
    assert 0 <= y3 <= 0xFFFF
    assert 0 <= y4 <= 0xFFFF
    z5, z6 = round_keys[4:6]
    assert 0 <= z5 <= 0xFFFF
    assert 0 <= z6 <= 0xFFFF

    p = y1 ^ y3
    q = y2 ^ y4

    s = _mul(p, z5)
    t = _mul((q + s) % 0x10000, z6)
    u = (s + t) % 0x10000

    x1 = y1 ^ t
    x2 = y2 ^ u
    x3 = y3 ^ t
    x4 = y4 ^ u

    return x1, x2, x3, x4


class IDEA:
    def __init__(self, key):
        self._expand_key = []
        self._encrypt_key = None
        self._decrypt_key = None
        self.expand_key(key)
        self.get_encrypt_key()
        self.get_decrypt_key()

    def expand_key(self, key):
        assert 0 <= key < (1 << 128)
        modulus = 1 << 128
        for i in range(6 * 8 + 4):
            self._expand_key.append((key >> (112 - 16 * (i % 8))) % 0x10000)
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % modulus
        return self._expand_key

    def get_encrypt_key(self):
        keys = []
        for i in range(9):
            round_keys = self._expand_key[6 * i:6 * (i + 1)]
            keys.append(tuple(round_keys))
        self._encrypt_key = tuple(keys)

    def get_decrypt_key(self):
        keys = [0] * 52
        for i in range(9):
            if i == 0:
                for j in range(6):
                    if j == 0 or j == 3:
                        if self._encrypt_key[8 - i][j] == 0:
                            keys[j] = 0
                        else:
                            keys[j] = mod_inv(self._encrypt_key[8 - i][j],
                                                   65537)
                    elif j == 1 or j == 2:
                        keys[j] = (65536 - self._encrypt_key[8 - i][j]) % 65536
                    else:
                        keys[j] = self._encrypt_key[7 - i][j]
            elif i < 8:
                for j in range(6):
                    if j == 0 or j == 3:
                        if self._encrypt_key[8 - i][j] == 0:
                            keys[i * 6 + j] = 0
                        else:
                            keys[i * 6 + j] = mod_inv(
                                self._encrypt_key[8 - i][j], 65537)
                    elif j == 1 or j == 2:
                        keys[i * 6 + 3 -
                             j] = (65536 - self._encrypt_key[8 - i][j]) % 65536
                    else:
                        keys[i * 6 + j] = self._encrypt_key[7 - i][j]
            else:
                for j in range(4):
                    if j == 0 or j == 3:
                        if self._encrypt_key[8 - i][j] == 0:
                            keys[i * 6 + j] = 0
                        else:
                            keys[i * 6 + j] = mod_inv(
                                self._encrypt_key[8 - i][j], 65537)
                    else:
                        keys[i * 6 +
                             j] = (65536 - self._encrypt_key[8 - i][j]) % 65536
        tmp = []
        for i in range(9):
            round_keys = keys[6 * i:6 * (i + 1)]
            tmp.append(tuple(round_keys))
        self._decrypt_key = tuple(tmp)

    def enc_dec(self, plaintext, flag):
        assert 0 <= plaintext < (1 << 64)
        x1 = (plaintext >> 48) & 0xFFFF
        x2 = (plaintext >> 32) & 0xFFFF
        x3 = (plaintext >> 16) & 0xFFFF
        x4 = plaintext & 0xFFFF
        if flag == 0:
            key = self._encrypt_key
        else:
            key = self._decrypt_key
        for i in range(8):
            round_keys = key[i]

            y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, round_keys)
            x1, x2, x3, x4 = _MA_layer(y1, y2, y3, y4, round_keys)

            x2, x3 = x3, x2

        # Note: The words x2 and x3 are not permuted in the last round
        # So here we use x1, x3, x2, x4 as input instead of x1, x2, x3, x4
        # in order to cancel the last permutation x2, x3 = x3, x2
        y1, y2, y3, y4 = _KA_layer(x1, x3, x2, x4, key[8])

        ciphertext = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return ciphertext

def IDEA_en(M, key):
    my_IDEA = IDEA(key)
    original_len = len(M)
    if len(M) % 8 != 0:
        #PADDING
        #填充后的长度是64bits的整数倍 即8bytes的整数倍
        M = M + bytes([1])
        pad_zero_len = 0
        while((pad_zero_len + original_len + 2) % 8 !=0):
            pad_zero_len += 1
        M = M + bytes(pad_zero_len)
        M = M + bytes([pad_zero_len]) #存储填充0的个数
        #print(M)
    else:
        #若已为8bytes的整数倍，填充8个bytes的0
        M = M + bytes(8)
    LEN = int(len(M) / 8)
    Cipher = bytes()
    for i in range(LEN):
        plain = M[i*8: i*8+8]
        plain = int.from_bytes(plain, byteorder='little', signed=False)
        #密文 10进制形式
        encrypted = my_IDEA.enc_dec(plain, 0)
        Cipher = Cipher + int(encrypted).to_bytes(8, byteorder='little', signed=False)
    return Cipher

def IDEA_de(Cipher, key):
    my_IDEA = IDEA(key)
    Decrypted = bytes()
    LEN = int(len(Cipher) / 8)
    for i in range(LEN):
        cipher = Cipher[i*8:i*8+8]
        cipher = int.from_bytes(cipher, byteorder='little', signed=False)
        decrypted = my_IDEA.enc_dec(cipher, 1)
        Decrypted = Decrypted + int(decrypted).to_bytes(8, byteorder='little', signed=False)
    pad_zero_len = Decrypted[-1]
    if pad_zero_len:
        #若padding过
        original_len = len(Cipher) - 2 - pad_zero_len
        Decrypted = Decrypted[:original_len]
    else:
        Decrypted = Decrypted[:-8]
    return Decrypted

def main():
    import time
    key = 0x2BD6459F82C5B300952C49104881FF48
    #print('key\t\t', hex(key))
    f = open("test.txt", "rb")
    M = f.read()
    my_IDEA = IDEA(key)
    s = 55
    s = '{:01024b}'.format(s)
    s = s.encode('utf-8')
    S = ''
    for i in range(int(len(s)/8)):
        tmp = s[i * 8 : i * 8 + 8]
        data = int(str(tmp, encoding='utf8'), 2)
        data = bytes([data])
        M = M + data
    original_len = len(M)
    if len(M) % 8 != 0:
        #PADDING
        #填充后的长度是64bits的整数倍 即8bytes的整数倍
        M = M + bytes([1])
        pad_zero_len = 0
        while((pad_zero_len + original_len + 2) % 8 !=0):
            pad_zero_len += 1
        M = M + bytes(pad_zero_len) #填充这么多个0
        M = M + bytes([pad_zero_len]) #存储填充0的个数
        #print(M)
    LEN = int(len(M) / 8)
    Cipher = bytes()

    for i in range(LEN):
        plain = M[i*8: i*8+8]
        plain = int.from_bytes(plain, byteorder='little', signed=False)
        #密文 10进制形式
        encrypted = my_IDEA.enc_dec(plain, 0)
        Cipher = Cipher + int(encrypted).to_bytes(8, byteorder='little', signed=False)
    print(Cipher)

    Decrypted = bytes()
    LEN = int(len(Cipher) / 8)
    for i in range(LEN):
        cipher = Cipher[i*8:i*8+8]
        cipher = int.from_bytes(cipher, byteorder='little', signed=False)
        decrypted = my_IDEA.enc_dec(cipher, 1)
        #print(int(decrypted).to_bytes(8, byteorder='little', signed=False))
        Decrypted = Decrypted + int(decrypted).to_bytes(8, byteorder='little', signed=False)
    pad_zero_len = Decrypted[-1]
    original_len = len(Cipher) - 2 - pad_zero_len
    Decrypted = Decrypted[:original_len]
    print(Decrypted)
if __name__ == '__main__':
    main()
