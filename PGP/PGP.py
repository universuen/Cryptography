import random
import base64

from md5 import md5sum as _md5
from rsa import RSA
from zip import LZ77Compressor
from idea import IDEA


class PGP:

    def __init__(self):
        super(PGP, self).__init__()
        self.rsa = RSA()
        self.zip = LZ77Compressor()
        self.idea = IDEA()

    def encrypt(self, bin_data):
        data = bin_data
        print("Calculating md5 ...")
        md5 = _md5(data)
        print("Calculating sign ...")
        sign = self.rsa.encrypt(md5)
        data = data + sign
        print("Compressing ...")
        data = self.zip.compress(data)
        print("Encrypting ...")

        en_data = bytes()
        for b in data:
            en_data += self.idea.encrypt(int(b))

        en_key = bytes()
        for i in self.idea.expand_key:
            en_key += self.rsa.encrypt(i)

        print(len(en_key))
        data = en_data + en_key
        print("Done")
        return data, self.rsa.private_key

    def decrypt(self, bin_data, rsa_private_key):
        en_key = bin_data[-1664:]
        data = bin_data[:len(bin_data) - 1664]
        rsa = RSA()
        rsa.private_key = rsa_private_key

        print("Extracting IDEA expand key...")
        de_key = list()
        for i in range(52):
            de_key.append(rsa.decrypt(en_key[32*i: 32*(i+1)]))
        idea = IDEA(de_key)

        print("Decrypting data")
        de_data = bytes()
        while len(data)!=0:
            de_data += idea.decrypt(int.from_bytes(data[:128], "big"))
            data = data[128:]
        # for b in data:
        #     de_data += idea.decrypt(int(b))

        print("Decompressing data...")
        data = self.zip.decompress(de_data)

        print("Verifying data...")
        data, original_sign = data[:len(data)-32], data[-32:]
        original_md5 = rsa.decrypt(original_sign)
        md5 = _md5(data)

        if original_md5 == md5:
            print("Verified!")
            return data
        else:
            print(f"Verification failed!\n"
                  f"Original md5: {original_md5}\n"
                  f"Calculated md5: {md5}\n")
            return None


if __name__ == '__main__':

    pgp = PGP()
    data = bytes("666".encode())
    en_data, rsa_key = pgp.encrypt(data)
    print(en_data)
    de_data = pgp.decrypt(en_data, rsa_key)
    print(de_data)

