import md5
import rsa
import IDEA
import base_64
import zipstream

p1 = 11892845164754857302192817993787160730215019683720078508868206227442930130722825064091815998764273410046313495341034135557819502333338074415976198866323473
q1 = 11367670600867484708699649015361923450974263455941875059545547729179804359361891954089186046814453092650085798107044468298400840193141395710340815439355097
e1 = 611

p2 = 9642527161848298071201545183109583441210324913672887812774031163540292555923225605591510697538531861645360860564168061047846750456591161660397179909428673
q2 = 12462877728415710567613768729223820618177080415134397242805949239369738252514787058260709601317833487891379767183882860432583979533234009460190395592629511
e2 = 931


class KeyPair:
    def __init__(self, pub_key, pri_key):
        self.pub_key = pub_key
        self.pri_key = pri_key


class PGP:
    def __init__(self):
        # Generate sender's key pair
        pub_key, pri_key = rsa.gen_key(p1, q1, e1)
        self.sender = KeyPair(pub_key, pri_key)
        # Generate receiver's key pair
        pub_key, pri_key = rsa.gen_key(p2, q2, e2)
        self.receiver = KeyPair(pub_key, pri_key)
        # Instantiate a zip compressor
        self.compressor = zipstream.LZ77Compressor()

    def encrypt(self, msg):
        print('Started encryption')
        # MD5(M)
        print('\tCalculating md5')
        md5_hash = md5.md5sum(msg)
        m = int(md5_hash, 16)

        # MD5(M) -> S
        print('\tGenerating signature')
        sign = rsa.decrypt(m, self.sender.pri_key)
        sign = '{:01024b}'.format(sign)
        sign = sign.encode('utf-8')

        # <M, S> -> ZIP(M, S)
        print('\tCompressing')
        new_msg = msg
        for i in range(int(len(sign) / 8)):
            tmp = sign[i * 8: i * 8 + 8]
            data = int(tmp, 2)
            data = bytes([data])
            new_msg = new_msg + data
        new_msg = self.compressor.compress(new_msg).tobytes()

        # IDEA(ZIP(M, S))
        print('\tEncrypting compressed data')
        idea_key = 0x4AD6459F82C5B300952C49104881EF51
        idea_msg = IDEA.IDEA_en(new_msg, idea_key)

        # RSA(k)
        print('\tEncrypting key')
        rsa_key = rsa.encrypt(idea_key, self.receiver.pub_key)
        rsa_key = '{:01024b}'.format(rsa_key)
        rsa_key = rsa_key.encode('utf-8')

        # <IDEA(ZIP(M, S)), RSA(k)>
        print('\tConcatenating')
        data_part = idea_msg
        for i in range(int(len(rsa_key) / 8)):
            tmp = rsa_key[i * 8: i * 8 + 8]
            data = int(str(tmp, encoding='utf8'), 2)  # bytes->str->int
            data = bytes([data])  # int->bytes
            data_part = data_part + data
        result = base_64.encode(data_part)
        print('Done!')
        return result

    def decrypt(self, en_msg):
        print('Started decryption')
        # <IDEA(ZIP(M, S)), RSA(k)> -> IDEA(ZIP(M, S)), RSA(k)
        print('\tExtracting key')
        bin_en_msg = base_64.decode(en_msg)
        idea_en_msg = bin_en_msg[:-128]
        en_key = bin_en_msg[-128:]

        # RSA(k) -> k
        print('\tDecrypting key')
        temp_key = "".encode('utf-8')
        for i in range(int(len(en_key))):
            tmp = en_key[i]
            tmp = int(tmp)  # bytes->int
            tmp = '{:08b}'.format(tmp).encode('utf-8')  # int->str->bytes
            temp_key = temp_key + tmp
        en_key = int(str(temp_key.decode('utf-8')), 2)
        idea_key = rsa.decrypt(en_key, self.receiver.pri_key)

        # IDEA(ZIP(M, S)) -> ZIP(M, S)
        print('\tDecrypting data')
        msg = IDEA.IDEA_de(idea_en_msg, idea_key)

        # ZIP(M, S) -> M, S
        print('\tDecompressing data')
        msg = zipstream.bytes2bitarray(msg)
        msg = self.compressor.decompress(msg)
        message = msg[:-128]
        sign = msg[-128:]
        temp_sign = "".encode('utf-8')
        for i in range(int(len(sign))):
            tmp = sign[i]
            tmp = int(tmp)  # bytes->int
            tmp = '{:08b}'.format(tmp).encode('utf-8')  # int->str->bytes
            temp_sign = temp_sign + tmp
        sign = int(str(temp_sign.decode('utf-8')), 2)

        # Verification
        print('\tVerifying')
        original_md5 = rsa.encrypt(sign, self.sender.pub_key)
        original_md5 = hex(original_md5)[2:]
        print(f'Original md5: \t{original_md5}')
        current_md5 = md5.md5sum(message)
        print(f'Current md5: \t{current_md5}')
        if current_md5 == original_md5:
            print('Verified!')
            return message
        else:
            print("Verification failed!")
            return None


if __name__ == '__main__':
    import time

    pgp = PGP()

    with open("./ys168.com.txt", "rb") as f:
        msg = f.read()

    start = time.perf_counter()
    en_msg = pgp.encrypt(msg)
    end = time.perf_counter()
    duration = end - start
    print(f'Encryption costs {duration: .3f} s')
    with open("./en_msg.txt", "w") as f:
        f.write(en_msg)

    start = time.perf_counter()
    de_msg = pgp.decrypt(en_msg)
    end = time.perf_counter()
    duration = end - start
    print(f'Decryption costs {duration: .3f} s')
    with open("./de_msg.txt", "wb") as f:
        f.write(de_msg)
