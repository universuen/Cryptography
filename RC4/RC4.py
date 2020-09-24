class RC4:
    def __init__(self, key:str):
        # 密钥长度应小于等于256
        assert len(key) <= 256

        # 线性填充S表
        self.S = [i for i in range(256)]

        # 使用密钥顺序填充R表
        R = []
        index = 0
        for i in range(256):
            R.append(ord(key[index]))
            index = (index+1)%len(key)

        # S表初始化
        j = 0
        for i in range(256):
            j = (j + self.S[i] + R[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def encrypt(self, file:str):
        # 读取文件内容
        with open(file, "rb") as f:
            data = f.read()

        # 产生密钥流
        key_stream = []
        i = 0
        j = 0
        for _ in range(len(data)):
            i = (i + 1)%256
            j = (j + self.S[i])%256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            t = (self.S[i] + self.S[j])%256
            key_stream.append(self.S[t])

        # 将bytes转换为bytearray
        data = bytearray(data)
        # 依据密钥流对数据进行加密
        for i in range(len(data)):
            data[i] = data[i]^key_stream[i]

        with open("encrypted_" + file, "wb") as f:
            f.write(data)

    def decrypt(self, file:str):
        # 读取文件内容
        with open(file, "rb") as f:
            data = f.read()

        # 产生密钥流
        key_stream = []
        i = 0
        j = 0
        for _ in range(len(data)):
            i = (i + 1)%256
            j = (j + self.S[i])%256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            t = (self.S[i] + self.S[j])%256
            key_stream.append(self.S[t])

        # 将bytes转换为bytearray
        data = bytearray(data)
        # 依据密钥流对数据进行加密
        for i in range(len(data)):
            data[i] = data[i]^key_stream[i]

        with open("decrypted_" + file, "wb") as f:
            f.write(data)






if __name__ == '__main__':
    rc4 = RC4("123456")
    rc4.encrypt("video.mp4")