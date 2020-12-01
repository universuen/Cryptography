import binascii
import sys
import os.path

SV = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
      0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
      0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
      0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
      0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
      0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
      0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
      0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
      0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039,
      0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
      0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
      0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
      0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]


def leftCircularShift(k, bits):
    bits = bits % 32
    k = k % (2 ** 32)
    upper = (k << bits) % (2 ** 32)
    result = upper | (k >> (32 - (bits)))
    return (result)


def blockDivide(block, chunks):
    result = []
    size = len(block) // chunks
    for i in range(0, chunks):
        result.append(int.from_bytes(block[i * size:(i + 1) * size], byteorder="little"))
    return (result)


def F(X, Y, Z):
    return ((X & Y) | ((~X) & Z))


def G(X, Y, Z):
    return ((X & Z) | (Y & (~Z)))


def H(X, Y, Z):
    return (X ^ Y ^ Z)


def I(X, Y, Z):
    return (Y ^ (X | (~Z)))


def FF(a, b, c, d, M, s, t):
    result = b + leftCircularShift((a + F(b, c, d) + M + t), s)
    return (result)


def GG(a, b, c, d, M, s, t):
    result = b + leftCircularShift((a + G(b, c, d) + M + t), s)
    return (result)


def HH(a, b, c, d, M, s, t):
    result = b + leftCircularShift((a + H(b, c, d) + M + t), s)
    return (result)


def II(a, b, c, d, M, s, t):
    result = b + leftCircularShift((a + I(b, c, d) + M + t), s)
    return (result)


def fmt8(num):
    bighex = "{0:08x}".format(num)
    binver = binascii.unhexlify(bighex)
    result = "{0:08x}".format(int.from_bytes(binver, byteorder='little'))
    return (result)


def bitlen(bitstring):
    return (len(bitstring) * 8)


def md5sum(msg):
    # First, we pad the message
    msgLen = bitlen(msg) % (2 ** 64)
    msg = msg + b'\x80'
    zeroPad = (448 - (msgLen + 8) % 512) % 512
    zeroPad //= 8
    msg = msg + b'\x00' * zeroPad + msgLen.to_bytes(8, byteorder='little')
    msgLen = bitlen(msg)
    iterations = msgLen // 512
    # chaining variables
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476
    # main loop
    for i in range(0, iterations):
        a = A
        b = B
        c = C
        d = D
        block = msg[i * 64:(i + 1) * 64]
        M = blockDivide(block, 16)
        # Rounds
        a = FF(a, b, c, d, M[0], 7, SV[0])
        d = FF(d, a, b, c, M[1], 12, SV[1])
        c = FF(c, d, a, b, M[2], 17, SV[2])
        b = FF(b, c, d, a, M[3], 22, SV[3])
        a = FF(a, b, c, d, M[4], 7, SV[4])
        d = FF(d, a, b, c, M[5], 12, SV[5])
        c = FF(c, d, a, b, M[6], 17, SV[6])
        b = FF(b, c, d, a, M[7], 22, SV[7])
        a = FF(a, b, c, d, M[8], 7, SV[8])
        d = FF(d, a, b, c, M[9], 12, SV[9])
        c = FF(c, d, a, b, M[10], 17, SV[10])
        b = FF(b, c, d, a, M[11], 22, SV[11])
        a = FF(a, b, c, d, M[12], 7, SV[12])
        d = FF(d, a, b, c, M[13], 12, SV[13])
        c = FF(c, d, a, b, M[14], 17, SV[14])
        b = FF(b, c, d, a, M[15], 22, SV[15])
        a = GG(a, b, c, d, M[1], 5, SV[16])
        d = GG(d, a, b, c, M[6], 9, SV[17])
        c = GG(c, d, a, b, M[11], 14, SV[18])
        b = GG(b, c, d, a, M[0], 20, SV[19])
        a = GG(a, b, c, d, M[5], 5, SV[20])
        d = GG(d, a, b, c, M[10], 9, SV[21])
        c = GG(c, d, a, b, M[15], 14, SV[22])
        b = GG(b, c, d, a, M[4], 20, SV[23])
        a = GG(a, b, c, d, M[9], 5, SV[24])
        d = GG(d, a, b, c, M[14], 9, SV[25])
        c = GG(c, d, a, b, M[3], 14, SV[26])
        b = GG(b, c, d, a, M[8], 20, SV[27])
        a = GG(a, b, c, d, M[13], 5, SV[28])
        d = GG(d, a, b, c, M[2], 9, SV[29])
        c = GG(c, d, a, b, M[7], 14, SV[30])
        b = GG(b, c, d, a, M[12], 20, SV[31])
        a = HH(a, b, c, d, M[5], 4, SV[32])
        d = HH(d, a, b, c, M[8], 11, SV[33])
        c = HH(c, d, a, b, M[11], 16, SV[34])
        b = HH(b, c, d, a, M[14], 23, SV[35])
        a = HH(a, b, c, d, M[1], 4, SV[36])
        d = HH(d, a, b, c, M[4], 11, SV[37])
        c = HH(c, d, a, b, M[7], 16, SV[38])
        b = HH(b, c, d, a, M[10], 23, SV[39])
        a = HH(a, b, c, d, M[13], 4, SV[40])
        d = HH(d, a, b, c, M[0], 11, SV[41])
        c = HH(c, d, a, b, M[3], 16, SV[42])
        b = HH(b, c, d, a, M[6], 23, SV[43])
        a = HH(a, b, c, d, M[9], 4, SV[44])
        d = HH(d, a, b, c, M[12], 11, SV[45])
        c = HH(c, d, a, b, M[15], 16, SV[46])
        b = HH(b, c, d, a, M[2], 23, SV[47])
        a = II(a, b, c, d, M[0], 6, SV[48])
        d = II(d, a, b, c, M[7], 10, SV[49])
        c = II(c, d, a, b, M[14], 15, SV[50])
        b = II(b, c, d, a, M[5], 21, SV[51])
        a = II(a, b, c, d, M[12], 6, SV[52])
        d = II(d, a, b, c, M[3], 10, SV[53])
        c = II(c, d, a, b, M[10], 15, SV[54])
        b = II(b, c, d, a, M[1], 21, SV[55])
        a = II(a, b, c, d, M[8], 6, SV[56])
        d = II(d, a, b, c, M[15], 10, SV[57])
        c = II(c, d, a, b, M[6], 15, SV[58])
        b = II(b, c, d, a, M[13], 21, SV[59])
        a = II(a, b, c, d, M[4], 6, SV[60])
        d = II(d, a, b, c, M[11], 10, SV[61])
        c = II(c, d, a, b, M[2], 15, SV[62])
        b = II(b, c, d, a, M[9], 21, SV[63])
        A = (A + a) % (2 ** 32)
        B = (B + b) % (2 ** 32)
        C = (C + c) % (2 ** 32)
        D = (D + d) % (2 ** 32)
    result = fmt8(A) + fmt8(B) + fmt8(C) + fmt8(D)
    return (result)


if __name__ == "__main__":
    # data = bytes("666".encode())
    data = b'ys168yy\tyy65035074\tys168@citiz.net\r\nty\tzyh888\t\r\nzlj\to1t2t3f4f5s6\t666\r\nwns\t95522039\twns_d0@citiz.net\r\nrj\tshanghairz\t\r\nlj\t9336\thaydeelj@163.com\r\njl\t8964\t-\r\nwangshuibin\twsba3203190812\twangshuibin@21cn.com\r\nhpwsb\thtwsb851123\twaxxbb@21cn.com\r\nsunjbh\t810512jbh*no603\tsunjbh@163.com\r\nmoonboy\t810512jbh*no603\tsunjbh@163.com\r\nNet-HoMe\t810512jbh*no603\tsunjbh@163.com\r\nkkk\tcomein\tgycctv@gmail.com\r\nkk\tcomeon\tsickdog@163.com\r\nys168\tsbgogl731218\tliyago@21cn.com\r\ndxh0564229\t861211\tdxh0564229@163.com\r\npalxex\t198484dzyhsf\tpalxex@163.com\r\nhyhack\tgaozhifeng2006\ta5648403@yahoo.com.cn\r\ncandy\tcandygirl\tsis2@163.com\r\nwljy\tyywljy\tyy\r\n168\tsbgogl731218\tliyago@21cn.com\r\n163\tsbgogl731218\tliyago@21cn.com\r\n45894600\tliweilovehacker\tliwei2070@sina.com\r\nzhouqi\t47603603\tzqzhouqi@163.com\r\nhappywap\tgdlfxyq1977\thappywap@21cn.com\r\ntyda\t908797\tsimee-yb@online.sh.cn\r\nyun\tcomein\tgycctv@gmail.com\r\ntxjlxs\t87136690\ttxjlxs@yahoo.com.cn\r\njinlong0091\tlinxi0091\tjinlong00@qq.com\r\n9huan\t2862emkdt\txingkong919@yahoo.com.cn\r\nmusic\tzlcc123\tsm2002sm@21cn.com\r\nok\tcomeon\tsickdog@163.com\r\nlzh520\twyswb513\twb1973@gmail.com\r\ncn\tqq1113xh2004b\t51eph@163.com\r\niceboy\tzhangyong1068\tabvf@163.com\r\naihua\tiloveyuo105\tfq147@mail.china.com\r\nhacker\tchobits87925\twwwbox@126.com\r\nhaze\t789654\thazevip@msn.com\r\ncs\tfollowme\tcs@sol.net.cn\r\nclon911\tmm51uc668xx\t51eph@163.com\r\nluwang\t8299188\t272715151@qq.com\r\nlh\tshangxin\tmingkai_008@163.com\r\nmgsz\tqq51vb25uc\tuc51@163.com\r\nyxxsh\t2218\tadite@qq.com\r\ncaps123cn\t105111\tcaps123cn@163.com\r\nlwj\twapadad928898\ttolwj@sina.com\r\nzhaoxin\t19820418\t9055765@qq.com\r\nwuaili\tFEIfei82\t10056@163.com\r\nnick\tnickzzw\tnickzzw@163.com\r\nabc\tjswl123\tsm2002sm@21cn.com\r\nzoti\talamode\tfsdafasf\r\nba\tsbgogl731218\tliyago@21cn.com\r\nfollow\tiloveyuo105\taijob@qq.com\r\nbb\t981123\tliyagomr@etang.com\r\nhaha\twlzl123\tsm2002sm@21cn.com\r\nloveliu\t831216\tloveliu83@sohu.com\r\n123\tsbgogl731218\tliyago@21cn.com\r\nchina\tsbgogl731218\tliyago@21cn.com\r\n7\t!&()*\tqun-er@tom.com\r\n1\tmydns810318131\tyanlei213@126.com\r\n3\tsbgogl731218\tliyago@21cn.com\r\nlzh3812560\t831015\tlzh3812560@163.com\r\njunjie\t6591543\t3207105@qq.com\r\nking\t1984414\tlizhejiang@eyou.com\r\nghol\t4721207\tmuronglingqian@MsN.CoM\r\n10\tsbgogl731218\tliyago@21cn.com\r\n789\tjscc123\tsm2002sm@21cn.com\r\ne\t643033\tqun-er@tom.com\r\nh\t!&()*\tqun-er@tom.com\r\nl\tzhjhklsq\tlushunqin@163.com\r\n0\tjskj123\tsm2002sm@21cn.com\r\nsss\twinntsss\tnetill@yeah.net\r\nzjsxzgx\t1309567962\tzjsxzgx@hotmail.com\r\nliyang\t616417\tcounseling75@yahoo.com.cn\r\nmm\tsbgogl731218\tliyago@21cn.com\r\nyongshuo\t74223\tmu_jiang113@163.com\r\n8\tsbgogl731218\tliyago@21cn.com\r\nken9cn\tronaldo\tken9cn@21cn.com\r\nyangguo\t222sss\tyangguo2s2@citiz.net\r\n2\tsbgogl731218\tliyago@21cn.com\r\nxtfs\t19860413\txihexiang@21cn.com\r\nxtf5\t19860413\tpilihu@21cn.com\r\nyang\tyouwen9904327\tcoollyct@hotmail.com\r\ndj\t18201708\tdjliudan@163.com\r\nSatan\t950976\tm.k.y_@163.com\r\nBAGsky\txiaohan\tzwkj@vip.qq.com\r\nxgwl\t775588\txgwl@yeah.net\r\nwoaini\t3960278\twabhs20dr@yahoo.com.cn\r\nyoyo\thxs379458\tadmin@yoyo.com.ru\r\nczw\tczw123811\tczwazd@sohu.com\r\nsisha\twr810929h\tv-k-v@163.com\r\n110\tsbgogl731218\tliyago@21cn.com\r\n119\t412722087mjy\t8587365@qq.com\r\naurora26\t60610\tsagi1128@163.com\r\ndfb886\tsfgygadfb886\tdfb886@163.com\r\nbycaiyj\t88918968\tbycaiyj2@163.com\r\nkanglin\tdalin1798\tymyvss@wapk.net\r\nyutonghack\t13999692958\t303963642@qq.com\r\nwzg\tys168wzg\twzg201@yahoo.com.cn\r\nzwj\twxj\t\r\nxie\txie2004\t\r\nJasonX\tjson1984\tyingzimax@yahoo.com.cn\r\nyystudy\t591401\tys168com@yahoo.com.cn\r\nnfans\tnfan521125\tjeke4@yahoo.com.cn\r\nalin\t131420\twzalin@hotmail.com\r\nliuqi\t3091573\t163lq@163.com\r\nweiguopei\t130107\tweiguopei@163.com\r\npclover\thello2104\tpclover2004@hotmail.com\r\nchinahyw\t44444444\tyongwei4444@yahoo.com.cn\r\n00000\t152932106\tfujianbows@126.com\r\nwww1\t815250\tyingjidoctor@hotmail.com\r\nboy\tw12301230\tpianshe@21cn.com\r\nbin\t820529\tbin@binjh.tk'
    print(md5sum(data))
