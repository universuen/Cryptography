import md5
import rsa
import IDEA
import base_64
import zipstream

if __name__ == '__main__':
    # 读取文件
    fp = open("../../../Documents/Tencent Files/2498537532/FileRecv/ys168.com.txt", "rb")
    msg = fp.read()
    fp.close()

    '''****************加密过程*******************'''

    '''1. 对M进行MD5散列计算，得到MD5(M)'''
    md5_hash = md5.md5sum(msg)

    '''2.利用RSA加密MD5(M)，得到S'''
    # 公钥私钥中用到的两个大质数p,q，都是512位；e是和(q-1)*(p-1)互质的另一个正整数
    p1 = 11892845164754857302192817993787160730215019683720078508868206227442930130722825064091815998764273410046313495341034135557819502333338074415976198866323473
    q1 = 11367670600867484708699649015361923450974263455941875059545547729179804359361891954089186046814453092650085798107044468298400840193141395710340815439355097
    e1 = 611


    # 1是发送者，2是接收者
    # 生成发送者公钥私钥
    pubkey_1, selfkey_1 = rsa.gen_key(p1, q1, e1)

    # 把hash值:十六进制->十进制
    m = int(md5_hash, 16)
    # 用发送者的私钥对hash进行加密得到签名S
    S = rsa.decrypt(m, selfkey_1)
    # 签名S共1024位，不足的高位补0
    S = '{:01024b}'.format(S)
    S = S.encode('utf-8')  # 转bytes类型

    '''3.利用ZIP压缩 < M, S >'''
    compress = zipstream.LZ77Compressor()
    # 拼接<M,S>
    new_msg = msg
    # 把1024位二进制的S转为128位16进制
    for i in range(int(len(S) / 8)):
        tmp = S[i * 8: i * 8 + 8]
        data = int(tmp, 2)
        data = bytes([data])
        new_msg = new_msg + data  # 拼接，后128位为签名S
    # print(new_msg[-128:])
    new_msg = compress.compress(new_msg).tobytes()

    '''4. 利用IDEA加密压缩数据'''
    # 生成一个随机的128位IDEA密钥
    IDEA_key = 0x4AD6459F82C5B300952C49104881EF51
    # 对拼接后的数据进行IDEA加密
    IDEA_MS = IDEA.IDEA_en(new_msg, IDEA_key)

    '''5. 用RSA加密IDEA的密钥k，得到RSA(k)'''
    # 公钥私钥中用到的两个大质数p,q，都是512位；e是和(q-1)*(p-1)互质的另一个正整数
    p2 = 9642527161848298071201545183109583441210324913672887812774031163540292555923225605591510697538531861645360860564168061047846750456591161660397179909428673
    q2 = 12462877728415710567613768729223820618177080415134397242805949239369738252514787058260709601317833487891379767183882860432583979533234009460190395592629511
    e2 = 931

    # 生成接收者公钥私钥
    pubkey_2, selfkey_2 = rsa.gen_key(p2, q2, e2)
    # 用接收者的公钥加密IDEA的密钥
    RSA_k = rsa.encrypt(IDEA_key, pubkey_2)
    # 高位补0 共1024位
    RSA_k = '{:01024b}'.format(RSA_k)
    RSA_k = RSA_k.encode('utf-8')  # 转bytes类型

    # 6.把IDEA加密后的压缩数据和RSA(k)拼接在一起,并转换为BASE64
    data_part = IDEA_MS
    for i in range(int(len(RSA_k) / 8)):
        tmp = RSA_k[i * 8: i * 8 + 8]
        data = int(str(tmp, encoding='utf8'), 2)  # bytes->str->int
        data = bytes([data])  # int->bytes
        data_part = data_part + data  # 拼接 后128位为S
    # 进行BASE 64变化
    base64_C = base_64.encode(data_part)
    # print(base64_C)

    '''****************解密过程*******************'''

    '''1. base64解码，拆解消息部分与加密密钥部分'''
    # UNZIP(C3) = <C1, C2>
    C3 = base_64.decode(base64_C)
    # 消息部分
    C1 = C3[:-128]
    # 加密密钥部分
    C2 = C3[-128:]

    '''2. RSA解密IDEA密钥K(128位)'''
    C2_bin = "".encode('utf-8')
    for i in range(int(len(C2))):
        tmp = C2[i]
        tmp = int(tmp)  # bytes->int
        tmp = '{:08b}'.format(tmp).encode('utf-8')  # int->str->bytes
        C2_bin = C2_bin + tmp
    C2 = int(str(C2_bin.decode('utf-8')), 2)
    IDEA_key = rsa.decrypt(C2, selfkey_2)

    '''3. IDEA解密数据部分明文M2'''
    # 用解得的密钥K解密IDEA，得到明文
    M2 = IDEA.IDEA_de(C1, IDEA_key)

    '''4. 拆解M与S'''
    # 解压缩
    M2 = zipstream.bytes2bitarray(M2)
    M2 = compress.decompress(M2)
    # 消息部分
    Message = M2[:-128]
    # 签名部分
    S = M2[-128:]
    S_bin = "".encode('utf-8')
    for i in range(int(len(S))):
        tmp = S[i]
        tmp = int(tmp)  # bytes->int
        tmp = '{:08b}'.format(tmp).encode('utf-8')  # int->str->bytes
        S_bin = S_bin + tmp
    S = int(str(S_bin.decode('utf-8')), 2)

    # 5. 验证签名
    # 用发送者公钥解密数字签名部分S，得到hash
    M1 = rsa.encrypt(S, pubkey_1)
    M1 = hex(M1)[2:]
    print('解密签名得到的hash:')
    print(M1)

    # 计算消息部分的hash，与解密S得到的hash进行对比，若一致，则解密成功
    md5_Message = md5.md5sum(Message)
    print('计算消息部分的hash:')
    print(md5_Message)
    if md5_Message == M1:
        print("验签认证成功")
    else:
        print("认证失败，签名错误")
