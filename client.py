#!/usr/bin/python
# -*- coding: UTF-8 -*-
# 文件名：client.py
# 普通消息测试
import socket  # 导入 socket 模块
import random
import string
import pysmx
import json
import hmac
import time


def recv_msg(client, session_key, recv_buf=4096):
    """
    接受消息并检验
    :param client: 连接的客户端
    :param session_key: 会话密钥
    :return: 接收到的消息
    """
    res = client.recv(recv_buf)
    res = pysmx.SM4.sm4_crypt_ecb(pysmx.SM4.DECRYPT, session_key, res).decode()
    res = json.loads(res)
    hashmac = res["hmac"]
    res = json.dumps(res["message"]).encode()
    h = hmac.new(session_key, res, digestmod="SHA1").hexdigest()
    if h == hashmac:
        return json.loads(res.decode())
    else:
        raise Exception("Transmission Error")


def send_msg(client, session_key, msg):
    """
    发送消息
    :param client: 连接的客户端
    :param session_key: 会话密钥
    :return: 接收到的消息
    """
    msg = json.dumps(msg).encode()
    hashmac = hmac.new(session_key, msg, digestmod="SHA1").hexdigest()
    msg = {
        "hmac": hashmac,
        "message": json.loads(msg.decode())
    }
    msg = json.dumps(msg).encode()
    msg = pysmx.SM4.sm4_crypt_ecb(pysmx.SM4.ENCRYPT, session_key, msg)
    client.send(msg)


#生成长度为n的字符串
def rand_str(n, hex_num = False):
    if hex_num:
        str_list = [random.choice(string.hexdigits) for i in range(n)]
    else:
        str_list = [random.choice(string.digits + string.ascii_letters) for i in range(n)]
    random_str = ''.join(str_list)
    return random_str

start = time.time()
s = socket.socket()  # 创建 socket 对象
host = socket.gethostname()  # 获取本地主机名
port = 12345  # 设置端口号

sign_private_key = open("sign_public_key.key", "rb")
sign_private_key = sign_private_key.read()
crypt_public_key = open("crypt_public_key.key", "rb")
crypt_public_key = crypt_public_key.read()

s.connect((host, port))
#===================握手过程===============================
# 第一次握手
rand1 = rand_str(32, hex_num = True).encode()  #32Bytes
s.send(rand1)

# 第二次握手
res = s.recv(1024)
rand2 = res[0:32]
sig = res[32:96]
if pysmx.SM2.Verify(sig, rand1, sign_private_key, 64) == False:
    s.close()  #验签失败（应该抛出异常）

# 第三次握手
rand3 = rand_str(32, hex_num = True).encode()
print(rand3)
cipher_rand3 = pysmx.SM2.Encrypt(rand3, crypt_public_key, 64) #128Byte
hashtext = pysmx.SM3.hash_msg(rand1+rand2+sig+rand3).encode() #64Byte
s.send(cipher_rand3+hashtext)
res3 = s.recv(1024)
if res3.decode() != "SUCCESS":
    print("异常！")

# 生成会话密钥
session_key = pysmx.SM3.hash_msg(rand2+rand3+rand1)
session_key = session_key[-16:].encode()
print(session_key)
#===================握手过程===============================
end = time.time()

print("密钥协商所用时间：", end - start)

# 开始发送数据
query = {"method": "test", "body": {"??":".."}}
send_msg(s, session_key, query)
response = recv_msg(s, session_key)
print(response)
s.close()