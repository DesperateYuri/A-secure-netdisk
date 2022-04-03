#!/usr/bin/python
# -*- coding: UTF-8 -*-
# 文件名：client.py
# 上传文件-测试

import socket  # 导入 socket 模块
import random
import string
import time
import hashlib

import pysmx
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac

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


def sha1_file(fineName, block_size=64 * 1024):
    """
    计算文件的SHA-1值
    :param fineName: 文件路径
    :param block_size: 每块大小
    :return: 十六进制的字符串
    """
    sha1 = hashlib.sha1()
    with open(fineName, 'rb') as f:
        while True:
            data = f.read(block_size)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()


# 生成长度为n的字符串
def rand_str(n, hex_num=False):
    if hex_num:
        str_list = [random.choice(string.hexdigits) for i in range(n)]
    else:
        str_list = [random.choice(string.digits + string.ascii_letters) for i in range(n)]
    random_str = ''.join(str_list)
    return random_str


s = socket.socket()  # 创建 socket 对象
host = socket.gethostname()  # 获取本地主机名
port = 12345  # 设置端口号

sign_private_key = open("sign_public_key.key", "rb")
sign_private_key = sign_private_key.read()
crypt_public_key = open("crypt_public_key.key", "rb")
crypt_public_key = crypt_public_key.read()

s.connect((host, port))

# 第一次握手
rand1 = rand_str(32, hex_num=True).encode()  # 32Bytes
s.send(rand1)

# 第二次握手
res = s.recv(1024)
rand2 = res[0:32]
sig = res[32:96]
if pysmx.SM2.Verify(sig, rand1, sign_private_key, 64) == False:
    s.close()  # 验签失败（应该抛出异常）

# 第三次握手
rand3 = rand_str(32, hex_num=True).encode()
print(rand3)
cipher_rand3 = pysmx.SM2.Encrypt(rand3, crypt_public_key, 64)  # 128Byte
hashtext = pysmx.SM3.hash_msg(rand1 + rand2 + sig + rand3).encode()  # 64Byte
s.send(cipher_rand3 + hashtext)
res3 = s.recv(1024)
if res3.decode() != "SUCCESS":
    print("异常！")

# 生成会话密钥
session_key = pysmx.SM3.hash_msg(rand2 + rand3 + rand1)
session_key = session_key[-16:].encode()
print(session_key)

start = time.time()
# 开始发送数据
filename = "D:\Code\TestFile\Client\TestFile.zip"
filesize = os.path.getsize(filename)
checksum = sha1_file(filename)
query = {
    "method": "upload",
    "body": {
        "filesize": filesize,
        "checksum": checksum
    }
}
send_msg(s, session_key, query)
response = recv_msg(s, session_key)
print(response)


restSize = filesize
send_buffer = 4095
f = open(filename, "rb")
cipher = AES.new(session_key, AES.MODE_ECB)
while restSize >= send_buffer:
    data = f.read(send_buffer)
    #data = pysmx.SM4.sm4_crypt_ecb(pysmx.SM4.ENCRYPT, session_key, data)
    data = cipher.encrypt(pad(data, AES.block_size))
    s.sendall(data)
    # print(len(data))
    restSize = restSize - send_buffer
data = f.read(restSize)
data = cipher.encrypt(pad(data, AES.block_size))
s.sendall(data)
f.close()
end = time.time()
print("文件大小 {} Bytes,文件上传所用时间{} s:".format(filesize,end-start))
res = recv_msg(s, session_key)
print(res)
s.close()
