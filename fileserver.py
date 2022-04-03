#!/usr/bin/python
# -*- coding: UTF-8 -*-
# 文件名：files.py
import os
import socket  # 导入 socket 模块
import random
import string
import json
import pysmx
import time
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#生成长度为n的字符串
def rand_str(n, hex_num = False):
    if hex_num:
        str_list = [random.choice(string.hexdigits) for i in range(n)]
    else:
        str_list = [random.choice(string.digits + string.ascii_letters) for i in range(n)]
    random_str = ''.join(str_list)
    return random_str

s = socket.socket()  # 创建 socket 对象
#host = socket.gethostname()  # 获取本地主机名
host = "0.0.0.0"
port = 12345  # 设置端口
s.bind((host, port))  # 绑定端口

s.listen(5)  # 等待客户端连接

sign_private_key = open("sign_private_key.key", "rb")
sign_private_key = sign_private_key.read()
crypt_private_key = open("crypt_private_key.key", "rb")
crypt_private_key = crypt_private_key.read()

while True:
    c, addr = s.accept()  # 建立客户端连接
    print('连接地址：', addr)
    # 第一次握手
    rand1 = c.recv(1024)

    # 第二次握手
    rand2 = rand_str(32, hex_num = True).encode()
    random_hex_str = rand_str(14, hex_num = True)
    sig = pysmx.SM2.Sign(rand1, sign_private_key, random_hex_str, 64)  #64Byte
    c.send(rand2+sig)

    # 第三次握手
    res3 = c.recv(1024)
    rand3 = pysmx.SM2.Decrypt(res3[0:128], crypt_private_key, 64)
    print(rand3)
    hashtext = res3[128:192]
    print(hashtext)
    if pysmx.SM3.hash_msg(rand1+rand2+sig+rand3).encode() != hashtext:
        print("异常！")
    c.send("SUCCESS".encode())

    # 生成会话密钥(取rand2+rand1+rand3的SM3的Hash值的最后16Byte)
    session_key = pysmx.SM3.hash_msg(rand2+rand3+rand1)
    session_key = session_key[-16:].encode()
    print(session_key)

    # 等待客户端数据
    cipher_query = c.recv(4096)
    print("cipher:",cipher_query)
    query = pysmx.SM4.sm4_crypt_ecb(pysmx.SM4.DECRYPT, session_key, cipher_query).decode()
    print(query)

    #upload test
    # 开始接收文件
    response = {"status": "file uploading"}
    response = json.dumps(response).encode()
    cipher_response = pysmx.SM4.sm4_crypt_ecb(pysmx.SM4.ENCRYPT, session_key, response)
    c.send(cipher_response)

    query = json.loads(query)
    filesize = int(query["filesize"])
    filename = os.path.join("tmp", "abcbig.zip")
    recved_size = 0
    recv_buffer = 4096
    f = open(filename, 'wb')
    count = 0
    cipher = AES.new(session_key, AES.MODE_ECB)
    while True:
        data = c.recv(recv_buffer)
        #data = pysmx.SM4.sm4_crypt_ecb(pysmx.SM4.DECRYPT, session_key, data)
        data = unpad(cipher.decrypt(data), AES.block_size)
        recved_size = recved_size + len(data)  # 虽然buffer大小是4096，但不一定能收满4096
        f.write(data)
        if recved_size == filesize:
            break
    f.close()
    print("success")
    c.close()  # 关闭连接