import sys, time, json, os
import socket
import hmac
from threading import Thread
import traceback

import pysmx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import utils
import method


class socket_server:
    def __init__(self, address):
        """
        :param address: 服务端地址
        """
        self.sign_private_key = open("sign_private_key.key", "rb")
        self.sign_private_key = self.sign_private_key.read()
        self.crypt_private_key = open("crypt_private_key.key", "rb")
        self.crypt_private_key = self.crypt_private_key.read()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(address)
        self.server.listen(1000)
        print("run server on \033[;34m{}:{}\033[0m, wait for connecting...".format(address[0], address[1]))
        thread = Thread(target=self.__accept_client__)
        thread.setDaemon(True)
        thread.start()

    def __accept_client__(self):
        """
        监听客户端的连接
        """
        while True:
            # 等待连接
            client, client_address = self.server.accept()
            # 为新连入的客户端创建新线程
            thread = Thread(target=self.__message_handle__, args=(client, client_address))
            thread.setDaemon(True)
            thread.start()

    def __key_agreement__(self, client):
        """
        密钥协商过程
        :param client: 和客户端的一个连接
        :return: 会话密钥
        """
        # 第一次握手
        rand1 = client.recv(4096)

        # 第二次握手
        rand2 = utils.rand_bytes(32).encode()
        random_hex_str = utils.rand_bytes(14)
        sig = pysmx.SM2.Sign(rand1, self.sign_private_key, random_hex_str, 64)  # 64Byte
        client.send(rand2 + sig)

        # 第三次握手
        res3 = client.recv(4096)
        rand3 = pysmx.SM2.Decrypt(res3[0:128], self.crypt_private_key, 64)
        hashtext = res3[128:192]
        if pysmx.SM3.hash_msg(rand1 + rand2 + sig + rand3).encode() != hashtext:
            raise Exception("Key agreement error.")
        client.send("SUCCESS".encode())

        # 生成会话密钥(取rand2+rand1+rand3的SM3的Hash值的最后16Byte)
        session_key = pysmx.SM3.hash_msg(rand2 + rand3 + rand1)
        session_key = session_key[-16:].encode()
        return session_key

    def __recv_msg__(self, client, session_key, recv_buf = 4096):
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

    def __send_msg__(self, client, session_key, msg):
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

    def __upload_files__(self, client, session_key, fileinfo, body, callback):
        """
        上传文件的逻辑
        :param client: 客户端连接实例
        :param session_key: 会话密钥
        :param fileinfo: 文件信息（filesize, filepath, checknum)
        :param body: 原始请求
        :param callback: 回调函数
        :return: 发给前端的response
        """
        try:
            # 获取文件信息
            filepath = fileinfo["filepath"]
            filesize = fileinfo["filesize"]
            checksum = fileinfo["checksum"]

            # 开始传输文件
            info = {"status": "uploading"}
            self.__send_msg__(client, session_key, info)

            received_size = 0
            recv_buffer = 4096
            upload_file = open(filepath, "wb")
            cipher = AES.new(session_key, AES.MODE_ECB)

            while received_size < filesize:
                data = client.recv(recv_buffer)
                while len(data) < recv_buffer and received_size + len(data) < filesize:
                    rest_buffer = recv_buffer - len(data)
                    data = data + client.recv(rest_buffer)
                data = unpad(cipher.decrypt(data), AES.block_size)
                received_size = received_size + len(data)
                upload_file.write(data)
            upload_file.close()

            # 文件校验
            my_check_sum = utils.sha1_file(filepath)
            if my_check_sum == checksum:
                response = callback("success", body)
            else:
                raise Exception("Upload Error.")
        except:
            response = callback("fail", body)
            print(traceback.format_exc())
        return response

    def __download_files__(self, client, session_key, fileinfo, body, callback):
        """
        下载文件的逻辑
        :param client: 客户端连接实例
        :param session_key: 会话密钥
        :param fileinfo: 文件信息（filesize, filepath, checknum)
        :param body: 原始请求
        :param callback: 回调函数
        :return: 发给前端的response
        """
        # 获取文件信息
        try:
            filepath = fileinfo["filepath"]
            filesize = fileinfo["filesize"]
            checksum = fileinfo["checksum"]
            filename = os.path.basename(filepath)

            info = {
                "filename": filename,
                "filesize": filesize,
                "checksum": checksum
            }
            self.__send_msg__(client, session_key, info)
            client.recv(4096)

            rest_size = filesize
            send_buffer = 4095
            download_file = open(filepath, "rb")
            cipher = AES.new(session_key, AES.MODE_ECB)
            while rest_size >= send_buffer:
                data = download_file.read(send_buffer)
                data = cipher.encrypt(pad(data, AES.block_size))
                client.sendall(data)
                rest_size = rest_size - send_buffer
            data = download_file.read(rest_size)
            data = cipher.encrypt(pad(data, AES.block_size))
            client.sendall(data)
            download_file.close()

            res = self.__recv_msg__(client, session_key)

            if res["status"] == "success":
                response = callback("success", body)
            else:
                raise Exception("Download Error.")
        except:
            response = callback("fail", body)
        return response

    def __message_handle__(self, client, client_address):
        """
        建立连接并选择消息处理
        :param client: 客户端实例
        :return: 客户端连接地址
        """
        try:
            # 密钥协商并获取会话密钥
            session_key = self.__key_agreement__(client)
            # 获取请求信息并解密获取请求方法
            request = self.__recv_msg__(client, session_key)
            print("client \033[;34m{}:{}\033[0m request \033[;34m{}\033[0m.".
                  format(client_address[0], client_address[1], request["method"]))
            res, callback = method.method_handle(request["method"], request["body"])

            response = None
            if res["file"] == "None":
                response = res["body"]
            elif res["file"] == "Upload":
                response = self.__upload_files__(client, session_key, res["fileinfo"], request["body"], callback)
            elif res["file"] == "Download":
                response = self.__download_files__(client, session_key, res["fileinfo"], request["body"], callback)

            self.__send_msg__(client, session_key, response)
            client.close()
        except:
            print("\033[;31m{}\033[0m".format(traceback.format_exc()))
            client.close()


if __name__ == "__main__":
    address = (str(sys.argv[1]), int(sys.argv[2]))
    my_server = socket_server(address)
    while True:
        time.sleep(60)