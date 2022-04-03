import random
import string
import hashlib


def rand_bytes(n):
    """
    生成n字节的随机字符串
    :param n: 字符串长度
    :return: n字节的字符串
    """
    str_list = [random.choice(string.hexdigits) for i in range(n)]
    random_str = ''.join(str_list)
    return random_str


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
