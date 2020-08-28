import base64
import random
import re


def encode_data(raw_data, encode_type):
    # 根据要求编码
    if "base64" == encode_type:
        data = base64.b64encode(raw_data.encode()).decode()
    elif "bin" == encode_type:
        data = str_to_bin(raw_data)
    elif "raw" == encode_type:
        data = raw_data
    else:
        raise Exception("type must in [base64, bin, raw]")
    return data


def decode_data(raw_data, encode_type):
    # 根据要求解码
    if "base64" == encode_type:
        data = base64.b64decode(raw_data).decode()
    elif "bin" == encode_type:
        data = bin_to_str(raw_data)
    elif "raw" == encode_type:
        data = raw_data
    else:
        raise Exception("type must in [base64, bin, raw]")
    return data


def str_to_bin(string):
    binary = "".join([bin(ord(char)).replace("0b", "").zfill(8) for char in string])
    return binary


def bin_to_str(binary):
    string = "".join([chr(int(char, 2)) for char in re.findall(r".{8}", binary)])
    return string


def otp_encrypt(plain, raw_key, encode_type):
    # 根据要求解码
    key = decode_data(raw_key, encode_type)
    # 明文和key的长度需要相同
    assert len(plain) == len(key), Exception("len(key) != len(plain)")
    # 加密
    raw_cipher = "".join([chr(ord(x) ^ ord(y)) for x, y in zip(plain, key)])
    # 根据要求编码
    cipher = encode_data(raw_cipher, encode_type)
    return cipher


def otp_decrypt(raw_cipher, key, encode_type):
    # 根据要求解码
    cipher = decode_data(raw_cipher, encode_type)
    # 密文和key的长度需要相同
    assert len(cipher) == len(key), Exception("len(key) != len(cipher)")
    # 解密
    plain = "".join([chr(ord(x) ^ ord(y)) for x, y in zip(cipher, key)])
    return plain


def gen_key(length, encode_type):
    # 生成key
    raw_key = "".join([chr(random.randint(0, 127)) for _ in range(length)])
    # 根据要求编码
    key = encode_data(raw_key, encode_type)
    return key
