from tools import str_to_bin, bin_to_str, otp_encrypt, otp_decrypt, gen_key
import base64


def reg_str_to_bin(args):
    try:
        binary = str_to_bin(args.text)
        print(binary)
    except Exception as msg:
        print(msg)


def reg_bin_to_str(args):
    try:
        string = bin_to_str(args.text)
        print(string)
    except Exception as msg:
        print(msg)


def reg_otp_encrypt(args):
    try:
        cipher = otp_encrypt(args.plain, args.key, args.type)
        print(cipher)
    except Exception as msg:
        print(msg)


def reg_otp_decrypt(args):
    try:
        plain = otp_decrypt(args.cipher, args.key, args.type)
        print(plain)
    except Exception as msg:
        print(msg)


def reg_gen_key(args):
    try:
        key = gen_key(int(args.length), args.type)
        print(key)
    except Exception as msg:
        print(msg)
