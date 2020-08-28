import sys
import argparse
from registry import (
    reg_str_to_bin,
    reg_bin_to_str,
    reg_otp_encrypt,
    reg_otp_decrypt,
    reg_gen_key,
)


def main():
    # 初始化解析器
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="sub-command help")
    # 添加子命令 str2bin
    parser_str2bin = subparsers.add_parser("str2bin", help="str to bin")
    parser_str2bin.add_argument("-t", "--text", help="text")
    parser_str2bin.set_defaults(func=reg_str_to_bin)
    # 添加子命令 bin2str
    parser_bin2str = subparsers.add_parser("bin2str", help="bin to str")
    parser_bin2str.add_argument("-t", "--text", help="text")
    parser_bin2str.set_defaults(func=reg_bin_to_str)
    # 添加子命令 encrypt
    parser_encrypt = subparsers.add_parser("encrypt", help="otp encrypt")
    parser_encrypt.add_argument("-k", "--key", help="key")
    parser_encrypt.add_argument("-p", "--plain", help="plain")
    parser_encrypt.add_argument(
        "-t", "--type", help="type of key and cipher [base64, bin, raw]"
    )
    parser_encrypt.set_defaults(func=reg_otp_encrypt)
    # 添加子命令 decrypt
    parser_decrypt = subparsers.add_parser("decrypt", help="otp decrypt")
    parser_decrypt.add_argument("-k", "--key", help="key")
    parser_decrypt.add_argument("-c", "--cipher", help="cipher")
    parser_decrypt.add_argument(
        "-t", "--type", help="type of key and cipher [base64, bin, raw]"
    )
    parser_decrypt.set_defaults(func=reg_otp_decrypt)
    # 添加子命令 genkey
    parser_genkey = subparsers.add_parser("genkey", help="generate key")
    parser_genkey.add_argument("-l", "--length", help="key length")
    parser_genkey.add_argument("-t", "--type", help="type of key [base64, bin, raw]")
    parser_genkey.set_defaults(func=reg_gen_key)
    # 执行函数功能
    try:
        args = parser.parse_args()
        args.func(args)
    except Exception as msg:
        parser.print_help()


if __name__ == "__main__":
    main()
