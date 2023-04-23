import sys
import os
import argparse
import re
import hashlib
import time
import base64
import pyotp


def encryptKey(file_name):
    with open(file_name, 'r') as file:
        key_hex = file.read()
        salt = os.urandom(16)
        comb = salt + bytes.fromhex(key_hex)
        hash_obj = hashlib.sha256(comb)
        encrypted_str = hash_obj.hexdigest()
        with open('ft_otp.key', 'w') as key_key:
            key_key.write(encrypted_str)
    print('Key was successfully saved in ft_otp.key.')


def generatePasswd(file_name):
    with open(file_name, 'r') as file:
        key_key = file.read()
        time_interval = int(time.time() // 30)
        passwd = pyotp.TOTP(base64.b32encode(key_key.encode())).now()
        print(passwd, ' ', time_interval)


def check(arg, form, err, typ):
    if arg.endswith(form) == False:
        print(f"./ft_otp: error: {typ} file must be in {form} format")
        exit(1)
    try:
        with open(arg, 'r') as file:
            content = file.read().split('\n')
            if len(content) != 1 or not re.match("^[0-9a-fA-F]{64}$", content[0]):
                print(err)
                exit(1)
    except Exception:
        print(f'./ft_otp: error: could not open file \'{arg}\'')
        exit(1)


def parse():
    parser = argparse.ArgumentParser(description='OTP generator')
    parser.add_argument('-g', type=str, help='Encrypt and save key')
    parser.add_argument('-k', type=str, help='Generate password')
    args = parser.parse_args()
    if len(sys.argv) != 3:
        print('./ft_otp: error: wrong number of arguments')
        exit(1)
    err = './ft_otp: error: key must be 64 hexadecimal characters'
    if args.g:
        check(args.g, '.hex', err, 'hexadecimal')
    else:
        check(args.k, '.key', err, 'key')
    return args


if __name__ == "__main__":
    args = parse()
    if args.g:
        encryptKey(args.g)
    else:
        generatePasswd(args.k)

