import sys
import argparse
import re
import os


def encryptKey(file_name):
    key = open(file_name, 'r').read()
    ran = os.urandom(16)


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
    parser = argparse.ArgumentParser(description='Web scrapper')
    parser.add_argument('-g', type=str, help='Recursive depth')
    parser.add_argument('-k', type=str, help='Path to store pictures')
    args = parser.parse_args()
    err = './ft_otp: error: key must be 64 hexadecimal characters'
    if args.g:
        check(args.g, '.hex', err, 'hexadecimal')
    else:
        check(args.k, '.key', err, 'key')
    return args


if __name__ == "__main__":
    args = parse()
    if args.g:
        print('encrypt key')
    else:
        print('generate key')

