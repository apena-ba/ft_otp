# Ft-Otp
Time-Based One-Time Password (TOTP) generation in Python

## Description
The goal of this project is implementing TOTP generation using Python from scratch, not using pyotp library.

Running `python3 ft_otp.py -g key.hex` the program hashes tje file key.hex, storing it in a file called `ft_otp.key`.

Running `python3 ft_otp.py -k ft_otp.key` the program uses the provided file to generate the TOTP