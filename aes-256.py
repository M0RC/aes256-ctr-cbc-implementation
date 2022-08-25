#!/usr/bin/env python3

import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long
from time import time


def aes_encrypt_cbc(plaintext_blocks, cipher, iv):
    """Encrypt a plaintext with AES-CBC. Return the bytes ciphertext"""

    ciphertext = bytes()

    # For the first plaintext block, we will xor it with the iv and encrypt the result with AES-ECB
    # For each other plaintext blocks, we will xor the previous block ciphered with it and encrypt the result with AES-ECB
    for i in range(len(plaintext_blocks)):
        if i == 0:
            xor = xor_byte(plaintext_blocks[i], iv)
            ciphertext_block = cipher.encrypt(xor)
        else:
            xor = xor_byte(ciphertext_block, plaintext_blocks[i])
            ciphertext_block = cipher.encrypt(xor)

        ciphertext += ciphertext_block
    
    return ciphertext

def aes_decrypt_cbc(ciphertext_blocks, cipher, iv, block_size):
    """Decrypt an AES-CBC ciphertext. Return the string plaintext"""

    plaintext = bytes()
    
    # For the first ciphertext block, we will decrypt it with AES-ECB and xor the result with the iv
    # For each other ciphertext blocks, we will decrypt them with AES-ECB and xor the result with the previous ciphertext block
    for i in range(len(ciphertext_blocks)):
        if i == 0:
            xor = cipher.decrypt(ciphertext_blocks[i])
            plaintext_block = xor_byte(xor, iv)
        else:
            xor = cipher.decrypt(ciphertext_blocks[i])
            plaintext_block = xor_byte(xor, ciphertext_blocks[i-1])
            
        plaintext += plaintext_block
    
    # Decode and remove padding of plaintext
    return unpad(plaintext, block_size).decode("utf-8")

def aes_encrypt_ctr(plaintext_blocks, cipher, iv, block_size):
    """Encrypt a plaintext with AES-CTR. Return the bytes ciphertext"""
    
    ciphertext = bytes()

    # For each plaintext blocks, we will encrypt the iv+i with AES-ECB and xor the result with it
    for i in range(len(plaintext_blocks)):
        cipher_iv = cipher.encrypt((int.from_bytes(iv, "big")+i).to_bytes(block_size, byteorder='big'))
        ciphertext_block = xor_byte(cipher_iv, plaintext_blocks[i])
        ciphertext += ciphertext_block

    return ciphertext

def aes_decrypt_ctr(ciphertext_blocks, cipher, iv, block_size):
    """Decrypt an AES-CTR ciphertext. Return the string plaintext"""

    plaintext = bytes()

    # For each ciphertext blocks, we will encrypt the iv+i with AES-ECB and xor the result with it
    for i in range(len(ciphertext_blocks)):
        cipher_iv = cipher.encrypt((int.from_bytes(iv, "big")+i).to_bytes(block_size, byteorder='big'))
        plaintext_block = xor_byte(cipher_iv, ciphertext_blocks[i])
        plaintext += plaintext_block
    
    # Decode and remove padding of plaintext
    return unpad(plaintext, block_size).decode("utf-8")
    
def convert_to_block(input_bytes, block_size):
    """Convert bytes to block of n byte. Return a list of all block"""

    return [input_bytes[i:i+block_size] for i in range(0, len(input_bytes), block_size)]

def xor_byte(ba1, ba2):
    """Xor 2 bytes. Return the bytes result of xor"""
    
    return bytes([a ^ b for a, b in zip(ba1, ba2)])

def check_args(parser, args):
    """Check if arguments from parser is valid"""

    # Check if file can be open
    try:
        with open(args.file) as f:
            pass
    except PermissionError:
        parser.error("File permission error")
    except FileNotFoundError:
        parser.error("File not found")

def get_args(parser):
    """Create arguments for the program and return parser"""

    parser_group = parser.add_mutually_exclusive_group(required=True)
    parser_group.add_argument('--cbc', action='store_true', help="Select CBC Mode")
    parser_group.add_argument('--ctr', action='store_true', help="Select CTR Mode")
    parser_group.add_argument('--all', '-a', action='store_true', help="Select CBC and CTR")
    parser.add_argument('--file', '-f', required=True, type=str, help="Path of plaintext file")
    args = parser.parse_args()
	
    return args

def main():
    parser = argparse.ArgumentParser()
    args = get_args(parser)
    check_args(parser, args)

    print("""
       .+------+    
     .' |    .'|    
    +---+--+'  |   Implementation of AES-256-CBC and AES-256-CTR 
    |   |  |   |   
    |  ,+--+---+   By Morc
    |.'    | .'    
    +------+'   
""")

    # Define byte size of a blocks
    block_size = 16

    # Generate 256-bit key
    key = get_random_bytes(32)
    
    # Random IV with the same size of a block
    iv = get_random_bytes(16)

    # Use AES-ECB as a cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # Plaintext
    with open(args.file, 'r') as f:
        # Encode and add padding on plaintext
        plaintext = pad(f.read().encode("utf-8"), block_size)
    
    # Convert plaintext to plaintext blocks
    plaintext_blocks = convert_to_block(plaintext, block_size)

    # Start CBC if user specified CBC parameter with argparse
    if args.cbc or args.all:
        print("")

        # CBC Library encryption implementation
        #print("Starting CBC lib encryption")
        #start_time = time()
        #library_cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
        #library_cbc_ciphertext = library_cbc_cipher.encrypt(plaintext)
        #print(f"[v] Finished in {time() - start_time} seconds")
        
        #with open('output_lib_cbc_enc.txt', 'wb') as f:
        #    f.write(library_cbc_ciphertext)
        #print("[+] Ciphertext saved in output_lib_cbc_enc.txt file.\n")
        
        # My CBC encryption implementation
        print("Starting my CBC encryption")
        start_time = time()
        my_cbc_ciphertext = aes_encrypt_cbc(plaintext_blocks, cipher, iv)
        print(f"[v] Finished in {time() - start_time} seconds")

        with open('output_my_cbc_enc.txt', 'wb') as f:
            f.write(my_cbc_ciphertext)
        print("[+] Ciphertext saved in output_my_cbc_enc.txt file.\n")

        # CBC Library decryption implementation
        #print("Starting CBC lib decryption")
        #start_time = time()
        #library_cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
        #library_cbc_plaintext = library_cbc_cipher.decrypt(library_cbc_ciphertext)
        #print(f"[v] Finished in {time() - start_time} seconds")

        #with open('output_lib_cbc_decrypt.txt', 'w') as f:
        #    f.write(unpad(library_cbc_plaintext, 16).decode("utf-8"))
        #print("[+] Plaintext saved in output_lib_cbc_decrypt.txt file.\n")

        # My CBC decryption implementation
        print("Starting my CBC decryption")
        start_time = time()
        my_cbc_ciphertext_blocks = convert_to_block(my_cbc_ciphertext, block_size)
        my_cbc_plaintext = aes_decrypt_cbc(my_cbc_ciphertext_blocks, cipher, iv, block_size)
        print(f"[v] Finished in {time() - start_time} seconds")

        with open('output_my_cbc_decrypt.txt', 'w') as f:
            f.write(my_cbc_plaintext)
        print("[+] Plaintext saved in output_my_cbc_decrypt.txt file.\n")
    
    # Start CTR if user specified CTR parameter with argparse
    if args.ctr or args.all:
        print("")
        
        # CTR Library implementation
        #print("Starting lib CTR encryption")
        #start_time = time()
        #library_ctr_cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(block_size*8, initial_value = bytes_to_long(iv)))
        #library_ctr_ciphertext = library_ctr_cipher.encrypt(plaintext)
        #print(f"[v] Finished in {time() - start_time} seconds")

        #with open('output_lib_ctr_enc.txt', 'wb') as f:
        #    f.write(library_ctr_ciphertext)
        #print("[+] Ciphertext saved in output_lib_ctr_enc.txt file.\n")

        # My CTR encryption implementation
        print("Starting my CTR encryption")
        start_time = time()
        my_ctr_ciphertext = aes_encrypt_ctr(plaintext_blocks, cipher, iv, block_size)
        print(f"[v] Finished in {time() - start_time} seconds")

        with open('output_my_ctr_enc.txt', 'wb') as f:
            f.write(my_ctr_ciphertext)
        print("[+] Ciphertext saved in output_my_ctr_enc.txt file.\n")

        # CTR Library decryption implementation
        #print("Starting lib CTR decryption")
        #start_time = time()
        #library_ctr_cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(block_size*8, initial_value = bytes_to_long(iv)))
        #library_ctr_plaintext = library_ctr_cipher.decrypt(library_ctr_ciphertext)
        #print(f"[v] Finished in {time() - start_time} seconds")

        #with open('output_lib_ctr_decrypt.txt', 'w') as f:
        #    f.write(unpad(library_ctr_plaintext, 16).decode("utf-8"))
        #print("[+] Plaintext saved in output_lib_ctr_decrypt.txt file.\n")

        # My CTR decryption implementation
        print("Starting my CTR decryption")
        start_time = time()
        my_ctr_ciphertext_blocks = convert_to_block(my_ctr_ciphertext, block_size)
        my_ctr_plaintext = aes_decrypt_ctr(my_ctr_ciphertext_blocks, cipher, iv, block_size)
        print(f"[v] Finished in {time() - start_time} seconds")

        with open('output_my_ctr_decrypt.txt', 'w') as f:
            f.write(my_ctr_plaintext)
        print("[+] Plaintext saved in output_my_ctr_decrypt.txt file.\n")

if __name__ == "__main__":
    main()
