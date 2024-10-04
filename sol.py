from pwn import *
import hashlib
import string
import itertools
from time import sleep
EXECUTABLE = "./chal"
binary = ELF(EXECUTABLE)

proc = remote("knife.2024.ctfcompetition.com", 1337)

"""
plain plain 0
plain plain 1
plain plain 2
plain plain 3
plain plain 4
plain plain 5
plain plain 6
plain plain 7
b'a85 plain 3b13ed6814a503113bdf38d952d07c62bdc5e1f045ab760fc8076445d5986aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabc2Y|'
b'a85 plain 3b13ed6814a503113bdf38d952d07c62bdc5e1f045ab760fc8076445d5986aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabc2Y|aaaaa'
b'a85 plain 3b13ed6814a503113bdf38d952d07c62bdc5e1f045ab760fc8076445d5986aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabc2Y|aaaaaaaaaa'
b'a85 plain 3b13ed6814a503113bdf38d952d07c62bdc5e1f045ab760fc8076445d5986aaaaaaaaaaaaaaaaaaaaaaaaaaaaabc2Y|aaaaaaaaaaaaaaa'
b'a85 plain 3b13ed6814a503113bdf38d952d07c62bdc5e1f045ab760fc8076445d5986aaaaaaaaaaaaaaaaaaaaaaaabc2Y|aaaaaaaaaaaaaaaaaaaa'
b'a85 plain 3b13ed6814a503113bdf38d952d07c62bdc5e1f045ab760fc8076445d5986aaaaaaaaaaaaaaaaaaabc2Y|aaaaaaaaaaaaaaaaaaaaaaaaa'
b'plain plain 00Wf'
"""
# find hash that generates a85
def my_hash(data):
    return hashlib.sha256(data).digest().hex()

def find_hash():
    for a in string.printable:
        for b in string.printable:
            for c in string.printable:
                for d in string.printable:
                    res = a + b + c + d
                    hashed = my_hash(res.encode())
                    if hashed.startswith("a85"):
                        return res, hashed

def effective():
    mapping = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
    data = 0x100616161
    result = []
    while data:
        mod = data % 85
        data = data // 85
        result.append(mapping[mod])
    return b"".join([i.encode() for i in result])

def build_equivalents():
    our_hash_seed, hashed = find_hash()
    hashed = hashed[3:] # no need a85
    base = b"moRPV"
    corruption = effective()
    # print("AAA", corruption, len(corruption))
    same_padding = []
    for i in range(6):
        result = hashed.encode() + b"aaaa" + (base * (8 - i)) + corruption + base * i
        same_padding.append(result)
    return same_padding, our_hash_seed

def recv():
    res = proc.recvuntil(b'Awaiting command...\n')
    try:
        print(res.decode())
    except:
        print(res)
        print()
def send_and_recv(data):
    recv()
    print("sending: ", data.decode())
    proc.sendline(data + b'\n')

def main():
    encodings, seed = build_equivalents()
    # get to first cache row
    for i in range(8):
        data = f"plain plain {i}"
        send_and_recv(data.encode())
    
    # we are in the first cache row
    for encoding in encodings:
        data = b"a85 plain " + encoding
        send_and_recv(data)
    send_and_recv(b"plain plain " + seed.encode())
    recv()

    # proc.interactive()
    # we have overridden the sha256 of the flag



if __name__ == "__main__":
    main()