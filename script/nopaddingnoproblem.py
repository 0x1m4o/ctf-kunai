from pwn import *

import binascii

r=remote("mercury.picoctf.net",28517)

print(r.recvuntil("n:"))

n=int(r.recvline())

print(n)

print(r.recvuntil("e:"))

e=int(r.recvline())

print(e)

print(r.recvuntil("ciphertext:"))

c=int(r.recvline())

print(c)

print(r.recvuntil("to decrypt:"))

# We will send c*2^e. It decrypts to c^d*2^(ed) = 2*c^d

# It is different, and will decrypt to plaintext*2

r.sendline(str(pow(2,e,n)*c))

print(r.recvuntil("you go:"))

p2=int(r.recvline())

print(p2)

print(p2//2)

st="{:x}".format(p2//2)

print(binascii.unhexlify(st))
