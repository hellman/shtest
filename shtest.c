#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/mman.h>
     
/*------------------------------------------
    Shellcode testing program
    Usage:
        shtest [-s sock_descriptor] {-f file | $'\xeb\xfe'}
    Usage example:
        $ shtest $'\xeb\xfe'
        $ shtest -f sh.bin
        $ shtest -s 4 $'\xeb\xfe'
    Compiling:
        gcc shtest.c -o shtest && execstack -s shtest
    Author: hellman
-------------------------------------------*/

//TODO: sock_descriptor
//TODO: -p  - set handler in SIGPIPE or not

char buf[4096];

void usage() {
    printf("Usage: shtest [-s sock_descriptor] {-f file | $'\\xeb\\xfe'}\n");
    printf("\t-s: emulate a socket (via sock_descriptor)\n");
    printf("\t-f: load shellcode from binaryfile\n");
    exit(1);
}

void run_shellcode(void *sc_ptr) {
    int (*ptr)();
    
    ptr = sc_ptr;
    mprotect((void *) ((unsigned int)ptr & 0xfffff000), 4096 * 2, 7);
    
    void *esp, *ebp;
    void *edi, *esi;

    asm ("movl %%esp, %0;"
         "movl %%ebp, %1;"
         :"=r"(esp), "=r"(ebp));
    
    asm ("movl %%esi, %0;"
         "movl %%edi, %1;"
         :"=r"(esi), "=r"(edi)); 
    
    printf("Shellcode at %p\n", ptr);
    printf("Registers before call:\n");
    printf("  esp: %p, ebp: %p\n", esp, ebp);
    printf("  esi: %p, edi: %p\n", esi, edi);
    
    printf("----------------------\n");
    (*ptr)();
    printf("----------------------\n");
    
    printf("Shellcode returned (nice!).\n");
    exit(0);
}

int main(int argc, char **argv) {
    
    if (argc < 2)
        usage();
    
    if (argc == 2 && (strlen(argv[1]) != 2 || argv[1][0] != '-'))
        run_shellcode(argv[1]);
    
    int sock = -1;
    char * fname = NULL;
    
    int c;
    while ((c = getopt (argc, argv, "hus:f:")) != -1) {
        switch (c) {
            case 's':
                sock = atoi(optarg);
                break;
            case 'f':
                fname = optarg;
                break;
            case 'h':
            case 'u':
            default:
                usage();
        }
    }
    
    //shellcode via argv
    if (optind < argc) {
        if (fname)
            usage();
        else
            run_shellcode(argv[optind]);
    }
    
    if (!fname)
        usage();

    FILE * fd = fopen(fname, "r");
    if (!fd) {
        perror("fopen");
        return 100;
    }

    c = fread(buf, 1, 4096, fd);
    printf("Read %d bytes from '%s'\n", c, fname);
    fclose(fd);

    run_shellcode(buf);
    
    return 100;
}
