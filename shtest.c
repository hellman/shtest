#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/mman.h>

/*------------------------------------------
    Shellcode testing program
    Usage:
        shtest {-f file | $'\xeb\xfe' | '\xb8\x39\x05\x00\x00\xc3'}
    Usage example:
        $ shtest $'\xeb\xfe'                 # raw shellcode
        $ shtest '\xb8\x39\x05\x00\x00\xc3'  # escaped shellcode
        $ shtest -f test.sc                  # shellcode from file
        $ shtest -f <(python gen_payload.py) # test generated payload
    Compiling:
        gcc -Wall shtest.c -o shtest
    Author: hellman (hellman1908@gmail.com)
-------------------------------------------*/

char buf[4096];

void usage() {
    printf("    Shellcode testing program\n\
    Usage:\n\
        shtest {-f file | $'\\xeb\\xfe' | '\\xb8\\x39\\x05\\x00\\x00\\xc3'}\n\
    Usage example:\n\
        $ shtest $'\\xeb\\xfe'                 # raw shellcode\n\
        $ shtest '\\xb8\\x39\\x05\\x00\\x00\\xc3'  # escaped shellcode\n\
        $ shtest -f test.sc                  # shellcode from file\n\
        $ shtest -f <(python gen_payload.py) # test generated payload\n\
    Compiling:\n\
        gcc -Wall shtest.c -o shtest\n\
    Author: hellman (hellman1908@gmail.com)\n");
    exit(1);
}

void escape_error() {
    printf("Shellcode is incorrectly escaped!\n");
    exit(1);
}

void run_shellcode(void *sc_ptr) {
    int ret = 0;
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
    ret = (*ptr)();
    printf("----------------------\n");
    
    printf("Shellcode returned %d\n", ret);
    exit(0);
}

int main(int argc, char **argv) {
    
    if (argc < 2 || argc > 3)
        usage();
    
    /*if (argc == 2 && (strlen(argv[1]) != 2 || argv[1][0] != '-'))
        run_shellcode(argv[1]);*/
    
    char * fname = NULL;
    
    int c;
    while ((c = getopt (argc, argv, "hus:f:")) != -1) {
        switch (c) {
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

        //try to translate from escapes ( \xc3 )
        int i;
        char *p1 = argv[optind];
        char *p2 = argv[optind];
        char *end = p1 + strlen(p1);

        while (p1 < end) {
            i = sscanf(p1, "\\x%02x", (unsigned int *)p2);
            if (i != 1) {
                if (p2 == p1) break;
                else escape_error();
            }

            p1 += 4;
            p2 += 1;
        }

        run_shellcode(argv[optind]);
        return 0;
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
