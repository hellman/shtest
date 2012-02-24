BITS 32

; SHELLCODE RETURN 1337

; COMPILE:
; nasm retcode.asm

; TEST:
; shtest -f retcode

START:
    xor eax, eax
    mov ax, 1337
    ret