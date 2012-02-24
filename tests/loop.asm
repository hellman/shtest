BITS 32

; LOOP SHELLCODE

; COMPILE:
; nasm loop.asm

; TEST:
; shtest -f loop
; shtest '\xeb\xfe'

START:
jmp START