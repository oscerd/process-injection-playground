.global _start
.section .text
_start:
    mov $60, %eax
    xor %edi, %edi
    syscall
