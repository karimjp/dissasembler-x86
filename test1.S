BITS 32

_start:

mov eax, 0x00000008
mov edx, [ebp + 0x08]
mov ecx, 0x00000008
mov eax, [ecx]	
mov [ecx], eax
add eax, ebx
add eax, ecx
add [eax],ecx
