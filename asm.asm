
sub esp, 0x7FFFFFFF

pushfd
pop dword ptr [esp+0x7FFFFFFF]

mov word ptr [esp+0x7FFFFFFF], cs
mov word ptr [esp+0x7FFFFFFF], ds
mov word ptr [esp+0x7FFFFFFF], ss
mov word ptr [esp+0x7FFFFFFF], es
mov word ptr [esp+0x7FFFFFFF], fs
mov word ptr [esp+0x7FFFFFFF], gs

mov dword ptr [esp+0x7FFFFFFF], eax
mov dword ptr [esp+0x7FFFFFFF], ecx
mov dword ptr [esp+0x7FFFFFFF], edx
mov dword ptr [esp+0x7FFFFFFF], ebx
mov dword ptr [esp+0x7FFFFFFF], esp
add dword ptr [esp+0x7FFFFFFF], 0x7FFFFFFF
mov dword ptr [esp+0x7FFFFFFF], ebp
mov dword ptr [esp+0x7FFFFFFF], esi
mov dword ptr [esp+0x7FFFFFFF], edi

movq [esp+0x7FFFFFFF], mm0
movq [esp+0x7FFFFFFF], mm1
movq [esp+0x7FFFFFFF], mm2
movq [esp+0x7FFFFFFF], mm3
movq [esp+0x7FFFFFFF], mm4
movq [esp+0x7FFFFFFF], mm5
movq [esp+0x7FFFFFFF], mm6
movq [esp+0x7FFFFFFF], mm7

vmovups [esp+0x7FFFFFFF], xmm0
vmovups [esp+0x7FFFFFFF], xmm1
vmovups [esp+0x7FFFFFFF], xmm2
vmovups [esp+0x7FFFFFFF], xmm3
vmovups [esp+0x7FFFFFFF], xmm4
vmovups [esp+0x7FFFFFFF], xmm5
vmovups [esp+0x7FFFFFFF], xmm6
vmovups [esp+0x7FFFFFFF], xmm7

vmovups [esp+0x7FFFFFFF], ymm0
vmovups [esp+0x7FFFFFFF], ymm1
vmovups [esp+0x7FFFFFFF], ymm2
vmovups [esp+0x7FFFFFFF], ymm3
vmovups [esp+0x7FFFFFFF], ymm4
vmovups [esp+0x7FFFFFFF], ymm5
vmovups [esp+0x7FFFFFFF], ymm6
vmovups [esp+0x7FFFFFFF], ymm7

vmovups [esp+0x7FFFFFFF], zmm0
vmovups [esp+0x7FFFFFFF], zmm1
vmovups [esp+0x7FFFFFFF], zmm2
vmovups [esp+0x7FFFFFFF], zmm3
vmovups [esp+0x7FFFFFFF], zmm4
vmovups [esp+0x7FFFFFFF], zmm5
vmovups [esp+0x7FFFFFFF], zmm6
vmovups [esp+0x7FFFFFFF], zmm7

fsave [esp+0x7FFFFFFF]

push eax
lea eax, [esp+0x4]
push eax
mov dword ptr [esp-0x4], 0x7FFFFFFF
call [esp-0x4]
add esp, 0x4
movzx eax, al
test eax, eax

je nothing_modified

pop eax

frstor [esp+0x7FFFFFFF]

vmovups zmm7, [esp+0x7FFFFFFF]
vmovups zmm6, [esp+0x7FFFFFFF]
vmovups zmm5, [esp+0x7FFFFFFF]
vmovups zmm4, [esp+0x7FFFFFFF]
vmovups zmm3, [esp+0x7FFFFFFF]
vmovups zmm2, [esp+0x7FFFFFFF]
vmovups zmm1, [esp+0x7FFFFFFF]
vmovups zmm0, [esp+0x7FFFFFFF]

vmovups ymm7, [esp+0x7FFFFFFF]
vmovups ymm6, [esp+0x7FFFFFFF]
vmovups ymm5, [esp+0x7FFFFFFF]
vmovups ymm4, [esp+0x7FFFFFFF]
vmovups ymm3, [esp+0x7FFFFFFF]
vmovups ymm2, [esp+0x7FFFFFFF]
vmovups ymm1, [esp+0x7FFFFFFF]
vmovups ymm0, [esp+0x7FFFFFFF]

vmovups xmm7, [esp+0x7FFFFFFF]
vmovups xmm6, [esp+0x7FFFFFFF]
vmovups xmm5, [esp+0x7FFFFFFF]
vmovups xmm4, [esp+0x7FFFFFFF]
vmovups xmm3, [esp+0x7FFFFFFF]
vmovups xmm2, [esp+0x7FFFFFFF]
vmovups xmm1, [esp+0x7FFFFFFF]
vmovups xmm0, [esp+0x7FFFFFFF]

movq mm7, [esp+0x7FFFFFFF]
movq mm6, [esp+0x7FFFFFFF]
movq mm5, [esp+0x7FFFFFFF]
movq mm4, [esp+0x7FFFFFFF]
movq mm3, [esp+0x7FFFFFFF]
movq mm2, [esp+0x7FFFFFFF]
movq mm1, [esp+0x7FFFFFFF]
movq mm0, [esp+0x7FFFFFFF]

mov edi, dword ptr [esp+0x7FFFFFFF]
mov esi, dword ptr [esp+0x7FFFFFFF]
mov ebp, dword ptr [esp+0x7FFFFFFF]

mov ebx, dword ptr [esp+0x7FFFFFFF]
mov edx, dword ptr [esp+0x7FFFFFFF]
mov ecx, dword ptr [esp+0x7FFFFFFF]
mov eax, dword ptr [esp+0x7FFFFFFF]

mov gs, word ptr [esp+0x7FFFFFFF]

mov es, word ptr [esp+0x7FFFFFFF]
mov ss, word ptr [esp+0x7FFFFFFF]
mov ds, word ptr [esp+0x7FFFFFFF]

push dword ptr [esp+0x7FFFFFFF]
popfd

mov esp, dword ptr [esp+0x7FFFFFFF]

ret 0x0

nothing_modified:
pop eax
add esp, 0x7FFFFFFF
