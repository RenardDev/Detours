
sub rsp, 0x7FFFFFFF

pushfq
pop qword ptr [rsp+0x7FFFFFFF]

mov qword ptr [rsp+0x7FFFFFFF], rax
mov qword ptr [rsp+0x7FFFFFFF], rcx
mov qword ptr [rsp+0x7FFFFFFF], rdx
mov qword ptr [rsp+0x7FFFFFFF], rbx
mov qword ptr [rsp+0x7FFFFFFF], rsp
add qword ptr [rsp+0x7FFFFFFF], 0x7FFFFFFF
mov qword ptr [rsp+0x7FFFFFFF], rbp
mov qword ptr [rsp+0x7FFFFFFF], rsi
mov qword ptr [rsp+0x7FFFFFFF], rdi
mov qword ptr [rsp+0x7FFFFFFF], r8
mov qword ptr [rsp+0x7FFFFFFF], r9
mov qword ptr [rsp+0x7FFFFFFF], r10
mov qword ptr [rsp+0x7FFFFFFF], r11
mov qword ptr [rsp+0x7FFFFFFF], r12
mov qword ptr [rsp+0x7FFFFFFF], r13
mov qword ptr [rsp+0x7FFFFFFF], r14
mov qword ptr [rsp+0x7FFFFFFF], r15

stmxcsr [rsp+0x7FFFFFFF]

vmovups [rsp+0x7FFFFFFF], xmm0
vmovups [rsp+0x7FFFFFFF], xmm1
vmovups [rsp+0x7FFFFFFF], xmm2
vmovups [rsp+0x7FFFFFFF], xmm3
vmovups [rsp+0x7FFFFFFF], xmm4
vmovups [rsp+0x7FFFFFFF], xmm5
vmovups [rsp+0x7FFFFFFF], xmm6
vmovups [rsp+0x7FFFFFFF], xmm7
vmovups [rsp+0x7FFFFFFF], xmm8
vmovups [rsp+0x7FFFFFFF], xmm9
vmovups [rsp+0x7FFFFFFF], xmm10
vmovups [rsp+0x7FFFFFFF], xmm11
vmovups [rsp+0x7FFFFFFF], xmm12
vmovups [rsp+0x7FFFFFFF], xmm13
vmovups [rsp+0x7FFFFFFF], xmm14
vmovups [rsp+0x7FFFFFFF], xmm15

vmovups [rsp+0x7FFFFFFF], ymm0
vmovups [rsp+0x7FFFFFFF], ymm1
vmovups [rsp+0x7FFFFFFF], ymm2
vmovups [rsp+0x7FFFFFFF], ymm3
vmovups [rsp+0x7FFFFFFF], ymm4
vmovups [rsp+0x7FFFFFFF], ymm5
vmovups [rsp+0x7FFFFFFF], ymm6
vmovups [rsp+0x7FFFFFFF], ymm7
vmovups [rsp+0x7FFFFFFF], ymm8
vmovups [rsp+0x7FFFFFFF], ymm9
vmovups [rsp+0x7FFFFFFF], ymm10
vmovups [rsp+0x7FFFFFFF], ymm11
vmovups [rsp+0x7FFFFFFF], ymm12
vmovups [rsp+0x7FFFFFFF], ymm13
vmovups [rsp+0x7FFFFFFF], ymm14
vmovups [rsp+0x7FFFFFFF], ymm15

vmovups [rsp+0x7FFFFFFF], zmm0
vmovups [rsp+0x7FFFFFFF], zmm1
vmovups [rsp+0x7FFFFFFF], zmm2
vmovups [rsp+0x7FFFFFFF], zmm3
vmovups [rsp+0x7FFFFFFF], zmm4
vmovups [rsp+0x7FFFFFFF], zmm5
vmovups [rsp+0x7FFFFFFF], zmm6
vmovups [rsp+0x7FFFFFFF], zmm7
vmovups [rsp+0x7FFFFFFF], zmm8
vmovups [rsp+0x7FFFFFFF], zmm9
vmovups [rsp+0x7FFFFFFF], zmm10
vmovups [rsp+0x7FFFFFFF], zmm11
vmovups [rsp+0x7FFFFFFF], zmm12
vmovups [rsp+0x7FFFFFFF], zmm13
vmovups [rsp+0x7FFFFFFF], zmm14
vmovups [rsp+0x7FFFFFFF], zmm15
vmovups [rsp+0x7FFFFFFF], zmm16
vmovups [rsp+0x7FFFFFFF], zmm17
vmovups [rsp+0x7FFFFFFF], zmm18
vmovups [rsp+0x7FFFFFFF], zmm19
vmovups [rsp+0x7FFFFFFF], zmm20
vmovups [rsp+0x7FFFFFFF], zmm21
vmovups [rsp+0x7FFFFFFF], zmm22
vmovups [rsp+0x7FFFFFFF], zmm23
vmovups [rsp+0x7FFFFFFF], zmm24
vmovups [rsp+0x7FFFFFFF], zmm25
vmovups [rsp+0x7FFFFFFF], zmm26
vmovups [rsp+0x7FFFFFFF], zmm27
vmovups [rsp+0x7FFFFFFF], zmm28
vmovups [rsp+0x7FFFFFFF], zmm29
vmovups [rsp+0x7FFFFFFF], zmm30
vmovups [rsp+0x7FFFFFFF], zmm31

fsave [rsp+0x7FFFFFFF]

push rax
push rcx
lea rcx, [rsp+0x10]
mov dword ptr [rsp-0x8], 0x7FFFFFFF
mov dword ptr [rsp-0x4], 0x7FFFFFFF
call [rsp-0x8]
movzx eax, al
test eax, eax

je nothing_modified

pop rcx
pop rax

frstor [rsp+0x7FFFFFFF]

vmovups zmm31, [rsp+0x7FFFFFFF]
vmovups zmm30, [rsp+0x7FFFFFFF]
vmovups zmm29, [rsp+0x7FFFFFFF]
vmovups zmm28, [rsp+0x7FFFFFFF]
vmovups zmm27, [rsp+0x7FFFFFFF]
vmovups zmm26, [rsp+0x7FFFFFFF]
vmovups zmm25, [rsp+0x7FFFFFFF]
vmovups zmm24, [rsp+0x7FFFFFFF]
vmovups zmm23, [rsp+0x7FFFFFFF]
vmovups zmm22, [rsp+0x7FFFFFFF]
vmovups zmm21, [rsp+0x7FFFFFFF]
vmovups zmm20, [rsp+0x7FFFFFFF]
vmovups zmm19, [rsp+0x7FFFFFFF]
vmovups zmm18, [rsp+0x7FFFFFFF]
vmovups zmm17, [rsp+0x7FFFFFFF]
vmovups zmm16, [rsp+0x7FFFFFFF]
vmovups zmm15, [rsp+0x7FFFFFFF]
vmovups zmm14, [rsp+0x7FFFFFFF]
vmovups zmm13, [rsp+0x7FFFFFFF]
vmovups zmm12, [rsp+0x7FFFFFFF]
vmovups zmm11, [rsp+0x7FFFFFFF]
vmovups zmm10, [rsp+0x7FFFFFFF]
vmovups  zmm9, [rsp+0x7FFFFFFF]
vmovups  zmm8, [rsp+0x7FFFFFFF]
vmovups  zmm7, [rsp+0x7FFFFFFF]
vmovups  zmm6, [rsp+0x7FFFFFFF]
vmovups  zmm5, [rsp+0x7FFFFFFF]
vmovups  zmm4, [rsp+0x7FFFFFFF]
vmovups  zmm3, [rsp+0x7FFFFFFF]
vmovups  zmm2, [rsp+0x7FFFFFFF]
vmovups  zmm1, [rsp+0x7FFFFFFF]
vmovups  zmm0, [rsp+0x7FFFFFFF]

vmovups ymm15, [rsp+0x7FFFFFFF]
vmovups ymm14, [rsp+0x7FFFFFFF]
vmovups ymm13, [rsp+0x7FFFFFFF]
vmovups ymm12, [rsp+0x7FFFFFFF]
vmovups ymm11, [rsp+0x7FFFFFFF]
vmovups ymm10, [rsp+0x7FFFFFFF]
vmovups  ymm9, [rsp+0x7FFFFFFF]
vmovups  ymm8, [rsp+0x7FFFFFFF]
vmovups  ymm7, [rsp+0x7FFFFFFF]
vmovups  ymm6, [rsp+0x7FFFFFFF]
vmovups  ymm5, [rsp+0x7FFFFFFF]
vmovups  ymm4, [rsp+0x7FFFFFFF]
vmovups  ymm3, [rsp+0x7FFFFFFF]
vmovups  ymm2, [rsp+0x7FFFFFFF]
vmovups  ymm1, [rsp+0x7FFFFFFF]
vmovups  ymm0, [rsp+0x7FFFFFFF]

vmovups xmm15, [rsp+0x7FFFFFFF]
vmovups xmm14, [rsp+0x7FFFFFFF]
vmovups xmm13, [rsp+0x7FFFFFFF]
vmovups xmm12, [rsp+0x7FFFFFFF]
vmovups xmm11, [rsp+0x7FFFFFFF]
vmovups xmm10, [rsp+0x7FFFFFFF]
vmovups  xmm9, [rsp+0x7FFFFFFF]
vmovups  xmm8, [rsp+0x7FFFFFFF]
vmovups  xmm7, [rsp+0x7FFFFFFF]
vmovups  xmm6, [rsp+0x7FFFFFFF]
vmovups  xmm5, [rsp+0x7FFFFFFF]
vmovups  xmm4, [rsp+0x7FFFFFFF]
vmovups  xmm3, [rsp+0x7FFFFFFF]
vmovups  xmm2, [rsp+0x7FFFFFFF]
vmovups  xmm1, [rsp+0x7FFFFFFF]
vmovups  xmm0, [rsp+0x7FFFFFFF]

ldmxcsr [rsp+0x7FFFFFFF]

mov r15, qword ptr [rsp+0x7FFFFFFF]
mov r14, qword ptr [rsp+0x7FFFFFFF]
mov r13, qword ptr [rsp+0x7FFFFFFF]
mov r12, qword ptr [rsp+0x7FFFFFFF]
mov r11, qword ptr [rsp+0x7FFFFFFF]
mov r10, qword ptr [rsp+0x7FFFFFFF]
mov  r9, qword ptr [rsp+0x7FFFFFFF]
mov  r8, qword ptr [rsp+0x7FFFFFFF]
mov rdi, qword ptr [rsp+0x7FFFFFFF]
mov rsi, qword ptr [rsp+0x7FFFFFFF]
mov rbp, qword ptr [rsp+0x7FFFFFFF]

mov rbx, qword ptr [rsp+0x7FFFFFFF]
mov rdx, qword ptr [rsp+0x7FFFFFFF]
mov rcx, qword ptr [rsp+0x7FFFFFFF]
mov rax, qword ptr [rsp+0x7FFFFFFF]

push qword ptr [rsp+0x7FFFFFFF]
popfq

mov rsp, qword ptr [rsp+0x7FFFFFFF]

ret 0x0

nothing_modified:
pop rax
pop rcx
add rsp, 0x7FFFFFFF
