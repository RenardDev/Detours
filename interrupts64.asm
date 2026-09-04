.code
	CallInterrupt proc frame
		push rax
		.allocstack 8
		push rcx
		.allocstack 8
		push rdx
		.allocstack 8
		push rbx
		.pushreg rbx
		; push rsp
		push rbp
		.pushreg rbp
		push rsi
		.pushreg rsi
		push rdi
		.pushreg rdi
		push r8
		.allocstack 8
		push r9
		.allocstack 8
		push r10
		.allocstack 8
		push r11
		.allocstack 8
		push r12
		.pushreg r12
		push r13
		.pushreg r13
		push r14
		.pushreg r14
		push r15
		.pushreg r15
		.endprolog

		mov rax, rcx
		mov rcx, rdx
		mov rdx, r8
		mov rbx, r9
		mov rbp, qword ptr [rsp+0A0h]
		mov rsi, qword ptr [rsp+0A8h]
		mov rdi, qword ptr [rsp+0B0h]
		mov r8, qword ptr [rsp+0B8h]
		mov r9, qword ptr [rsp+0C0h]
		mov r10, qword ptr [rsp+0C8h]
		mov r11, qword ptr [rsp+0D0h]
		mov r12, qword ptr [rsp+0D8h]
		mov r13, qword ptr [rsp+0E0h]
		mov r14, qword ptr [rsp+0E8h]
		mov r15, qword ptr [rsp+0F0h]

		int 7Eh

		mov r15, qword ptr [rsp+00h]
		mov r14, qword ptr [rsp+08h]
		mov r13, qword ptr [rsp+10h]
		mov r12, qword ptr [rsp+18h]
		mov r11, qword ptr [rsp+20h]
		mov r10, qword ptr [rsp+28h]
		mov r9, qword ptr [rsp+30h]
		mov r8, qword ptr [rsp+38h]
		mov rdi, qword ptr [rsp+40h]
		mov rsi, qword ptr [rsp+48h]
		mov rbp, qword ptr [rsp+50h]
		mov rbx, qword ptr [rsp+58h]
		mov rdx, qword ptr [rsp+60h]
		mov rcx, qword ptr [rsp+68h]
		add rsp, 78h
		ret
	CallInterrupt endp

	CallInterruptReturn proc
		add rsp, 8
		iretq
	CallInterruptReturn endp

	TryRead proc
		mov rax, rcx
		mov al, byte ptr [rax]
		ret
	TryRead endp

end
