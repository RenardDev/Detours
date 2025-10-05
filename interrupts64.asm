
.code
	CallInterrupt proc
		push rax
		push rcx
		push rdx
		push rbx
		; push rsp
		push rbp
		push rsi
		push rdi
		push r8
		push r9
		push r10
		push r11
		push r12
		push r13
		push r14
		push r15

		add rsp, 78h
		add rsp, 28h

		mov rax, rcx
		mov rcx, rdx
		mov rdx, r8
		mov rbx, r9
		mov rbp, qword ptr [rsp+00h]
		mov rsi, qword ptr [rsp+08h]
		mov rdi, qword ptr [rsp+10h]
		mov  r8, qword ptr [rsp+18h]
		mov  r9, qword ptr [rsp+20h]
		mov r10, qword ptr [rsp+28h]
		mov r11, qword ptr [rsp+30h]
		mov r12, qword ptr [rsp+38h]
		mov r13, qword ptr [rsp+40h]
		mov r14, qword ptr [rsp+48h]
		mov r15, qword ptr [rsp+50h]

		sub rsp, 28h
		sub rsp, 78h

		int 7Eh

		pop r15
		pop r14
		pop r13
		pop r12
		pop r11
		pop r10
		pop r9
		pop r8
		pop rdi
		pop rsi
		pop rbp
		; pop rsp
		pop rbx
		pop rdx
		pop rcx
		; pop rax
		add rsp, 8
		ret
	CallInterrupt endp

	CallInrerruptReturn proc
		add rsp, 8
		iretq
	CallInrerruptReturn endp
end
