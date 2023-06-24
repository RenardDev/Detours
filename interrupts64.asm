
.code
	CallInterrupt proc
		push rax
		push rcx
		push rdx
		push rbx
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

		mov rax, rcx
		mov rcx, rdx
		mov rdx, r8
		mov rbx, r9
		mov rbp, qword ptr [rsp+78h+28h]
		mov rsi, qword ptr [rsp+78h+30h]
		mov rdi, qword ptr [rsp+78h+38h]
		mov  r8, qword ptr [rsp+78h+40h]
		mov  r9, qword ptr [rsp+78h+48h]
		mov r10, qword ptr [rsp+78h+50h]
		mov r11, qword ptr [rsp+78h+58h]
		mov r12, qword ptr [rsp+78h+60h]
		mov r13, qword ptr [rsp+78h+68h]
		mov r14, qword ptr [rsp+78h+70h]
		mov r15, qword ptr [rsp+78h+78h]

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
		pop rbx
		pop rdx
		pop rcx
		pop rax
		ret
	CallInterrupt endp
end
