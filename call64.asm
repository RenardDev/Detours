; ============================================================================
; CallAddress / RawHook::CallTrampoline monolithic machine-code blocks - x86-64
; ============================================================================
;
; Each variant is a complete executable byte-array template. Native GPR/flags
; and stack handling live in every variant. Higher ISA variants cumulatively
; include the lower SIMD levels:
;
;   AVX-512 -> AVX/AVX2/YMM -> SSE/XMM -> native
;   AVX/AVX2/YMM -> SSE/XMM -> native
;   SSE/XMM -> native
;
; x87 state is an orthogonal suffix. Restore order is XMM, then YMM, then ZMM;
; this is intentional because narrower VEX/EVEX writes clear upper lanes.
;
; Every 32-bit structure displacement is 0x7FFFFFFF and every 64-bit helper
; address is 0x7FFFFFFFFFFFFFFF. Detours.cpp patches fixed positions with
; sizeof(...), offsetof(...), and helper addresses before making code executable.
; The post-call gate recovers its frame from a guarded mirrored-stack header;
; no per-thread frame variable or global active-frame chain is required.
;

; ----------------------------------------------------------------------------
; CallAddressCode64WindowsNative: tier=native, fpu=false
; ----------------------------------------------------------------------------
call_address_code_win64_native:
	push rbp
	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0xC8

	movdqu xmmword ptr [rsp + 0x20], xmm6
	movdqu xmmword ptr [rsp + 0x30], xmm7
	movdqu xmmword ptr [rsp + 0x40], xmm8
	movdqu xmmword ptr [rsp + 0x50], xmm9
	movdqu xmmword ptr [rsp + 0x60], xmm10
	movdqu xmmword ptr [rsp + 0x70], xmm11
	movdqu xmmword ptr [rsp + 0x80], xmm12
	movdqu xmmword ptr [rsp + 0x90], xmm13
	movdqu xmmword ptr [rsp + 0xA0], xmm14
	movdqu xmmword ptr [rsp + 0xB0], xmm15
	stmxcsr dword ptr [rsp + 0xC0]
	fnstcw word ptr [rsp + 0xC4]

	mov r12, rcx
	mov rcx, r12
	mov rdx, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_win64_native

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	; No extended RAW_CONTEXT state for this variant.

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_win64_native:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	sub rsp, 0x20
	mov r10, r12
	; No extended RAW_CONTEXT state for this variant.

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_win64_native
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_win64_native
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_win64_native
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_failure_win64_native:
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_fatal_win64_native:
	ud2

; ----------------------------------------------------------------------------
; System V AMD64 ABI common state
; ----------------------------------------------------------------------------

call_address_code_win64_native_end:

; ----------------------------------------------------------------------------
; CallAddressCode64WindowsFPU: tier=native, fpu=true
; ----------------------------------------------------------------------------
call_address_code_win64_fpu:
	push rbp
	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0xC8

	movdqu xmmword ptr [rsp + 0x20], xmm6
	movdqu xmmword ptr [rsp + 0x30], xmm7
	movdqu xmmword ptr [rsp + 0x40], xmm8
	movdqu xmmword ptr [rsp + 0x50], xmm9
	movdqu xmmword ptr [rsp + 0x60], xmm10
	movdqu xmmword ptr [rsp + 0x70], xmm11
	movdqu xmmword ptr [rsp + 0x80], xmm12
	movdqu xmmword ptr [rsp + 0x90], xmm13
	movdqu xmmword ptr [rsp + 0xA0], xmm14
	movdqu xmmword ptr [rsp + 0xB0], xmm15
	stmxcsr dword ptr [rsp + 0xC0]
	fnstcw word ptr [rsp + 0xC4]

	mov r12, rcx
	mov rcx, r12
	mov rdx, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_win64_fpu

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	frstor [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_win64_fpu:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	sub rsp, 0x20
	mov r10, r12
	fsave [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_win64_fpu
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_win64_fpu
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_win64_fpu
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_failure_win64_fpu:
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_fatal_win64_fpu:
	ud2

; ----------------------------------------------------------------------------
; System V AMD64 ABI common state
; ----------------------------------------------------------------------------

call_address_code_win64_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode64WindowsSSE: tier=sse, fpu=false
; ----------------------------------------------------------------------------
call_address_code_win64_sse:
	push rbp
	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0xC8

	movdqu xmmword ptr [rsp + 0x20], xmm6
	movdqu xmmword ptr [rsp + 0x30], xmm7
	movdqu xmmword ptr [rsp + 0x40], xmm8
	movdqu xmmword ptr [rsp + 0x50], xmm9
	movdqu xmmword ptr [rsp + 0x60], xmm10
	movdqu xmmword ptr [rsp + 0x70], xmm11
	movdqu xmmword ptr [rsp + 0x80], xmm12
	movdqu xmmword ptr [rsp + 0x90], xmm13
	movdqu xmmword ptr [rsp + 0xA0], xmm14
	movdqu xmmword ptr [rsp + 0xB0], xmm15
	stmxcsr dword ptr [rsp + 0xC0]
	fnstcw word ptr [rsp + 0xC4]

	mov r12, rcx
	mov rcx, r12
	mov rdx, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_win64_sse

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	movups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	movups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	movups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	movups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	movups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	movups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	movups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	movups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_win64_sse:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	sub rsp, 0x20
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_win64_sse
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_win64_sse
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_win64_sse
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_failure_win64_sse:
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_fatal_win64_sse:
	ud2

; ----------------------------------------------------------------------------
; System V AMD64 ABI common state
; ----------------------------------------------------------------------------

call_address_code_win64_sse_end:

; ----------------------------------------------------------------------------
; CallAddressCode64WindowsSSEFPU: tier=sse, fpu=true
; ----------------------------------------------------------------------------
call_address_code_win64_sse_fpu:
	push rbp
	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0xC8

	movdqu xmmword ptr [rsp + 0x20], xmm6
	movdqu xmmword ptr [rsp + 0x30], xmm7
	movdqu xmmword ptr [rsp + 0x40], xmm8
	movdqu xmmword ptr [rsp + 0x50], xmm9
	movdqu xmmword ptr [rsp + 0x60], xmm10
	movdqu xmmword ptr [rsp + 0x70], xmm11
	movdqu xmmword ptr [rsp + 0x80], xmm12
	movdqu xmmword ptr [rsp + 0x90], xmm13
	movdqu xmmword ptr [rsp + 0xA0], xmm14
	movdqu xmmword ptr [rsp + 0xB0], xmm15
	stmxcsr dword ptr [rsp + 0xC0]
	fnstcw word ptr [rsp + 0xC4]

	mov r12, rcx
	mov rcx, r12
	mov rdx, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_win64_sse_fpu

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	frstor [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	movups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	movups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	movups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	movups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	movups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	movups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	movups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	movups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_win64_sse_fpu:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	sub rsp, 0x20
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	fsave [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_win64_sse_fpu
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_win64_sse_fpu
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_win64_sse_fpu
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_failure_win64_sse_fpu:
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_fatal_win64_sse_fpu:
	ud2

; ----------------------------------------------------------------------------
; System V AMD64 ABI common state
; ----------------------------------------------------------------------------

call_address_code_win64_sse_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode64WindowsAVX: tier=avx, fpu=false
; ----------------------------------------------------------------------------
call_address_code_win64_avx:
	push rbp
	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0xC8

	movdqu xmmword ptr [rsp + 0x20], xmm6
	movdqu xmmword ptr [rsp + 0x30], xmm7
	movdqu xmmword ptr [rsp + 0x40], xmm8
	movdqu xmmword ptr [rsp + 0x50], xmm9
	movdqu xmmword ptr [rsp + 0x60], xmm10
	movdqu xmmword ptr [rsp + 0x70], xmm11
	movdqu xmmword ptr [rsp + 0x80], xmm12
	movdqu xmmword ptr [rsp + 0x90], xmm13
	movdqu xmmword ptr [rsp + 0xA0], xmm14
	movdqu xmmword ptr [rsp + 0xB0], xmm15
	stmxcsr dword ptr [rsp + 0xC0]
	fnstcw word ptr [rsp + 0xC4]

	mov r12, rcx
	mov rcx, r12
	mov rdx, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_win64_avx

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm15, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups ymm14, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymm13, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymm12, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymm11, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymm10, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymm9, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymm8, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymm7, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_win64_avx:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	sub rsp, 0x20
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm8 ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm9 ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm10 ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm11 ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm12 ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm13 ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm14 ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm15 ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_win64_avx
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_win64_avx
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_win64_avx
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_failure_win64_avx:
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_fatal_win64_avx:
	ud2

; ----------------------------------------------------------------------------
; System V AMD64 ABI common state
; ----------------------------------------------------------------------------

call_address_code_win64_avx_end:

; ----------------------------------------------------------------------------
; CallAddressCode64WindowsAVXFPU: tier=avx, fpu=true
; ----------------------------------------------------------------------------
call_address_code_win64_avx_fpu:
	push rbp
	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0xC8

	movdqu xmmword ptr [rsp + 0x20], xmm6
	movdqu xmmword ptr [rsp + 0x30], xmm7
	movdqu xmmword ptr [rsp + 0x40], xmm8
	movdqu xmmword ptr [rsp + 0x50], xmm9
	movdqu xmmword ptr [rsp + 0x60], xmm10
	movdqu xmmword ptr [rsp + 0x70], xmm11
	movdqu xmmword ptr [rsp + 0x80], xmm12
	movdqu xmmword ptr [rsp + 0x90], xmm13
	movdqu xmmword ptr [rsp + 0xA0], xmm14
	movdqu xmmword ptr [rsp + 0xB0], xmm15
	stmxcsr dword ptr [rsp + 0xC0]
	fnstcw word ptr [rsp + 0xC4]

	mov r12, rcx
	mov rcx, r12
	mov rdx, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_win64_avx_fpu

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	frstor [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm15, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups ymm14, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymm13, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymm12, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymm11, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymm10, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymm9, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymm8, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymm7, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_win64_avx_fpu:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	sub rsp, 0x20
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm8 ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm9 ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm10 ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm11 ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm12 ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm13 ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm14 ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm15 ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	fsave [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_win64_avx_fpu
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_win64_avx_fpu
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_win64_avx_fpu
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_failure_win64_avx_fpu:
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_fatal_win64_avx_fpu:
	ud2

; ----------------------------------------------------------------------------
; System V AMD64 ABI common state
; ----------------------------------------------------------------------------

call_address_code_win64_avx_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode64WindowsAVX512: tier=avx512, fpu=false
; ----------------------------------------------------------------------------
call_address_code_win64_avx512:
	push rbp
	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0xC8

	movdqu xmmword ptr [rsp + 0x20], xmm6
	movdqu xmmword ptr [rsp + 0x30], xmm7
	movdqu xmmword ptr [rsp + 0x40], xmm8
	movdqu xmmword ptr [rsp + 0x50], xmm9
	movdqu xmmword ptr [rsp + 0x60], xmm10
	movdqu xmmword ptr [rsp + 0x70], xmm11
	movdqu xmmword ptr [rsp + 0x80], xmm12
	movdqu xmmword ptr [rsp + 0x90], xmm13
	movdqu xmmword ptr [rsp + 0xA0], xmm14
	movdqu xmmword ptr [rsp + 0xB0], xmm15
	stmxcsr dword ptr [rsp + 0xC0]
	fnstcw word ptr [rsp + 0xC4]

	mov r12, rcx
	mov rcx, r12
	mov rdx, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_win64_avx512

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm15, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups ymm14, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymm13, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymm12, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymm11, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymm10, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymm9, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymm8, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymm7, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups zmm31, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM31)
	vmovups zmm30, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM30)
	vmovups zmm29, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM29)
	vmovups zmm28, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM28)
	vmovups zmm27, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM27)
	vmovups zmm26, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM26)
	vmovups zmm25, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM25)
	vmovups zmm24, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM24)
	vmovups zmm23, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM23)
	vmovups zmm22, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM22)
	vmovups zmm21, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM21)
	vmovups zmm20, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM20)
	vmovups zmm19, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM19)
	vmovups zmm18, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM18)
	vmovups zmm17, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM17)
	vmovups zmm16, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM16)
	vmovups zmm15, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM15)
	vmovups zmm14, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM14)
	vmovups zmm13, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM13)
	vmovups zmm12, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM12)
	vmovups zmm11, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM11)
	vmovups zmm10, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM10)
	vmovups zmm9, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM9)
	vmovups zmm8, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM8)
	vmovups zmm7, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmm6, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmm5, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmm4, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmm3, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmm2, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmm1, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmm0, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_win64_avx512:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	sub rsp, 0x20
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm8 ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm9 ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm10 ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm11 ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm12 ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm13 ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm14 ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm15 ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm0 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm1 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm2 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm3 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm4 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm5 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm6 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm7 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm8 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM8)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm9 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM9)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm10 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM10)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm11 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM11)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm12 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM12)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm13 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM13)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm14 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM14)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm15 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM15)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm16 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM16)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm17 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM17)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm18 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM18)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm19 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM19)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm20 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM20)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm21 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM21)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm22 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM22)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm23 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM23)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm24 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM24)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm25 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM25)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm26 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM26)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm27 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM27)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm28 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM28)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm29 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM29)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm30 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM30)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm31 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM31)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_win64_avx512
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_win64_avx512
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_win64_avx512
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_failure_win64_avx512:
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_fatal_win64_avx512:
	ud2

; ----------------------------------------------------------------------------
; System V AMD64 ABI common state
; ----------------------------------------------------------------------------

call_address_code_win64_avx512_end:

; ----------------------------------------------------------------------------
; CallAddressCode64WindowsAVX512FPU: tier=avx512, fpu=true
; ----------------------------------------------------------------------------
call_address_code_win64_avx512_fpu:
	push rbp
	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0xC8

	movdqu xmmword ptr [rsp + 0x20], xmm6
	movdqu xmmword ptr [rsp + 0x30], xmm7
	movdqu xmmword ptr [rsp + 0x40], xmm8
	movdqu xmmword ptr [rsp + 0x50], xmm9
	movdqu xmmword ptr [rsp + 0x60], xmm10
	movdqu xmmword ptr [rsp + 0x70], xmm11
	movdqu xmmword ptr [rsp + 0x80], xmm12
	movdqu xmmword ptr [rsp + 0x90], xmm13
	movdqu xmmword ptr [rsp + 0xA0], xmm14
	movdqu xmmword ptr [rsp + 0xB0], xmm15
	stmxcsr dword ptr [rsp + 0xC0]
	fnstcw word ptr [rsp + 0xC4]

	mov r12, rcx
	mov rcx, r12
	mov rdx, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_win64_avx512_fpu

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	frstor [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm15, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups ymm14, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymm13, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymm12, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymm11, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymm10, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymm9, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymm8, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymm7, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups zmm31, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM31)
	vmovups zmm30, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM30)
	vmovups zmm29, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM29)
	vmovups zmm28, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM28)
	vmovups zmm27, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM27)
	vmovups zmm26, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM26)
	vmovups zmm25, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM25)
	vmovups zmm24, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM24)
	vmovups zmm23, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM23)
	vmovups zmm22, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM22)
	vmovups zmm21, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM21)
	vmovups zmm20, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM20)
	vmovups zmm19, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM19)
	vmovups zmm18, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM18)
	vmovups zmm17, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM17)
	vmovups zmm16, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM16)
	vmovups zmm15, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM15)
	vmovups zmm14, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM14)
	vmovups zmm13, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM13)
	vmovups zmm12, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM12)
	vmovups zmm11, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM11)
	vmovups zmm10, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM10)
	vmovups zmm9, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM9)
	vmovups zmm8, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM8)
	vmovups zmm7, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmm6, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmm5, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmm4, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmm3, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmm2, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmm1, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmm0, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_win64_avx512_fpu:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	sub rsp, 0x20
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm8 ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm9 ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm10 ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm11 ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm12 ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm13 ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm14 ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm15 ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm0 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm1 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm2 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm3 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm4 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm5 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm6 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm7 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm8 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM8)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm9 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM9)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm10 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM10)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm11 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM11)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm12 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM12)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm13 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM13)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm14 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM14)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm15 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM15)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm16 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM16)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm17 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM17)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm18 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM18)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm19 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM19)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm20 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM20)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm21 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM21)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm22 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM22)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm23 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM23)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm24 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM24)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm25 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM25)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm26 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM26)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm27 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM27)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm28 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM28)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm29 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM29)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm30 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM30)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm31 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM31)
	fsave [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_win64_avx512_fpu
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_win64_avx512_fpu
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_win64_avx512_fpu
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_failure_win64_avx512_fpu:
	movdqu xmm6, xmmword ptr [rsp + 0x20]
	movdqu xmm7, xmmword ptr [rsp + 0x30]
	movdqu xmm8, xmmword ptr [rsp + 0x40]
	movdqu xmm9, xmmword ptr [rsp + 0x50]
	movdqu xmm10, xmmword ptr [rsp + 0x60]
	movdqu xmm11, xmmword ptr [rsp + 0x70]
	movdqu xmm12, xmmword ptr [rsp + 0x80]
	movdqu xmm13, xmmword ptr [rsp + 0x90]
	movdqu xmm14, xmmword ptr [rsp + 0xA0]
	movdqu xmm15, xmmword ptr [rsp + 0xB0]
	ldmxcsr dword ptr [rsp + 0xC0]
	fldcw word ptr [rsp + 0xC4]
	add rsp, 0xC8
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	pop rbp
	ret

call_address_fatal_win64_avx512_fpu:
	ud2

; ----------------------------------------------------------------------------
; System V AMD64 ABI common state
; ----------------------------------------------------------------------------

call_address_code_win64_avx512_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode64SystemVNative: tier=native, fpu=false
; ----------------------------------------------------------------------------
call_address_code_sysv64_native:
	push rbp
	push rbx
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0x18
	stmxcsr dword ptr [rsp]
	fnstcw word ptr [rsp + 4]

	mov r12, rdi
	mov rdi, r12
	mov rsi, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_sysv64_native

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	; No extended RAW_CONTEXT state for this variant.

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_sysv64_native:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	mov r10, r12
	; No extended RAW_CONTEXT state for this variant.

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_sysv64_native
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_sysv64_native
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_sysv64_native
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_failure_sysv64_native:
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_fatal_sysv64_native:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (R10 = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code_sysv64_native_end:

; ----------------------------------------------------------------------------
; CallAddressCode64SystemVFPU: tier=native, fpu=true
; ----------------------------------------------------------------------------
call_address_code_sysv64_fpu:
	push rbp
	push rbx
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0x18
	stmxcsr dword ptr [rsp]
	fnstcw word ptr [rsp + 4]

	mov r12, rdi
	mov rdi, r12
	mov rsi, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_sysv64_fpu

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	frstor [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_sysv64_fpu:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	mov r10, r12
	fsave [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_sysv64_fpu
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_sysv64_fpu
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_sysv64_fpu
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_failure_sysv64_fpu:
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_fatal_sysv64_fpu:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (R10 = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code_sysv64_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode64SystemVSSE: tier=sse, fpu=false
; ----------------------------------------------------------------------------
call_address_code_sysv64_sse:
	push rbp
	push rbx
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0x18
	stmxcsr dword ptr [rsp]
	fnstcw word ptr [rsp + 4]

	mov r12, rdi
	mov rdi, r12
	mov rsi, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_sysv64_sse

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	movups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	movups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	movups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	movups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	movups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	movups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	movups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	movups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_sysv64_sse:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_sysv64_sse
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_sysv64_sse
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_sysv64_sse
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_failure_sysv64_sse:
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_fatal_sysv64_sse:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (R10 = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code_sysv64_sse_end:

; ----------------------------------------------------------------------------
; CallAddressCode64SystemVSSEFPU: tier=sse, fpu=true
; ----------------------------------------------------------------------------
call_address_code_sysv64_sse_fpu:
	push rbp
	push rbx
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0x18
	stmxcsr dword ptr [rsp]
	fnstcw word ptr [rsp + 4]

	mov r12, rdi
	mov rdi, r12
	mov rsi, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_sysv64_sse_fpu

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	frstor [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	movups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	movups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	movups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	movups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	movups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	movups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	movups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	movups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_sysv64_sse_fpu:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	movups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	fsave [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_sysv64_sse_fpu
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_sysv64_sse_fpu
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_sysv64_sse_fpu
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_failure_sysv64_sse_fpu:
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_fatal_sysv64_sse_fpu:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (R10 = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code_sysv64_sse_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode64SystemVAVX: tier=avx, fpu=false
; ----------------------------------------------------------------------------
call_address_code_sysv64_avx:
	push rbp
	push rbx
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0x18
	stmxcsr dword ptr [rsp]
	fnstcw word ptr [rsp + 4]

	mov r12, rdi
	mov rdi, r12
	mov rsi, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_sysv64_avx

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm15, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups ymm14, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymm13, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymm12, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymm11, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymm10, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymm9, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymm8, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymm7, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_sysv64_avx:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm8 ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm9 ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm10 ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm11 ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm12 ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm13 ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm14 ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm15 ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_sysv64_avx
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_sysv64_avx
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_sysv64_avx
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_failure_sysv64_avx:
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_fatal_sysv64_avx:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (R10 = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code_sysv64_avx_end:

; ----------------------------------------------------------------------------
; CallAddressCode64SystemVAVXFPU: tier=avx, fpu=true
; ----------------------------------------------------------------------------
call_address_code_sysv64_avx_fpu:
	push rbp
	push rbx
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0x18
	stmxcsr dword ptr [rsp]
	fnstcw word ptr [rsp + 4]

	mov r12, rdi
	mov rdi, r12
	mov rsi, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_sysv64_avx_fpu

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	frstor [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm15, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups ymm14, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymm13, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymm12, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymm11, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymm10, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymm9, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymm8, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymm7, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_sysv64_avx_fpu:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm8 ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm9 ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm10 ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm11 ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm12 ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm13 ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm14 ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm15 ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	fsave [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_sysv64_avx_fpu
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_sysv64_avx_fpu
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_sysv64_avx_fpu
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_failure_sysv64_avx_fpu:
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_fatal_sysv64_avx_fpu:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (R10 = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code_sysv64_avx_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode64SystemVAVX512: tier=avx512, fpu=false
; ----------------------------------------------------------------------------
call_address_code_sysv64_avx512:
	push rbp
	push rbx
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0x18
	stmxcsr dword ptr [rsp]
	fnstcw word ptr [rsp + 4]

	mov r12, rdi
	mov rdi, r12
	mov rsi, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_sysv64_avx512

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm15, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups ymm14, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymm13, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymm12, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymm11, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymm10, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymm9, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymm8, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymm7, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups zmm31, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM31)
	vmovups zmm30, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM30)
	vmovups zmm29, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM29)
	vmovups zmm28, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM28)
	vmovups zmm27, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM27)
	vmovups zmm26, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM26)
	vmovups zmm25, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM25)
	vmovups zmm24, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM24)
	vmovups zmm23, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM23)
	vmovups zmm22, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM22)
	vmovups zmm21, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM21)
	vmovups zmm20, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM20)
	vmovups zmm19, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM19)
	vmovups zmm18, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM18)
	vmovups zmm17, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM17)
	vmovups zmm16, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM16)
	vmovups zmm15, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM15)
	vmovups zmm14, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM14)
	vmovups zmm13, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM13)
	vmovups zmm12, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM12)
	vmovups zmm11, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM11)
	vmovups zmm10, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM10)
	vmovups zmm9, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM9)
	vmovups zmm8, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM8)
	vmovups zmm7, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmm6, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmm5, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmm4, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmm3, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmm2, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmm1, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmm0, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_sysv64_avx512:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm8 ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm9 ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm10 ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm11 ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm12 ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm13 ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm14 ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm15 ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm0 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm1 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm2 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm3 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm4 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm5 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm6 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm7 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm8 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM8)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm9 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM9)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm10 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM10)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm11 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM11)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm12 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM12)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm13 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM13)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm14 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM14)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm15 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM15)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm16 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM16)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm17 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM17)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm18 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM18)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm19 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM19)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm20 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM20)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm21 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM21)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm22 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM22)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm23 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM23)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm24 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM24)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm25 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM25)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm26 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM26)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm27 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM27)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm28 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM28)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm29 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM29)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm30 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM30)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm31 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM31)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_sysv64_avx512
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_sysv64_avx512
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_sysv64_avx512
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_failure_sysv64_avx512:
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_fatal_sysv64_avx512:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (R10 = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code_sysv64_avx512_end:

; ----------------------------------------------------------------------------
; CallAddressCode64SystemVAVX512FPU: tier=avx512, fpu=true
; ----------------------------------------------------------------------------
call_address_code_sysv64_avx512_fpu:
	push rbp
	push rbx
	push r12
	push r13
	push r14
	push r15
	sub rsp, 0x18
	stmxcsr dword ptr [rsp]
	fnstcw word ptr [rsp + 4]

	mov r12, rdi
	mov rdi, r12
	mov rsi, rsp
	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(PrepareRawCall)
	call rax
	test al, al
	je call_address_failure_sysv64_avx512_fpu

	mov r10, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov r11, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov rax, qword ptr [r12 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov qword ptr [r11], rax

	frstor [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm15, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups xmm14, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmm13, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmm12, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmm11, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmm10, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmm9, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmm8, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmm7, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm15, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups ymm14, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymm13, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymm12, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymm11, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymm10, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymm9, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymm8, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymm7, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups zmm31, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM31)
	vmovups zmm30, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM30)
	vmovups zmm29, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM29)
	vmovups zmm28, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM28)
	vmovups zmm27, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM27)
	vmovups zmm26, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM26)
	vmovups zmm25, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM25)
	vmovups zmm24, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM24)
	vmovups zmm23, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM23)
	vmovups zmm22, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM22)
	vmovups zmm21, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM21)
	vmovups zmm20, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM20)
	vmovups zmm19, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM19)
	vmovups zmm18, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM18)
	vmovups zmm17, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM17)
	vmovups zmm16, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM16)
	vmovups zmm15, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM15)
	vmovups zmm14, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM14)
	vmovups zmm13, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM13)
	vmovups zmm12, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM12)
	vmovups zmm11, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM11)
	vmovups zmm10, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM10)
	vmovups zmm9, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM9)
	vmovups zmm8, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM8)
	vmovups zmm7, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmm6, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmm5, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmm4, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmm3, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmm2, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmm1, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmm0, zmmword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)

	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [r11 - 16], rax
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [r11 - 8], rax

	push qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)
	popfq

	mov r15, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov r14, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov r13, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov r12, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov r9,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov r8,  qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov rdi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov rsi, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov rbp, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov rbx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	mov rdx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov rcx, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov rax, qword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)

	mov rsp, r11
	mov r11, qword ptr [rsp - 8]
	mov r10, qword ptr [rsp - 16]
	lea rsp, [rsp + 8]
	call qword ptr [rsp - 8]

call_address_gate_sysv64_avx512_fpu:
	pushfq
	cld
	sub rsp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRAX)
	mov qword ptr [rsp + 0x7FFFFFFF], rcx ; PATCH: offsetof(RAW_CONTEXT, m_unRCX)
	mov qword ptr [rsp + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CONTEXT, m_unRDX)
	mov qword ptr [rsp + 0x7FFFFFFF], rbx ; PATCH: offsetof(RAW_CONTEXT, m_unRBX)
	lea rax, [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRSP)
	mov qword ptr [rsp + 0x7FFFFFFF], rbp ; PATCH: offsetof(RAW_CONTEXT, m_unRBP)
	mov qword ptr [rsp + 0x7FFFFFFF], rsi ; PATCH: offsetof(RAW_CONTEXT, m_unRSI)
	mov qword ptr [rsp + 0x7FFFFFFF], rdi ; PATCH: offsetof(RAW_CONTEXT, m_unRDI)
	mov qword ptr [rsp + 0x7FFFFFFF], r8 ; PATCH: offsetof(RAW_CONTEXT, m_unR8)
	mov qword ptr [rsp + 0x7FFFFFFF], r9 ; PATCH: offsetof(RAW_CONTEXT, m_unR9)
	mov qword ptr [rsp + 0x7FFFFFFF], r10 ; PATCH: offsetof(RAW_CONTEXT, m_unR10)
	mov qword ptr [rsp + 0x7FFFFFFF], r11 ; PATCH: offsetof(RAW_CONTEXT, m_unR11)
	mov qword ptr [rsp + 0x7FFFFFFF], r12 ; PATCH: offsetof(RAW_CONTEXT, m_unR12)
	mov qword ptr [rsp + 0x7FFFFFFF], r13 ; PATCH: offsetof(RAW_CONTEXT, m_unR13)
	mov qword ptr [rsp + 0x7FFFFFFF], r14 ; PATCH: offsetof(RAW_CONTEXT, m_unR14)
	mov qword ptr [rsp + 0x7FFFFFFF], r15 ; PATCH: offsetof(RAW_CONTEXT, m_unR15)
	mov rax, qword ptr [rsp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov qword ptr [rsp + 0x7FFFFFFF], rax ; PATCH: offsetof(RAW_CONTEXT, m_unRFLAGS)

	mov r12, rsp
	mov r10, r12
	stmxcsr dword ptr [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm8 ; PATCH: offsetof(RAW_CONTEXT, m_XMM8)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm9 ; PATCH: offsetof(RAW_CONTEXT, m_XMM9)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm10 ; PATCH: offsetof(RAW_CONTEXT, m_XMM10)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm11 ; PATCH: offsetof(RAW_CONTEXT, m_XMM11)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm12 ; PATCH: offsetof(RAW_CONTEXT, m_XMM12)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm13 ; PATCH: offsetof(RAW_CONTEXT, m_XMM13)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm14 ; PATCH: offsetof(RAW_CONTEXT, m_XMM14)
	vmovups xmmword ptr [r10 + 0x7FFFFFFF], xmm15 ; PATCH: offsetof(RAW_CONTEXT, m_XMM15)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm8 ; PATCH: offsetof(RAW_CONTEXT, m_YMM8)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm9 ; PATCH: offsetof(RAW_CONTEXT, m_YMM9)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm10 ; PATCH: offsetof(RAW_CONTEXT, m_YMM10)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm11 ; PATCH: offsetof(RAW_CONTEXT, m_YMM11)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm12 ; PATCH: offsetof(RAW_CONTEXT, m_YMM12)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm13 ; PATCH: offsetof(RAW_CONTEXT, m_YMM13)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm14 ; PATCH: offsetof(RAW_CONTEXT, m_YMM14)
	vmovups ymmword ptr [r10 + 0x7FFFFFFF], ymm15 ; PATCH: offsetof(RAW_CONTEXT, m_YMM15)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm0 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm1 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm2 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm3 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm4 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm5 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm6 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm7 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm8 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM8)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm9 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM9)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm10 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM10)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm11 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM11)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm12 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM12)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm13 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM13)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm14 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM14)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm15 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM15)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm16 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM16)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm17 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM17)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm18 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM18)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm19 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM19)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm20 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM20)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm21 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM21)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm22 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM22)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm23 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM23)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm24 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM24)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm25 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM25)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm26 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM26)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm27 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM27)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm28 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM28)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm29 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM29)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm30 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM30)
	vmovups zmmword ptr [r10 + 0x7FFFFFFF], zmm31 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM31)
	fsave [r10 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	movabs rax, 0x7FFFFFFFFFFFFFFF ; PATCH: reinterpret_cast<size_t>(GetRawCallFrameFromStack)
	call rax
	test rax, rax
	je call_address_fatal_sysv64_avx512_fpu
	mov r13, rax

	mov rsi, r12
	lea rdi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rdx, 8
	cmp rax, rdx
	jb call_address_fatal_sysv64_avx512_fpu
	sub rax, rdx
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	cmp rax, rcx
	ja call_address_fatal_sysv64_avx512_fpu
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdx, rax
	mov qword ptr [r13 + 0x7FFFFFFF], rdx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)

	mov rsi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add rsi, 8
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add rdi, 8
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub rcx, 8
	rep movsb

	mov rax, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unRSP)
	mov rdx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub rax, rdx
	mov rcx, qword ptr [rdx]
	mov qword ptr [rdx + rax], rcx

	lea rsi, [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov rdi, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov rcx, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov rdx, rcx
	shr rcx, 3
	rep movsq
	mov rcx, rdx
	and rcx, 7
	rep movsb

	mov rsp, qword ptr [r13 + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_failure_sysv64_avx512_fpu:
	ldmxcsr dword ptr [rsp]
	fldcw word ptr [rsp + 4]
	add rsp, 0x18
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret

call_address_fatal_sysv64_avx512_fpu:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (R10 = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code_sysv64_avx512_fpu_end:
