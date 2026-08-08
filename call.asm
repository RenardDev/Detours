; ============================================================================
; CallAddress / RawHook::CallTrampoline monolithic machine-code blocks - x86
; ============================================================================
;
; Native GPR/flags and stack handling live in every variant. Higher ISA
; variants cumulatively include lower SIMD levels:
;
;   AVX-512 -> AVX/AVX2/YMM -> SSE/XMM -> native
;   AVX/AVX2/YMM -> SSE/XMM -> native
;   SSE/XMM -> native
;
; x87 state is orthogonal. Native-only variants also preserve whichever host
; control state is available without exposing it through RAW_NATIVE_CONTEXT.
; Restore order is XMM, then YMM, then ZMM so upper lanes survive VEX/EVEX
; zeroing semantics.
;
; Every patchable immediate/displacement is 0x7FFFFFFF. Detours.cpp patches
; fixed positions with sizeof(...), offsetof(...), and helper addresses.
; The post-call gate recovers its frame from a guarded mirrored-stack header;
; no per-thread frame variable or global active-frame chain is required.
;

; ----------------------------------------------------------------------------
; CallAddressCode32NativeHostNative: source=native, tier=native, fpu=false
; ----------------------------------------------------------------------------
call_address_code32_native_host_native:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10

	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_native_host_native

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	; No extended RAW_CONTEXT state for this variant.

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_native_host_native:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	; No extended RAW_CONTEXT state for this variant.

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_native_host_native
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_native_host_native
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_native_host_native
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)

	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_native_host_native:

	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_native_host_native:
	ud2

; ----------------------------------------------------------------------------
; Common state: fpu
; ----------------------------------------------------------------------------

call_address_code32_native_host_native_end:

; ----------------------------------------------------------------------------
; CallAddressCode32NativeHostFPU: source=fpu, tier=native, fpu=false
; ----------------------------------------------------------------------------
call_address_code32_native_host_fpu:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	fnstcw word ptr [esp + 4]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_native_host_fpu

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	; No extended RAW_CONTEXT state for this variant.

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_native_host_fpu:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	; No extended RAW_CONTEXT state for this variant.

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_native_host_fpu
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_native_host_fpu
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_native_host_fpu
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_native_host_fpu:
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_native_host_fpu:
	ud2

; ----------------------------------------------------------------------------
; Common state: sse
; ----------------------------------------------------------------------------

call_address_code32_native_host_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode32NativeHostSSE: source=sse, tier=native, fpu=false
; ----------------------------------------------------------------------------
call_address_code32_native_host_sse:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	stmxcsr dword ptr [esp]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_native_host_sse

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	; No extended RAW_CONTEXT state for this variant.

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_native_host_sse:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	; No extended RAW_CONTEXT state for this variant.

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_native_host_sse
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_native_host_sse
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_native_host_sse
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [esp]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_native_host_sse:
	ldmxcsr dword ptr [esp]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_native_host_sse:
	ud2

; ----------------------------------------------------------------------------
; Common state: sse_fpu
; ----------------------------------------------------------------------------

call_address_code32_native_host_sse_end:

; ----------------------------------------------------------------------------
; CallAddressCode32NativeHostSSEFPU: source=sse_fpu, tier=native, fpu=false
; ----------------------------------------------------------------------------
call_address_code32_native_host_sse_fpu:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	stmxcsr dword ptr [esp]
	fnstcw word ptr [esp + 4]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_native_host_sse_fpu

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	; No extended RAW_CONTEXT state for this variant.

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_native_host_sse_fpu:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	; No extended RAW_CONTEXT state for this variant.

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_native_host_sse_fpu
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_native_host_sse_fpu
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_native_host_sse_fpu
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [esp]
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_native_host_sse_fpu:
	ldmxcsr dword ptr [esp]
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_native_host_sse_fpu:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (EDX = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code32_native_host_sse_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode32FPU: source=fpu, tier=native, fpu=true
; ----------------------------------------------------------------------------
call_address_code32_fpu:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	fnstcw word ptr [esp + 4]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_fpu

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	frstor [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_fpu:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	fsave [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_fpu
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_fpu
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_fpu
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_fpu:
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_fpu:
	ud2

; ----------------------------------------------------------------------------
; Common state: sse
; ----------------------------------------------------------------------------

call_address_code32_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode32SSE: source=sse, tier=sse, fpu=false
; ----------------------------------------------------------------------------
call_address_code32_sse:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	stmxcsr dword ptr [esp]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_sse

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	ldmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmm7, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmm6, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmm5, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmm4, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmm3, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmm2, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmm1, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmm0, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_sse:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	stmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_sse
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_sse
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_sse
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [esp]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_sse:
	ldmxcsr dword ptr [esp]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_sse:
	ud2

; ----------------------------------------------------------------------------
; Common state: sse_fpu
; ----------------------------------------------------------------------------

call_address_code32_sse_end:

; ----------------------------------------------------------------------------
; CallAddressCode32SSEFPU: source=sse_fpu, tier=sse, fpu=true
; ----------------------------------------------------------------------------
call_address_code32_sse_fpu:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	stmxcsr dword ptr [esp]
	fnstcw word ptr [esp + 4]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_sse_fpu

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	frstor [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmm7, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	movups xmm6, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmm5, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmm4, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmm3, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmm2, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmm1, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmm0, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_sse_fpu:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	stmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	movups xmmword ptr [edx + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	fsave [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_sse_fpu
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_sse_fpu
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_sse_fpu
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [esp]
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_sse_fpu:
	ldmxcsr dword ptr [esp]
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_sse_fpu:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (EDX = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code32_sse_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode32AVX: source=sse, tier=avx, fpu=false
; ----------------------------------------------------------------------------
call_address_code32_avx:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	stmxcsr dword ptr [esp]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_avx

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	ldmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm7, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm7, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_avx:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	stmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_avx
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_avx
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_avx
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [esp]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_avx:
	ldmxcsr dword ptr [esp]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_avx:
	ud2

; ----------------------------------------------------------------------------
; Common state: sse_fpu
; ----------------------------------------------------------------------------

call_address_code32_avx_end:

; ----------------------------------------------------------------------------
; CallAddressCode32AVXFPU: source=sse_fpu, tier=avx, fpu=true
; ----------------------------------------------------------------------------
call_address_code32_avx_fpu:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	stmxcsr dword ptr [esp]
	fnstcw word ptr [esp + 4]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_avx_fpu

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	frstor [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm7, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm7, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_avx_fpu:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	stmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	fsave [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_avx_fpu
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_avx_fpu
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_avx_fpu
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [esp]
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_avx_fpu:
	ldmxcsr dword ptr [esp]
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_avx_fpu:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (EDX = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code32_avx_fpu_end:

; ----------------------------------------------------------------------------
; CallAddressCode32AVX512: source=sse, tier=avx512, fpu=false
; ----------------------------------------------------------------------------
call_address_code32_avx512:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	stmxcsr dword ptr [esp]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_avx512

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	ldmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm7, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm7, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups zmm7, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmm6, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmm5, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmm4, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmm3, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmm2, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmm1, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmm0, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_avx512:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	stmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm0 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm1 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm2 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm3 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm4 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm5 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm6 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm7 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_avx512
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_avx512
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_avx512
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [esp]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_avx512:
	ldmxcsr dword ptr [esp]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_avx512:
	ud2

; ----------------------------------------------------------------------------
; Common state: sse_fpu
; ----------------------------------------------------------------------------

call_address_code32_avx512_end:

; ----------------------------------------------------------------------------
; CallAddressCode32AVX512FPU: source=sse_fpu, tier=avx512, fpu=true
; ----------------------------------------------------------------------------
call_address_code32_avx512_fpu:
	push ebp
	push ebx
	push esi
	push edi
	sub esp, 0x10
	stmxcsr dword ptr [esp]
	fnstcw word ptr [esp + 4]
	mov esi, dword ptr [esp + 0x24]
	mov edi, esp

	mov ebx, esp
	and esp, -16
	sub esp, 8
	push edi
	push esi
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(PrepareRawCall))
	call eax
	mov esp, ebx
	test al, al
	je call_address_failure32_avx512_fpu

	mov edx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	mov eax, dword ptr [esi + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pAddress)
	mov dword ptr [ecx], eax

	frstor [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)
	ldmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmm7, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups xmm6, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmm5, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmm4, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmm3, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmm2, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmm1, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmm0, xmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups ymm7, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups ymm6, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymm5, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymm4, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymm3, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymm2, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymm1, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymm0, ymmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups zmm7, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	vmovups zmm6, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmm5, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmm4, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmm3, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmm2, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmm1, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmm0, zmmword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)

	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [ecx - 4], eax
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [ecx - 8], eax

	push dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)
	popfd

	mov edi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov esi, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov ebp, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov ebx, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	mov eax, dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)

	mov esp, ecx
	mov ecx, dword ptr [esp - 4]
	mov edx, dword ptr [esp - 8]
	lea esp, [esp + 4]
	call dword ptr [esp - 4]

call_address_gate32_avx512_fpu:
	pushfd
	cld
	sub esp, 0x7FFFFFFF ; PATCH: sizeof(RAW_CONTEXT)

	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEAX)
	mov dword ptr [esp + 0x7FFFFFFF], ecx ; PATCH: offsetof(RAW_CONTEXT, m_unECX)
	mov dword ptr [esp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CONTEXT, m_unEDX)
	mov dword ptr [esp + 0x7FFFFFFF], ebx ; PATCH: offsetof(RAW_CONTEXT, m_unEBX)
	lea eax, [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT) + sizeof(void*)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unESP)
	mov dword ptr [esp + 0x7FFFFFFF], ebp ; PATCH: offsetof(RAW_CONTEXT, m_unEBP)
	mov dword ptr [esp + 0x7FFFFFFF], esi ; PATCH: offsetof(RAW_CONTEXT, m_unESI)
	mov dword ptr [esp + 0x7FFFFFFF], edi ; PATCH: offsetof(RAW_CONTEXT, m_unEDI)
	mov eax, dword ptr [esp + 0x7FFFFFFF] ; PATCH: sizeof(RAW_CONTEXT)
	mov dword ptr [esp + 0x7FFFFFFF], eax ; PATCH: offsetof(RAW_CONTEXT, m_unEFLAGS)

	mov esi, esp
	mov edx, esi
	stmxcsr dword ptr [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_unMXCSR)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm0 ; PATCH: offsetof(RAW_CONTEXT, m_XMM0)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm1 ; PATCH: offsetof(RAW_CONTEXT, m_XMM1)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm2 ; PATCH: offsetof(RAW_CONTEXT, m_XMM2)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm3 ; PATCH: offsetof(RAW_CONTEXT, m_XMM3)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm4 ; PATCH: offsetof(RAW_CONTEXT, m_XMM4)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm5 ; PATCH: offsetof(RAW_CONTEXT, m_XMM5)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm6 ; PATCH: offsetof(RAW_CONTEXT, m_XMM6)
	vmovups xmmword ptr [edx + 0x7FFFFFFF], xmm7 ; PATCH: offsetof(RAW_CONTEXT, m_XMM7)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm0 ; PATCH: offsetof(RAW_CONTEXT, m_YMM0)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm1 ; PATCH: offsetof(RAW_CONTEXT, m_YMM1)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm2 ; PATCH: offsetof(RAW_CONTEXT, m_YMM2)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm3 ; PATCH: offsetof(RAW_CONTEXT, m_YMM3)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm4 ; PATCH: offsetof(RAW_CONTEXT, m_YMM4)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm5 ; PATCH: offsetof(RAW_CONTEXT, m_YMM5)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm6 ; PATCH: offsetof(RAW_CONTEXT, m_YMM6)
	vmovups ymmword ptr [edx + 0x7FFFFFFF], ymm7 ; PATCH: offsetof(RAW_CONTEXT, m_YMM7)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm0 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM0)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm1 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM1)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm2 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM2)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm3 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM3)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm4 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM4)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm5 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM5)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm6 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM6)
	vmovups zmmword ptr [edx + 0x7FFFFFFF], zmm7 ; PATCH: offsetof(RAW_CONTEXT, m_ZMM7)
	fsave [edx + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CONTEXT, m_FPU)

	mov ebx, esp
	and esp, -16
	mov eax, 0x7FFFFFFF ; PATCH: static_cast<unsigned int>(reinterpret_cast<size_t>(GetRawCallFrameFromStack))
	call eax
	mov esp, ebx
	test eax, eax
	je call_address_fatal32_avx512_fpu
	mov ebp, eax

	mov esi, esi
	lea edi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add edx, 4
	cmp eax, edx
	jb call_address_fatal32_avx512_fpu
	sub eax, edx
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	cmp eax, ecx
	ja call_address_fatal32_avx512_fpu
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edx, eax
	mov dword ptr [ebp + 0x7FFFFFFF], edx ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)

	mov esi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pTargetStackAddress)
	add esi, 4
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	add edi, 4
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unStackCopySize)
	sub ecx, 4
	rep movsb

	mov eax, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext) + offsetof(RAW_CONTEXT, m_unESP)
	mov edx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pOriginalStackAddress)
	sub eax, edx
	mov ecx, dword ptr [edx]
	mov dword ptr [edx + eax], ecx

	lea esi, [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_ResultContext)
	mov edi, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pContext)
	mov ecx, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_unContextCopySize)
	mov edx, ecx
	shr ecx, 2
	rep movsd
	mov ecx, edx
	and ecx, 3
	rep movsb

	mov esp, dword ptr [ebp + 0x7FFFFFFF] ; PATCH: offsetof(RAW_CALL_FRAME, m_pHostStackAddress)
	ldmxcsr dword ptr [esp]
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_failure32_avx512_fpu:
	ldmxcsr dword ptr [esp]
	fldcw word ptr [esp + 4]
	add esp, 0x10
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret

call_address_fatal32_avx512_fpu:
	ud2

; ----------------------------------------------------------------------------
; Restore SSE fragment (EDX = PRAW_CONTEXT)
; ----------------------------------------------------------------------------

call_address_code32_avx512_fpu_end:
