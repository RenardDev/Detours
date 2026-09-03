.code
	DetoursWindowsTwoArgumentNativeSystemCall proc
		mov r10, rcx
		mov eax, r8d
		test byte ptr [07FFE0308h], 1
		jne TwoArgumentInt2E
		syscall
		ret

	TwoArgumentInt2E:
		int 2Eh
		ret
	DetoursWindowsTwoArgumentNativeSystemCall endp

	DetoursWindowsThreeArgumentNativeSystemCall proc
		mov r10, rcx
		mov eax, r9d
		test byte ptr [07FFE0308h], 1
		jne ThreeArgumentInt2E
		syscall
		ret

	ThreeArgumentInt2E:
		int 2Eh
		ret
	DetoursWindowsThreeArgumentNativeSystemCall endp

	DetoursWindowsFiveArgumentNativeSystemCall proc
		mov r10, rcx
		mov eax, dword ptr [rsp+30h]
		test byte ptr [07FFE0308h], 1
		jne FiveArgumentInt2E
		syscall
		ret

	FiveArgumentInt2E:
		int 2Eh
		ret
	DetoursWindowsFiveArgumentNativeSystemCall endp

	DetoursWindowsQueryThreadNativeSystemCall proc
		mov r10, rcx
		mov eax, dword ptr [rsp+30h]
		test byte ptr [07FFE0308h], 1
		jne QueryThreadInt2E
		syscall
		ret

	QueryThreadInt2E:
		int 2Eh
		ret
	DetoursWindowsQueryThreadNativeSystemCall endp

	DetoursWindowsReadVirtualMemoryNativeSystemCall proc
		mov r10, rcx
		mov eax, dword ptr [rsp+30h]
		test byte ptr [07FFE0308h], 1
		jne ReadVirtualMemoryInt2E
		syscall
		ret

	ReadVirtualMemoryInt2E:
		int 2Eh
		ret
	DetoursWindowsReadVirtualMemoryNativeSystemCall endp

	DetoursWindowsSixArgumentNativeSystemCall proc
		mov r10, rcx
		mov eax, dword ptr [rsp+38h]
		test byte ptr [07FFE0308h], 1
		jne SixArgumentInt2E
		syscall
		ret

	SixArgumentInt2E:
		int 2Eh
		ret
	DetoursWindowsSixArgumentNativeSystemCall endp

	DetoursWindowsQueryVirtualMemoryNativeSystemCall proc
		mov r10, rcx
		mov eax, dword ptr [rsp+38h]
		test byte ptr [07FFE0308h], 1
		jne QueryVirtualMemoryInt2E
		syscall
		ret

	QueryVirtualMemoryInt2E:
		int 2Eh
		ret
	DetoursWindowsQueryVirtualMemoryNativeSystemCall endp
end
