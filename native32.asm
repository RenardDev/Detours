.686
.model flat, C

.code
	DetoursWindowsTwoArgumentNativeSystemCall proc
		mov eax, dword ptr [esp+0Ch]
		mov edx, dword ptr [esp+10h]
		call edx
		ret
	DetoursWindowsTwoArgumentNativeSystemCall endp

	DetoursWindowsThreeArgumentNativeSystemCall proc
		mov eax, dword ptr [esp+10h]
		mov edx, dword ptr [esp+14h]
		call edx
		ret
	DetoursWindowsThreeArgumentNativeSystemCall endp

	DetoursWindowsFiveArgumentNativeSystemCall proc
		mov eax, dword ptr [esp+18h]
		mov edx, dword ptr [esp+1Ch]
		call edx
		ret
	DetoursWindowsFiveArgumentNativeSystemCall endp

	DetoursWindowsQueryThreadNativeSystemCall proc
		mov eax, dword ptr [esp+18h]
		mov edx, dword ptr [esp+1Ch]
		call edx
		ret
	DetoursWindowsQueryThreadNativeSystemCall endp

	DetoursWindowsReadVirtualMemoryNativeSystemCall proc
		mov eax, dword ptr [esp+18h]
		mov edx, dword ptr [esp+1Ch]
		call edx
		ret
	DetoursWindowsReadVirtualMemoryNativeSystemCall endp

	DetoursWindowsSixArgumentNativeSystemCall proc
		mov eax, dword ptr [esp+1Ch]
		mov edx, dword ptr [esp+20h]
		call edx
		ret
	DetoursWindowsSixArgumentNativeSystemCall endp

	DetoursWindowsQueryVirtualMemoryNativeSystemCall proc
		mov eax, dword ptr [esp+1Ch]
		mov edx, dword ptr [esp+20h]
		call edx
		ret
	DetoursWindowsQueryVirtualMemoryNativeSystemCall endp
end
