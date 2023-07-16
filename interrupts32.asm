.686
.model flat, C

.stack

.data

.code
	CallInterrupt proc
		push eax
		push ecx
		push edx
		push ebx
		; push esp
		push ebp
		push esi
		push edi

		add esp, 1Ch
		add esp, 04h

		mov eax, dword ptr [esp+00h]
		mov ecx, dword ptr [esp+04h]
		mov edx, dword ptr [esp+08h]
		mov ebx, dword ptr [esp+0Ch]
		mov ebp, dword ptr [esp+10h]
		mov esi, dword ptr [esp+14h]
		mov edi, dword ptr [esp+18h]

		sub esp, 04h
		sub esp, 1Ch

		int 7Eh

		pop edi
		pop esi
		pop ebp
		; pop esp
		pop ebx
		pop edx
		pop ecx
		pop eax
		ret
	CallInterrupt endp
end
