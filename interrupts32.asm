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
		push ebp
		push esi
		push edi

		mov eax, dword ptr [esp+1Ch+04h]
		mov ecx, dword ptr [esp+1Ch+08h]
		mov edx, dword ptr [esp+1Ch+0Ch]
		mov ebx, dword ptr [esp+1Ch+10h]
		mov ebp, dword ptr [esp+1Ch+14h]
		mov esi, dword ptr [esp+1Ch+18h]
		mov edi, dword ptr [esp+1Ch+1Ch]

		int 7Eh

		pop edi
		pop esi
		pop ebp
		pop ebx
		pop edx
		pop ecx
		pop eax
		ret
	CallInterrupt endp
end
