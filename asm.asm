# Generated source templates for RawHook and GetCurrentContext machine code.
# Every variant is cumulative: AVX-512 includes AVX/YMM, SSE/XMM and native state.
# FPU and non-FPU variants are emitted independently.

# RawHook wrapper: x86 AVX512FPU
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x86_cdecl_avx512fpu
raw_hook_wrapper_x86_cdecl_avx512fpu:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_0
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_0_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_0_end:
	pushfd
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_1
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_1:
	pop dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_1_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_1_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_2
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_2_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_2_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_3
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_3:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_3_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_3_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_4
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_4:
	mov dword ptr [esp + 0x7fffffff], edx
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_4_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_4_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_5
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_5:
	mov dword ptr [esp + 0x7fffffff], ebx
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_5_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_5_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_6
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_6:
	mov dword ptr [esp + 0x7fffffff], esp
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_6_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_6_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_7
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_7:
	add dword ptr [esp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_7_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_8
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_8:
	mov dword ptr [esp + 0x7fffffff], ebp
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_8_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_9
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_9:
	mov dword ptr [esp + 0x7fffffff], esi
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_9_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_9_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_10
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_10:
	mov dword ptr [esp + 0x7fffffff], edi
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_10_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_10_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_11
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_11:
	stmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_11_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_12
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_12:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_12_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_13
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_13:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_13_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_14
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_14:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_14_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_14_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_15
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_15:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_15_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_15_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_16
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_16:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_16_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_16_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_17
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_17:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_17_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_17_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_18
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_18:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_18_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_18_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_19
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_19:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_19_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_19_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_20
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_20:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_20_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_20_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_21
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_21:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_21_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_21_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_22
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_22:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_22_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_22_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_23
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_23:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_23_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_23_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_24
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_24:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_24_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_24_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_25
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_25:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_25_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_25_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_26
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_26:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_26_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_26_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_27
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_27:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_27_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_27_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_28
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_28:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm0
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_28_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_28_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_29
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_29:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm1
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_29_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_29_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_30
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_30:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm2
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_30_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_30_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_31
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_31:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm3
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_31_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_31_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_32
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_32:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm4
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_32_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_32_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_33
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_33:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm5
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_33_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_33_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_34
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_34:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm6
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_34_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_34_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_35
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_35:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm7
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_35_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_35_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_36
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_36:
	fsave [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_36_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_36_end:
	mov eax, esp
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_0
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_0:
	add eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_0_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_0_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_1
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_1:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_1_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_1_end:
	mov eax, dword ptr [eax]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_2
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_2_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_2_end:
	mov eax, esp
	push eax
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_37
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_37:
	mov eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_37_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_37_end:
	call eax
	add esp, 0x4
	test al, al
	je raw_hook_wrapper_x86_cdecl_avx512fpu_nothing_modified
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_38
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_38:
	frstor [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_38_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_38_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_39
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_39:
	vmovups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_39_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_39_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_40
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_40:
	vmovups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_40_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_40_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_41
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_41:
	vmovups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_41_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_41_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_42
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_42:
	vmovups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_42_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_42_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_43
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_43:
	vmovups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_43_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_43_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_44
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_44:
	vmovups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_44_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_44_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_45
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_45:
	vmovups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_45_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_45_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_46
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_46:
	vmovups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_46_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_46_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_47
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_47:
	vmovups ymm0, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_47_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_47_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_48
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_48:
	vmovups ymm1, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_48_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_48_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_49
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_49:
	vmovups ymm2, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_49_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_49_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_50
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_50:
	vmovups ymm3, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_50_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_50_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_51
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_51:
	vmovups ymm4, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_51_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_51_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_52
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_52:
	vmovups ymm5, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_52_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_52_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_53
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_53:
	vmovups ymm6, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_53_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_53_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_54
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_54:
	vmovups ymm7, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_54_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_54_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_55
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_55:
	vmovups zmm0, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_55_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_55_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_56
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_56:
	vmovups zmm1, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_56_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_56_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_57
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_57:
	vmovups zmm2, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_57_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_57_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_58
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_58:
	vmovups zmm3, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_58_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_58_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_59
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_59:
	vmovups zmm4, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_59_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_59_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_60
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_60:
	vmovups zmm5, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_60_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_60_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_61
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_61:
	vmovups zmm6, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_61_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_61_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_62
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_62:
	vmovups zmm7, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_62_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_62_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_63
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_63:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_63_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_63_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_65
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_65:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_65_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_65_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_66
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_66:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_66_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_66_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_67
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_67:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_67_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_67_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_68
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_68:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_68_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_68_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_3
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_3:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_3_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_3_end:
	test eax, 0x3
	jne raw_hook_wrapper_x86_cdecl_avx512fpu_unsupported_stack
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_4
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_4:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_4_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_4_end:
	cmp eax, ecx
	ja raw_hook_wrapper_x86_cdecl_avx512fpu_unsupported_stack
	lea edx, [eax + 0x4]
	cmp edx, ecx
	jb raw_hook_wrapper_x86_cdecl_avx512fpu_unsupported_stack
	nop
	nop
	nop
	nop
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_6
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_6:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_6_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_6_end:
	cmp dword ptr [ecx], edx
	jne raw_hook_wrapper_x86_cdecl_avx512fpu_unsupported_stack
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_avx512fpu_direct_return
	lea eax, [eax + 0x4]
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_avx512fpu_redirect_return
raw_hook_wrapper_x86_cdecl_avx512fpu_unsupported_stack:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_7
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_7:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_7_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_8
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_8:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_8_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_9
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_9_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_9_end:
	mov dword ptr [ecx], edx
raw_hook_wrapper_x86_cdecl_avx512fpu_direct_return:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_64
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_64:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_64_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_64_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_69
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_69:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_69_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_69_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_70
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_70:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_70_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_70_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_71
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_71:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_71_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_71_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_72
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_72:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_72_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_72_end:
	ret
raw_hook_wrapper_x86_cdecl_avx512fpu_redirect_return:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_10
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_10:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_10_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_10_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_11
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_11:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_11_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_12
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_12:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_12_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_13
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_13:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_13_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_14
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_14:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_14_end
raw_hook_wrapper_x86_cdecl_avx512fpu_cet_patch_14_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]
raw_hook_wrapper_x86_cdecl_avx512fpu_nothing_modified:
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_73
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_73:
	add esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512fpu_patch_73_end
raw_hook_wrapper_x86_cdecl_avx512fpu_patch_73_end:

# RawHook wrapper: x86 AVX512
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x86_cdecl_avx512
raw_hook_wrapper_x86_cdecl_avx512:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_0
raw_hook_wrapper_x86_cdecl_avx512_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_0_end
raw_hook_wrapper_x86_cdecl_avx512_patch_0_end:
	pushfd
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_1
raw_hook_wrapper_x86_cdecl_avx512_patch_1:
	pop dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_1_end
raw_hook_wrapper_x86_cdecl_avx512_patch_1_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_2
raw_hook_wrapper_x86_cdecl_avx512_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_2_end
raw_hook_wrapper_x86_cdecl_avx512_patch_2_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_3
raw_hook_wrapper_x86_cdecl_avx512_patch_3:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_3_end
raw_hook_wrapper_x86_cdecl_avx512_patch_3_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_4
raw_hook_wrapper_x86_cdecl_avx512_patch_4:
	mov dword ptr [esp + 0x7fffffff], edx
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_4_end
raw_hook_wrapper_x86_cdecl_avx512_patch_4_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_5
raw_hook_wrapper_x86_cdecl_avx512_patch_5:
	mov dword ptr [esp + 0x7fffffff], ebx
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_5_end
raw_hook_wrapper_x86_cdecl_avx512_patch_5_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_6
raw_hook_wrapper_x86_cdecl_avx512_patch_6:
	mov dword ptr [esp + 0x7fffffff], esp
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_6_end
raw_hook_wrapper_x86_cdecl_avx512_patch_6_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_7
raw_hook_wrapper_x86_cdecl_avx512_patch_7:
	add dword ptr [esp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_7_end
raw_hook_wrapper_x86_cdecl_avx512_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_8
raw_hook_wrapper_x86_cdecl_avx512_patch_8:
	mov dword ptr [esp + 0x7fffffff], ebp
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_8_end
raw_hook_wrapper_x86_cdecl_avx512_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_9
raw_hook_wrapper_x86_cdecl_avx512_patch_9:
	mov dword ptr [esp + 0x7fffffff], esi
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_9_end
raw_hook_wrapper_x86_cdecl_avx512_patch_9_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_10
raw_hook_wrapper_x86_cdecl_avx512_patch_10:
	mov dword ptr [esp + 0x7fffffff], edi
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_10_end
raw_hook_wrapper_x86_cdecl_avx512_patch_10_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_11
raw_hook_wrapper_x86_cdecl_avx512_patch_11:
	stmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_11_end
raw_hook_wrapper_x86_cdecl_avx512_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_12
raw_hook_wrapper_x86_cdecl_avx512_patch_12:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_12_end
raw_hook_wrapper_x86_cdecl_avx512_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_13
raw_hook_wrapper_x86_cdecl_avx512_patch_13:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_13_end
raw_hook_wrapper_x86_cdecl_avx512_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_14
raw_hook_wrapper_x86_cdecl_avx512_patch_14:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_14_end
raw_hook_wrapper_x86_cdecl_avx512_patch_14_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_15
raw_hook_wrapper_x86_cdecl_avx512_patch_15:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_15_end
raw_hook_wrapper_x86_cdecl_avx512_patch_15_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_16
raw_hook_wrapper_x86_cdecl_avx512_patch_16:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_16_end
raw_hook_wrapper_x86_cdecl_avx512_patch_16_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_17
raw_hook_wrapper_x86_cdecl_avx512_patch_17:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_17_end
raw_hook_wrapper_x86_cdecl_avx512_patch_17_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_18
raw_hook_wrapper_x86_cdecl_avx512_patch_18:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_18_end
raw_hook_wrapper_x86_cdecl_avx512_patch_18_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_19
raw_hook_wrapper_x86_cdecl_avx512_patch_19:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_19_end
raw_hook_wrapper_x86_cdecl_avx512_patch_19_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_20
raw_hook_wrapper_x86_cdecl_avx512_patch_20:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_20_end
raw_hook_wrapper_x86_cdecl_avx512_patch_20_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_21
raw_hook_wrapper_x86_cdecl_avx512_patch_21:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_21_end
raw_hook_wrapper_x86_cdecl_avx512_patch_21_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_22
raw_hook_wrapper_x86_cdecl_avx512_patch_22:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_22_end
raw_hook_wrapper_x86_cdecl_avx512_patch_22_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_23
raw_hook_wrapper_x86_cdecl_avx512_patch_23:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_23_end
raw_hook_wrapper_x86_cdecl_avx512_patch_23_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_24
raw_hook_wrapper_x86_cdecl_avx512_patch_24:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_24_end
raw_hook_wrapper_x86_cdecl_avx512_patch_24_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_25
raw_hook_wrapper_x86_cdecl_avx512_patch_25:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_25_end
raw_hook_wrapper_x86_cdecl_avx512_patch_25_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_26
raw_hook_wrapper_x86_cdecl_avx512_patch_26:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_26_end
raw_hook_wrapper_x86_cdecl_avx512_patch_26_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_27
raw_hook_wrapper_x86_cdecl_avx512_patch_27:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_27_end
raw_hook_wrapper_x86_cdecl_avx512_patch_27_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_28
raw_hook_wrapper_x86_cdecl_avx512_patch_28:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm0
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_28_end
raw_hook_wrapper_x86_cdecl_avx512_patch_28_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_29
raw_hook_wrapper_x86_cdecl_avx512_patch_29:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm1
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_29_end
raw_hook_wrapper_x86_cdecl_avx512_patch_29_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_30
raw_hook_wrapper_x86_cdecl_avx512_patch_30:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm2
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_30_end
raw_hook_wrapper_x86_cdecl_avx512_patch_30_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_31
raw_hook_wrapper_x86_cdecl_avx512_patch_31:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm3
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_31_end
raw_hook_wrapper_x86_cdecl_avx512_patch_31_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_32
raw_hook_wrapper_x86_cdecl_avx512_patch_32:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm4
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_32_end
raw_hook_wrapper_x86_cdecl_avx512_patch_32_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_33
raw_hook_wrapper_x86_cdecl_avx512_patch_33:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm5
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_33_end
raw_hook_wrapper_x86_cdecl_avx512_patch_33_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_34
raw_hook_wrapper_x86_cdecl_avx512_patch_34:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm6
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_34_end
raw_hook_wrapper_x86_cdecl_avx512_patch_34_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_35
raw_hook_wrapper_x86_cdecl_avx512_patch_35:
	vmovups zmmword ptr [esp + 0x7fffffff], zmm7
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_35_end
raw_hook_wrapper_x86_cdecl_avx512_patch_35_end:
	mov eax, esp
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_0
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_0:
	add eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_0_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_0_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_1
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_1:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_1_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_1_end:
	mov eax, dword ptr [eax]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_2
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_2_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_2_end:
	mov eax, esp
	push eax
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_36
raw_hook_wrapper_x86_cdecl_avx512_patch_36:
	mov eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_36_end
raw_hook_wrapper_x86_cdecl_avx512_patch_36_end:
	call eax
	add esp, 0x4
	test al, al
	je raw_hook_wrapper_x86_cdecl_avx512_nothing_modified
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_37
raw_hook_wrapper_x86_cdecl_avx512_patch_37:
	vmovups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_37_end
raw_hook_wrapper_x86_cdecl_avx512_patch_37_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_38
raw_hook_wrapper_x86_cdecl_avx512_patch_38:
	vmovups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_38_end
raw_hook_wrapper_x86_cdecl_avx512_patch_38_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_39
raw_hook_wrapper_x86_cdecl_avx512_patch_39:
	vmovups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_39_end
raw_hook_wrapper_x86_cdecl_avx512_patch_39_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_40
raw_hook_wrapper_x86_cdecl_avx512_patch_40:
	vmovups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_40_end
raw_hook_wrapper_x86_cdecl_avx512_patch_40_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_41
raw_hook_wrapper_x86_cdecl_avx512_patch_41:
	vmovups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_41_end
raw_hook_wrapper_x86_cdecl_avx512_patch_41_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_42
raw_hook_wrapper_x86_cdecl_avx512_patch_42:
	vmovups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_42_end
raw_hook_wrapper_x86_cdecl_avx512_patch_42_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_43
raw_hook_wrapper_x86_cdecl_avx512_patch_43:
	vmovups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_43_end
raw_hook_wrapper_x86_cdecl_avx512_patch_43_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_44
raw_hook_wrapper_x86_cdecl_avx512_patch_44:
	vmovups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_44_end
raw_hook_wrapper_x86_cdecl_avx512_patch_44_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_45
raw_hook_wrapper_x86_cdecl_avx512_patch_45:
	vmovups ymm0, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_45_end
raw_hook_wrapper_x86_cdecl_avx512_patch_45_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_46
raw_hook_wrapper_x86_cdecl_avx512_patch_46:
	vmovups ymm1, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_46_end
raw_hook_wrapper_x86_cdecl_avx512_patch_46_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_47
raw_hook_wrapper_x86_cdecl_avx512_patch_47:
	vmovups ymm2, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_47_end
raw_hook_wrapper_x86_cdecl_avx512_patch_47_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_48
raw_hook_wrapper_x86_cdecl_avx512_patch_48:
	vmovups ymm3, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_48_end
raw_hook_wrapper_x86_cdecl_avx512_patch_48_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_49
raw_hook_wrapper_x86_cdecl_avx512_patch_49:
	vmovups ymm4, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_49_end
raw_hook_wrapper_x86_cdecl_avx512_patch_49_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_50
raw_hook_wrapper_x86_cdecl_avx512_patch_50:
	vmovups ymm5, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_50_end
raw_hook_wrapper_x86_cdecl_avx512_patch_50_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_51
raw_hook_wrapper_x86_cdecl_avx512_patch_51:
	vmovups ymm6, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_51_end
raw_hook_wrapper_x86_cdecl_avx512_patch_51_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_52
raw_hook_wrapper_x86_cdecl_avx512_patch_52:
	vmovups ymm7, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_52_end
raw_hook_wrapper_x86_cdecl_avx512_patch_52_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_53
raw_hook_wrapper_x86_cdecl_avx512_patch_53:
	vmovups zmm0, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_53_end
raw_hook_wrapper_x86_cdecl_avx512_patch_53_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_54
raw_hook_wrapper_x86_cdecl_avx512_patch_54:
	vmovups zmm1, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_54_end
raw_hook_wrapper_x86_cdecl_avx512_patch_54_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_55
raw_hook_wrapper_x86_cdecl_avx512_patch_55:
	vmovups zmm2, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_55_end
raw_hook_wrapper_x86_cdecl_avx512_patch_55_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_56
raw_hook_wrapper_x86_cdecl_avx512_patch_56:
	vmovups zmm3, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_56_end
raw_hook_wrapper_x86_cdecl_avx512_patch_56_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_57
raw_hook_wrapper_x86_cdecl_avx512_patch_57:
	vmovups zmm4, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_57_end
raw_hook_wrapper_x86_cdecl_avx512_patch_57_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_58
raw_hook_wrapper_x86_cdecl_avx512_patch_58:
	vmovups zmm5, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_58_end
raw_hook_wrapper_x86_cdecl_avx512_patch_58_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_59
raw_hook_wrapper_x86_cdecl_avx512_patch_59:
	vmovups zmm6, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_59_end
raw_hook_wrapper_x86_cdecl_avx512_patch_59_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_60
raw_hook_wrapper_x86_cdecl_avx512_patch_60:
	vmovups zmm7, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_60_end
raw_hook_wrapper_x86_cdecl_avx512_patch_60_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_61
raw_hook_wrapper_x86_cdecl_avx512_patch_61:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_61_end
raw_hook_wrapper_x86_cdecl_avx512_patch_61_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_63
raw_hook_wrapper_x86_cdecl_avx512_patch_63:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_63_end
raw_hook_wrapper_x86_cdecl_avx512_patch_63_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_64
raw_hook_wrapper_x86_cdecl_avx512_patch_64:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_64_end
raw_hook_wrapper_x86_cdecl_avx512_patch_64_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_65
raw_hook_wrapper_x86_cdecl_avx512_patch_65:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_65_end
raw_hook_wrapper_x86_cdecl_avx512_patch_65_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_66
raw_hook_wrapper_x86_cdecl_avx512_patch_66:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_66_end
raw_hook_wrapper_x86_cdecl_avx512_patch_66_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_3
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_3:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_3_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_3_end:
	test eax, 0x3
	jne raw_hook_wrapper_x86_cdecl_avx512_unsupported_stack
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_4
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_4:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_4_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_4_end:
	cmp eax, ecx
	ja raw_hook_wrapper_x86_cdecl_avx512_unsupported_stack
	lea edx, [eax + 0x4]
	cmp edx, ecx
	jb raw_hook_wrapper_x86_cdecl_avx512_unsupported_stack
	nop
	nop
	nop
	nop
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_6
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_6:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_6_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_6_end:
	cmp dword ptr [ecx], edx
	jne raw_hook_wrapper_x86_cdecl_avx512_unsupported_stack
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_avx512_direct_return
	lea eax, [eax + 0x4]
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_avx512_redirect_return
raw_hook_wrapper_x86_cdecl_avx512_unsupported_stack:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_7
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_7:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_7_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_8
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_8:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_8_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_9
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_9_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_9_end:
	mov dword ptr [ecx], edx
raw_hook_wrapper_x86_cdecl_avx512_direct_return:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_62
raw_hook_wrapper_x86_cdecl_avx512_patch_62:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_62_end
raw_hook_wrapper_x86_cdecl_avx512_patch_62_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_67
raw_hook_wrapper_x86_cdecl_avx512_patch_67:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_67_end
raw_hook_wrapper_x86_cdecl_avx512_patch_67_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_68
raw_hook_wrapper_x86_cdecl_avx512_patch_68:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_68_end
raw_hook_wrapper_x86_cdecl_avx512_patch_68_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_69
raw_hook_wrapper_x86_cdecl_avx512_patch_69:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_69_end
raw_hook_wrapper_x86_cdecl_avx512_patch_69_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_70
raw_hook_wrapper_x86_cdecl_avx512_patch_70:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_70_end
raw_hook_wrapper_x86_cdecl_avx512_patch_70_end:
	ret
raw_hook_wrapper_x86_cdecl_avx512_redirect_return:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_10
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_10:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_10_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_10_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_11
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_11:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_11_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_12
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_12:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_12_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_13
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_13:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_13_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_14
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_14:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx512_cet_patch_14_end
raw_hook_wrapper_x86_cdecl_avx512_cet_patch_14_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]
raw_hook_wrapper_x86_cdecl_avx512_nothing_modified:
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_71
raw_hook_wrapper_x86_cdecl_avx512_patch_71:
	add esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx512_patch_71_end
raw_hook_wrapper_x86_cdecl_avx512_patch_71_end:

# RawHook wrapper: x86 AVXFPU
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x86_cdecl_avxfpu
raw_hook_wrapper_x86_cdecl_avxfpu:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_0
raw_hook_wrapper_x86_cdecl_avxfpu_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_0_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_0_end:
	pushfd
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_1
raw_hook_wrapper_x86_cdecl_avxfpu_patch_1:
	pop dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_1_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_1_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_2
raw_hook_wrapper_x86_cdecl_avxfpu_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_2_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_2_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_3
raw_hook_wrapper_x86_cdecl_avxfpu_patch_3:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_3_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_3_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_4
raw_hook_wrapper_x86_cdecl_avxfpu_patch_4:
	mov dword ptr [esp + 0x7fffffff], edx
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_4_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_4_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_5
raw_hook_wrapper_x86_cdecl_avxfpu_patch_5:
	mov dword ptr [esp + 0x7fffffff], ebx
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_5_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_5_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_6
raw_hook_wrapper_x86_cdecl_avxfpu_patch_6:
	mov dword ptr [esp + 0x7fffffff], esp
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_6_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_6_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_7
raw_hook_wrapper_x86_cdecl_avxfpu_patch_7:
	add dword ptr [esp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_7_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_8
raw_hook_wrapper_x86_cdecl_avxfpu_patch_8:
	mov dword ptr [esp + 0x7fffffff], ebp
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_8_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_9
raw_hook_wrapper_x86_cdecl_avxfpu_patch_9:
	mov dword ptr [esp + 0x7fffffff], esi
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_9_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_9_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_10
raw_hook_wrapper_x86_cdecl_avxfpu_patch_10:
	mov dword ptr [esp + 0x7fffffff], edi
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_10_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_10_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_11
raw_hook_wrapper_x86_cdecl_avxfpu_patch_11:
	stmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_11_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_12
raw_hook_wrapper_x86_cdecl_avxfpu_patch_12:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_12_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_13
raw_hook_wrapper_x86_cdecl_avxfpu_patch_13:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_13_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_14
raw_hook_wrapper_x86_cdecl_avxfpu_patch_14:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_14_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_14_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_15
raw_hook_wrapper_x86_cdecl_avxfpu_patch_15:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_15_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_15_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_16
raw_hook_wrapper_x86_cdecl_avxfpu_patch_16:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_16_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_16_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_17
raw_hook_wrapper_x86_cdecl_avxfpu_patch_17:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_17_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_17_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_18
raw_hook_wrapper_x86_cdecl_avxfpu_patch_18:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_18_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_18_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_19
raw_hook_wrapper_x86_cdecl_avxfpu_patch_19:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_19_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_19_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_20
raw_hook_wrapper_x86_cdecl_avxfpu_patch_20:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_20_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_20_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_21
raw_hook_wrapper_x86_cdecl_avxfpu_patch_21:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_21_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_21_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_22
raw_hook_wrapper_x86_cdecl_avxfpu_patch_22:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_22_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_22_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_23
raw_hook_wrapper_x86_cdecl_avxfpu_patch_23:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_23_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_23_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_24
raw_hook_wrapper_x86_cdecl_avxfpu_patch_24:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_24_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_24_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_25
raw_hook_wrapper_x86_cdecl_avxfpu_patch_25:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_25_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_25_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_26
raw_hook_wrapper_x86_cdecl_avxfpu_patch_26:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_26_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_26_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_27
raw_hook_wrapper_x86_cdecl_avxfpu_patch_27:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_27_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_27_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_28
raw_hook_wrapper_x86_cdecl_avxfpu_patch_28:
	fsave [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_28_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_28_end:
	mov eax, esp
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_0
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_0:
	add eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_0_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_0_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_1
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_1:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_1_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_1_end:
	mov eax, dword ptr [eax]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_2
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_2_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_2_end:
	mov eax, esp
	push eax
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_29
raw_hook_wrapper_x86_cdecl_avxfpu_patch_29:
	mov eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_29_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_29_end:
	call eax
	add esp, 0x4
	test al, al
	je raw_hook_wrapper_x86_cdecl_avxfpu_nothing_modified
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_30
raw_hook_wrapper_x86_cdecl_avxfpu_patch_30:
	frstor [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_30_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_30_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_31
raw_hook_wrapper_x86_cdecl_avxfpu_patch_31:
	vmovups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_31_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_31_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_32
raw_hook_wrapper_x86_cdecl_avxfpu_patch_32:
	vmovups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_32_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_32_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_33
raw_hook_wrapper_x86_cdecl_avxfpu_patch_33:
	vmovups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_33_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_33_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_34
raw_hook_wrapper_x86_cdecl_avxfpu_patch_34:
	vmovups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_34_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_34_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_35
raw_hook_wrapper_x86_cdecl_avxfpu_patch_35:
	vmovups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_35_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_35_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_36
raw_hook_wrapper_x86_cdecl_avxfpu_patch_36:
	vmovups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_36_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_36_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_37
raw_hook_wrapper_x86_cdecl_avxfpu_patch_37:
	vmovups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_37_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_37_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_38
raw_hook_wrapper_x86_cdecl_avxfpu_patch_38:
	vmovups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_38_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_38_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_39
raw_hook_wrapper_x86_cdecl_avxfpu_patch_39:
	vmovups ymm0, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_39_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_39_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_40
raw_hook_wrapper_x86_cdecl_avxfpu_patch_40:
	vmovups ymm1, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_40_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_40_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_41
raw_hook_wrapper_x86_cdecl_avxfpu_patch_41:
	vmovups ymm2, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_41_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_41_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_42
raw_hook_wrapper_x86_cdecl_avxfpu_patch_42:
	vmovups ymm3, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_42_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_42_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_43
raw_hook_wrapper_x86_cdecl_avxfpu_patch_43:
	vmovups ymm4, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_43_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_43_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_44
raw_hook_wrapper_x86_cdecl_avxfpu_patch_44:
	vmovups ymm5, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_44_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_44_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_45
raw_hook_wrapper_x86_cdecl_avxfpu_patch_45:
	vmovups ymm6, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_45_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_45_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_46
raw_hook_wrapper_x86_cdecl_avxfpu_patch_46:
	vmovups ymm7, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_46_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_46_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_47
raw_hook_wrapper_x86_cdecl_avxfpu_patch_47:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_47_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_47_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_49
raw_hook_wrapper_x86_cdecl_avxfpu_patch_49:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_49_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_49_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_50
raw_hook_wrapper_x86_cdecl_avxfpu_patch_50:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_50_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_50_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_51
raw_hook_wrapper_x86_cdecl_avxfpu_patch_51:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_51_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_51_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_52
raw_hook_wrapper_x86_cdecl_avxfpu_patch_52:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_52_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_52_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_3
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_3:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_3_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_3_end:
	test eax, 0x3
	jne raw_hook_wrapper_x86_cdecl_avxfpu_unsupported_stack
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_4
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_4:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_4_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_4_end:
	cmp eax, ecx
	ja raw_hook_wrapper_x86_cdecl_avxfpu_unsupported_stack
	lea edx, [eax + 0x4]
	cmp edx, ecx
	jb raw_hook_wrapper_x86_cdecl_avxfpu_unsupported_stack
	nop
	nop
	nop
	nop
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_6
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_6:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_6_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_6_end:
	cmp dword ptr [ecx], edx
	jne raw_hook_wrapper_x86_cdecl_avxfpu_unsupported_stack
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_avxfpu_direct_return
	lea eax, [eax + 0x4]
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_avxfpu_redirect_return
raw_hook_wrapper_x86_cdecl_avxfpu_unsupported_stack:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_7
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_7:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_7_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_8
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_8:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_8_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_9
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_9_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_9_end:
	mov dword ptr [ecx], edx
raw_hook_wrapper_x86_cdecl_avxfpu_direct_return:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_48
raw_hook_wrapper_x86_cdecl_avxfpu_patch_48:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_48_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_48_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_53
raw_hook_wrapper_x86_cdecl_avxfpu_patch_53:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_53_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_53_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_54
raw_hook_wrapper_x86_cdecl_avxfpu_patch_54:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_54_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_54_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_55
raw_hook_wrapper_x86_cdecl_avxfpu_patch_55:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_55_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_55_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_56
raw_hook_wrapper_x86_cdecl_avxfpu_patch_56:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_56_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_56_end:
	ret
raw_hook_wrapper_x86_cdecl_avxfpu_redirect_return:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_10
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_10:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_10_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_10_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_11
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_11:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_11_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_12
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_12:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_12_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_13
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_13:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_13_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_14
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_14:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_14_end
raw_hook_wrapper_x86_cdecl_avxfpu_cet_patch_14_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]
raw_hook_wrapper_x86_cdecl_avxfpu_nothing_modified:
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_57
raw_hook_wrapper_x86_cdecl_avxfpu_patch_57:
	add esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avxfpu_patch_57_end
raw_hook_wrapper_x86_cdecl_avxfpu_patch_57_end:

# RawHook wrapper: x86 AVX
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x86_cdecl_avx
raw_hook_wrapper_x86_cdecl_avx:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_0
raw_hook_wrapper_x86_cdecl_avx_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx_patch_0_end
raw_hook_wrapper_x86_cdecl_avx_patch_0_end:
	pushfd
.globl raw_hook_wrapper_x86_cdecl_avx_patch_1
raw_hook_wrapper_x86_cdecl_avx_patch_1:
	pop dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_1_end
raw_hook_wrapper_x86_cdecl_avx_patch_1_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_2
raw_hook_wrapper_x86_cdecl_avx_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx_patch_2_end
raw_hook_wrapper_x86_cdecl_avx_patch_2_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_3
raw_hook_wrapper_x86_cdecl_avx_patch_3:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_avx_patch_3_end
raw_hook_wrapper_x86_cdecl_avx_patch_3_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_4
raw_hook_wrapper_x86_cdecl_avx_patch_4:
	mov dword ptr [esp + 0x7fffffff], edx
.globl raw_hook_wrapper_x86_cdecl_avx_patch_4_end
raw_hook_wrapper_x86_cdecl_avx_patch_4_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_5
raw_hook_wrapper_x86_cdecl_avx_patch_5:
	mov dword ptr [esp + 0x7fffffff], ebx
.globl raw_hook_wrapper_x86_cdecl_avx_patch_5_end
raw_hook_wrapper_x86_cdecl_avx_patch_5_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_6
raw_hook_wrapper_x86_cdecl_avx_patch_6:
	mov dword ptr [esp + 0x7fffffff], esp
.globl raw_hook_wrapper_x86_cdecl_avx_patch_6_end
raw_hook_wrapper_x86_cdecl_avx_patch_6_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_7
raw_hook_wrapper_x86_cdecl_avx_patch_7:
	add dword ptr [esp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx_patch_7_end
raw_hook_wrapper_x86_cdecl_avx_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_8
raw_hook_wrapper_x86_cdecl_avx_patch_8:
	mov dword ptr [esp + 0x7fffffff], ebp
.globl raw_hook_wrapper_x86_cdecl_avx_patch_8_end
raw_hook_wrapper_x86_cdecl_avx_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_9
raw_hook_wrapper_x86_cdecl_avx_patch_9:
	mov dword ptr [esp + 0x7fffffff], esi
.globl raw_hook_wrapper_x86_cdecl_avx_patch_9_end
raw_hook_wrapper_x86_cdecl_avx_patch_9_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_10
raw_hook_wrapper_x86_cdecl_avx_patch_10:
	mov dword ptr [esp + 0x7fffffff], edi
.globl raw_hook_wrapper_x86_cdecl_avx_patch_10_end
raw_hook_wrapper_x86_cdecl_avx_patch_10_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_11
raw_hook_wrapper_x86_cdecl_avx_patch_11:
	stmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_11_end
raw_hook_wrapper_x86_cdecl_avx_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_12
raw_hook_wrapper_x86_cdecl_avx_patch_12:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x86_cdecl_avx_patch_12_end
raw_hook_wrapper_x86_cdecl_avx_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_13
raw_hook_wrapper_x86_cdecl_avx_patch_13:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x86_cdecl_avx_patch_13_end
raw_hook_wrapper_x86_cdecl_avx_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_14
raw_hook_wrapper_x86_cdecl_avx_patch_14:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x86_cdecl_avx_patch_14_end
raw_hook_wrapper_x86_cdecl_avx_patch_14_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_15
raw_hook_wrapper_x86_cdecl_avx_patch_15:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x86_cdecl_avx_patch_15_end
raw_hook_wrapper_x86_cdecl_avx_patch_15_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_16
raw_hook_wrapper_x86_cdecl_avx_patch_16:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x86_cdecl_avx_patch_16_end
raw_hook_wrapper_x86_cdecl_avx_patch_16_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_17
raw_hook_wrapper_x86_cdecl_avx_patch_17:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x86_cdecl_avx_patch_17_end
raw_hook_wrapper_x86_cdecl_avx_patch_17_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_18
raw_hook_wrapper_x86_cdecl_avx_patch_18:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x86_cdecl_avx_patch_18_end
raw_hook_wrapper_x86_cdecl_avx_patch_18_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_19
raw_hook_wrapper_x86_cdecl_avx_patch_19:
	vmovups xmmword ptr [esp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x86_cdecl_avx_patch_19_end
raw_hook_wrapper_x86_cdecl_avx_patch_19_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_20
raw_hook_wrapper_x86_cdecl_avx_patch_20:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x86_cdecl_avx_patch_20_end
raw_hook_wrapper_x86_cdecl_avx_patch_20_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_21
raw_hook_wrapper_x86_cdecl_avx_patch_21:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x86_cdecl_avx_patch_21_end
raw_hook_wrapper_x86_cdecl_avx_patch_21_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_22
raw_hook_wrapper_x86_cdecl_avx_patch_22:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x86_cdecl_avx_patch_22_end
raw_hook_wrapper_x86_cdecl_avx_patch_22_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_23
raw_hook_wrapper_x86_cdecl_avx_patch_23:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x86_cdecl_avx_patch_23_end
raw_hook_wrapper_x86_cdecl_avx_patch_23_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_24
raw_hook_wrapper_x86_cdecl_avx_patch_24:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x86_cdecl_avx_patch_24_end
raw_hook_wrapper_x86_cdecl_avx_patch_24_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_25
raw_hook_wrapper_x86_cdecl_avx_patch_25:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x86_cdecl_avx_patch_25_end
raw_hook_wrapper_x86_cdecl_avx_patch_25_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_26
raw_hook_wrapper_x86_cdecl_avx_patch_26:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x86_cdecl_avx_patch_26_end
raw_hook_wrapper_x86_cdecl_avx_patch_26_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_27
raw_hook_wrapper_x86_cdecl_avx_patch_27:
	vmovups ymmword ptr [esp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x86_cdecl_avx_patch_27_end
raw_hook_wrapper_x86_cdecl_avx_patch_27_end:
	mov eax, esp
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_0
raw_hook_wrapper_x86_cdecl_avx_cet_patch_0:
	add eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_0_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_0_end:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_1
raw_hook_wrapper_x86_cdecl_avx_cet_patch_1:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_1_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_1_end:
	mov eax, dword ptr [eax]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_2
raw_hook_wrapper_x86_cdecl_avx_cet_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_2_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_2_end:
	mov eax, esp
	push eax
.globl raw_hook_wrapper_x86_cdecl_avx_patch_28
raw_hook_wrapper_x86_cdecl_avx_patch_28:
	mov eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx_patch_28_end
raw_hook_wrapper_x86_cdecl_avx_patch_28_end:
	call eax
	add esp, 0x4
	test al, al
	je raw_hook_wrapper_x86_cdecl_avx_nothing_modified
.globl raw_hook_wrapper_x86_cdecl_avx_patch_29
raw_hook_wrapper_x86_cdecl_avx_patch_29:
	vmovups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_29_end
raw_hook_wrapper_x86_cdecl_avx_patch_29_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_30
raw_hook_wrapper_x86_cdecl_avx_patch_30:
	vmovups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_30_end
raw_hook_wrapper_x86_cdecl_avx_patch_30_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_31
raw_hook_wrapper_x86_cdecl_avx_patch_31:
	vmovups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_31_end
raw_hook_wrapper_x86_cdecl_avx_patch_31_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_32
raw_hook_wrapper_x86_cdecl_avx_patch_32:
	vmovups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_32_end
raw_hook_wrapper_x86_cdecl_avx_patch_32_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_33
raw_hook_wrapper_x86_cdecl_avx_patch_33:
	vmovups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_33_end
raw_hook_wrapper_x86_cdecl_avx_patch_33_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_34
raw_hook_wrapper_x86_cdecl_avx_patch_34:
	vmovups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_34_end
raw_hook_wrapper_x86_cdecl_avx_patch_34_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_35
raw_hook_wrapper_x86_cdecl_avx_patch_35:
	vmovups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_35_end
raw_hook_wrapper_x86_cdecl_avx_patch_35_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_36
raw_hook_wrapper_x86_cdecl_avx_patch_36:
	vmovups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_36_end
raw_hook_wrapper_x86_cdecl_avx_patch_36_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_37
raw_hook_wrapper_x86_cdecl_avx_patch_37:
	vmovups ymm0, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_37_end
raw_hook_wrapper_x86_cdecl_avx_patch_37_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_38
raw_hook_wrapper_x86_cdecl_avx_patch_38:
	vmovups ymm1, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_38_end
raw_hook_wrapper_x86_cdecl_avx_patch_38_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_39
raw_hook_wrapper_x86_cdecl_avx_patch_39:
	vmovups ymm2, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_39_end
raw_hook_wrapper_x86_cdecl_avx_patch_39_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_40
raw_hook_wrapper_x86_cdecl_avx_patch_40:
	vmovups ymm3, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_40_end
raw_hook_wrapper_x86_cdecl_avx_patch_40_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_41
raw_hook_wrapper_x86_cdecl_avx_patch_41:
	vmovups ymm4, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_41_end
raw_hook_wrapper_x86_cdecl_avx_patch_41_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_42
raw_hook_wrapper_x86_cdecl_avx_patch_42:
	vmovups ymm5, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_42_end
raw_hook_wrapper_x86_cdecl_avx_patch_42_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_43
raw_hook_wrapper_x86_cdecl_avx_patch_43:
	vmovups ymm6, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_43_end
raw_hook_wrapper_x86_cdecl_avx_patch_43_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_44
raw_hook_wrapper_x86_cdecl_avx_patch_44:
	vmovups ymm7, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_44_end
raw_hook_wrapper_x86_cdecl_avx_patch_44_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_45
raw_hook_wrapper_x86_cdecl_avx_patch_45:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_45_end
raw_hook_wrapper_x86_cdecl_avx_patch_45_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_47
raw_hook_wrapper_x86_cdecl_avx_patch_47:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_47_end
raw_hook_wrapper_x86_cdecl_avx_patch_47_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_48
raw_hook_wrapper_x86_cdecl_avx_patch_48:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_48_end
raw_hook_wrapper_x86_cdecl_avx_patch_48_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_49
raw_hook_wrapper_x86_cdecl_avx_patch_49:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_49_end
raw_hook_wrapper_x86_cdecl_avx_patch_49_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_50
raw_hook_wrapper_x86_cdecl_avx_patch_50:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_50_end
raw_hook_wrapper_x86_cdecl_avx_patch_50_end:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_3
raw_hook_wrapper_x86_cdecl_avx_cet_patch_3:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_3_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_3_end:
	test eax, 0x3
	jne raw_hook_wrapper_x86_cdecl_avx_unsupported_stack
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_4
raw_hook_wrapper_x86_cdecl_avx_cet_patch_4:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_4_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_4_end:
	cmp eax, ecx
	ja raw_hook_wrapper_x86_cdecl_avx_unsupported_stack
	lea edx, [eax + 0x4]
	cmp edx, ecx
	jb raw_hook_wrapper_x86_cdecl_avx_unsupported_stack
	nop
	nop
	nop
	nop
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_6
raw_hook_wrapper_x86_cdecl_avx_cet_patch_6:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_6_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_6_end:
	cmp dword ptr [ecx], edx
	jne raw_hook_wrapper_x86_cdecl_avx_unsupported_stack
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_avx_direct_return
	lea eax, [eax + 0x4]
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_avx_redirect_return
raw_hook_wrapper_x86_cdecl_avx_unsupported_stack:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_7
raw_hook_wrapper_x86_cdecl_avx_cet_patch_7:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_7_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_8
raw_hook_wrapper_x86_cdecl_avx_cet_patch_8:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_8_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_9
raw_hook_wrapper_x86_cdecl_avx_cet_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_9_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_9_end:
	mov dword ptr [ecx], edx
raw_hook_wrapper_x86_cdecl_avx_direct_return:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_46
raw_hook_wrapper_x86_cdecl_avx_patch_46:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_46_end
raw_hook_wrapper_x86_cdecl_avx_patch_46_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_avx_patch_51
raw_hook_wrapper_x86_cdecl_avx_patch_51:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_51_end
raw_hook_wrapper_x86_cdecl_avx_patch_51_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_52
raw_hook_wrapper_x86_cdecl_avx_patch_52:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_52_end
raw_hook_wrapper_x86_cdecl_avx_patch_52_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_53
raw_hook_wrapper_x86_cdecl_avx_patch_53:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_53_end
raw_hook_wrapper_x86_cdecl_avx_patch_53_end:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_54
raw_hook_wrapper_x86_cdecl_avx_patch_54:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_patch_54_end
raw_hook_wrapper_x86_cdecl_avx_patch_54_end:
	ret
raw_hook_wrapper_x86_cdecl_avx_redirect_return:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_10
raw_hook_wrapper_x86_cdecl_avx_cet_patch_10:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_10_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_10_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_11
raw_hook_wrapper_x86_cdecl_avx_cet_patch_11:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_11_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_12
raw_hook_wrapper_x86_cdecl_avx_cet_patch_12:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_12_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_13
raw_hook_wrapper_x86_cdecl_avx_cet_patch_13:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_13_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_14
raw_hook_wrapper_x86_cdecl_avx_cet_patch_14:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_avx_cet_patch_14_end
raw_hook_wrapper_x86_cdecl_avx_cet_patch_14_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]
raw_hook_wrapper_x86_cdecl_avx_nothing_modified:
.globl raw_hook_wrapper_x86_cdecl_avx_patch_55
raw_hook_wrapper_x86_cdecl_avx_patch_55:
	add esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_avx_patch_55_end
raw_hook_wrapper_x86_cdecl_avx_patch_55_end:

# RawHook wrapper: x86 SSEFPU
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x86_cdecl_ssefpu
raw_hook_wrapper_x86_cdecl_ssefpu:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_0
raw_hook_wrapper_x86_cdecl_ssefpu_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_0_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_0_end:
	pushfd
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_1
raw_hook_wrapper_x86_cdecl_ssefpu_patch_1:
	pop dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_1_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_1_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_2
raw_hook_wrapper_x86_cdecl_ssefpu_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_2_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_2_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_3
raw_hook_wrapper_x86_cdecl_ssefpu_patch_3:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_3_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_3_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_4
raw_hook_wrapper_x86_cdecl_ssefpu_patch_4:
	mov dword ptr [esp + 0x7fffffff], edx
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_4_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_4_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_5
raw_hook_wrapper_x86_cdecl_ssefpu_patch_5:
	mov dword ptr [esp + 0x7fffffff], ebx
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_5_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_5_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_6
raw_hook_wrapper_x86_cdecl_ssefpu_patch_6:
	mov dword ptr [esp + 0x7fffffff], esp
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_6_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_6_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_7
raw_hook_wrapper_x86_cdecl_ssefpu_patch_7:
	add dword ptr [esp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_7_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_8
raw_hook_wrapper_x86_cdecl_ssefpu_patch_8:
	mov dword ptr [esp + 0x7fffffff], ebp
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_8_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_9
raw_hook_wrapper_x86_cdecl_ssefpu_patch_9:
	mov dword ptr [esp + 0x7fffffff], esi
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_9_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_9_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_10
raw_hook_wrapper_x86_cdecl_ssefpu_patch_10:
	mov dword ptr [esp + 0x7fffffff], edi
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_10_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_10_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_11
raw_hook_wrapper_x86_cdecl_ssefpu_patch_11:
	stmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_11_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_12
raw_hook_wrapper_x86_cdecl_ssefpu_patch_12:
	movups xmmword ptr [esp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_12_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_13
raw_hook_wrapper_x86_cdecl_ssefpu_patch_13:
	movups xmmword ptr [esp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_13_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_14
raw_hook_wrapper_x86_cdecl_ssefpu_patch_14:
	movups xmmword ptr [esp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_14_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_14_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_15
raw_hook_wrapper_x86_cdecl_ssefpu_patch_15:
	movups xmmword ptr [esp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_15_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_15_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_16
raw_hook_wrapper_x86_cdecl_ssefpu_patch_16:
	movups xmmword ptr [esp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_16_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_16_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_17
raw_hook_wrapper_x86_cdecl_ssefpu_patch_17:
	movups xmmword ptr [esp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_17_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_17_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_18
raw_hook_wrapper_x86_cdecl_ssefpu_patch_18:
	movups xmmword ptr [esp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_18_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_18_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_19
raw_hook_wrapper_x86_cdecl_ssefpu_patch_19:
	movups xmmword ptr [esp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_19_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_19_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_20
raw_hook_wrapper_x86_cdecl_ssefpu_patch_20:
	fsave [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_20_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_20_end:
	mov eax, esp
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_0
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_0:
	add eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_0_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_0_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_1
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_1:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_1_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_1_end:
	mov eax, dword ptr [eax]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_2
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_2_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_2_end:
	mov eax, esp
	push eax
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_21
raw_hook_wrapper_x86_cdecl_ssefpu_patch_21:
	mov eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_21_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_21_end:
	call eax
	add esp, 0x4
	test al, al
	je raw_hook_wrapper_x86_cdecl_ssefpu_nothing_modified
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_22
raw_hook_wrapper_x86_cdecl_ssefpu_patch_22:
	frstor [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_22_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_22_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_23
raw_hook_wrapper_x86_cdecl_ssefpu_patch_23:
	movups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_23_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_23_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_24
raw_hook_wrapper_x86_cdecl_ssefpu_patch_24:
	movups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_24_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_24_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_25
raw_hook_wrapper_x86_cdecl_ssefpu_patch_25:
	movups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_25_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_25_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_26
raw_hook_wrapper_x86_cdecl_ssefpu_patch_26:
	movups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_26_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_26_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_27
raw_hook_wrapper_x86_cdecl_ssefpu_patch_27:
	movups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_27_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_27_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_28
raw_hook_wrapper_x86_cdecl_ssefpu_patch_28:
	movups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_28_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_28_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_29
raw_hook_wrapper_x86_cdecl_ssefpu_patch_29:
	movups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_29_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_29_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_30
raw_hook_wrapper_x86_cdecl_ssefpu_patch_30:
	movups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_30_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_30_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_31
raw_hook_wrapper_x86_cdecl_ssefpu_patch_31:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_31_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_31_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_33
raw_hook_wrapper_x86_cdecl_ssefpu_patch_33:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_33_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_33_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_34
raw_hook_wrapper_x86_cdecl_ssefpu_patch_34:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_34_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_34_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_35
raw_hook_wrapper_x86_cdecl_ssefpu_patch_35:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_35_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_35_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_36
raw_hook_wrapper_x86_cdecl_ssefpu_patch_36:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_36_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_36_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_3
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_3:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_3_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_3_end:
	test eax, 0x3
	jne raw_hook_wrapper_x86_cdecl_ssefpu_unsupported_stack
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_4
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_4:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_4_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_4_end:
	cmp eax, ecx
	ja raw_hook_wrapper_x86_cdecl_ssefpu_unsupported_stack
	lea edx, [eax + 0x4]
	cmp edx, ecx
	jb raw_hook_wrapper_x86_cdecl_ssefpu_unsupported_stack
	nop
	nop
	nop
	nop
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_6
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_6:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_6_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_6_end:
	cmp dword ptr [ecx], edx
	jne raw_hook_wrapper_x86_cdecl_ssefpu_unsupported_stack
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_ssefpu_direct_return
	lea eax, [eax + 0x4]
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_ssefpu_redirect_return
raw_hook_wrapper_x86_cdecl_ssefpu_unsupported_stack:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_7
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_7:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_7_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_8
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_8:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_8_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_9
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_9_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_9_end:
	mov dword ptr [ecx], edx
raw_hook_wrapper_x86_cdecl_ssefpu_direct_return:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_32
raw_hook_wrapper_x86_cdecl_ssefpu_patch_32:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_32_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_32_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_37
raw_hook_wrapper_x86_cdecl_ssefpu_patch_37:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_37_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_37_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_38
raw_hook_wrapper_x86_cdecl_ssefpu_patch_38:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_38_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_38_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_39
raw_hook_wrapper_x86_cdecl_ssefpu_patch_39:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_39_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_39_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_40
raw_hook_wrapper_x86_cdecl_ssefpu_patch_40:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_40_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_40_end:
	ret
raw_hook_wrapper_x86_cdecl_ssefpu_redirect_return:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_10
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_10:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_10_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_10_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_11
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_11:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_11_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_12
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_12:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_12_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_13
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_13:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_13_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_14
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_14:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_14_end
raw_hook_wrapper_x86_cdecl_ssefpu_cet_patch_14_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]
raw_hook_wrapper_x86_cdecl_ssefpu_nothing_modified:
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_41
raw_hook_wrapper_x86_cdecl_ssefpu_patch_41:
	add esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_ssefpu_patch_41_end
raw_hook_wrapper_x86_cdecl_ssefpu_patch_41_end:

# RawHook wrapper: x86 SSE
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x86_cdecl_sse
raw_hook_wrapper_x86_cdecl_sse:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_0
raw_hook_wrapper_x86_cdecl_sse_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_sse_patch_0_end
raw_hook_wrapper_x86_cdecl_sse_patch_0_end:
	pushfd
.globl raw_hook_wrapper_x86_cdecl_sse_patch_1
raw_hook_wrapper_x86_cdecl_sse_patch_1:
	pop dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_1_end
raw_hook_wrapper_x86_cdecl_sse_patch_1_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_2
raw_hook_wrapper_x86_cdecl_sse_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_sse_patch_2_end
raw_hook_wrapper_x86_cdecl_sse_patch_2_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_3
raw_hook_wrapper_x86_cdecl_sse_patch_3:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_sse_patch_3_end
raw_hook_wrapper_x86_cdecl_sse_patch_3_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_4
raw_hook_wrapper_x86_cdecl_sse_patch_4:
	mov dword ptr [esp + 0x7fffffff], edx
.globl raw_hook_wrapper_x86_cdecl_sse_patch_4_end
raw_hook_wrapper_x86_cdecl_sse_patch_4_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_5
raw_hook_wrapper_x86_cdecl_sse_patch_5:
	mov dword ptr [esp + 0x7fffffff], ebx
.globl raw_hook_wrapper_x86_cdecl_sse_patch_5_end
raw_hook_wrapper_x86_cdecl_sse_patch_5_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_6
raw_hook_wrapper_x86_cdecl_sse_patch_6:
	mov dword ptr [esp + 0x7fffffff], esp
.globl raw_hook_wrapper_x86_cdecl_sse_patch_6_end
raw_hook_wrapper_x86_cdecl_sse_patch_6_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_7
raw_hook_wrapper_x86_cdecl_sse_patch_7:
	add dword ptr [esp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_sse_patch_7_end
raw_hook_wrapper_x86_cdecl_sse_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_8
raw_hook_wrapper_x86_cdecl_sse_patch_8:
	mov dword ptr [esp + 0x7fffffff], ebp
.globl raw_hook_wrapper_x86_cdecl_sse_patch_8_end
raw_hook_wrapper_x86_cdecl_sse_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_9
raw_hook_wrapper_x86_cdecl_sse_patch_9:
	mov dword ptr [esp + 0x7fffffff], esi
.globl raw_hook_wrapper_x86_cdecl_sse_patch_9_end
raw_hook_wrapper_x86_cdecl_sse_patch_9_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_10
raw_hook_wrapper_x86_cdecl_sse_patch_10:
	mov dword ptr [esp + 0x7fffffff], edi
.globl raw_hook_wrapper_x86_cdecl_sse_patch_10_end
raw_hook_wrapper_x86_cdecl_sse_patch_10_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_11
raw_hook_wrapper_x86_cdecl_sse_patch_11:
	stmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_11_end
raw_hook_wrapper_x86_cdecl_sse_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_12
raw_hook_wrapper_x86_cdecl_sse_patch_12:
	movups xmmword ptr [esp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x86_cdecl_sse_patch_12_end
raw_hook_wrapper_x86_cdecl_sse_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_13
raw_hook_wrapper_x86_cdecl_sse_patch_13:
	movups xmmword ptr [esp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x86_cdecl_sse_patch_13_end
raw_hook_wrapper_x86_cdecl_sse_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_14
raw_hook_wrapper_x86_cdecl_sse_patch_14:
	movups xmmword ptr [esp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x86_cdecl_sse_patch_14_end
raw_hook_wrapper_x86_cdecl_sse_patch_14_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_15
raw_hook_wrapper_x86_cdecl_sse_patch_15:
	movups xmmword ptr [esp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x86_cdecl_sse_patch_15_end
raw_hook_wrapper_x86_cdecl_sse_patch_15_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_16
raw_hook_wrapper_x86_cdecl_sse_patch_16:
	movups xmmword ptr [esp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x86_cdecl_sse_patch_16_end
raw_hook_wrapper_x86_cdecl_sse_patch_16_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_17
raw_hook_wrapper_x86_cdecl_sse_patch_17:
	movups xmmword ptr [esp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x86_cdecl_sse_patch_17_end
raw_hook_wrapper_x86_cdecl_sse_patch_17_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_18
raw_hook_wrapper_x86_cdecl_sse_patch_18:
	movups xmmword ptr [esp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x86_cdecl_sse_patch_18_end
raw_hook_wrapper_x86_cdecl_sse_patch_18_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_19
raw_hook_wrapper_x86_cdecl_sse_patch_19:
	movups xmmword ptr [esp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x86_cdecl_sse_patch_19_end
raw_hook_wrapper_x86_cdecl_sse_patch_19_end:
	mov eax, esp
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_0
raw_hook_wrapper_x86_cdecl_sse_cet_patch_0:
	add eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_0_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_0_end:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_1
raw_hook_wrapper_x86_cdecl_sse_cet_patch_1:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_1_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_1_end:
	mov eax, dword ptr [eax]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_2
raw_hook_wrapper_x86_cdecl_sse_cet_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_2_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_2_end:
	mov eax, esp
	push eax
.globl raw_hook_wrapper_x86_cdecl_sse_patch_20
raw_hook_wrapper_x86_cdecl_sse_patch_20:
	mov eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_sse_patch_20_end
raw_hook_wrapper_x86_cdecl_sse_patch_20_end:
	call eax
	add esp, 0x4
	test al, al
	je raw_hook_wrapper_x86_cdecl_sse_nothing_modified
.globl raw_hook_wrapper_x86_cdecl_sse_patch_21
raw_hook_wrapper_x86_cdecl_sse_patch_21:
	movups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_21_end
raw_hook_wrapper_x86_cdecl_sse_patch_21_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_22
raw_hook_wrapper_x86_cdecl_sse_patch_22:
	movups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_22_end
raw_hook_wrapper_x86_cdecl_sse_patch_22_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_23
raw_hook_wrapper_x86_cdecl_sse_patch_23:
	movups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_23_end
raw_hook_wrapper_x86_cdecl_sse_patch_23_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_24
raw_hook_wrapper_x86_cdecl_sse_patch_24:
	movups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_24_end
raw_hook_wrapper_x86_cdecl_sse_patch_24_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_25
raw_hook_wrapper_x86_cdecl_sse_patch_25:
	movups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_25_end
raw_hook_wrapper_x86_cdecl_sse_patch_25_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_26
raw_hook_wrapper_x86_cdecl_sse_patch_26:
	movups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_26_end
raw_hook_wrapper_x86_cdecl_sse_patch_26_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_27
raw_hook_wrapper_x86_cdecl_sse_patch_27:
	movups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_27_end
raw_hook_wrapper_x86_cdecl_sse_patch_27_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_28
raw_hook_wrapper_x86_cdecl_sse_patch_28:
	movups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_28_end
raw_hook_wrapper_x86_cdecl_sse_patch_28_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_29
raw_hook_wrapper_x86_cdecl_sse_patch_29:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_29_end
raw_hook_wrapper_x86_cdecl_sse_patch_29_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_31
raw_hook_wrapper_x86_cdecl_sse_patch_31:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_31_end
raw_hook_wrapper_x86_cdecl_sse_patch_31_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_32
raw_hook_wrapper_x86_cdecl_sse_patch_32:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_32_end
raw_hook_wrapper_x86_cdecl_sse_patch_32_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_33
raw_hook_wrapper_x86_cdecl_sse_patch_33:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_33_end
raw_hook_wrapper_x86_cdecl_sse_patch_33_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_34
raw_hook_wrapper_x86_cdecl_sse_patch_34:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_34_end
raw_hook_wrapper_x86_cdecl_sse_patch_34_end:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_3
raw_hook_wrapper_x86_cdecl_sse_cet_patch_3:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_3_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_3_end:
	test eax, 0x3
	jne raw_hook_wrapper_x86_cdecl_sse_unsupported_stack
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_4
raw_hook_wrapper_x86_cdecl_sse_cet_patch_4:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_4_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_4_end:
	cmp eax, ecx
	ja raw_hook_wrapper_x86_cdecl_sse_unsupported_stack
	lea edx, [eax + 0x4]
	cmp edx, ecx
	jb raw_hook_wrapper_x86_cdecl_sse_unsupported_stack
	nop
	nop
	nop
	nop
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_6
raw_hook_wrapper_x86_cdecl_sse_cet_patch_6:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_6_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_6_end:
	cmp dword ptr [ecx], edx
	jne raw_hook_wrapper_x86_cdecl_sse_unsupported_stack
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_sse_direct_return
	lea eax, [eax + 0x4]
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_sse_redirect_return
raw_hook_wrapper_x86_cdecl_sse_unsupported_stack:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_7
raw_hook_wrapper_x86_cdecl_sse_cet_patch_7:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_7_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_8
raw_hook_wrapper_x86_cdecl_sse_cet_patch_8:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_8_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_9
raw_hook_wrapper_x86_cdecl_sse_cet_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_9_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_9_end:
	mov dword ptr [ecx], edx
raw_hook_wrapper_x86_cdecl_sse_direct_return:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_30
raw_hook_wrapper_x86_cdecl_sse_patch_30:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_30_end
raw_hook_wrapper_x86_cdecl_sse_patch_30_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_sse_patch_35
raw_hook_wrapper_x86_cdecl_sse_patch_35:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_35_end
raw_hook_wrapper_x86_cdecl_sse_patch_35_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_36
raw_hook_wrapper_x86_cdecl_sse_patch_36:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_36_end
raw_hook_wrapper_x86_cdecl_sse_patch_36_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_37
raw_hook_wrapper_x86_cdecl_sse_patch_37:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_37_end
raw_hook_wrapper_x86_cdecl_sse_patch_37_end:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_38
raw_hook_wrapper_x86_cdecl_sse_patch_38:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_patch_38_end
raw_hook_wrapper_x86_cdecl_sse_patch_38_end:
	ret
raw_hook_wrapper_x86_cdecl_sse_redirect_return:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_10
raw_hook_wrapper_x86_cdecl_sse_cet_patch_10:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_10_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_10_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_11
raw_hook_wrapper_x86_cdecl_sse_cet_patch_11:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_11_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_12
raw_hook_wrapper_x86_cdecl_sse_cet_patch_12:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_12_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_13
raw_hook_wrapper_x86_cdecl_sse_cet_patch_13:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_13_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_14
raw_hook_wrapper_x86_cdecl_sse_cet_patch_14:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_sse_cet_patch_14_end
raw_hook_wrapper_x86_cdecl_sse_cet_patch_14_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]
raw_hook_wrapper_x86_cdecl_sse_nothing_modified:
.globl raw_hook_wrapper_x86_cdecl_sse_patch_39
raw_hook_wrapper_x86_cdecl_sse_patch_39:
	add esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_sse_patch_39_end
raw_hook_wrapper_x86_cdecl_sse_patch_39_end:

# RawHook wrapper: x86 FPU
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x86_cdecl_fpu
raw_hook_wrapper_x86_cdecl_fpu:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_0
raw_hook_wrapper_x86_cdecl_fpu_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_0_end
raw_hook_wrapper_x86_cdecl_fpu_patch_0_end:
	pushfd
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_1
raw_hook_wrapper_x86_cdecl_fpu_patch_1:
	pop dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_1_end
raw_hook_wrapper_x86_cdecl_fpu_patch_1_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_2
raw_hook_wrapper_x86_cdecl_fpu_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_2_end
raw_hook_wrapper_x86_cdecl_fpu_patch_2_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_3
raw_hook_wrapper_x86_cdecl_fpu_patch_3:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_3_end
raw_hook_wrapper_x86_cdecl_fpu_patch_3_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_4
raw_hook_wrapper_x86_cdecl_fpu_patch_4:
	mov dword ptr [esp + 0x7fffffff], edx
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_4_end
raw_hook_wrapper_x86_cdecl_fpu_patch_4_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_5
raw_hook_wrapper_x86_cdecl_fpu_patch_5:
	mov dword ptr [esp + 0x7fffffff], ebx
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_5_end
raw_hook_wrapper_x86_cdecl_fpu_patch_5_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_6
raw_hook_wrapper_x86_cdecl_fpu_patch_6:
	mov dword ptr [esp + 0x7fffffff], esp
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_6_end
raw_hook_wrapper_x86_cdecl_fpu_patch_6_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_7
raw_hook_wrapper_x86_cdecl_fpu_patch_7:
	add dword ptr [esp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_7_end
raw_hook_wrapper_x86_cdecl_fpu_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_8
raw_hook_wrapper_x86_cdecl_fpu_patch_8:
	mov dword ptr [esp + 0x7fffffff], ebp
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_8_end
raw_hook_wrapper_x86_cdecl_fpu_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_9
raw_hook_wrapper_x86_cdecl_fpu_patch_9:
	mov dword ptr [esp + 0x7fffffff], esi
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_9_end
raw_hook_wrapper_x86_cdecl_fpu_patch_9_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_10
raw_hook_wrapper_x86_cdecl_fpu_patch_10:
	mov dword ptr [esp + 0x7fffffff], edi
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_10_end
raw_hook_wrapper_x86_cdecl_fpu_patch_10_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_11
raw_hook_wrapper_x86_cdecl_fpu_patch_11:
	fsave [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_11_end
raw_hook_wrapper_x86_cdecl_fpu_patch_11_end:
	mov eax, esp
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_0
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_0:
	add eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_0_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_0_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_1
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_1:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_1_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_1_end:
	mov eax, dword ptr [eax]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_2
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_2_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_2_end:
	mov eax, esp
	push eax
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_12
raw_hook_wrapper_x86_cdecl_fpu_patch_12:
	mov eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_12_end
raw_hook_wrapper_x86_cdecl_fpu_patch_12_end:
	call eax
	add esp, 0x4
	test al, al
	je raw_hook_wrapper_x86_cdecl_fpu_nothing_modified
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_13
raw_hook_wrapper_x86_cdecl_fpu_patch_13:
	frstor [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_13_end
raw_hook_wrapper_x86_cdecl_fpu_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_15
raw_hook_wrapper_x86_cdecl_fpu_patch_15:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_15_end
raw_hook_wrapper_x86_cdecl_fpu_patch_15_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_16
raw_hook_wrapper_x86_cdecl_fpu_patch_16:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_16_end
raw_hook_wrapper_x86_cdecl_fpu_patch_16_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_17
raw_hook_wrapper_x86_cdecl_fpu_patch_17:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_17_end
raw_hook_wrapper_x86_cdecl_fpu_patch_17_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_18
raw_hook_wrapper_x86_cdecl_fpu_patch_18:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_18_end
raw_hook_wrapper_x86_cdecl_fpu_patch_18_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_3
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_3:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_3_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_3_end:
	test eax, 0x3
	jne raw_hook_wrapper_x86_cdecl_fpu_unsupported_stack
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_4
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_4:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_4_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_4_end:
	cmp eax, ecx
	ja raw_hook_wrapper_x86_cdecl_fpu_unsupported_stack
	lea edx, [eax + 0x4]
	cmp edx, ecx
	jb raw_hook_wrapper_x86_cdecl_fpu_unsupported_stack
	nop
	nop
	nop
	nop
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_6
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_6:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_6_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_6_end:
	cmp dword ptr [ecx], edx
	jne raw_hook_wrapper_x86_cdecl_fpu_unsupported_stack
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_fpu_direct_return
	lea eax, [eax + 0x4]
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_fpu_redirect_return
raw_hook_wrapper_x86_cdecl_fpu_unsupported_stack:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_7
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_7:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_7_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_8
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_8:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_8_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_9
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_9_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_9_end:
	mov dword ptr [ecx], edx
raw_hook_wrapper_x86_cdecl_fpu_direct_return:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_14
raw_hook_wrapper_x86_cdecl_fpu_patch_14:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_14_end
raw_hook_wrapper_x86_cdecl_fpu_patch_14_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_19
raw_hook_wrapper_x86_cdecl_fpu_patch_19:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_19_end
raw_hook_wrapper_x86_cdecl_fpu_patch_19_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_20
raw_hook_wrapper_x86_cdecl_fpu_patch_20:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_20_end
raw_hook_wrapper_x86_cdecl_fpu_patch_20_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_21
raw_hook_wrapper_x86_cdecl_fpu_patch_21:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_21_end
raw_hook_wrapper_x86_cdecl_fpu_patch_21_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_22
raw_hook_wrapper_x86_cdecl_fpu_patch_22:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_22_end
raw_hook_wrapper_x86_cdecl_fpu_patch_22_end:
	ret
raw_hook_wrapper_x86_cdecl_fpu_redirect_return:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_10
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_10:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_10_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_10_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_11
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_11:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_11_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_12
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_12:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_12_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_13
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_13:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_13_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_14
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_14:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_fpu_cet_patch_14_end
raw_hook_wrapper_x86_cdecl_fpu_cet_patch_14_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]
raw_hook_wrapper_x86_cdecl_fpu_nothing_modified:
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_23
raw_hook_wrapper_x86_cdecl_fpu_patch_23:
	add esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_fpu_patch_23_end
raw_hook_wrapper_x86_cdecl_fpu_patch_23_end:

# RawHook wrapper: x86 Native
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x86_cdecl_native
raw_hook_wrapper_x86_cdecl_native:
.globl raw_hook_wrapper_x86_cdecl_native_patch_0
raw_hook_wrapper_x86_cdecl_native_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_native_patch_0_end
raw_hook_wrapper_x86_cdecl_native_patch_0_end:
	pushfd
.globl raw_hook_wrapper_x86_cdecl_native_patch_1
raw_hook_wrapper_x86_cdecl_native_patch_1:
	pop dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_1_end
raw_hook_wrapper_x86_cdecl_native_patch_1_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_2
raw_hook_wrapper_x86_cdecl_native_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_native_patch_2_end
raw_hook_wrapper_x86_cdecl_native_patch_2_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_3
raw_hook_wrapper_x86_cdecl_native_patch_3:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_native_patch_3_end
raw_hook_wrapper_x86_cdecl_native_patch_3_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_4
raw_hook_wrapper_x86_cdecl_native_patch_4:
	mov dword ptr [esp + 0x7fffffff], edx
.globl raw_hook_wrapper_x86_cdecl_native_patch_4_end
raw_hook_wrapper_x86_cdecl_native_patch_4_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_5
raw_hook_wrapper_x86_cdecl_native_patch_5:
	mov dword ptr [esp + 0x7fffffff], ebx
.globl raw_hook_wrapper_x86_cdecl_native_patch_5_end
raw_hook_wrapper_x86_cdecl_native_patch_5_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_6
raw_hook_wrapper_x86_cdecl_native_patch_6:
	mov dword ptr [esp + 0x7fffffff], esp
.globl raw_hook_wrapper_x86_cdecl_native_patch_6_end
raw_hook_wrapper_x86_cdecl_native_patch_6_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_7
raw_hook_wrapper_x86_cdecl_native_patch_7:
	add dword ptr [esp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_native_patch_7_end
raw_hook_wrapper_x86_cdecl_native_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_8
raw_hook_wrapper_x86_cdecl_native_patch_8:
	mov dword ptr [esp + 0x7fffffff], ebp
.globl raw_hook_wrapper_x86_cdecl_native_patch_8_end
raw_hook_wrapper_x86_cdecl_native_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_9
raw_hook_wrapper_x86_cdecl_native_patch_9:
	mov dword ptr [esp + 0x7fffffff], esi
.globl raw_hook_wrapper_x86_cdecl_native_patch_9_end
raw_hook_wrapper_x86_cdecl_native_patch_9_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_10
raw_hook_wrapper_x86_cdecl_native_patch_10:
	mov dword ptr [esp + 0x7fffffff], edi
.globl raw_hook_wrapper_x86_cdecl_native_patch_10_end
raw_hook_wrapper_x86_cdecl_native_patch_10_end:
	mov eax, esp
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_0
raw_hook_wrapper_x86_cdecl_native_cet_patch_0:
	add eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_0_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_0_end:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_1
raw_hook_wrapper_x86_cdecl_native_cet_patch_1:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_1_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_1_end:
	mov eax, dword ptr [eax]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_2
raw_hook_wrapper_x86_cdecl_native_cet_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_2_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_2_end:
	mov eax, esp
	push eax
.globl raw_hook_wrapper_x86_cdecl_native_patch_11
raw_hook_wrapper_x86_cdecl_native_patch_11:
	mov eax, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_native_patch_11_end
raw_hook_wrapper_x86_cdecl_native_patch_11_end:
	call eax
	add esp, 0x4
	test al, al
	je raw_hook_wrapper_x86_cdecl_native_nothing_modified
.globl raw_hook_wrapper_x86_cdecl_native_patch_13
raw_hook_wrapper_x86_cdecl_native_patch_13:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_13_end
raw_hook_wrapper_x86_cdecl_native_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_14
raw_hook_wrapper_x86_cdecl_native_patch_14:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_14_end
raw_hook_wrapper_x86_cdecl_native_patch_14_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_15
raw_hook_wrapper_x86_cdecl_native_patch_15:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_15_end
raw_hook_wrapper_x86_cdecl_native_patch_15_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_16
raw_hook_wrapper_x86_cdecl_native_patch_16:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_16_end
raw_hook_wrapper_x86_cdecl_native_patch_16_end:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_3
raw_hook_wrapper_x86_cdecl_native_cet_patch_3:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_3_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_3_end:
	test eax, 0x3
	jne raw_hook_wrapper_x86_cdecl_native_unsupported_stack
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_4
raw_hook_wrapper_x86_cdecl_native_cet_patch_4:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_4_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_4_end:
	cmp eax, ecx
	ja raw_hook_wrapper_x86_cdecl_native_unsupported_stack
	lea edx, [eax + 0x4]
	cmp edx, ecx
	jb raw_hook_wrapper_x86_cdecl_native_unsupported_stack
	nop
	nop
	nop
	nop
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_6
raw_hook_wrapper_x86_cdecl_native_cet_patch_6:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_6_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_6_end:
	cmp dword ptr [ecx], edx
	jne raw_hook_wrapper_x86_cdecl_native_unsupported_stack
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_native_direct_return
	lea eax, [eax + 0x4]
	cmp eax, ecx
	je raw_hook_wrapper_x86_cdecl_native_redirect_return
raw_hook_wrapper_x86_cdecl_native_unsupported_stack:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_7
raw_hook_wrapper_x86_cdecl_native_cet_patch_7:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_7_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_7_end:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_8
raw_hook_wrapper_x86_cdecl_native_cet_patch_8:
	mov dword ptr [esp + 0x7fffffff], ecx
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_8_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_8_end:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_9
raw_hook_wrapper_x86_cdecl_native_cet_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_9_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_9_end:
	mov dword ptr [ecx], edx
raw_hook_wrapper_x86_cdecl_native_direct_return:
.globl raw_hook_wrapper_x86_cdecl_native_patch_12
raw_hook_wrapper_x86_cdecl_native_patch_12:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_12_end
raw_hook_wrapper_x86_cdecl_native_patch_12_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_native_patch_17
raw_hook_wrapper_x86_cdecl_native_patch_17:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_17_end
raw_hook_wrapper_x86_cdecl_native_patch_17_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_18
raw_hook_wrapper_x86_cdecl_native_patch_18:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_18_end
raw_hook_wrapper_x86_cdecl_native_patch_18_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_19
raw_hook_wrapper_x86_cdecl_native_patch_19:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_19_end
raw_hook_wrapper_x86_cdecl_native_patch_19_end:
.globl raw_hook_wrapper_x86_cdecl_native_patch_20
raw_hook_wrapper_x86_cdecl_native_patch_20:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_patch_20_end
raw_hook_wrapper_x86_cdecl_native_patch_20_end:
	ret
raw_hook_wrapper_x86_cdecl_native_redirect_return:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_10
raw_hook_wrapper_x86_cdecl_native_cet_patch_10:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_10_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_10_end:
	popfd
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_11
raw_hook_wrapper_x86_cdecl_native_cet_patch_11:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_11_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_11_end:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_12
raw_hook_wrapper_x86_cdecl_native_cet_patch_12:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_12_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_12_end:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_13
raw_hook_wrapper_x86_cdecl_native_cet_patch_13:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_13_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_13_end:
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_14
raw_hook_wrapper_x86_cdecl_native_cet_patch_14:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_wrapper_x86_cdecl_native_cet_patch_14_end
raw_hook_wrapper_x86_cdecl_native_cet_patch_14_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]
raw_hook_wrapper_x86_cdecl_native_nothing_modified:
.globl raw_hook_wrapper_x86_cdecl_native_patch_21
raw_hook_wrapper_x86_cdecl_native_patch_21:
	add esp, 0x7fffffff
.globl raw_hook_wrapper_x86_cdecl_native_patch_21_end
raw_hook_wrapper_x86_cdecl_native_patch_21_end:

# RawHook restore: x86 AVX512FPU
.intel_syntax noprefix
.text
.globl raw_hook_restore_x86_avx512fpu
raw_hook_restore_x86_avx512fpu:
.globl raw_hook_restore_x86_avx512fpu_patch_0
raw_hook_restore_x86_avx512fpu_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_restore_x86_avx512fpu_patch_0_end
raw_hook_restore_x86_avx512fpu_patch_0_end:
.globl raw_hook_restore_x86_avx512fpu_patch_1
raw_hook_restore_x86_avx512fpu_patch_1:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_1_end
raw_hook_restore_x86_avx512fpu_patch_1_end:
	sub eax, 0x4
.globl raw_hook_restore_x86_avx512fpu_patch_2
raw_hook_restore_x86_avx512fpu_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_restore_x86_avx512fpu_patch_2_end
raw_hook_restore_x86_avx512fpu_patch_2_end:
.globl raw_hook_restore_x86_avx512fpu_patch_3
raw_hook_restore_x86_avx512fpu_patch_3:
	mov edx, 0x7fffffff
.globl raw_hook_restore_x86_avx512fpu_patch_3_end
raw_hook_restore_x86_avx512fpu_patch_3_end:
	mov dword ptr [eax], edx
.globl raw_hook_restore_x86_avx512fpu_patch_4
raw_hook_restore_x86_avx512fpu_patch_4:
	frstor [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_4_end
raw_hook_restore_x86_avx512fpu_patch_4_end:
.globl raw_hook_restore_x86_avx512fpu_patch_5
raw_hook_restore_x86_avx512fpu_patch_5:
	vmovups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_5_end
raw_hook_restore_x86_avx512fpu_patch_5_end:
.globl raw_hook_restore_x86_avx512fpu_patch_6
raw_hook_restore_x86_avx512fpu_patch_6:
	vmovups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_6_end
raw_hook_restore_x86_avx512fpu_patch_6_end:
.globl raw_hook_restore_x86_avx512fpu_patch_7
raw_hook_restore_x86_avx512fpu_patch_7:
	vmovups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_7_end
raw_hook_restore_x86_avx512fpu_patch_7_end:
.globl raw_hook_restore_x86_avx512fpu_patch_8
raw_hook_restore_x86_avx512fpu_patch_8:
	vmovups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_8_end
raw_hook_restore_x86_avx512fpu_patch_8_end:
.globl raw_hook_restore_x86_avx512fpu_patch_9
raw_hook_restore_x86_avx512fpu_patch_9:
	vmovups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_9_end
raw_hook_restore_x86_avx512fpu_patch_9_end:
.globl raw_hook_restore_x86_avx512fpu_patch_10
raw_hook_restore_x86_avx512fpu_patch_10:
	vmovups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_10_end
raw_hook_restore_x86_avx512fpu_patch_10_end:
.globl raw_hook_restore_x86_avx512fpu_patch_11
raw_hook_restore_x86_avx512fpu_patch_11:
	vmovups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_11_end
raw_hook_restore_x86_avx512fpu_patch_11_end:
.globl raw_hook_restore_x86_avx512fpu_patch_12
raw_hook_restore_x86_avx512fpu_patch_12:
	vmovups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_12_end
raw_hook_restore_x86_avx512fpu_patch_12_end:
.globl raw_hook_restore_x86_avx512fpu_patch_13
raw_hook_restore_x86_avx512fpu_patch_13:
	vmovups ymm0, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_13_end
raw_hook_restore_x86_avx512fpu_patch_13_end:
.globl raw_hook_restore_x86_avx512fpu_patch_14
raw_hook_restore_x86_avx512fpu_patch_14:
	vmovups ymm1, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_14_end
raw_hook_restore_x86_avx512fpu_patch_14_end:
.globl raw_hook_restore_x86_avx512fpu_patch_15
raw_hook_restore_x86_avx512fpu_patch_15:
	vmovups ymm2, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_15_end
raw_hook_restore_x86_avx512fpu_patch_15_end:
.globl raw_hook_restore_x86_avx512fpu_patch_16
raw_hook_restore_x86_avx512fpu_patch_16:
	vmovups ymm3, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_16_end
raw_hook_restore_x86_avx512fpu_patch_16_end:
.globl raw_hook_restore_x86_avx512fpu_patch_17
raw_hook_restore_x86_avx512fpu_patch_17:
	vmovups ymm4, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_17_end
raw_hook_restore_x86_avx512fpu_patch_17_end:
.globl raw_hook_restore_x86_avx512fpu_patch_18
raw_hook_restore_x86_avx512fpu_patch_18:
	vmovups ymm5, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_18_end
raw_hook_restore_x86_avx512fpu_patch_18_end:
.globl raw_hook_restore_x86_avx512fpu_patch_19
raw_hook_restore_x86_avx512fpu_patch_19:
	vmovups ymm6, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_19_end
raw_hook_restore_x86_avx512fpu_patch_19_end:
.globl raw_hook_restore_x86_avx512fpu_patch_20
raw_hook_restore_x86_avx512fpu_patch_20:
	vmovups ymm7, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_20_end
raw_hook_restore_x86_avx512fpu_patch_20_end:
.globl raw_hook_restore_x86_avx512fpu_patch_21
raw_hook_restore_x86_avx512fpu_patch_21:
	vmovups zmm0, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_21_end
raw_hook_restore_x86_avx512fpu_patch_21_end:
.globl raw_hook_restore_x86_avx512fpu_patch_22
raw_hook_restore_x86_avx512fpu_patch_22:
	vmovups zmm1, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_22_end
raw_hook_restore_x86_avx512fpu_patch_22_end:
.globl raw_hook_restore_x86_avx512fpu_patch_23
raw_hook_restore_x86_avx512fpu_patch_23:
	vmovups zmm2, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_23_end
raw_hook_restore_x86_avx512fpu_patch_23_end:
.globl raw_hook_restore_x86_avx512fpu_patch_24
raw_hook_restore_x86_avx512fpu_patch_24:
	vmovups zmm3, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_24_end
raw_hook_restore_x86_avx512fpu_patch_24_end:
.globl raw_hook_restore_x86_avx512fpu_patch_25
raw_hook_restore_x86_avx512fpu_patch_25:
	vmovups zmm4, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_25_end
raw_hook_restore_x86_avx512fpu_patch_25_end:
.globl raw_hook_restore_x86_avx512fpu_patch_26
raw_hook_restore_x86_avx512fpu_patch_26:
	vmovups zmm5, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_26_end
raw_hook_restore_x86_avx512fpu_patch_26_end:
.globl raw_hook_restore_x86_avx512fpu_patch_27
raw_hook_restore_x86_avx512fpu_patch_27:
	vmovups zmm6, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_27_end
raw_hook_restore_x86_avx512fpu_patch_27_end:
.globl raw_hook_restore_x86_avx512fpu_patch_28
raw_hook_restore_x86_avx512fpu_patch_28:
	vmovups zmm7, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_28_end
raw_hook_restore_x86_avx512fpu_patch_28_end:
.globl raw_hook_restore_x86_avx512fpu_patch_29
raw_hook_restore_x86_avx512fpu_patch_29:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_29_end
raw_hook_restore_x86_avx512fpu_patch_29_end:
.globl raw_hook_restore_x86_avx512fpu_patch_30
raw_hook_restore_x86_avx512fpu_patch_30:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_30_end
raw_hook_restore_x86_avx512fpu_patch_30_end:
	popfd
.globl raw_hook_restore_x86_avx512fpu_patch_31
raw_hook_restore_x86_avx512fpu_patch_31:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_31_end
raw_hook_restore_x86_avx512fpu_patch_31_end:
.globl raw_hook_restore_x86_avx512fpu_patch_32
raw_hook_restore_x86_avx512fpu_patch_32:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_32_end
raw_hook_restore_x86_avx512fpu_patch_32_end:
.globl raw_hook_restore_x86_avx512fpu_patch_33
raw_hook_restore_x86_avx512fpu_patch_33:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_33_end
raw_hook_restore_x86_avx512fpu_patch_33_end:
.globl raw_hook_restore_x86_avx512fpu_patch_34
raw_hook_restore_x86_avx512fpu_patch_34:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_34_end
raw_hook_restore_x86_avx512fpu_patch_34_end:
.globl raw_hook_restore_x86_avx512fpu_patch_35
raw_hook_restore_x86_avx512fpu_patch_35:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_35_end
raw_hook_restore_x86_avx512fpu_patch_35_end:
.globl raw_hook_restore_x86_avx512fpu_patch_36
raw_hook_restore_x86_avx512fpu_patch_36:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_36_end
raw_hook_restore_x86_avx512fpu_patch_36_end:
.globl raw_hook_restore_x86_avx512fpu_patch_37
raw_hook_restore_x86_avx512fpu_patch_37:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_37_end
raw_hook_restore_x86_avx512fpu_patch_37_end:
.globl raw_hook_restore_x86_avx512fpu_patch_38
raw_hook_restore_x86_avx512fpu_patch_38:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512fpu_patch_38_end
raw_hook_restore_x86_avx512fpu_patch_38_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]

# RawHook restore: x86 AVX512
.intel_syntax noprefix
.text
.globl raw_hook_restore_x86_avx512
raw_hook_restore_x86_avx512:
.globl raw_hook_restore_x86_avx512_patch_0
raw_hook_restore_x86_avx512_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_restore_x86_avx512_patch_0_end
raw_hook_restore_x86_avx512_patch_0_end:
.globl raw_hook_restore_x86_avx512_patch_1
raw_hook_restore_x86_avx512_patch_1:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_1_end
raw_hook_restore_x86_avx512_patch_1_end:
	sub eax, 0x4
.globl raw_hook_restore_x86_avx512_patch_2
raw_hook_restore_x86_avx512_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_restore_x86_avx512_patch_2_end
raw_hook_restore_x86_avx512_patch_2_end:
.globl raw_hook_restore_x86_avx512_patch_3
raw_hook_restore_x86_avx512_patch_3:
	mov edx, 0x7fffffff
.globl raw_hook_restore_x86_avx512_patch_3_end
raw_hook_restore_x86_avx512_patch_3_end:
	mov dword ptr [eax], edx
.globl raw_hook_restore_x86_avx512_patch_4
raw_hook_restore_x86_avx512_patch_4:
	vmovups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_4_end
raw_hook_restore_x86_avx512_patch_4_end:
.globl raw_hook_restore_x86_avx512_patch_5
raw_hook_restore_x86_avx512_patch_5:
	vmovups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_5_end
raw_hook_restore_x86_avx512_patch_5_end:
.globl raw_hook_restore_x86_avx512_patch_6
raw_hook_restore_x86_avx512_patch_6:
	vmovups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_6_end
raw_hook_restore_x86_avx512_patch_6_end:
.globl raw_hook_restore_x86_avx512_patch_7
raw_hook_restore_x86_avx512_patch_7:
	vmovups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_7_end
raw_hook_restore_x86_avx512_patch_7_end:
.globl raw_hook_restore_x86_avx512_patch_8
raw_hook_restore_x86_avx512_patch_8:
	vmovups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_8_end
raw_hook_restore_x86_avx512_patch_8_end:
.globl raw_hook_restore_x86_avx512_patch_9
raw_hook_restore_x86_avx512_patch_9:
	vmovups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_9_end
raw_hook_restore_x86_avx512_patch_9_end:
.globl raw_hook_restore_x86_avx512_patch_10
raw_hook_restore_x86_avx512_patch_10:
	vmovups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_10_end
raw_hook_restore_x86_avx512_patch_10_end:
.globl raw_hook_restore_x86_avx512_patch_11
raw_hook_restore_x86_avx512_patch_11:
	vmovups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_11_end
raw_hook_restore_x86_avx512_patch_11_end:
.globl raw_hook_restore_x86_avx512_patch_12
raw_hook_restore_x86_avx512_patch_12:
	vmovups ymm0, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_12_end
raw_hook_restore_x86_avx512_patch_12_end:
.globl raw_hook_restore_x86_avx512_patch_13
raw_hook_restore_x86_avx512_patch_13:
	vmovups ymm1, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_13_end
raw_hook_restore_x86_avx512_patch_13_end:
.globl raw_hook_restore_x86_avx512_patch_14
raw_hook_restore_x86_avx512_patch_14:
	vmovups ymm2, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_14_end
raw_hook_restore_x86_avx512_patch_14_end:
.globl raw_hook_restore_x86_avx512_patch_15
raw_hook_restore_x86_avx512_patch_15:
	vmovups ymm3, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_15_end
raw_hook_restore_x86_avx512_patch_15_end:
.globl raw_hook_restore_x86_avx512_patch_16
raw_hook_restore_x86_avx512_patch_16:
	vmovups ymm4, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_16_end
raw_hook_restore_x86_avx512_patch_16_end:
.globl raw_hook_restore_x86_avx512_patch_17
raw_hook_restore_x86_avx512_patch_17:
	vmovups ymm5, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_17_end
raw_hook_restore_x86_avx512_patch_17_end:
.globl raw_hook_restore_x86_avx512_patch_18
raw_hook_restore_x86_avx512_patch_18:
	vmovups ymm6, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_18_end
raw_hook_restore_x86_avx512_patch_18_end:
.globl raw_hook_restore_x86_avx512_patch_19
raw_hook_restore_x86_avx512_patch_19:
	vmovups ymm7, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_19_end
raw_hook_restore_x86_avx512_patch_19_end:
.globl raw_hook_restore_x86_avx512_patch_20
raw_hook_restore_x86_avx512_patch_20:
	vmovups zmm0, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_20_end
raw_hook_restore_x86_avx512_patch_20_end:
.globl raw_hook_restore_x86_avx512_patch_21
raw_hook_restore_x86_avx512_patch_21:
	vmovups zmm1, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_21_end
raw_hook_restore_x86_avx512_patch_21_end:
.globl raw_hook_restore_x86_avx512_patch_22
raw_hook_restore_x86_avx512_patch_22:
	vmovups zmm2, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_22_end
raw_hook_restore_x86_avx512_patch_22_end:
.globl raw_hook_restore_x86_avx512_patch_23
raw_hook_restore_x86_avx512_patch_23:
	vmovups zmm3, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_23_end
raw_hook_restore_x86_avx512_patch_23_end:
.globl raw_hook_restore_x86_avx512_patch_24
raw_hook_restore_x86_avx512_patch_24:
	vmovups zmm4, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_24_end
raw_hook_restore_x86_avx512_patch_24_end:
.globl raw_hook_restore_x86_avx512_patch_25
raw_hook_restore_x86_avx512_patch_25:
	vmovups zmm5, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_25_end
raw_hook_restore_x86_avx512_patch_25_end:
.globl raw_hook_restore_x86_avx512_patch_26
raw_hook_restore_x86_avx512_patch_26:
	vmovups zmm6, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_26_end
raw_hook_restore_x86_avx512_patch_26_end:
.globl raw_hook_restore_x86_avx512_patch_27
raw_hook_restore_x86_avx512_patch_27:
	vmovups zmm7, zmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_27_end
raw_hook_restore_x86_avx512_patch_27_end:
.globl raw_hook_restore_x86_avx512_patch_28
raw_hook_restore_x86_avx512_patch_28:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_28_end
raw_hook_restore_x86_avx512_patch_28_end:
.globl raw_hook_restore_x86_avx512_patch_29
raw_hook_restore_x86_avx512_patch_29:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_29_end
raw_hook_restore_x86_avx512_patch_29_end:
	popfd
.globl raw_hook_restore_x86_avx512_patch_30
raw_hook_restore_x86_avx512_patch_30:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_30_end
raw_hook_restore_x86_avx512_patch_30_end:
.globl raw_hook_restore_x86_avx512_patch_31
raw_hook_restore_x86_avx512_patch_31:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_31_end
raw_hook_restore_x86_avx512_patch_31_end:
.globl raw_hook_restore_x86_avx512_patch_32
raw_hook_restore_x86_avx512_patch_32:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_32_end
raw_hook_restore_x86_avx512_patch_32_end:
.globl raw_hook_restore_x86_avx512_patch_33
raw_hook_restore_x86_avx512_patch_33:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_33_end
raw_hook_restore_x86_avx512_patch_33_end:
.globl raw_hook_restore_x86_avx512_patch_34
raw_hook_restore_x86_avx512_patch_34:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_34_end
raw_hook_restore_x86_avx512_patch_34_end:
.globl raw_hook_restore_x86_avx512_patch_35
raw_hook_restore_x86_avx512_patch_35:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_35_end
raw_hook_restore_x86_avx512_patch_35_end:
.globl raw_hook_restore_x86_avx512_patch_36
raw_hook_restore_x86_avx512_patch_36:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_36_end
raw_hook_restore_x86_avx512_patch_36_end:
.globl raw_hook_restore_x86_avx512_patch_37
raw_hook_restore_x86_avx512_patch_37:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx512_patch_37_end
raw_hook_restore_x86_avx512_patch_37_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]

# RawHook restore: x86 AVXFPU
.intel_syntax noprefix
.text
.globl raw_hook_restore_x86_avxfpu
raw_hook_restore_x86_avxfpu:
.globl raw_hook_restore_x86_avxfpu_patch_0
raw_hook_restore_x86_avxfpu_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_restore_x86_avxfpu_patch_0_end
raw_hook_restore_x86_avxfpu_patch_0_end:
.globl raw_hook_restore_x86_avxfpu_patch_1
raw_hook_restore_x86_avxfpu_patch_1:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_1_end
raw_hook_restore_x86_avxfpu_patch_1_end:
	sub eax, 0x4
.globl raw_hook_restore_x86_avxfpu_patch_2
raw_hook_restore_x86_avxfpu_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_restore_x86_avxfpu_patch_2_end
raw_hook_restore_x86_avxfpu_patch_2_end:
.globl raw_hook_restore_x86_avxfpu_patch_3
raw_hook_restore_x86_avxfpu_patch_3:
	mov edx, 0x7fffffff
.globl raw_hook_restore_x86_avxfpu_patch_3_end
raw_hook_restore_x86_avxfpu_patch_3_end:
	mov dword ptr [eax], edx
.globl raw_hook_restore_x86_avxfpu_patch_4
raw_hook_restore_x86_avxfpu_patch_4:
	frstor [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_4_end
raw_hook_restore_x86_avxfpu_patch_4_end:
.globl raw_hook_restore_x86_avxfpu_patch_5
raw_hook_restore_x86_avxfpu_patch_5:
	vmovups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_5_end
raw_hook_restore_x86_avxfpu_patch_5_end:
.globl raw_hook_restore_x86_avxfpu_patch_6
raw_hook_restore_x86_avxfpu_patch_6:
	vmovups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_6_end
raw_hook_restore_x86_avxfpu_patch_6_end:
.globl raw_hook_restore_x86_avxfpu_patch_7
raw_hook_restore_x86_avxfpu_patch_7:
	vmovups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_7_end
raw_hook_restore_x86_avxfpu_patch_7_end:
.globl raw_hook_restore_x86_avxfpu_patch_8
raw_hook_restore_x86_avxfpu_patch_8:
	vmovups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_8_end
raw_hook_restore_x86_avxfpu_patch_8_end:
.globl raw_hook_restore_x86_avxfpu_patch_9
raw_hook_restore_x86_avxfpu_patch_9:
	vmovups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_9_end
raw_hook_restore_x86_avxfpu_patch_9_end:
.globl raw_hook_restore_x86_avxfpu_patch_10
raw_hook_restore_x86_avxfpu_patch_10:
	vmovups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_10_end
raw_hook_restore_x86_avxfpu_patch_10_end:
.globl raw_hook_restore_x86_avxfpu_patch_11
raw_hook_restore_x86_avxfpu_patch_11:
	vmovups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_11_end
raw_hook_restore_x86_avxfpu_patch_11_end:
.globl raw_hook_restore_x86_avxfpu_patch_12
raw_hook_restore_x86_avxfpu_patch_12:
	vmovups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_12_end
raw_hook_restore_x86_avxfpu_patch_12_end:
.globl raw_hook_restore_x86_avxfpu_patch_13
raw_hook_restore_x86_avxfpu_patch_13:
	vmovups ymm0, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_13_end
raw_hook_restore_x86_avxfpu_patch_13_end:
.globl raw_hook_restore_x86_avxfpu_patch_14
raw_hook_restore_x86_avxfpu_patch_14:
	vmovups ymm1, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_14_end
raw_hook_restore_x86_avxfpu_patch_14_end:
.globl raw_hook_restore_x86_avxfpu_patch_15
raw_hook_restore_x86_avxfpu_patch_15:
	vmovups ymm2, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_15_end
raw_hook_restore_x86_avxfpu_patch_15_end:
.globl raw_hook_restore_x86_avxfpu_patch_16
raw_hook_restore_x86_avxfpu_patch_16:
	vmovups ymm3, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_16_end
raw_hook_restore_x86_avxfpu_patch_16_end:
.globl raw_hook_restore_x86_avxfpu_patch_17
raw_hook_restore_x86_avxfpu_patch_17:
	vmovups ymm4, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_17_end
raw_hook_restore_x86_avxfpu_patch_17_end:
.globl raw_hook_restore_x86_avxfpu_patch_18
raw_hook_restore_x86_avxfpu_patch_18:
	vmovups ymm5, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_18_end
raw_hook_restore_x86_avxfpu_patch_18_end:
.globl raw_hook_restore_x86_avxfpu_patch_19
raw_hook_restore_x86_avxfpu_patch_19:
	vmovups ymm6, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_19_end
raw_hook_restore_x86_avxfpu_patch_19_end:
.globl raw_hook_restore_x86_avxfpu_patch_20
raw_hook_restore_x86_avxfpu_patch_20:
	vmovups ymm7, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_20_end
raw_hook_restore_x86_avxfpu_patch_20_end:
.globl raw_hook_restore_x86_avxfpu_patch_21
raw_hook_restore_x86_avxfpu_patch_21:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_21_end
raw_hook_restore_x86_avxfpu_patch_21_end:
.globl raw_hook_restore_x86_avxfpu_patch_22
raw_hook_restore_x86_avxfpu_patch_22:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_22_end
raw_hook_restore_x86_avxfpu_patch_22_end:
	popfd
.globl raw_hook_restore_x86_avxfpu_patch_23
raw_hook_restore_x86_avxfpu_patch_23:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_23_end
raw_hook_restore_x86_avxfpu_patch_23_end:
.globl raw_hook_restore_x86_avxfpu_patch_24
raw_hook_restore_x86_avxfpu_patch_24:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_24_end
raw_hook_restore_x86_avxfpu_patch_24_end:
.globl raw_hook_restore_x86_avxfpu_patch_25
raw_hook_restore_x86_avxfpu_patch_25:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_25_end
raw_hook_restore_x86_avxfpu_patch_25_end:
.globl raw_hook_restore_x86_avxfpu_patch_26
raw_hook_restore_x86_avxfpu_patch_26:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_26_end
raw_hook_restore_x86_avxfpu_patch_26_end:
.globl raw_hook_restore_x86_avxfpu_patch_27
raw_hook_restore_x86_avxfpu_patch_27:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_27_end
raw_hook_restore_x86_avxfpu_patch_27_end:
.globl raw_hook_restore_x86_avxfpu_patch_28
raw_hook_restore_x86_avxfpu_patch_28:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_28_end
raw_hook_restore_x86_avxfpu_patch_28_end:
.globl raw_hook_restore_x86_avxfpu_patch_29
raw_hook_restore_x86_avxfpu_patch_29:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_29_end
raw_hook_restore_x86_avxfpu_patch_29_end:
.globl raw_hook_restore_x86_avxfpu_patch_30
raw_hook_restore_x86_avxfpu_patch_30:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avxfpu_patch_30_end
raw_hook_restore_x86_avxfpu_patch_30_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]

# RawHook restore: x86 AVX
.intel_syntax noprefix
.text
.globl raw_hook_restore_x86_avx
raw_hook_restore_x86_avx:
.globl raw_hook_restore_x86_avx_patch_0
raw_hook_restore_x86_avx_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_restore_x86_avx_patch_0_end
raw_hook_restore_x86_avx_patch_0_end:
.globl raw_hook_restore_x86_avx_patch_1
raw_hook_restore_x86_avx_patch_1:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_1_end
raw_hook_restore_x86_avx_patch_1_end:
	sub eax, 0x4
.globl raw_hook_restore_x86_avx_patch_2
raw_hook_restore_x86_avx_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_restore_x86_avx_patch_2_end
raw_hook_restore_x86_avx_patch_2_end:
.globl raw_hook_restore_x86_avx_patch_3
raw_hook_restore_x86_avx_patch_3:
	mov edx, 0x7fffffff
.globl raw_hook_restore_x86_avx_patch_3_end
raw_hook_restore_x86_avx_patch_3_end:
	mov dword ptr [eax], edx
.globl raw_hook_restore_x86_avx_patch_4
raw_hook_restore_x86_avx_patch_4:
	vmovups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_4_end
raw_hook_restore_x86_avx_patch_4_end:
.globl raw_hook_restore_x86_avx_patch_5
raw_hook_restore_x86_avx_patch_5:
	vmovups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_5_end
raw_hook_restore_x86_avx_patch_5_end:
.globl raw_hook_restore_x86_avx_patch_6
raw_hook_restore_x86_avx_patch_6:
	vmovups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_6_end
raw_hook_restore_x86_avx_patch_6_end:
.globl raw_hook_restore_x86_avx_patch_7
raw_hook_restore_x86_avx_patch_7:
	vmovups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_7_end
raw_hook_restore_x86_avx_patch_7_end:
.globl raw_hook_restore_x86_avx_patch_8
raw_hook_restore_x86_avx_patch_8:
	vmovups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_8_end
raw_hook_restore_x86_avx_patch_8_end:
.globl raw_hook_restore_x86_avx_patch_9
raw_hook_restore_x86_avx_patch_9:
	vmovups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_9_end
raw_hook_restore_x86_avx_patch_9_end:
.globl raw_hook_restore_x86_avx_patch_10
raw_hook_restore_x86_avx_patch_10:
	vmovups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_10_end
raw_hook_restore_x86_avx_patch_10_end:
.globl raw_hook_restore_x86_avx_patch_11
raw_hook_restore_x86_avx_patch_11:
	vmovups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_11_end
raw_hook_restore_x86_avx_patch_11_end:
.globl raw_hook_restore_x86_avx_patch_12
raw_hook_restore_x86_avx_patch_12:
	vmovups ymm0, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_12_end
raw_hook_restore_x86_avx_patch_12_end:
.globl raw_hook_restore_x86_avx_patch_13
raw_hook_restore_x86_avx_patch_13:
	vmovups ymm1, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_13_end
raw_hook_restore_x86_avx_patch_13_end:
.globl raw_hook_restore_x86_avx_patch_14
raw_hook_restore_x86_avx_patch_14:
	vmovups ymm2, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_14_end
raw_hook_restore_x86_avx_patch_14_end:
.globl raw_hook_restore_x86_avx_patch_15
raw_hook_restore_x86_avx_patch_15:
	vmovups ymm3, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_15_end
raw_hook_restore_x86_avx_patch_15_end:
.globl raw_hook_restore_x86_avx_patch_16
raw_hook_restore_x86_avx_patch_16:
	vmovups ymm4, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_16_end
raw_hook_restore_x86_avx_patch_16_end:
.globl raw_hook_restore_x86_avx_patch_17
raw_hook_restore_x86_avx_patch_17:
	vmovups ymm5, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_17_end
raw_hook_restore_x86_avx_patch_17_end:
.globl raw_hook_restore_x86_avx_patch_18
raw_hook_restore_x86_avx_patch_18:
	vmovups ymm6, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_18_end
raw_hook_restore_x86_avx_patch_18_end:
.globl raw_hook_restore_x86_avx_patch_19
raw_hook_restore_x86_avx_patch_19:
	vmovups ymm7, ymmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_19_end
raw_hook_restore_x86_avx_patch_19_end:
.globl raw_hook_restore_x86_avx_patch_20
raw_hook_restore_x86_avx_patch_20:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_20_end
raw_hook_restore_x86_avx_patch_20_end:
.globl raw_hook_restore_x86_avx_patch_21
raw_hook_restore_x86_avx_patch_21:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_21_end
raw_hook_restore_x86_avx_patch_21_end:
	popfd
.globl raw_hook_restore_x86_avx_patch_22
raw_hook_restore_x86_avx_patch_22:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_22_end
raw_hook_restore_x86_avx_patch_22_end:
.globl raw_hook_restore_x86_avx_patch_23
raw_hook_restore_x86_avx_patch_23:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_23_end
raw_hook_restore_x86_avx_patch_23_end:
.globl raw_hook_restore_x86_avx_patch_24
raw_hook_restore_x86_avx_patch_24:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_24_end
raw_hook_restore_x86_avx_patch_24_end:
.globl raw_hook_restore_x86_avx_patch_25
raw_hook_restore_x86_avx_patch_25:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_25_end
raw_hook_restore_x86_avx_patch_25_end:
.globl raw_hook_restore_x86_avx_patch_26
raw_hook_restore_x86_avx_patch_26:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_26_end
raw_hook_restore_x86_avx_patch_26_end:
.globl raw_hook_restore_x86_avx_patch_27
raw_hook_restore_x86_avx_patch_27:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_27_end
raw_hook_restore_x86_avx_patch_27_end:
.globl raw_hook_restore_x86_avx_patch_28
raw_hook_restore_x86_avx_patch_28:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_28_end
raw_hook_restore_x86_avx_patch_28_end:
.globl raw_hook_restore_x86_avx_patch_29
raw_hook_restore_x86_avx_patch_29:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_avx_patch_29_end
raw_hook_restore_x86_avx_patch_29_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]

# RawHook restore: x86 SSEFPU
.intel_syntax noprefix
.text
.globl raw_hook_restore_x86_ssefpu
raw_hook_restore_x86_ssefpu:
.globl raw_hook_restore_x86_ssefpu_patch_0
raw_hook_restore_x86_ssefpu_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_restore_x86_ssefpu_patch_0_end
raw_hook_restore_x86_ssefpu_patch_0_end:
.globl raw_hook_restore_x86_ssefpu_patch_1
raw_hook_restore_x86_ssefpu_patch_1:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_1_end
raw_hook_restore_x86_ssefpu_patch_1_end:
	sub eax, 0x4
.globl raw_hook_restore_x86_ssefpu_patch_2
raw_hook_restore_x86_ssefpu_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_restore_x86_ssefpu_patch_2_end
raw_hook_restore_x86_ssefpu_patch_2_end:
.globl raw_hook_restore_x86_ssefpu_patch_3
raw_hook_restore_x86_ssefpu_patch_3:
	mov edx, 0x7fffffff
.globl raw_hook_restore_x86_ssefpu_patch_3_end
raw_hook_restore_x86_ssefpu_patch_3_end:
	mov dword ptr [eax], edx
.globl raw_hook_restore_x86_ssefpu_patch_4
raw_hook_restore_x86_ssefpu_patch_4:
	frstor [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_4_end
raw_hook_restore_x86_ssefpu_patch_4_end:
.globl raw_hook_restore_x86_ssefpu_patch_5
raw_hook_restore_x86_ssefpu_patch_5:
	movups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_5_end
raw_hook_restore_x86_ssefpu_patch_5_end:
.globl raw_hook_restore_x86_ssefpu_patch_6
raw_hook_restore_x86_ssefpu_patch_6:
	movups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_6_end
raw_hook_restore_x86_ssefpu_patch_6_end:
.globl raw_hook_restore_x86_ssefpu_patch_7
raw_hook_restore_x86_ssefpu_patch_7:
	movups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_7_end
raw_hook_restore_x86_ssefpu_patch_7_end:
.globl raw_hook_restore_x86_ssefpu_patch_8
raw_hook_restore_x86_ssefpu_patch_8:
	movups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_8_end
raw_hook_restore_x86_ssefpu_patch_8_end:
.globl raw_hook_restore_x86_ssefpu_patch_9
raw_hook_restore_x86_ssefpu_patch_9:
	movups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_9_end
raw_hook_restore_x86_ssefpu_patch_9_end:
.globl raw_hook_restore_x86_ssefpu_patch_10
raw_hook_restore_x86_ssefpu_patch_10:
	movups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_10_end
raw_hook_restore_x86_ssefpu_patch_10_end:
.globl raw_hook_restore_x86_ssefpu_patch_11
raw_hook_restore_x86_ssefpu_patch_11:
	movups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_11_end
raw_hook_restore_x86_ssefpu_patch_11_end:
.globl raw_hook_restore_x86_ssefpu_patch_12
raw_hook_restore_x86_ssefpu_patch_12:
	movups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_12_end
raw_hook_restore_x86_ssefpu_patch_12_end:
.globl raw_hook_restore_x86_ssefpu_patch_13
raw_hook_restore_x86_ssefpu_patch_13:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_13_end
raw_hook_restore_x86_ssefpu_patch_13_end:
.globl raw_hook_restore_x86_ssefpu_patch_14
raw_hook_restore_x86_ssefpu_patch_14:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_14_end
raw_hook_restore_x86_ssefpu_patch_14_end:
	popfd
.globl raw_hook_restore_x86_ssefpu_patch_15
raw_hook_restore_x86_ssefpu_patch_15:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_15_end
raw_hook_restore_x86_ssefpu_patch_15_end:
.globl raw_hook_restore_x86_ssefpu_patch_16
raw_hook_restore_x86_ssefpu_patch_16:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_16_end
raw_hook_restore_x86_ssefpu_patch_16_end:
.globl raw_hook_restore_x86_ssefpu_patch_17
raw_hook_restore_x86_ssefpu_patch_17:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_17_end
raw_hook_restore_x86_ssefpu_patch_17_end:
.globl raw_hook_restore_x86_ssefpu_patch_18
raw_hook_restore_x86_ssefpu_patch_18:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_18_end
raw_hook_restore_x86_ssefpu_patch_18_end:
.globl raw_hook_restore_x86_ssefpu_patch_19
raw_hook_restore_x86_ssefpu_patch_19:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_19_end
raw_hook_restore_x86_ssefpu_patch_19_end:
.globl raw_hook_restore_x86_ssefpu_patch_20
raw_hook_restore_x86_ssefpu_patch_20:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_20_end
raw_hook_restore_x86_ssefpu_patch_20_end:
.globl raw_hook_restore_x86_ssefpu_patch_21
raw_hook_restore_x86_ssefpu_patch_21:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_21_end
raw_hook_restore_x86_ssefpu_patch_21_end:
.globl raw_hook_restore_x86_ssefpu_patch_22
raw_hook_restore_x86_ssefpu_patch_22:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_ssefpu_patch_22_end
raw_hook_restore_x86_ssefpu_patch_22_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]

# RawHook restore: x86 SSE
.intel_syntax noprefix
.text
.globl raw_hook_restore_x86_sse
raw_hook_restore_x86_sse:
.globl raw_hook_restore_x86_sse_patch_0
raw_hook_restore_x86_sse_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_restore_x86_sse_patch_0_end
raw_hook_restore_x86_sse_patch_0_end:
.globl raw_hook_restore_x86_sse_patch_1
raw_hook_restore_x86_sse_patch_1:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_1_end
raw_hook_restore_x86_sse_patch_1_end:
	sub eax, 0x4
.globl raw_hook_restore_x86_sse_patch_2
raw_hook_restore_x86_sse_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_restore_x86_sse_patch_2_end
raw_hook_restore_x86_sse_patch_2_end:
.globl raw_hook_restore_x86_sse_patch_3
raw_hook_restore_x86_sse_patch_3:
	mov edx, 0x7fffffff
.globl raw_hook_restore_x86_sse_patch_3_end
raw_hook_restore_x86_sse_patch_3_end:
	mov dword ptr [eax], edx
.globl raw_hook_restore_x86_sse_patch_4
raw_hook_restore_x86_sse_patch_4:
	movups xmm0, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_4_end
raw_hook_restore_x86_sse_patch_4_end:
.globl raw_hook_restore_x86_sse_patch_5
raw_hook_restore_x86_sse_patch_5:
	movups xmm1, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_5_end
raw_hook_restore_x86_sse_patch_5_end:
.globl raw_hook_restore_x86_sse_patch_6
raw_hook_restore_x86_sse_patch_6:
	movups xmm2, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_6_end
raw_hook_restore_x86_sse_patch_6_end:
.globl raw_hook_restore_x86_sse_patch_7
raw_hook_restore_x86_sse_patch_7:
	movups xmm3, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_7_end
raw_hook_restore_x86_sse_patch_7_end:
.globl raw_hook_restore_x86_sse_patch_8
raw_hook_restore_x86_sse_patch_8:
	movups xmm4, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_8_end
raw_hook_restore_x86_sse_patch_8_end:
.globl raw_hook_restore_x86_sse_patch_9
raw_hook_restore_x86_sse_patch_9:
	movups xmm5, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_9_end
raw_hook_restore_x86_sse_patch_9_end:
.globl raw_hook_restore_x86_sse_patch_10
raw_hook_restore_x86_sse_patch_10:
	movups xmm6, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_10_end
raw_hook_restore_x86_sse_patch_10_end:
.globl raw_hook_restore_x86_sse_patch_11
raw_hook_restore_x86_sse_patch_11:
	movups xmm7, xmmword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_11_end
raw_hook_restore_x86_sse_patch_11_end:
.globl raw_hook_restore_x86_sse_patch_12
raw_hook_restore_x86_sse_patch_12:
	ldmxcsr dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_12_end
raw_hook_restore_x86_sse_patch_12_end:
.globl raw_hook_restore_x86_sse_patch_13
raw_hook_restore_x86_sse_patch_13:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_13_end
raw_hook_restore_x86_sse_patch_13_end:
	popfd
.globl raw_hook_restore_x86_sse_patch_14
raw_hook_restore_x86_sse_patch_14:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_14_end
raw_hook_restore_x86_sse_patch_14_end:
.globl raw_hook_restore_x86_sse_patch_15
raw_hook_restore_x86_sse_patch_15:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_15_end
raw_hook_restore_x86_sse_patch_15_end:
.globl raw_hook_restore_x86_sse_patch_16
raw_hook_restore_x86_sse_patch_16:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_16_end
raw_hook_restore_x86_sse_patch_16_end:
.globl raw_hook_restore_x86_sse_patch_17
raw_hook_restore_x86_sse_patch_17:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_17_end
raw_hook_restore_x86_sse_patch_17_end:
.globl raw_hook_restore_x86_sse_patch_18
raw_hook_restore_x86_sse_patch_18:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_18_end
raw_hook_restore_x86_sse_patch_18_end:
.globl raw_hook_restore_x86_sse_patch_19
raw_hook_restore_x86_sse_patch_19:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_19_end
raw_hook_restore_x86_sse_patch_19_end:
.globl raw_hook_restore_x86_sse_patch_20
raw_hook_restore_x86_sse_patch_20:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_20_end
raw_hook_restore_x86_sse_patch_20_end:
.globl raw_hook_restore_x86_sse_patch_21
raw_hook_restore_x86_sse_patch_21:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_sse_patch_21_end
raw_hook_restore_x86_sse_patch_21_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]

# RawHook restore: x86 FPU
.intel_syntax noprefix
.text
.globl raw_hook_restore_x86_fpu
raw_hook_restore_x86_fpu:
.globl raw_hook_restore_x86_fpu_patch_0
raw_hook_restore_x86_fpu_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_restore_x86_fpu_patch_0_end
raw_hook_restore_x86_fpu_patch_0_end:
.globl raw_hook_restore_x86_fpu_patch_1
raw_hook_restore_x86_fpu_patch_1:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_1_end
raw_hook_restore_x86_fpu_patch_1_end:
	sub eax, 0x4
.globl raw_hook_restore_x86_fpu_patch_2
raw_hook_restore_x86_fpu_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_restore_x86_fpu_patch_2_end
raw_hook_restore_x86_fpu_patch_2_end:
.globl raw_hook_restore_x86_fpu_patch_3
raw_hook_restore_x86_fpu_patch_3:
	mov edx, 0x7fffffff
.globl raw_hook_restore_x86_fpu_patch_3_end
raw_hook_restore_x86_fpu_patch_3_end:
	mov dword ptr [eax], edx
.globl raw_hook_restore_x86_fpu_patch_4
raw_hook_restore_x86_fpu_patch_4:
	frstor [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_4_end
raw_hook_restore_x86_fpu_patch_4_end:
.globl raw_hook_restore_x86_fpu_patch_5
raw_hook_restore_x86_fpu_patch_5:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_5_end
raw_hook_restore_x86_fpu_patch_5_end:
	popfd
.globl raw_hook_restore_x86_fpu_patch_6
raw_hook_restore_x86_fpu_patch_6:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_6_end
raw_hook_restore_x86_fpu_patch_6_end:
.globl raw_hook_restore_x86_fpu_patch_7
raw_hook_restore_x86_fpu_patch_7:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_7_end
raw_hook_restore_x86_fpu_patch_7_end:
.globl raw_hook_restore_x86_fpu_patch_8
raw_hook_restore_x86_fpu_patch_8:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_8_end
raw_hook_restore_x86_fpu_patch_8_end:
.globl raw_hook_restore_x86_fpu_patch_9
raw_hook_restore_x86_fpu_patch_9:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_9_end
raw_hook_restore_x86_fpu_patch_9_end:
.globl raw_hook_restore_x86_fpu_patch_10
raw_hook_restore_x86_fpu_patch_10:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_10_end
raw_hook_restore_x86_fpu_patch_10_end:
.globl raw_hook_restore_x86_fpu_patch_11
raw_hook_restore_x86_fpu_patch_11:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_11_end
raw_hook_restore_x86_fpu_patch_11_end:
.globl raw_hook_restore_x86_fpu_patch_12
raw_hook_restore_x86_fpu_patch_12:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_12_end
raw_hook_restore_x86_fpu_patch_12_end:
.globl raw_hook_restore_x86_fpu_patch_13
raw_hook_restore_x86_fpu_patch_13:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_fpu_patch_13_end
raw_hook_restore_x86_fpu_patch_13_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]

# RawHook restore: x86 Native
.intel_syntax noprefix
.text
.globl raw_hook_restore_x86_native
raw_hook_restore_x86_native:
.globl raw_hook_restore_x86_native_patch_0
raw_hook_restore_x86_native_patch_0:
	sub esp, 0x7fffffff
.globl raw_hook_restore_x86_native_patch_0_end
raw_hook_restore_x86_native_patch_0_end:
.globl raw_hook_restore_x86_native_patch_1
raw_hook_restore_x86_native_patch_1:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_1_end
raw_hook_restore_x86_native_patch_1_end:
	sub eax, 0x4
.globl raw_hook_restore_x86_native_patch_2
raw_hook_restore_x86_native_patch_2:
	mov dword ptr [esp + 0x7fffffff], eax
.globl raw_hook_restore_x86_native_patch_2_end
raw_hook_restore_x86_native_patch_2_end:
.globl raw_hook_restore_x86_native_patch_3
raw_hook_restore_x86_native_patch_3:
	mov edx, 0x7fffffff
.globl raw_hook_restore_x86_native_patch_3_end
raw_hook_restore_x86_native_patch_3_end:
	mov dword ptr [eax], edx
.globl raw_hook_restore_x86_native_patch_4
raw_hook_restore_x86_native_patch_4:
	push dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_4_end
raw_hook_restore_x86_native_patch_4_end:
	popfd
.globl raw_hook_restore_x86_native_patch_5
raw_hook_restore_x86_native_patch_5:
	mov edi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_5_end
raw_hook_restore_x86_native_patch_5_end:
.globl raw_hook_restore_x86_native_patch_6
raw_hook_restore_x86_native_patch_6:
	mov esi, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_6_end
raw_hook_restore_x86_native_patch_6_end:
.globl raw_hook_restore_x86_native_patch_7
raw_hook_restore_x86_native_patch_7:
	mov ebp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_7_end
raw_hook_restore_x86_native_patch_7_end:
.globl raw_hook_restore_x86_native_patch_8
raw_hook_restore_x86_native_patch_8:
	mov ebx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_8_end
raw_hook_restore_x86_native_patch_8_end:
.globl raw_hook_restore_x86_native_patch_9
raw_hook_restore_x86_native_patch_9:
	mov edx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_9_end
raw_hook_restore_x86_native_patch_9_end:
.globl raw_hook_restore_x86_native_patch_10
raw_hook_restore_x86_native_patch_10:
	mov ecx, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_10_end
raw_hook_restore_x86_native_patch_10_end:
.globl raw_hook_restore_x86_native_patch_11
raw_hook_restore_x86_native_patch_11:
	mov eax, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_11_end
raw_hook_restore_x86_native_patch_11_end:
.globl raw_hook_restore_x86_native_patch_12
raw_hook_restore_x86_native_patch_12:
	mov esp, dword ptr [esp + 0x7fffffff]
.globl raw_hook_restore_x86_native_patch_12_end
raw_hook_restore_x86_native_patch_12_end:
	lea esp, [esp + 0x4]
	jmp dword ptr [esp - 0x4]

# GetCurrentContext: x86 AVX512FPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x86_cdecl_avx512fpu
raw_get_current_context_x86_cdecl_avx512fpu:
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov edi, dword ptr [esp + 0x24]
	mov eax, dword ptr [esp + 0x1C]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_0
raw_get_current_context_x86_cdecl_avx512fpu_patch_0:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_0_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_0_end:
	mov eax, dword ptr [esp + 0x18]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_1
raw_get_current_context_x86_cdecl_avx512fpu_patch_1:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_1_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_1_end:
	mov eax, dword ptr [esp + 0x14]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_2
raw_get_current_context_x86_cdecl_avx512fpu_patch_2:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_2_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_2_end:
	mov eax, dword ptr [esp + 0x10]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_3
raw_get_current_context_x86_cdecl_avx512fpu_patch_3:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_3_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_3_end:
	mov eax, dword ptr [esp + 0xc]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_4
raw_get_current_context_x86_cdecl_avx512fpu_patch_4:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_4_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_4_end:
	lea eax, [esp + 0x20]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_5
raw_get_current_context_x86_cdecl_avx512fpu_patch_5:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_5_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_5_end:
	mov eax, dword ptr [esp + 0x8]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_6
raw_get_current_context_x86_cdecl_avx512fpu_patch_6:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_6_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_6_end:
	mov eax, dword ptr [esp + 0x4]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_7
raw_get_current_context_x86_cdecl_avx512fpu_patch_7:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_7_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_7_end:
	mov eax, dword ptr [esp + 0x0]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_8
raw_get_current_context_x86_cdecl_avx512fpu_patch_8:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_8_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_8_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_9
raw_get_current_context_x86_cdecl_avx512fpu_patch_9:
	stmxcsr dword ptr [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_9_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_9_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_10
raw_get_current_context_x86_cdecl_avx512fpu_patch_10:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm0
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_10_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_10_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_11
raw_get_current_context_x86_cdecl_avx512fpu_patch_11:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm1
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_11_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_11_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_12
raw_get_current_context_x86_cdecl_avx512fpu_patch_12:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm2
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_12_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_12_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_13
raw_get_current_context_x86_cdecl_avx512fpu_patch_13:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm3
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_13_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_13_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_14
raw_get_current_context_x86_cdecl_avx512fpu_patch_14:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm4
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_14_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_14_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_15
raw_get_current_context_x86_cdecl_avx512fpu_patch_15:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm5
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_15_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_15_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_16
raw_get_current_context_x86_cdecl_avx512fpu_patch_16:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm6
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_16_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_16_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_17
raw_get_current_context_x86_cdecl_avx512fpu_patch_17:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm7
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_17_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_17_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_18
raw_get_current_context_x86_cdecl_avx512fpu_patch_18:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm0
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_18_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_18_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_19
raw_get_current_context_x86_cdecl_avx512fpu_patch_19:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm1
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_19_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_19_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_20
raw_get_current_context_x86_cdecl_avx512fpu_patch_20:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm2
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_20_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_20_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_21
raw_get_current_context_x86_cdecl_avx512fpu_patch_21:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm3
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_21_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_21_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_22
raw_get_current_context_x86_cdecl_avx512fpu_patch_22:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm4
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_22_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_22_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_23
raw_get_current_context_x86_cdecl_avx512fpu_patch_23:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm5
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_23_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_23_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_24
raw_get_current_context_x86_cdecl_avx512fpu_patch_24:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm6
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_24_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_24_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_25
raw_get_current_context_x86_cdecl_avx512fpu_patch_25:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm7
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_25_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_25_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_26
raw_get_current_context_x86_cdecl_avx512fpu_patch_26:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm0
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_26_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_26_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_27
raw_get_current_context_x86_cdecl_avx512fpu_patch_27:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm1
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_27_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_27_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_28
raw_get_current_context_x86_cdecl_avx512fpu_patch_28:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm2
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_28_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_28_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_29
raw_get_current_context_x86_cdecl_avx512fpu_patch_29:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm3
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_29_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_29_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_30
raw_get_current_context_x86_cdecl_avx512fpu_patch_30:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm4
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_30_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_30_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_31
raw_get_current_context_x86_cdecl_avx512fpu_patch_31:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm5
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_31_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_31_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_32
raw_get_current_context_x86_cdecl_avx512fpu_patch_32:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm6
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_32_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_32_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_33
raw_get_current_context_x86_cdecl_avx512fpu_patch_33:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm7
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_33_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_33_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_34
raw_get_current_context_x86_cdecl_avx512fpu_patch_34:
	fsave [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_34_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_34_end:
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_35
raw_get_current_context_x86_cdecl_avx512fpu_patch_35:
	frstor [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_avx512fpu_patch_35_end
raw_get_current_context_x86_cdecl_avx512fpu_patch_35_end:
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret

# GetCurrentContext: x86 AVX512
.intel_syntax noprefix
.text
.globl raw_get_current_context_x86_cdecl_avx512
raw_get_current_context_x86_cdecl_avx512:
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov edi, dword ptr [esp + 0x24]
	mov eax, dword ptr [esp + 0x1C]
.globl raw_get_current_context_x86_cdecl_avx512_patch_0
raw_get_current_context_x86_cdecl_avx512_patch_0:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_0_end
raw_get_current_context_x86_cdecl_avx512_patch_0_end:
	mov eax, dword ptr [esp + 0x18]
.globl raw_get_current_context_x86_cdecl_avx512_patch_1
raw_get_current_context_x86_cdecl_avx512_patch_1:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_1_end
raw_get_current_context_x86_cdecl_avx512_patch_1_end:
	mov eax, dword ptr [esp + 0x14]
.globl raw_get_current_context_x86_cdecl_avx512_patch_2
raw_get_current_context_x86_cdecl_avx512_patch_2:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_2_end
raw_get_current_context_x86_cdecl_avx512_patch_2_end:
	mov eax, dword ptr [esp + 0x10]
.globl raw_get_current_context_x86_cdecl_avx512_patch_3
raw_get_current_context_x86_cdecl_avx512_patch_3:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_3_end
raw_get_current_context_x86_cdecl_avx512_patch_3_end:
	mov eax, dword ptr [esp + 0xc]
.globl raw_get_current_context_x86_cdecl_avx512_patch_4
raw_get_current_context_x86_cdecl_avx512_patch_4:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_4_end
raw_get_current_context_x86_cdecl_avx512_patch_4_end:
	lea eax, [esp + 0x20]
.globl raw_get_current_context_x86_cdecl_avx512_patch_5
raw_get_current_context_x86_cdecl_avx512_patch_5:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_5_end
raw_get_current_context_x86_cdecl_avx512_patch_5_end:
	mov eax, dword ptr [esp + 0x8]
.globl raw_get_current_context_x86_cdecl_avx512_patch_6
raw_get_current_context_x86_cdecl_avx512_patch_6:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_6_end
raw_get_current_context_x86_cdecl_avx512_patch_6_end:
	mov eax, dword ptr [esp + 0x4]
.globl raw_get_current_context_x86_cdecl_avx512_patch_7
raw_get_current_context_x86_cdecl_avx512_patch_7:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_7_end
raw_get_current_context_x86_cdecl_avx512_patch_7_end:
	mov eax, dword ptr [esp + 0x0]
.globl raw_get_current_context_x86_cdecl_avx512_patch_8
raw_get_current_context_x86_cdecl_avx512_patch_8:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx512_patch_8_end
raw_get_current_context_x86_cdecl_avx512_patch_8_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_9
raw_get_current_context_x86_cdecl_avx512_patch_9:
	stmxcsr dword ptr [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_avx512_patch_9_end
raw_get_current_context_x86_cdecl_avx512_patch_9_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_10
raw_get_current_context_x86_cdecl_avx512_patch_10:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm0
.globl raw_get_current_context_x86_cdecl_avx512_patch_10_end
raw_get_current_context_x86_cdecl_avx512_patch_10_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_11
raw_get_current_context_x86_cdecl_avx512_patch_11:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm1
.globl raw_get_current_context_x86_cdecl_avx512_patch_11_end
raw_get_current_context_x86_cdecl_avx512_patch_11_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_12
raw_get_current_context_x86_cdecl_avx512_patch_12:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm2
.globl raw_get_current_context_x86_cdecl_avx512_patch_12_end
raw_get_current_context_x86_cdecl_avx512_patch_12_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_13
raw_get_current_context_x86_cdecl_avx512_patch_13:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm3
.globl raw_get_current_context_x86_cdecl_avx512_patch_13_end
raw_get_current_context_x86_cdecl_avx512_patch_13_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_14
raw_get_current_context_x86_cdecl_avx512_patch_14:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm4
.globl raw_get_current_context_x86_cdecl_avx512_patch_14_end
raw_get_current_context_x86_cdecl_avx512_patch_14_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_15
raw_get_current_context_x86_cdecl_avx512_patch_15:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm5
.globl raw_get_current_context_x86_cdecl_avx512_patch_15_end
raw_get_current_context_x86_cdecl_avx512_patch_15_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_16
raw_get_current_context_x86_cdecl_avx512_patch_16:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm6
.globl raw_get_current_context_x86_cdecl_avx512_patch_16_end
raw_get_current_context_x86_cdecl_avx512_patch_16_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_17
raw_get_current_context_x86_cdecl_avx512_patch_17:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm7
.globl raw_get_current_context_x86_cdecl_avx512_patch_17_end
raw_get_current_context_x86_cdecl_avx512_patch_17_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_18
raw_get_current_context_x86_cdecl_avx512_patch_18:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm0
.globl raw_get_current_context_x86_cdecl_avx512_patch_18_end
raw_get_current_context_x86_cdecl_avx512_patch_18_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_19
raw_get_current_context_x86_cdecl_avx512_patch_19:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm1
.globl raw_get_current_context_x86_cdecl_avx512_patch_19_end
raw_get_current_context_x86_cdecl_avx512_patch_19_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_20
raw_get_current_context_x86_cdecl_avx512_patch_20:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm2
.globl raw_get_current_context_x86_cdecl_avx512_patch_20_end
raw_get_current_context_x86_cdecl_avx512_patch_20_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_21
raw_get_current_context_x86_cdecl_avx512_patch_21:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm3
.globl raw_get_current_context_x86_cdecl_avx512_patch_21_end
raw_get_current_context_x86_cdecl_avx512_patch_21_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_22
raw_get_current_context_x86_cdecl_avx512_patch_22:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm4
.globl raw_get_current_context_x86_cdecl_avx512_patch_22_end
raw_get_current_context_x86_cdecl_avx512_patch_22_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_23
raw_get_current_context_x86_cdecl_avx512_patch_23:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm5
.globl raw_get_current_context_x86_cdecl_avx512_patch_23_end
raw_get_current_context_x86_cdecl_avx512_patch_23_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_24
raw_get_current_context_x86_cdecl_avx512_patch_24:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm6
.globl raw_get_current_context_x86_cdecl_avx512_patch_24_end
raw_get_current_context_x86_cdecl_avx512_patch_24_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_25
raw_get_current_context_x86_cdecl_avx512_patch_25:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm7
.globl raw_get_current_context_x86_cdecl_avx512_patch_25_end
raw_get_current_context_x86_cdecl_avx512_patch_25_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_26
raw_get_current_context_x86_cdecl_avx512_patch_26:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm0
.globl raw_get_current_context_x86_cdecl_avx512_patch_26_end
raw_get_current_context_x86_cdecl_avx512_patch_26_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_27
raw_get_current_context_x86_cdecl_avx512_patch_27:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm1
.globl raw_get_current_context_x86_cdecl_avx512_patch_27_end
raw_get_current_context_x86_cdecl_avx512_patch_27_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_28
raw_get_current_context_x86_cdecl_avx512_patch_28:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm2
.globl raw_get_current_context_x86_cdecl_avx512_patch_28_end
raw_get_current_context_x86_cdecl_avx512_patch_28_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_29
raw_get_current_context_x86_cdecl_avx512_patch_29:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm3
.globl raw_get_current_context_x86_cdecl_avx512_patch_29_end
raw_get_current_context_x86_cdecl_avx512_patch_29_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_30
raw_get_current_context_x86_cdecl_avx512_patch_30:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm4
.globl raw_get_current_context_x86_cdecl_avx512_patch_30_end
raw_get_current_context_x86_cdecl_avx512_patch_30_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_31
raw_get_current_context_x86_cdecl_avx512_patch_31:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm5
.globl raw_get_current_context_x86_cdecl_avx512_patch_31_end
raw_get_current_context_x86_cdecl_avx512_patch_31_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_32
raw_get_current_context_x86_cdecl_avx512_patch_32:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm6
.globl raw_get_current_context_x86_cdecl_avx512_patch_32_end
raw_get_current_context_x86_cdecl_avx512_patch_32_end:
.globl raw_get_current_context_x86_cdecl_avx512_patch_33
raw_get_current_context_x86_cdecl_avx512_patch_33:
	vmovups zmmword ptr [edi + 0x7fffffff], zmm7
.globl raw_get_current_context_x86_cdecl_avx512_patch_33_end
raw_get_current_context_x86_cdecl_avx512_patch_33_end:
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret

# GetCurrentContext: x86 AVXFPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x86_cdecl_avxfpu
raw_get_current_context_x86_cdecl_avxfpu:
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov edi, dword ptr [esp + 0x24]
	mov eax, dword ptr [esp + 0x1C]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_0
raw_get_current_context_x86_cdecl_avxfpu_patch_0:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_0_end
raw_get_current_context_x86_cdecl_avxfpu_patch_0_end:
	mov eax, dword ptr [esp + 0x18]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_1
raw_get_current_context_x86_cdecl_avxfpu_patch_1:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_1_end
raw_get_current_context_x86_cdecl_avxfpu_patch_1_end:
	mov eax, dword ptr [esp + 0x14]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_2
raw_get_current_context_x86_cdecl_avxfpu_patch_2:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_2_end
raw_get_current_context_x86_cdecl_avxfpu_patch_2_end:
	mov eax, dword ptr [esp + 0x10]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_3
raw_get_current_context_x86_cdecl_avxfpu_patch_3:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_3_end
raw_get_current_context_x86_cdecl_avxfpu_patch_3_end:
	mov eax, dword ptr [esp + 0xc]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_4
raw_get_current_context_x86_cdecl_avxfpu_patch_4:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_4_end
raw_get_current_context_x86_cdecl_avxfpu_patch_4_end:
	lea eax, [esp + 0x20]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_5
raw_get_current_context_x86_cdecl_avxfpu_patch_5:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_5_end
raw_get_current_context_x86_cdecl_avxfpu_patch_5_end:
	mov eax, dword ptr [esp + 0x8]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_6
raw_get_current_context_x86_cdecl_avxfpu_patch_6:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_6_end
raw_get_current_context_x86_cdecl_avxfpu_patch_6_end:
	mov eax, dword ptr [esp + 0x4]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_7
raw_get_current_context_x86_cdecl_avxfpu_patch_7:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_7_end
raw_get_current_context_x86_cdecl_avxfpu_patch_7_end:
	mov eax, dword ptr [esp + 0x0]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_8
raw_get_current_context_x86_cdecl_avxfpu_patch_8:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_8_end
raw_get_current_context_x86_cdecl_avxfpu_patch_8_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_9
raw_get_current_context_x86_cdecl_avxfpu_patch_9:
	stmxcsr dword ptr [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_9_end
raw_get_current_context_x86_cdecl_avxfpu_patch_9_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_10
raw_get_current_context_x86_cdecl_avxfpu_patch_10:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm0
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_10_end
raw_get_current_context_x86_cdecl_avxfpu_patch_10_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_11
raw_get_current_context_x86_cdecl_avxfpu_patch_11:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm1
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_11_end
raw_get_current_context_x86_cdecl_avxfpu_patch_11_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_12
raw_get_current_context_x86_cdecl_avxfpu_patch_12:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm2
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_12_end
raw_get_current_context_x86_cdecl_avxfpu_patch_12_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_13
raw_get_current_context_x86_cdecl_avxfpu_patch_13:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm3
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_13_end
raw_get_current_context_x86_cdecl_avxfpu_patch_13_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_14
raw_get_current_context_x86_cdecl_avxfpu_patch_14:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm4
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_14_end
raw_get_current_context_x86_cdecl_avxfpu_patch_14_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_15
raw_get_current_context_x86_cdecl_avxfpu_patch_15:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm5
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_15_end
raw_get_current_context_x86_cdecl_avxfpu_patch_15_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_16
raw_get_current_context_x86_cdecl_avxfpu_patch_16:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm6
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_16_end
raw_get_current_context_x86_cdecl_avxfpu_patch_16_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_17
raw_get_current_context_x86_cdecl_avxfpu_patch_17:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm7
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_17_end
raw_get_current_context_x86_cdecl_avxfpu_patch_17_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_18
raw_get_current_context_x86_cdecl_avxfpu_patch_18:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm0
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_18_end
raw_get_current_context_x86_cdecl_avxfpu_patch_18_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_19
raw_get_current_context_x86_cdecl_avxfpu_patch_19:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm1
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_19_end
raw_get_current_context_x86_cdecl_avxfpu_patch_19_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_20
raw_get_current_context_x86_cdecl_avxfpu_patch_20:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm2
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_20_end
raw_get_current_context_x86_cdecl_avxfpu_patch_20_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_21
raw_get_current_context_x86_cdecl_avxfpu_patch_21:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm3
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_21_end
raw_get_current_context_x86_cdecl_avxfpu_patch_21_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_22
raw_get_current_context_x86_cdecl_avxfpu_patch_22:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm4
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_22_end
raw_get_current_context_x86_cdecl_avxfpu_patch_22_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_23
raw_get_current_context_x86_cdecl_avxfpu_patch_23:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm5
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_23_end
raw_get_current_context_x86_cdecl_avxfpu_patch_23_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_24
raw_get_current_context_x86_cdecl_avxfpu_patch_24:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm6
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_24_end
raw_get_current_context_x86_cdecl_avxfpu_patch_24_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_25
raw_get_current_context_x86_cdecl_avxfpu_patch_25:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm7
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_25_end
raw_get_current_context_x86_cdecl_avxfpu_patch_25_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_26
raw_get_current_context_x86_cdecl_avxfpu_patch_26:
	fsave [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_26_end
raw_get_current_context_x86_cdecl_avxfpu_patch_26_end:
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_27
raw_get_current_context_x86_cdecl_avxfpu_patch_27:
	frstor [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_avxfpu_patch_27_end
raw_get_current_context_x86_cdecl_avxfpu_patch_27_end:
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret

# GetCurrentContext: x86 AVX
.intel_syntax noprefix
.text
.globl raw_get_current_context_x86_cdecl_avx
raw_get_current_context_x86_cdecl_avx:
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov edi, dword ptr [esp + 0x24]
	mov eax, dword ptr [esp + 0x1C]
.globl raw_get_current_context_x86_cdecl_avx_patch_0
raw_get_current_context_x86_cdecl_avx_patch_0:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_0_end
raw_get_current_context_x86_cdecl_avx_patch_0_end:
	mov eax, dword ptr [esp + 0x18]
.globl raw_get_current_context_x86_cdecl_avx_patch_1
raw_get_current_context_x86_cdecl_avx_patch_1:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_1_end
raw_get_current_context_x86_cdecl_avx_patch_1_end:
	mov eax, dword ptr [esp + 0x14]
.globl raw_get_current_context_x86_cdecl_avx_patch_2
raw_get_current_context_x86_cdecl_avx_patch_2:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_2_end
raw_get_current_context_x86_cdecl_avx_patch_2_end:
	mov eax, dword ptr [esp + 0x10]
.globl raw_get_current_context_x86_cdecl_avx_patch_3
raw_get_current_context_x86_cdecl_avx_patch_3:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_3_end
raw_get_current_context_x86_cdecl_avx_patch_3_end:
	mov eax, dword ptr [esp + 0xc]
.globl raw_get_current_context_x86_cdecl_avx_patch_4
raw_get_current_context_x86_cdecl_avx_patch_4:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_4_end
raw_get_current_context_x86_cdecl_avx_patch_4_end:
	lea eax, [esp + 0x20]
.globl raw_get_current_context_x86_cdecl_avx_patch_5
raw_get_current_context_x86_cdecl_avx_patch_5:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_5_end
raw_get_current_context_x86_cdecl_avx_patch_5_end:
	mov eax, dword ptr [esp + 0x8]
.globl raw_get_current_context_x86_cdecl_avx_patch_6
raw_get_current_context_x86_cdecl_avx_patch_6:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_6_end
raw_get_current_context_x86_cdecl_avx_patch_6_end:
	mov eax, dword ptr [esp + 0x4]
.globl raw_get_current_context_x86_cdecl_avx_patch_7
raw_get_current_context_x86_cdecl_avx_patch_7:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_7_end
raw_get_current_context_x86_cdecl_avx_patch_7_end:
	mov eax, dword ptr [esp + 0x0]
.globl raw_get_current_context_x86_cdecl_avx_patch_8
raw_get_current_context_x86_cdecl_avx_patch_8:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_avx_patch_8_end
raw_get_current_context_x86_cdecl_avx_patch_8_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_9
raw_get_current_context_x86_cdecl_avx_patch_9:
	stmxcsr dword ptr [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_avx_patch_9_end
raw_get_current_context_x86_cdecl_avx_patch_9_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_10
raw_get_current_context_x86_cdecl_avx_patch_10:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm0
.globl raw_get_current_context_x86_cdecl_avx_patch_10_end
raw_get_current_context_x86_cdecl_avx_patch_10_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_11
raw_get_current_context_x86_cdecl_avx_patch_11:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm1
.globl raw_get_current_context_x86_cdecl_avx_patch_11_end
raw_get_current_context_x86_cdecl_avx_patch_11_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_12
raw_get_current_context_x86_cdecl_avx_patch_12:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm2
.globl raw_get_current_context_x86_cdecl_avx_patch_12_end
raw_get_current_context_x86_cdecl_avx_patch_12_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_13
raw_get_current_context_x86_cdecl_avx_patch_13:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm3
.globl raw_get_current_context_x86_cdecl_avx_patch_13_end
raw_get_current_context_x86_cdecl_avx_patch_13_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_14
raw_get_current_context_x86_cdecl_avx_patch_14:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm4
.globl raw_get_current_context_x86_cdecl_avx_patch_14_end
raw_get_current_context_x86_cdecl_avx_patch_14_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_15
raw_get_current_context_x86_cdecl_avx_patch_15:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm5
.globl raw_get_current_context_x86_cdecl_avx_patch_15_end
raw_get_current_context_x86_cdecl_avx_patch_15_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_16
raw_get_current_context_x86_cdecl_avx_patch_16:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm6
.globl raw_get_current_context_x86_cdecl_avx_patch_16_end
raw_get_current_context_x86_cdecl_avx_patch_16_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_17
raw_get_current_context_x86_cdecl_avx_patch_17:
	vmovups xmmword ptr [edi + 0x7fffffff], xmm7
.globl raw_get_current_context_x86_cdecl_avx_patch_17_end
raw_get_current_context_x86_cdecl_avx_patch_17_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_18
raw_get_current_context_x86_cdecl_avx_patch_18:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm0
.globl raw_get_current_context_x86_cdecl_avx_patch_18_end
raw_get_current_context_x86_cdecl_avx_patch_18_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_19
raw_get_current_context_x86_cdecl_avx_patch_19:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm1
.globl raw_get_current_context_x86_cdecl_avx_patch_19_end
raw_get_current_context_x86_cdecl_avx_patch_19_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_20
raw_get_current_context_x86_cdecl_avx_patch_20:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm2
.globl raw_get_current_context_x86_cdecl_avx_patch_20_end
raw_get_current_context_x86_cdecl_avx_patch_20_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_21
raw_get_current_context_x86_cdecl_avx_patch_21:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm3
.globl raw_get_current_context_x86_cdecl_avx_patch_21_end
raw_get_current_context_x86_cdecl_avx_patch_21_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_22
raw_get_current_context_x86_cdecl_avx_patch_22:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm4
.globl raw_get_current_context_x86_cdecl_avx_patch_22_end
raw_get_current_context_x86_cdecl_avx_patch_22_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_23
raw_get_current_context_x86_cdecl_avx_patch_23:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm5
.globl raw_get_current_context_x86_cdecl_avx_patch_23_end
raw_get_current_context_x86_cdecl_avx_patch_23_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_24
raw_get_current_context_x86_cdecl_avx_patch_24:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm6
.globl raw_get_current_context_x86_cdecl_avx_patch_24_end
raw_get_current_context_x86_cdecl_avx_patch_24_end:
.globl raw_get_current_context_x86_cdecl_avx_patch_25
raw_get_current_context_x86_cdecl_avx_patch_25:
	vmovups ymmword ptr [edi + 0x7fffffff], ymm7
.globl raw_get_current_context_x86_cdecl_avx_patch_25_end
raw_get_current_context_x86_cdecl_avx_patch_25_end:
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret

# GetCurrentContext: x86 SSEFPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x86_cdecl_ssefpu
raw_get_current_context_x86_cdecl_ssefpu:
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov edi, dword ptr [esp + 0x24]
	mov eax, dword ptr [esp + 0x1C]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_0
raw_get_current_context_x86_cdecl_ssefpu_patch_0:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_0_end
raw_get_current_context_x86_cdecl_ssefpu_patch_0_end:
	mov eax, dword ptr [esp + 0x18]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_1
raw_get_current_context_x86_cdecl_ssefpu_patch_1:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_1_end
raw_get_current_context_x86_cdecl_ssefpu_patch_1_end:
	mov eax, dword ptr [esp + 0x14]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_2
raw_get_current_context_x86_cdecl_ssefpu_patch_2:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_2_end
raw_get_current_context_x86_cdecl_ssefpu_patch_2_end:
	mov eax, dword ptr [esp + 0x10]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_3
raw_get_current_context_x86_cdecl_ssefpu_patch_3:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_3_end
raw_get_current_context_x86_cdecl_ssefpu_patch_3_end:
	mov eax, dword ptr [esp + 0xc]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_4
raw_get_current_context_x86_cdecl_ssefpu_patch_4:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_4_end
raw_get_current_context_x86_cdecl_ssefpu_patch_4_end:
	lea eax, [esp + 0x20]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_5
raw_get_current_context_x86_cdecl_ssefpu_patch_5:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_5_end
raw_get_current_context_x86_cdecl_ssefpu_patch_5_end:
	mov eax, dword ptr [esp + 0x8]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_6
raw_get_current_context_x86_cdecl_ssefpu_patch_6:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_6_end
raw_get_current_context_x86_cdecl_ssefpu_patch_6_end:
	mov eax, dword ptr [esp + 0x4]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_7
raw_get_current_context_x86_cdecl_ssefpu_patch_7:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_7_end
raw_get_current_context_x86_cdecl_ssefpu_patch_7_end:
	mov eax, dword ptr [esp + 0x0]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_8
raw_get_current_context_x86_cdecl_ssefpu_patch_8:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_8_end
raw_get_current_context_x86_cdecl_ssefpu_patch_8_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_9
raw_get_current_context_x86_cdecl_ssefpu_patch_9:
	stmxcsr dword ptr [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_9_end
raw_get_current_context_x86_cdecl_ssefpu_patch_9_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_10
raw_get_current_context_x86_cdecl_ssefpu_patch_10:
	movups xmmword ptr [edi + 0x7fffffff], xmm0
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_10_end
raw_get_current_context_x86_cdecl_ssefpu_patch_10_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_11
raw_get_current_context_x86_cdecl_ssefpu_patch_11:
	movups xmmword ptr [edi + 0x7fffffff], xmm1
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_11_end
raw_get_current_context_x86_cdecl_ssefpu_patch_11_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_12
raw_get_current_context_x86_cdecl_ssefpu_patch_12:
	movups xmmword ptr [edi + 0x7fffffff], xmm2
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_12_end
raw_get_current_context_x86_cdecl_ssefpu_patch_12_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_13
raw_get_current_context_x86_cdecl_ssefpu_patch_13:
	movups xmmword ptr [edi + 0x7fffffff], xmm3
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_13_end
raw_get_current_context_x86_cdecl_ssefpu_patch_13_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_14
raw_get_current_context_x86_cdecl_ssefpu_patch_14:
	movups xmmword ptr [edi + 0x7fffffff], xmm4
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_14_end
raw_get_current_context_x86_cdecl_ssefpu_patch_14_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_15
raw_get_current_context_x86_cdecl_ssefpu_patch_15:
	movups xmmword ptr [edi + 0x7fffffff], xmm5
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_15_end
raw_get_current_context_x86_cdecl_ssefpu_patch_15_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_16
raw_get_current_context_x86_cdecl_ssefpu_patch_16:
	movups xmmword ptr [edi + 0x7fffffff], xmm6
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_16_end
raw_get_current_context_x86_cdecl_ssefpu_patch_16_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_17
raw_get_current_context_x86_cdecl_ssefpu_patch_17:
	movups xmmword ptr [edi + 0x7fffffff], xmm7
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_17_end
raw_get_current_context_x86_cdecl_ssefpu_patch_17_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_18
raw_get_current_context_x86_cdecl_ssefpu_patch_18:
	fsave [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_18_end
raw_get_current_context_x86_cdecl_ssefpu_patch_18_end:
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_19
raw_get_current_context_x86_cdecl_ssefpu_patch_19:
	frstor [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_ssefpu_patch_19_end
raw_get_current_context_x86_cdecl_ssefpu_patch_19_end:
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret

# GetCurrentContext: x86 SSE
.intel_syntax noprefix
.text
.globl raw_get_current_context_x86_cdecl_sse
raw_get_current_context_x86_cdecl_sse:
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov edi, dword ptr [esp + 0x24]
	mov eax, dword ptr [esp + 0x1C]
.globl raw_get_current_context_x86_cdecl_sse_patch_0
raw_get_current_context_x86_cdecl_sse_patch_0:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_0_end
raw_get_current_context_x86_cdecl_sse_patch_0_end:
	mov eax, dword ptr [esp + 0x18]
.globl raw_get_current_context_x86_cdecl_sse_patch_1
raw_get_current_context_x86_cdecl_sse_patch_1:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_1_end
raw_get_current_context_x86_cdecl_sse_patch_1_end:
	mov eax, dword ptr [esp + 0x14]
.globl raw_get_current_context_x86_cdecl_sse_patch_2
raw_get_current_context_x86_cdecl_sse_patch_2:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_2_end
raw_get_current_context_x86_cdecl_sse_patch_2_end:
	mov eax, dword ptr [esp + 0x10]
.globl raw_get_current_context_x86_cdecl_sse_patch_3
raw_get_current_context_x86_cdecl_sse_patch_3:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_3_end
raw_get_current_context_x86_cdecl_sse_patch_3_end:
	mov eax, dword ptr [esp + 0xc]
.globl raw_get_current_context_x86_cdecl_sse_patch_4
raw_get_current_context_x86_cdecl_sse_patch_4:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_4_end
raw_get_current_context_x86_cdecl_sse_patch_4_end:
	lea eax, [esp + 0x20]
.globl raw_get_current_context_x86_cdecl_sse_patch_5
raw_get_current_context_x86_cdecl_sse_patch_5:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_5_end
raw_get_current_context_x86_cdecl_sse_patch_5_end:
	mov eax, dword ptr [esp + 0x8]
.globl raw_get_current_context_x86_cdecl_sse_patch_6
raw_get_current_context_x86_cdecl_sse_patch_6:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_6_end
raw_get_current_context_x86_cdecl_sse_patch_6_end:
	mov eax, dword ptr [esp + 0x4]
.globl raw_get_current_context_x86_cdecl_sse_patch_7
raw_get_current_context_x86_cdecl_sse_patch_7:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_7_end
raw_get_current_context_x86_cdecl_sse_patch_7_end:
	mov eax, dword ptr [esp + 0x0]
.globl raw_get_current_context_x86_cdecl_sse_patch_8
raw_get_current_context_x86_cdecl_sse_patch_8:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_sse_patch_8_end
raw_get_current_context_x86_cdecl_sse_patch_8_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_9
raw_get_current_context_x86_cdecl_sse_patch_9:
	stmxcsr dword ptr [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_sse_patch_9_end
raw_get_current_context_x86_cdecl_sse_patch_9_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_10
raw_get_current_context_x86_cdecl_sse_patch_10:
	movups xmmword ptr [edi + 0x7fffffff], xmm0
.globl raw_get_current_context_x86_cdecl_sse_patch_10_end
raw_get_current_context_x86_cdecl_sse_patch_10_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_11
raw_get_current_context_x86_cdecl_sse_patch_11:
	movups xmmword ptr [edi + 0x7fffffff], xmm1
.globl raw_get_current_context_x86_cdecl_sse_patch_11_end
raw_get_current_context_x86_cdecl_sse_patch_11_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_12
raw_get_current_context_x86_cdecl_sse_patch_12:
	movups xmmword ptr [edi + 0x7fffffff], xmm2
.globl raw_get_current_context_x86_cdecl_sse_patch_12_end
raw_get_current_context_x86_cdecl_sse_patch_12_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_13
raw_get_current_context_x86_cdecl_sse_patch_13:
	movups xmmword ptr [edi + 0x7fffffff], xmm3
.globl raw_get_current_context_x86_cdecl_sse_patch_13_end
raw_get_current_context_x86_cdecl_sse_patch_13_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_14
raw_get_current_context_x86_cdecl_sse_patch_14:
	movups xmmword ptr [edi + 0x7fffffff], xmm4
.globl raw_get_current_context_x86_cdecl_sse_patch_14_end
raw_get_current_context_x86_cdecl_sse_patch_14_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_15
raw_get_current_context_x86_cdecl_sse_patch_15:
	movups xmmword ptr [edi + 0x7fffffff], xmm5
.globl raw_get_current_context_x86_cdecl_sse_patch_15_end
raw_get_current_context_x86_cdecl_sse_patch_15_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_16
raw_get_current_context_x86_cdecl_sse_patch_16:
	movups xmmword ptr [edi + 0x7fffffff], xmm6
.globl raw_get_current_context_x86_cdecl_sse_patch_16_end
raw_get_current_context_x86_cdecl_sse_patch_16_end:
.globl raw_get_current_context_x86_cdecl_sse_patch_17
raw_get_current_context_x86_cdecl_sse_patch_17:
	movups xmmword ptr [edi + 0x7fffffff], xmm7
.globl raw_get_current_context_x86_cdecl_sse_patch_17_end
raw_get_current_context_x86_cdecl_sse_patch_17_end:
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret

# GetCurrentContext: x86 FPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x86_cdecl_fpu
raw_get_current_context_x86_cdecl_fpu:
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov edi, dword ptr [esp + 0x24]
	mov eax, dword ptr [esp + 0x1C]
.globl raw_get_current_context_x86_cdecl_fpu_patch_0
raw_get_current_context_x86_cdecl_fpu_patch_0:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_0_end
raw_get_current_context_x86_cdecl_fpu_patch_0_end:
	mov eax, dword ptr [esp + 0x18]
.globl raw_get_current_context_x86_cdecl_fpu_patch_1
raw_get_current_context_x86_cdecl_fpu_patch_1:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_1_end
raw_get_current_context_x86_cdecl_fpu_patch_1_end:
	mov eax, dword ptr [esp + 0x14]
.globl raw_get_current_context_x86_cdecl_fpu_patch_2
raw_get_current_context_x86_cdecl_fpu_patch_2:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_2_end
raw_get_current_context_x86_cdecl_fpu_patch_2_end:
	mov eax, dword ptr [esp + 0x10]
.globl raw_get_current_context_x86_cdecl_fpu_patch_3
raw_get_current_context_x86_cdecl_fpu_patch_3:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_3_end
raw_get_current_context_x86_cdecl_fpu_patch_3_end:
	mov eax, dword ptr [esp + 0xc]
.globl raw_get_current_context_x86_cdecl_fpu_patch_4
raw_get_current_context_x86_cdecl_fpu_patch_4:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_4_end
raw_get_current_context_x86_cdecl_fpu_patch_4_end:
	lea eax, [esp + 0x20]
.globl raw_get_current_context_x86_cdecl_fpu_patch_5
raw_get_current_context_x86_cdecl_fpu_patch_5:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_5_end
raw_get_current_context_x86_cdecl_fpu_patch_5_end:
	mov eax, dword ptr [esp + 0x8]
.globl raw_get_current_context_x86_cdecl_fpu_patch_6
raw_get_current_context_x86_cdecl_fpu_patch_6:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_6_end
raw_get_current_context_x86_cdecl_fpu_patch_6_end:
	mov eax, dword ptr [esp + 0x4]
.globl raw_get_current_context_x86_cdecl_fpu_patch_7
raw_get_current_context_x86_cdecl_fpu_patch_7:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_7_end
raw_get_current_context_x86_cdecl_fpu_patch_7_end:
	mov eax, dword ptr [esp + 0x0]
.globl raw_get_current_context_x86_cdecl_fpu_patch_8
raw_get_current_context_x86_cdecl_fpu_patch_8:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_fpu_patch_8_end
raw_get_current_context_x86_cdecl_fpu_patch_8_end:
.globl raw_get_current_context_x86_cdecl_fpu_patch_9
raw_get_current_context_x86_cdecl_fpu_patch_9:
	fsave [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_fpu_patch_9_end
raw_get_current_context_x86_cdecl_fpu_patch_9_end:
.globl raw_get_current_context_x86_cdecl_fpu_patch_10
raw_get_current_context_x86_cdecl_fpu_patch_10:
	frstor [edi + 0x7fffffff]
.globl raw_get_current_context_x86_cdecl_fpu_patch_10_end
raw_get_current_context_x86_cdecl_fpu_patch_10_end:
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret

# GetCurrentContext: x86 Native
.intel_syntax noprefix
.text
.globl raw_get_current_context_x86_cdecl_native
raw_get_current_context_x86_cdecl_native:
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov edi, dword ptr [esp + 0x24]
	mov eax, dword ptr [esp + 0x1C]
.globl raw_get_current_context_x86_cdecl_native_patch_0
raw_get_current_context_x86_cdecl_native_patch_0:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_0_end
raw_get_current_context_x86_cdecl_native_patch_0_end:
	mov eax, dword ptr [esp + 0x18]
.globl raw_get_current_context_x86_cdecl_native_patch_1
raw_get_current_context_x86_cdecl_native_patch_1:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_1_end
raw_get_current_context_x86_cdecl_native_patch_1_end:
	mov eax, dword ptr [esp + 0x14]
.globl raw_get_current_context_x86_cdecl_native_patch_2
raw_get_current_context_x86_cdecl_native_patch_2:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_2_end
raw_get_current_context_x86_cdecl_native_patch_2_end:
	mov eax, dword ptr [esp + 0x10]
.globl raw_get_current_context_x86_cdecl_native_patch_3
raw_get_current_context_x86_cdecl_native_patch_3:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_3_end
raw_get_current_context_x86_cdecl_native_patch_3_end:
	mov eax, dword ptr [esp + 0xc]
.globl raw_get_current_context_x86_cdecl_native_patch_4
raw_get_current_context_x86_cdecl_native_patch_4:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_4_end
raw_get_current_context_x86_cdecl_native_patch_4_end:
	lea eax, [esp + 0x20]
.globl raw_get_current_context_x86_cdecl_native_patch_5
raw_get_current_context_x86_cdecl_native_patch_5:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_5_end
raw_get_current_context_x86_cdecl_native_patch_5_end:
	mov eax, dword ptr [esp + 0x8]
.globl raw_get_current_context_x86_cdecl_native_patch_6
raw_get_current_context_x86_cdecl_native_patch_6:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_6_end
raw_get_current_context_x86_cdecl_native_patch_6_end:
	mov eax, dword ptr [esp + 0x4]
.globl raw_get_current_context_x86_cdecl_native_patch_7
raw_get_current_context_x86_cdecl_native_patch_7:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_7_end
raw_get_current_context_x86_cdecl_native_patch_7_end:
	mov eax, dword ptr [esp + 0x0]
.globl raw_get_current_context_x86_cdecl_native_patch_8
raw_get_current_context_x86_cdecl_native_patch_8:
	mov dword ptr [edi + 0x7fffffff], eax
.globl raw_get_current_context_x86_cdecl_native_patch_8_end
raw_get_current_context_x86_cdecl_native_patch_8_end:
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret
