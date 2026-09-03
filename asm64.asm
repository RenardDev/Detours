# Generated source templates for RawHook and GetCurrentContext machine code.
# Every variant is cumulative: AVX-512 includes AVX/YMM, SSE/XMM and native state.
# FPU and non-FPU variants are emitted independently.

# ----------------------------------------------------------------
# RawHook wrapper: x64 windows AVX512FPU
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_windows_avx512fpu
raw_hook_wrapper_x64_windows_avx512fpu:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_0
raw_hook_wrapper_x64_windows_avx512fpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_0_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_1
raw_hook_wrapper_x64_windows_avx512fpu_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_1_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_1_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_2
raw_hook_wrapper_x64_windows_avx512fpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_2_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_2_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_3
raw_hook_wrapper_x64_windows_avx512fpu_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_3_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_3_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_4
raw_hook_wrapper_x64_windows_avx512fpu_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_4_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_4_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_5
raw_hook_wrapper_x64_windows_avx512fpu_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_5_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_5_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_6
raw_hook_wrapper_x64_windows_avx512fpu_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_6_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_6_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_7
raw_hook_wrapper_x64_windows_avx512fpu_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_7_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_7_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_8
raw_hook_wrapper_x64_windows_avx512fpu_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_8_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_8_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_9
raw_hook_wrapper_x64_windows_avx512fpu_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_9_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_9_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_10
raw_hook_wrapper_x64_windows_avx512fpu_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_10_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_10_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_11
raw_hook_wrapper_x64_windows_avx512fpu_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_11_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_11_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_12
raw_hook_wrapper_x64_windows_avx512fpu_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_12_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_12_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_13
raw_hook_wrapper_x64_windows_avx512fpu_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_13_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_13_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_14
raw_hook_wrapper_x64_windows_avx512fpu_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_14_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_14_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_15
raw_hook_wrapper_x64_windows_avx512fpu_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_15_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_15_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_16
raw_hook_wrapper_x64_windows_avx512fpu_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_16_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_16_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_17
raw_hook_wrapper_x64_windows_avx512fpu_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_17_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_17_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_18
raw_hook_wrapper_x64_windows_avx512fpu_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_18_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_18_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_19
raw_hook_wrapper_x64_windows_avx512fpu_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_19_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_19_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_20
raw_hook_wrapper_x64_windows_avx512fpu_patch_20:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_20_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_20_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_21
raw_hook_wrapper_x64_windows_avx512fpu_patch_21:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_21_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_21_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_22
raw_hook_wrapper_x64_windows_avx512fpu_patch_22:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_22_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_22_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_23
raw_hook_wrapper_x64_windows_avx512fpu_patch_23:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_23_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_23_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_24
raw_hook_wrapper_x64_windows_avx512fpu_patch_24:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_24_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_24_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_25
raw_hook_wrapper_x64_windows_avx512fpu_patch_25:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_25_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_25_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_26
raw_hook_wrapper_x64_windows_avx512fpu_patch_26:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_26_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_26_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_27
raw_hook_wrapper_x64_windows_avx512fpu_patch_27:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_27_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_27_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_28
raw_hook_wrapper_x64_windows_avx512fpu_patch_28:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_28_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_28_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_29
raw_hook_wrapper_x64_windows_avx512fpu_patch_29:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_29_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_29_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_30
raw_hook_wrapper_x64_windows_avx512fpu_patch_30:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_30_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_30_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_31
raw_hook_wrapper_x64_windows_avx512fpu_patch_31:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_31_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_31_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_32
raw_hook_wrapper_x64_windows_avx512fpu_patch_32:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_32_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_32_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_33
raw_hook_wrapper_x64_windows_avx512fpu_patch_33:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_33_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_33_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_34
raw_hook_wrapper_x64_windows_avx512fpu_patch_34:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_34_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_34_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_35
raw_hook_wrapper_x64_windows_avx512fpu_patch_35:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_35_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_35_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_36
raw_hook_wrapper_x64_windows_avx512fpu_patch_36:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_36_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_36_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_37
raw_hook_wrapper_x64_windows_avx512fpu_patch_37:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_37_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_37_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_38
raw_hook_wrapper_x64_windows_avx512fpu_patch_38:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_38_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_38_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_39
raw_hook_wrapper_x64_windows_avx512fpu_patch_39:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_39_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_39_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_40
raw_hook_wrapper_x64_windows_avx512fpu_patch_40:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_40_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_40_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_41
raw_hook_wrapper_x64_windows_avx512fpu_patch_41:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_41_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_41_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_42
raw_hook_wrapper_x64_windows_avx512fpu_patch_42:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_42_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_42_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_43
raw_hook_wrapper_x64_windows_avx512fpu_patch_43:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_43_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_43_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_44
raw_hook_wrapper_x64_windows_avx512fpu_patch_44:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm8
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_44_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_44_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_45
raw_hook_wrapper_x64_windows_avx512fpu_patch_45:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm9
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_45_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_45_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_46
raw_hook_wrapper_x64_windows_avx512fpu_patch_46:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm10
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_46_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_46_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_47
raw_hook_wrapper_x64_windows_avx512fpu_patch_47:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm11
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_47_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_47_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_48
raw_hook_wrapper_x64_windows_avx512fpu_patch_48:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm12
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_48_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_48_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_49
raw_hook_wrapper_x64_windows_avx512fpu_patch_49:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm13
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_49_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_49_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_50
raw_hook_wrapper_x64_windows_avx512fpu_patch_50:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm14
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_50_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_50_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_51
raw_hook_wrapper_x64_windows_avx512fpu_patch_51:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm15
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_51_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_51_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_52
raw_hook_wrapper_x64_windows_avx512fpu_patch_52:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm0
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_52_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_52_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_53
raw_hook_wrapper_x64_windows_avx512fpu_patch_53:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm1
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_53_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_53_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_54
raw_hook_wrapper_x64_windows_avx512fpu_patch_54:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm2
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_54_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_54_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_55
raw_hook_wrapper_x64_windows_avx512fpu_patch_55:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm3
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_55_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_55_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_56
raw_hook_wrapper_x64_windows_avx512fpu_patch_56:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm4
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_56_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_56_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_57
raw_hook_wrapper_x64_windows_avx512fpu_patch_57:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm5
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_57_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_57_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_58
raw_hook_wrapper_x64_windows_avx512fpu_patch_58:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm6
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_58_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_58_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_59
raw_hook_wrapper_x64_windows_avx512fpu_patch_59:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm7
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_59_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_59_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_60
raw_hook_wrapper_x64_windows_avx512fpu_patch_60:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm8
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_60_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_60_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_61
raw_hook_wrapper_x64_windows_avx512fpu_patch_61:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm9
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_61_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_61_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_62
raw_hook_wrapper_x64_windows_avx512fpu_patch_62:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm10
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_62_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_62_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_63
raw_hook_wrapper_x64_windows_avx512fpu_patch_63:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm11
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_63_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_63_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_64
raw_hook_wrapper_x64_windows_avx512fpu_patch_64:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm12
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_64_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_64_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_65
raw_hook_wrapper_x64_windows_avx512fpu_patch_65:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm13
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_65_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_65_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_66
raw_hook_wrapper_x64_windows_avx512fpu_patch_66:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm14
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_66_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_66_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_67
raw_hook_wrapper_x64_windows_avx512fpu_patch_67:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm15
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_67_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_67_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_68
raw_hook_wrapper_x64_windows_avx512fpu_patch_68:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm16
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_68_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_68_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_69
raw_hook_wrapper_x64_windows_avx512fpu_patch_69:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm17
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_69_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_69_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_70
raw_hook_wrapper_x64_windows_avx512fpu_patch_70:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm18
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_70_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_70_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_71
raw_hook_wrapper_x64_windows_avx512fpu_patch_71:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm19
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_71_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_71_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_72
raw_hook_wrapper_x64_windows_avx512fpu_patch_72:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm20
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_72_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_72_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_73
raw_hook_wrapper_x64_windows_avx512fpu_patch_73:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm21
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_73_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_73_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_74
raw_hook_wrapper_x64_windows_avx512fpu_patch_74:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm22
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_74_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_74_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_75
raw_hook_wrapper_x64_windows_avx512fpu_patch_75:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm23
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_75_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_75_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_76
raw_hook_wrapper_x64_windows_avx512fpu_patch_76:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm24
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_76_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_76_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_77
raw_hook_wrapper_x64_windows_avx512fpu_patch_77:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm25
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_77_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_77_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_78
raw_hook_wrapper_x64_windows_avx512fpu_patch_78:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm26
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_78_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_78_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_79
raw_hook_wrapper_x64_windows_avx512fpu_patch_79:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm27
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_79_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_79_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_80
raw_hook_wrapper_x64_windows_avx512fpu_patch_80:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm28
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_80_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_80_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_81
raw_hook_wrapper_x64_windows_avx512fpu_patch_81:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm29
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_81_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_81_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_82
raw_hook_wrapper_x64_windows_avx512fpu_patch_82:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm30
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_82_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_82_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_83
raw_hook_wrapper_x64_windows_avx512fpu_patch_83:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm31
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_83_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_83_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_84
raw_hook_wrapper_x64_windows_avx512fpu_patch_84:
	fsave [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_84_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_84_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_0
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_0_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_0_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_1
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_1_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_2
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_2_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_2_end:
	mov rcx, rsp
	sub rsp, 0x20
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_85
raw_hook_wrapper_x64_windows_avx512fpu_patch_85:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_85_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_85_end:
	call rax
	add rsp, 0x20
	test al, al
	je raw_hook_wrapper_x64_windows_avx512fpu_nothing_modified
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_86
raw_hook_wrapper_x64_windows_avx512fpu_patch_86:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_86_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_86_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_87
raw_hook_wrapper_x64_windows_avx512fpu_patch_87:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_87_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_87_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_88
raw_hook_wrapper_x64_windows_avx512fpu_patch_88:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_88_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_88_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_89
raw_hook_wrapper_x64_windows_avx512fpu_patch_89:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_89_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_89_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_90
raw_hook_wrapper_x64_windows_avx512fpu_patch_90:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_90_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_90_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_91
raw_hook_wrapper_x64_windows_avx512fpu_patch_91:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_91_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_91_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_92
raw_hook_wrapper_x64_windows_avx512fpu_patch_92:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_92_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_92_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_93
raw_hook_wrapper_x64_windows_avx512fpu_patch_93:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_93_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_93_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_94
raw_hook_wrapper_x64_windows_avx512fpu_patch_94:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_94_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_94_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_95
raw_hook_wrapper_x64_windows_avx512fpu_patch_95:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_95_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_95_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_96
raw_hook_wrapper_x64_windows_avx512fpu_patch_96:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_96_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_96_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_97
raw_hook_wrapper_x64_windows_avx512fpu_patch_97:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_97_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_97_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_98
raw_hook_wrapper_x64_windows_avx512fpu_patch_98:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_98_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_98_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_99
raw_hook_wrapper_x64_windows_avx512fpu_patch_99:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_99_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_99_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_100
raw_hook_wrapper_x64_windows_avx512fpu_patch_100:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_100_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_100_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_101
raw_hook_wrapper_x64_windows_avx512fpu_patch_101:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_101_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_101_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_102
raw_hook_wrapper_x64_windows_avx512fpu_patch_102:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_102_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_102_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_103
raw_hook_wrapper_x64_windows_avx512fpu_patch_103:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_103_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_103_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_104
raw_hook_wrapper_x64_windows_avx512fpu_patch_104:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_104_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_104_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_105
raw_hook_wrapper_x64_windows_avx512fpu_patch_105:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_105_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_105_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_106
raw_hook_wrapper_x64_windows_avx512fpu_patch_106:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_106_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_106_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_107
raw_hook_wrapper_x64_windows_avx512fpu_patch_107:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_107_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_107_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_108
raw_hook_wrapper_x64_windows_avx512fpu_patch_108:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_108_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_108_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_109
raw_hook_wrapper_x64_windows_avx512fpu_patch_109:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_109_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_109_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_110
raw_hook_wrapper_x64_windows_avx512fpu_patch_110:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_110_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_110_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_111
raw_hook_wrapper_x64_windows_avx512fpu_patch_111:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_111_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_111_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_112
raw_hook_wrapper_x64_windows_avx512fpu_patch_112:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_112_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_112_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_113
raw_hook_wrapper_x64_windows_avx512fpu_patch_113:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_113_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_113_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_114
raw_hook_wrapper_x64_windows_avx512fpu_patch_114:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_114_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_114_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_115
raw_hook_wrapper_x64_windows_avx512fpu_patch_115:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_115_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_115_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_116
raw_hook_wrapper_x64_windows_avx512fpu_patch_116:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_116_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_116_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_117
raw_hook_wrapper_x64_windows_avx512fpu_patch_117:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_117_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_117_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_118
raw_hook_wrapper_x64_windows_avx512fpu_patch_118:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_118_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_118_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_119
raw_hook_wrapper_x64_windows_avx512fpu_patch_119:
	vmovups zmm0, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_119_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_119_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_120
raw_hook_wrapper_x64_windows_avx512fpu_patch_120:
	vmovups zmm1, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_120_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_120_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_121
raw_hook_wrapper_x64_windows_avx512fpu_patch_121:
	vmovups zmm2, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_121_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_121_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_122
raw_hook_wrapper_x64_windows_avx512fpu_patch_122:
	vmovups zmm3, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_122_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_122_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_123
raw_hook_wrapper_x64_windows_avx512fpu_patch_123:
	vmovups zmm4, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_123_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_123_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_124
raw_hook_wrapper_x64_windows_avx512fpu_patch_124:
	vmovups zmm5, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_124_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_124_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_125
raw_hook_wrapper_x64_windows_avx512fpu_patch_125:
	vmovups zmm6, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_125_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_125_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_126
raw_hook_wrapper_x64_windows_avx512fpu_patch_126:
	vmovups zmm7, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_126_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_126_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_127
raw_hook_wrapper_x64_windows_avx512fpu_patch_127:
	vmovups zmm8, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_127_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_127_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_128
raw_hook_wrapper_x64_windows_avx512fpu_patch_128:
	vmovups zmm9, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_128_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_128_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_129
raw_hook_wrapper_x64_windows_avx512fpu_patch_129:
	vmovups zmm10, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_129_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_129_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_130
raw_hook_wrapper_x64_windows_avx512fpu_patch_130:
	vmovups zmm11, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_130_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_130_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_131
raw_hook_wrapper_x64_windows_avx512fpu_patch_131:
	vmovups zmm12, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_131_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_131_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_132
raw_hook_wrapper_x64_windows_avx512fpu_patch_132:
	vmovups zmm13, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_132_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_132_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_133
raw_hook_wrapper_x64_windows_avx512fpu_patch_133:
	vmovups zmm14, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_133_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_133_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_134
raw_hook_wrapper_x64_windows_avx512fpu_patch_134:
	vmovups zmm15, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_134_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_134_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_135
raw_hook_wrapper_x64_windows_avx512fpu_patch_135:
	vmovups zmm16, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_135_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_135_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_136
raw_hook_wrapper_x64_windows_avx512fpu_patch_136:
	vmovups zmm17, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_136_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_136_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_137
raw_hook_wrapper_x64_windows_avx512fpu_patch_137:
	vmovups zmm18, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_137_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_137_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_138
raw_hook_wrapper_x64_windows_avx512fpu_patch_138:
	vmovups zmm19, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_138_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_138_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_139
raw_hook_wrapper_x64_windows_avx512fpu_patch_139:
	vmovups zmm20, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_139_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_139_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_140
raw_hook_wrapper_x64_windows_avx512fpu_patch_140:
	vmovups zmm21, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_140_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_140_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_141
raw_hook_wrapper_x64_windows_avx512fpu_patch_141:
	vmovups zmm22, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_141_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_141_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_142
raw_hook_wrapper_x64_windows_avx512fpu_patch_142:
	vmovups zmm23, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_142_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_142_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_143
raw_hook_wrapper_x64_windows_avx512fpu_patch_143:
	vmovups zmm24, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_143_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_143_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_144
raw_hook_wrapper_x64_windows_avx512fpu_patch_144:
	vmovups zmm25, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_144_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_144_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_145
raw_hook_wrapper_x64_windows_avx512fpu_patch_145:
	vmovups zmm26, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_145_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_145_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_146
raw_hook_wrapper_x64_windows_avx512fpu_patch_146:
	vmovups zmm27, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_146_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_146_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_147
raw_hook_wrapper_x64_windows_avx512fpu_patch_147:
	vmovups zmm28, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_147_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_147_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_148
raw_hook_wrapper_x64_windows_avx512fpu_patch_148:
	vmovups zmm29, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_148_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_148_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_149
raw_hook_wrapper_x64_windows_avx512fpu_patch_149:
	vmovups zmm30, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_149_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_149_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_150
raw_hook_wrapper_x64_windows_avx512fpu_patch_150:
	vmovups zmm31, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_150_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_150_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_151
raw_hook_wrapper_x64_windows_avx512fpu_patch_151:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_151_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_151_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_153
raw_hook_wrapper_x64_windows_avx512fpu_patch_153:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_153_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_153_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_154
raw_hook_wrapper_x64_windows_avx512fpu_patch_154:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_154_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_154_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_155
raw_hook_wrapper_x64_windows_avx512fpu_patch_155:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_155_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_155_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_156
raw_hook_wrapper_x64_windows_avx512fpu_patch_156:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_156_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_156_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_157
raw_hook_wrapper_x64_windows_avx512fpu_patch_157:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_157_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_157_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_158
raw_hook_wrapper_x64_windows_avx512fpu_patch_158:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_158_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_158_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_159
raw_hook_wrapper_x64_windows_avx512fpu_patch_159:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_159_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_159_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_160
raw_hook_wrapper_x64_windows_avx512fpu_patch_160:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_160_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_160_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_161
raw_hook_wrapper_x64_windows_avx512fpu_patch_161:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_161_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_161_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_162
raw_hook_wrapper_x64_windows_avx512fpu_patch_162:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_162_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_162_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_163
raw_hook_wrapper_x64_windows_avx512fpu_patch_163:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_163_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_163_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_164
raw_hook_wrapper_x64_windows_avx512fpu_patch_164:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_164_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_164_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_3
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_3_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_windows_avx512fpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_4
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_4_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_windows_avx512fpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_5
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_5_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_windows_avx512fpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_6
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_6_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_windows_avx512fpu_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_avx512fpu_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_avx512fpu_redirect_return
raw_hook_wrapper_x64_windows_avx512fpu_unsupported_stack:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_7
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_7_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_7_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_8
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_8_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_8_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_9
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_9_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_windows_avx512fpu_direct_return:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_152
raw_hook_wrapper_x64_windows_avx512fpu_patch_152:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_152_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_152_end:
	popfq
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_165
raw_hook_wrapper_x64_windows_avx512fpu_patch_165:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_165_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_165_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_166
raw_hook_wrapper_x64_windows_avx512fpu_patch_166:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_166_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_166_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_167
raw_hook_wrapper_x64_windows_avx512fpu_patch_167:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_167_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_167_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_168
raw_hook_wrapper_x64_windows_avx512fpu_patch_168:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_168_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_168_end:
	ret
raw_hook_wrapper_x64_windows_avx512fpu_redirect_return:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_10
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_10_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_11
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_11_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_11_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_12
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_12_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_12_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_13
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_13_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_13_end:
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_14
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_14_end
raw_hook_wrapper_x64_windows_avx512fpu_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_windows_avx512fpu_nothing_modified:
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_169
raw_hook_wrapper_x64_windows_avx512fpu_patch_169:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx512fpu_patch_169_end
raw_hook_wrapper_x64_windows_avx512fpu_patch_169_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 windows AVX512
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_windows_avx512
raw_hook_wrapper_x64_windows_avx512:
.globl raw_hook_wrapper_x64_windows_avx512_patch_0
raw_hook_wrapper_x64_windows_avx512_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx512_patch_0_end
raw_hook_wrapper_x64_windows_avx512_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_windows_avx512_patch_1
raw_hook_wrapper_x64_windows_avx512_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_1_end
raw_hook_wrapper_x64_windows_avx512_patch_1_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_2
raw_hook_wrapper_x64_windows_avx512_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx512_patch_2_end
raw_hook_wrapper_x64_windows_avx512_patch_2_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_3
raw_hook_wrapper_x64_windows_avx512_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_avx512_patch_3_end
raw_hook_wrapper_x64_windows_avx512_patch_3_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_4
raw_hook_wrapper_x64_windows_avx512_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_windows_avx512_patch_4_end
raw_hook_wrapper_x64_windows_avx512_patch_4_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_5
raw_hook_wrapper_x64_windows_avx512_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_windows_avx512_patch_5_end
raw_hook_wrapper_x64_windows_avx512_patch_5_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_6
raw_hook_wrapper_x64_windows_avx512_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_windows_avx512_patch_6_end
raw_hook_wrapper_x64_windows_avx512_patch_6_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_7
raw_hook_wrapper_x64_windows_avx512_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx512_patch_7_end
raw_hook_wrapper_x64_windows_avx512_patch_7_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_8
raw_hook_wrapper_x64_windows_avx512_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_windows_avx512_patch_8_end
raw_hook_wrapper_x64_windows_avx512_patch_8_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_9
raw_hook_wrapper_x64_windows_avx512_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_windows_avx512_patch_9_end
raw_hook_wrapper_x64_windows_avx512_patch_9_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_10
raw_hook_wrapper_x64_windows_avx512_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_windows_avx512_patch_10_end
raw_hook_wrapper_x64_windows_avx512_patch_10_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_11
raw_hook_wrapper_x64_windows_avx512_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_windows_avx512_patch_11_end
raw_hook_wrapper_x64_windows_avx512_patch_11_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_12
raw_hook_wrapper_x64_windows_avx512_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_windows_avx512_patch_12_end
raw_hook_wrapper_x64_windows_avx512_patch_12_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_13
raw_hook_wrapper_x64_windows_avx512_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_windows_avx512_patch_13_end
raw_hook_wrapper_x64_windows_avx512_patch_13_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_14
raw_hook_wrapper_x64_windows_avx512_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_windows_avx512_patch_14_end
raw_hook_wrapper_x64_windows_avx512_patch_14_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_15
raw_hook_wrapper_x64_windows_avx512_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_windows_avx512_patch_15_end
raw_hook_wrapper_x64_windows_avx512_patch_15_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_16
raw_hook_wrapper_x64_windows_avx512_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_windows_avx512_patch_16_end
raw_hook_wrapper_x64_windows_avx512_patch_16_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_17
raw_hook_wrapper_x64_windows_avx512_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_windows_avx512_patch_17_end
raw_hook_wrapper_x64_windows_avx512_patch_17_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_18
raw_hook_wrapper_x64_windows_avx512_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_windows_avx512_patch_18_end
raw_hook_wrapper_x64_windows_avx512_patch_18_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_19
raw_hook_wrapper_x64_windows_avx512_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_19_end
raw_hook_wrapper_x64_windows_avx512_patch_19_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_20
raw_hook_wrapper_x64_windows_avx512_patch_20:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_windows_avx512_patch_20_end
raw_hook_wrapper_x64_windows_avx512_patch_20_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_21
raw_hook_wrapper_x64_windows_avx512_patch_21:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_windows_avx512_patch_21_end
raw_hook_wrapper_x64_windows_avx512_patch_21_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_22
raw_hook_wrapper_x64_windows_avx512_patch_22:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_windows_avx512_patch_22_end
raw_hook_wrapper_x64_windows_avx512_patch_22_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_23
raw_hook_wrapper_x64_windows_avx512_patch_23:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_windows_avx512_patch_23_end
raw_hook_wrapper_x64_windows_avx512_patch_23_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_24
raw_hook_wrapper_x64_windows_avx512_patch_24:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_windows_avx512_patch_24_end
raw_hook_wrapper_x64_windows_avx512_patch_24_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_25
raw_hook_wrapper_x64_windows_avx512_patch_25:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_windows_avx512_patch_25_end
raw_hook_wrapper_x64_windows_avx512_patch_25_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_26
raw_hook_wrapper_x64_windows_avx512_patch_26:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_windows_avx512_patch_26_end
raw_hook_wrapper_x64_windows_avx512_patch_26_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_27
raw_hook_wrapper_x64_windows_avx512_patch_27:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_windows_avx512_patch_27_end
raw_hook_wrapper_x64_windows_avx512_patch_27_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_28
raw_hook_wrapper_x64_windows_avx512_patch_28:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_windows_avx512_patch_28_end
raw_hook_wrapper_x64_windows_avx512_patch_28_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_29
raw_hook_wrapper_x64_windows_avx512_patch_29:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_windows_avx512_patch_29_end
raw_hook_wrapper_x64_windows_avx512_patch_29_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_30
raw_hook_wrapper_x64_windows_avx512_patch_30:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_windows_avx512_patch_30_end
raw_hook_wrapper_x64_windows_avx512_patch_30_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_31
raw_hook_wrapper_x64_windows_avx512_patch_31:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_windows_avx512_patch_31_end
raw_hook_wrapper_x64_windows_avx512_patch_31_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_32
raw_hook_wrapper_x64_windows_avx512_patch_32:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_windows_avx512_patch_32_end
raw_hook_wrapper_x64_windows_avx512_patch_32_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_33
raw_hook_wrapper_x64_windows_avx512_patch_33:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_windows_avx512_patch_33_end
raw_hook_wrapper_x64_windows_avx512_patch_33_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_34
raw_hook_wrapper_x64_windows_avx512_patch_34:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_windows_avx512_patch_34_end
raw_hook_wrapper_x64_windows_avx512_patch_34_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_35
raw_hook_wrapper_x64_windows_avx512_patch_35:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_windows_avx512_patch_35_end
raw_hook_wrapper_x64_windows_avx512_patch_35_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_36
raw_hook_wrapper_x64_windows_avx512_patch_36:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x64_windows_avx512_patch_36_end
raw_hook_wrapper_x64_windows_avx512_patch_36_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_37
raw_hook_wrapper_x64_windows_avx512_patch_37:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x64_windows_avx512_patch_37_end
raw_hook_wrapper_x64_windows_avx512_patch_37_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_38
raw_hook_wrapper_x64_windows_avx512_patch_38:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x64_windows_avx512_patch_38_end
raw_hook_wrapper_x64_windows_avx512_patch_38_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_39
raw_hook_wrapper_x64_windows_avx512_patch_39:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x64_windows_avx512_patch_39_end
raw_hook_wrapper_x64_windows_avx512_patch_39_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_40
raw_hook_wrapper_x64_windows_avx512_patch_40:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x64_windows_avx512_patch_40_end
raw_hook_wrapper_x64_windows_avx512_patch_40_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_41
raw_hook_wrapper_x64_windows_avx512_patch_41:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x64_windows_avx512_patch_41_end
raw_hook_wrapper_x64_windows_avx512_patch_41_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_42
raw_hook_wrapper_x64_windows_avx512_patch_42:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x64_windows_avx512_patch_42_end
raw_hook_wrapper_x64_windows_avx512_patch_42_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_43
raw_hook_wrapper_x64_windows_avx512_patch_43:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x64_windows_avx512_patch_43_end
raw_hook_wrapper_x64_windows_avx512_patch_43_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_44
raw_hook_wrapper_x64_windows_avx512_patch_44:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm8
.globl raw_hook_wrapper_x64_windows_avx512_patch_44_end
raw_hook_wrapper_x64_windows_avx512_patch_44_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_45
raw_hook_wrapper_x64_windows_avx512_patch_45:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm9
.globl raw_hook_wrapper_x64_windows_avx512_patch_45_end
raw_hook_wrapper_x64_windows_avx512_patch_45_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_46
raw_hook_wrapper_x64_windows_avx512_patch_46:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm10
.globl raw_hook_wrapper_x64_windows_avx512_patch_46_end
raw_hook_wrapper_x64_windows_avx512_patch_46_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_47
raw_hook_wrapper_x64_windows_avx512_patch_47:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm11
.globl raw_hook_wrapper_x64_windows_avx512_patch_47_end
raw_hook_wrapper_x64_windows_avx512_patch_47_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_48
raw_hook_wrapper_x64_windows_avx512_patch_48:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm12
.globl raw_hook_wrapper_x64_windows_avx512_patch_48_end
raw_hook_wrapper_x64_windows_avx512_patch_48_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_49
raw_hook_wrapper_x64_windows_avx512_patch_49:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm13
.globl raw_hook_wrapper_x64_windows_avx512_patch_49_end
raw_hook_wrapper_x64_windows_avx512_patch_49_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_50
raw_hook_wrapper_x64_windows_avx512_patch_50:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm14
.globl raw_hook_wrapper_x64_windows_avx512_patch_50_end
raw_hook_wrapper_x64_windows_avx512_patch_50_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_51
raw_hook_wrapper_x64_windows_avx512_patch_51:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm15
.globl raw_hook_wrapper_x64_windows_avx512_patch_51_end
raw_hook_wrapper_x64_windows_avx512_patch_51_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_52
raw_hook_wrapper_x64_windows_avx512_patch_52:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm0
.globl raw_hook_wrapper_x64_windows_avx512_patch_52_end
raw_hook_wrapper_x64_windows_avx512_patch_52_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_53
raw_hook_wrapper_x64_windows_avx512_patch_53:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm1
.globl raw_hook_wrapper_x64_windows_avx512_patch_53_end
raw_hook_wrapper_x64_windows_avx512_patch_53_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_54
raw_hook_wrapper_x64_windows_avx512_patch_54:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm2
.globl raw_hook_wrapper_x64_windows_avx512_patch_54_end
raw_hook_wrapper_x64_windows_avx512_patch_54_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_55
raw_hook_wrapper_x64_windows_avx512_patch_55:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm3
.globl raw_hook_wrapper_x64_windows_avx512_patch_55_end
raw_hook_wrapper_x64_windows_avx512_patch_55_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_56
raw_hook_wrapper_x64_windows_avx512_patch_56:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm4
.globl raw_hook_wrapper_x64_windows_avx512_patch_56_end
raw_hook_wrapper_x64_windows_avx512_patch_56_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_57
raw_hook_wrapper_x64_windows_avx512_patch_57:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm5
.globl raw_hook_wrapper_x64_windows_avx512_patch_57_end
raw_hook_wrapper_x64_windows_avx512_patch_57_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_58
raw_hook_wrapper_x64_windows_avx512_patch_58:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm6
.globl raw_hook_wrapper_x64_windows_avx512_patch_58_end
raw_hook_wrapper_x64_windows_avx512_patch_58_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_59
raw_hook_wrapper_x64_windows_avx512_patch_59:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm7
.globl raw_hook_wrapper_x64_windows_avx512_patch_59_end
raw_hook_wrapper_x64_windows_avx512_patch_59_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_60
raw_hook_wrapper_x64_windows_avx512_patch_60:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm8
.globl raw_hook_wrapper_x64_windows_avx512_patch_60_end
raw_hook_wrapper_x64_windows_avx512_patch_60_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_61
raw_hook_wrapper_x64_windows_avx512_patch_61:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm9
.globl raw_hook_wrapper_x64_windows_avx512_patch_61_end
raw_hook_wrapper_x64_windows_avx512_patch_61_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_62
raw_hook_wrapper_x64_windows_avx512_patch_62:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm10
.globl raw_hook_wrapper_x64_windows_avx512_patch_62_end
raw_hook_wrapper_x64_windows_avx512_patch_62_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_63
raw_hook_wrapper_x64_windows_avx512_patch_63:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm11
.globl raw_hook_wrapper_x64_windows_avx512_patch_63_end
raw_hook_wrapper_x64_windows_avx512_patch_63_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_64
raw_hook_wrapper_x64_windows_avx512_patch_64:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm12
.globl raw_hook_wrapper_x64_windows_avx512_patch_64_end
raw_hook_wrapper_x64_windows_avx512_patch_64_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_65
raw_hook_wrapper_x64_windows_avx512_patch_65:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm13
.globl raw_hook_wrapper_x64_windows_avx512_patch_65_end
raw_hook_wrapper_x64_windows_avx512_patch_65_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_66
raw_hook_wrapper_x64_windows_avx512_patch_66:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm14
.globl raw_hook_wrapper_x64_windows_avx512_patch_66_end
raw_hook_wrapper_x64_windows_avx512_patch_66_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_67
raw_hook_wrapper_x64_windows_avx512_patch_67:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm15
.globl raw_hook_wrapper_x64_windows_avx512_patch_67_end
raw_hook_wrapper_x64_windows_avx512_patch_67_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_68
raw_hook_wrapper_x64_windows_avx512_patch_68:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm16
.globl raw_hook_wrapper_x64_windows_avx512_patch_68_end
raw_hook_wrapper_x64_windows_avx512_patch_68_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_69
raw_hook_wrapper_x64_windows_avx512_patch_69:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm17
.globl raw_hook_wrapper_x64_windows_avx512_patch_69_end
raw_hook_wrapper_x64_windows_avx512_patch_69_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_70
raw_hook_wrapper_x64_windows_avx512_patch_70:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm18
.globl raw_hook_wrapper_x64_windows_avx512_patch_70_end
raw_hook_wrapper_x64_windows_avx512_patch_70_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_71
raw_hook_wrapper_x64_windows_avx512_patch_71:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm19
.globl raw_hook_wrapper_x64_windows_avx512_patch_71_end
raw_hook_wrapper_x64_windows_avx512_patch_71_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_72
raw_hook_wrapper_x64_windows_avx512_patch_72:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm20
.globl raw_hook_wrapper_x64_windows_avx512_patch_72_end
raw_hook_wrapper_x64_windows_avx512_patch_72_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_73
raw_hook_wrapper_x64_windows_avx512_patch_73:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm21
.globl raw_hook_wrapper_x64_windows_avx512_patch_73_end
raw_hook_wrapper_x64_windows_avx512_patch_73_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_74
raw_hook_wrapper_x64_windows_avx512_patch_74:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm22
.globl raw_hook_wrapper_x64_windows_avx512_patch_74_end
raw_hook_wrapper_x64_windows_avx512_patch_74_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_75
raw_hook_wrapper_x64_windows_avx512_patch_75:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm23
.globl raw_hook_wrapper_x64_windows_avx512_patch_75_end
raw_hook_wrapper_x64_windows_avx512_patch_75_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_76
raw_hook_wrapper_x64_windows_avx512_patch_76:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm24
.globl raw_hook_wrapper_x64_windows_avx512_patch_76_end
raw_hook_wrapper_x64_windows_avx512_patch_76_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_77
raw_hook_wrapper_x64_windows_avx512_patch_77:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm25
.globl raw_hook_wrapper_x64_windows_avx512_patch_77_end
raw_hook_wrapper_x64_windows_avx512_patch_77_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_78
raw_hook_wrapper_x64_windows_avx512_patch_78:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm26
.globl raw_hook_wrapper_x64_windows_avx512_patch_78_end
raw_hook_wrapper_x64_windows_avx512_patch_78_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_79
raw_hook_wrapper_x64_windows_avx512_patch_79:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm27
.globl raw_hook_wrapper_x64_windows_avx512_patch_79_end
raw_hook_wrapper_x64_windows_avx512_patch_79_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_80
raw_hook_wrapper_x64_windows_avx512_patch_80:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm28
.globl raw_hook_wrapper_x64_windows_avx512_patch_80_end
raw_hook_wrapper_x64_windows_avx512_patch_80_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_81
raw_hook_wrapper_x64_windows_avx512_patch_81:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm29
.globl raw_hook_wrapper_x64_windows_avx512_patch_81_end
raw_hook_wrapper_x64_windows_avx512_patch_81_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_82
raw_hook_wrapper_x64_windows_avx512_patch_82:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm30
.globl raw_hook_wrapper_x64_windows_avx512_patch_82_end
raw_hook_wrapper_x64_windows_avx512_patch_82_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_83
raw_hook_wrapper_x64_windows_avx512_patch_83:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm31
.globl raw_hook_wrapper_x64_windows_avx512_patch_83_end
raw_hook_wrapper_x64_windows_avx512_patch_83_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_0
raw_hook_wrapper_x64_windows_avx512_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_0_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_0_end:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_1
raw_hook_wrapper_x64_windows_avx512_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_1_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_2
raw_hook_wrapper_x64_windows_avx512_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_2_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_2_end:
	mov rcx, rsp
	sub rsp, 0x20
.globl raw_hook_wrapper_x64_windows_avx512_patch_84
raw_hook_wrapper_x64_windows_avx512_patch_84:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_windows_avx512_patch_84_end
raw_hook_wrapper_x64_windows_avx512_patch_84_end:
	call rax
	add rsp, 0x20
	test al, al
	je raw_hook_wrapper_x64_windows_avx512_nothing_modified
.globl raw_hook_wrapper_x64_windows_avx512_patch_85
raw_hook_wrapper_x64_windows_avx512_patch_85:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_85_end
raw_hook_wrapper_x64_windows_avx512_patch_85_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_86
raw_hook_wrapper_x64_windows_avx512_patch_86:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_86_end
raw_hook_wrapper_x64_windows_avx512_patch_86_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_87
raw_hook_wrapper_x64_windows_avx512_patch_87:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_87_end
raw_hook_wrapper_x64_windows_avx512_patch_87_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_88
raw_hook_wrapper_x64_windows_avx512_patch_88:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_88_end
raw_hook_wrapper_x64_windows_avx512_patch_88_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_89
raw_hook_wrapper_x64_windows_avx512_patch_89:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_89_end
raw_hook_wrapper_x64_windows_avx512_patch_89_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_90
raw_hook_wrapper_x64_windows_avx512_patch_90:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_90_end
raw_hook_wrapper_x64_windows_avx512_patch_90_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_91
raw_hook_wrapper_x64_windows_avx512_patch_91:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_91_end
raw_hook_wrapper_x64_windows_avx512_patch_91_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_92
raw_hook_wrapper_x64_windows_avx512_patch_92:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_92_end
raw_hook_wrapper_x64_windows_avx512_patch_92_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_93
raw_hook_wrapper_x64_windows_avx512_patch_93:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_93_end
raw_hook_wrapper_x64_windows_avx512_patch_93_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_94
raw_hook_wrapper_x64_windows_avx512_patch_94:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_94_end
raw_hook_wrapper_x64_windows_avx512_patch_94_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_95
raw_hook_wrapper_x64_windows_avx512_patch_95:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_95_end
raw_hook_wrapper_x64_windows_avx512_patch_95_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_96
raw_hook_wrapper_x64_windows_avx512_patch_96:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_96_end
raw_hook_wrapper_x64_windows_avx512_patch_96_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_97
raw_hook_wrapper_x64_windows_avx512_patch_97:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_97_end
raw_hook_wrapper_x64_windows_avx512_patch_97_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_98
raw_hook_wrapper_x64_windows_avx512_patch_98:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_98_end
raw_hook_wrapper_x64_windows_avx512_patch_98_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_99
raw_hook_wrapper_x64_windows_avx512_patch_99:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_99_end
raw_hook_wrapper_x64_windows_avx512_patch_99_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_100
raw_hook_wrapper_x64_windows_avx512_patch_100:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_100_end
raw_hook_wrapper_x64_windows_avx512_patch_100_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_101
raw_hook_wrapper_x64_windows_avx512_patch_101:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_101_end
raw_hook_wrapper_x64_windows_avx512_patch_101_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_102
raw_hook_wrapper_x64_windows_avx512_patch_102:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_102_end
raw_hook_wrapper_x64_windows_avx512_patch_102_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_103
raw_hook_wrapper_x64_windows_avx512_patch_103:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_103_end
raw_hook_wrapper_x64_windows_avx512_patch_103_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_104
raw_hook_wrapper_x64_windows_avx512_patch_104:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_104_end
raw_hook_wrapper_x64_windows_avx512_patch_104_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_105
raw_hook_wrapper_x64_windows_avx512_patch_105:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_105_end
raw_hook_wrapper_x64_windows_avx512_patch_105_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_106
raw_hook_wrapper_x64_windows_avx512_patch_106:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_106_end
raw_hook_wrapper_x64_windows_avx512_patch_106_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_107
raw_hook_wrapper_x64_windows_avx512_patch_107:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_107_end
raw_hook_wrapper_x64_windows_avx512_patch_107_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_108
raw_hook_wrapper_x64_windows_avx512_patch_108:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_108_end
raw_hook_wrapper_x64_windows_avx512_patch_108_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_109
raw_hook_wrapper_x64_windows_avx512_patch_109:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_109_end
raw_hook_wrapper_x64_windows_avx512_patch_109_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_110
raw_hook_wrapper_x64_windows_avx512_patch_110:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_110_end
raw_hook_wrapper_x64_windows_avx512_patch_110_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_111
raw_hook_wrapper_x64_windows_avx512_patch_111:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_111_end
raw_hook_wrapper_x64_windows_avx512_patch_111_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_112
raw_hook_wrapper_x64_windows_avx512_patch_112:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_112_end
raw_hook_wrapper_x64_windows_avx512_patch_112_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_113
raw_hook_wrapper_x64_windows_avx512_patch_113:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_113_end
raw_hook_wrapper_x64_windows_avx512_patch_113_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_114
raw_hook_wrapper_x64_windows_avx512_patch_114:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_114_end
raw_hook_wrapper_x64_windows_avx512_patch_114_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_115
raw_hook_wrapper_x64_windows_avx512_patch_115:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_115_end
raw_hook_wrapper_x64_windows_avx512_patch_115_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_116
raw_hook_wrapper_x64_windows_avx512_patch_116:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_116_end
raw_hook_wrapper_x64_windows_avx512_patch_116_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_117
raw_hook_wrapper_x64_windows_avx512_patch_117:
	vmovups zmm0, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_117_end
raw_hook_wrapper_x64_windows_avx512_patch_117_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_118
raw_hook_wrapper_x64_windows_avx512_patch_118:
	vmovups zmm1, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_118_end
raw_hook_wrapper_x64_windows_avx512_patch_118_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_119
raw_hook_wrapper_x64_windows_avx512_patch_119:
	vmovups zmm2, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_119_end
raw_hook_wrapper_x64_windows_avx512_patch_119_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_120
raw_hook_wrapper_x64_windows_avx512_patch_120:
	vmovups zmm3, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_120_end
raw_hook_wrapper_x64_windows_avx512_patch_120_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_121
raw_hook_wrapper_x64_windows_avx512_patch_121:
	vmovups zmm4, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_121_end
raw_hook_wrapper_x64_windows_avx512_patch_121_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_122
raw_hook_wrapper_x64_windows_avx512_patch_122:
	vmovups zmm5, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_122_end
raw_hook_wrapper_x64_windows_avx512_patch_122_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_123
raw_hook_wrapper_x64_windows_avx512_patch_123:
	vmovups zmm6, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_123_end
raw_hook_wrapper_x64_windows_avx512_patch_123_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_124
raw_hook_wrapper_x64_windows_avx512_patch_124:
	vmovups zmm7, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_124_end
raw_hook_wrapper_x64_windows_avx512_patch_124_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_125
raw_hook_wrapper_x64_windows_avx512_patch_125:
	vmovups zmm8, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_125_end
raw_hook_wrapper_x64_windows_avx512_patch_125_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_126
raw_hook_wrapper_x64_windows_avx512_patch_126:
	vmovups zmm9, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_126_end
raw_hook_wrapper_x64_windows_avx512_patch_126_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_127
raw_hook_wrapper_x64_windows_avx512_patch_127:
	vmovups zmm10, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_127_end
raw_hook_wrapper_x64_windows_avx512_patch_127_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_128
raw_hook_wrapper_x64_windows_avx512_patch_128:
	vmovups zmm11, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_128_end
raw_hook_wrapper_x64_windows_avx512_patch_128_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_129
raw_hook_wrapper_x64_windows_avx512_patch_129:
	vmovups zmm12, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_129_end
raw_hook_wrapper_x64_windows_avx512_patch_129_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_130
raw_hook_wrapper_x64_windows_avx512_patch_130:
	vmovups zmm13, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_130_end
raw_hook_wrapper_x64_windows_avx512_patch_130_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_131
raw_hook_wrapper_x64_windows_avx512_patch_131:
	vmovups zmm14, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_131_end
raw_hook_wrapper_x64_windows_avx512_patch_131_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_132
raw_hook_wrapper_x64_windows_avx512_patch_132:
	vmovups zmm15, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_132_end
raw_hook_wrapper_x64_windows_avx512_patch_132_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_133
raw_hook_wrapper_x64_windows_avx512_patch_133:
	vmovups zmm16, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_133_end
raw_hook_wrapper_x64_windows_avx512_patch_133_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_134
raw_hook_wrapper_x64_windows_avx512_patch_134:
	vmovups zmm17, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_134_end
raw_hook_wrapper_x64_windows_avx512_patch_134_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_135
raw_hook_wrapper_x64_windows_avx512_patch_135:
	vmovups zmm18, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_135_end
raw_hook_wrapper_x64_windows_avx512_patch_135_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_136
raw_hook_wrapper_x64_windows_avx512_patch_136:
	vmovups zmm19, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_136_end
raw_hook_wrapper_x64_windows_avx512_patch_136_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_137
raw_hook_wrapper_x64_windows_avx512_patch_137:
	vmovups zmm20, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_137_end
raw_hook_wrapper_x64_windows_avx512_patch_137_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_138
raw_hook_wrapper_x64_windows_avx512_patch_138:
	vmovups zmm21, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_138_end
raw_hook_wrapper_x64_windows_avx512_patch_138_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_139
raw_hook_wrapper_x64_windows_avx512_patch_139:
	vmovups zmm22, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_139_end
raw_hook_wrapper_x64_windows_avx512_patch_139_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_140
raw_hook_wrapper_x64_windows_avx512_patch_140:
	vmovups zmm23, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_140_end
raw_hook_wrapper_x64_windows_avx512_patch_140_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_141
raw_hook_wrapper_x64_windows_avx512_patch_141:
	vmovups zmm24, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_141_end
raw_hook_wrapper_x64_windows_avx512_patch_141_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_142
raw_hook_wrapper_x64_windows_avx512_patch_142:
	vmovups zmm25, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_142_end
raw_hook_wrapper_x64_windows_avx512_patch_142_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_143
raw_hook_wrapper_x64_windows_avx512_patch_143:
	vmovups zmm26, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_143_end
raw_hook_wrapper_x64_windows_avx512_patch_143_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_144
raw_hook_wrapper_x64_windows_avx512_patch_144:
	vmovups zmm27, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_144_end
raw_hook_wrapper_x64_windows_avx512_patch_144_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_145
raw_hook_wrapper_x64_windows_avx512_patch_145:
	vmovups zmm28, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_145_end
raw_hook_wrapper_x64_windows_avx512_patch_145_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_146
raw_hook_wrapper_x64_windows_avx512_patch_146:
	vmovups zmm29, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_146_end
raw_hook_wrapper_x64_windows_avx512_patch_146_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_147
raw_hook_wrapper_x64_windows_avx512_patch_147:
	vmovups zmm30, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_147_end
raw_hook_wrapper_x64_windows_avx512_patch_147_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_148
raw_hook_wrapper_x64_windows_avx512_patch_148:
	vmovups zmm31, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_148_end
raw_hook_wrapper_x64_windows_avx512_patch_148_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_149
raw_hook_wrapper_x64_windows_avx512_patch_149:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_149_end
raw_hook_wrapper_x64_windows_avx512_patch_149_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_151
raw_hook_wrapper_x64_windows_avx512_patch_151:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_151_end
raw_hook_wrapper_x64_windows_avx512_patch_151_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_152
raw_hook_wrapper_x64_windows_avx512_patch_152:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_152_end
raw_hook_wrapper_x64_windows_avx512_patch_152_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_153
raw_hook_wrapper_x64_windows_avx512_patch_153:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_153_end
raw_hook_wrapper_x64_windows_avx512_patch_153_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_154
raw_hook_wrapper_x64_windows_avx512_patch_154:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_154_end
raw_hook_wrapper_x64_windows_avx512_patch_154_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_155
raw_hook_wrapper_x64_windows_avx512_patch_155:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_155_end
raw_hook_wrapper_x64_windows_avx512_patch_155_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_156
raw_hook_wrapper_x64_windows_avx512_patch_156:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_156_end
raw_hook_wrapper_x64_windows_avx512_patch_156_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_157
raw_hook_wrapper_x64_windows_avx512_patch_157:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_157_end
raw_hook_wrapper_x64_windows_avx512_patch_157_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_158
raw_hook_wrapper_x64_windows_avx512_patch_158:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_158_end
raw_hook_wrapper_x64_windows_avx512_patch_158_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_159
raw_hook_wrapper_x64_windows_avx512_patch_159:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_159_end
raw_hook_wrapper_x64_windows_avx512_patch_159_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_160
raw_hook_wrapper_x64_windows_avx512_patch_160:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_160_end
raw_hook_wrapper_x64_windows_avx512_patch_160_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_161
raw_hook_wrapper_x64_windows_avx512_patch_161:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_161_end
raw_hook_wrapper_x64_windows_avx512_patch_161_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_162
raw_hook_wrapper_x64_windows_avx512_patch_162:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_162_end
raw_hook_wrapper_x64_windows_avx512_patch_162_end:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_3
raw_hook_wrapper_x64_windows_avx512_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_3_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_windows_avx512_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_4
raw_hook_wrapper_x64_windows_avx512_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_4_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_windows_avx512_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_5
raw_hook_wrapper_x64_windows_avx512_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_5_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_windows_avx512_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_6
raw_hook_wrapper_x64_windows_avx512_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_6_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_windows_avx512_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_avx512_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_avx512_redirect_return
raw_hook_wrapper_x64_windows_avx512_unsupported_stack:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_7
raw_hook_wrapper_x64_windows_avx512_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_7_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_7_end:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_8
raw_hook_wrapper_x64_windows_avx512_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_8_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_8_end:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_9
raw_hook_wrapper_x64_windows_avx512_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_9_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_windows_avx512_direct_return:
.globl raw_hook_wrapper_x64_windows_avx512_patch_150
raw_hook_wrapper_x64_windows_avx512_patch_150:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_150_end
raw_hook_wrapper_x64_windows_avx512_patch_150_end:
	popfq
.globl raw_hook_wrapper_x64_windows_avx512_patch_163
raw_hook_wrapper_x64_windows_avx512_patch_163:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_163_end
raw_hook_wrapper_x64_windows_avx512_patch_163_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_164
raw_hook_wrapper_x64_windows_avx512_patch_164:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_164_end
raw_hook_wrapper_x64_windows_avx512_patch_164_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_165
raw_hook_wrapper_x64_windows_avx512_patch_165:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_165_end
raw_hook_wrapper_x64_windows_avx512_patch_165_end:
.globl raw_hook_wrapper_x64_windows_avx512_patch_166
raw_hook_wrapper_x64_windows_avx512_patch_166:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_patch_166_end
raw_hook_wrapper_x64_windows_avx512_patch_166_end:
	ret
raw_hook_wrapper_x64_windows_avx512_redirect_return:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_10
raw_hook_wrapper_x64_windows_avx512_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_10_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_11
raw_hook_wrapper_x64_windows_avx512_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_11_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_11_end:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_12
raw_hook_wrapper_x64_windows_avx512_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_12_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_12_end:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_13
raw_hook_wrapper_x64_windows_avx512_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_13_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_13_end:
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_14
raw_hook_wrapper_x64_windows_avx512_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx512_cet_patch_14_end
raw_hook_wrapper_x64_windows_avx512_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_windows_avx512_nothing_modified:
.globl raw_hook_wrapper_x64_windows_avx512_patch_167
raw_hook_wrapper_x64_windows_avx512_patch_167:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx512_patch_167_end
raw_hook_wrapper_x64_windows_avx512_patch_167_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 windows AVXFPU
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_windows_avxfpu
raw_hook_wrapper_x64_windows_avxfpu:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_0
raw_hook_wrapper_x64_windows_avxfpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_0_end
raw_hook_wrapper_x64_windows_avxfpu_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_1
raw_hook_wrapper_x64_windows_avxfpu_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_1_end
raw_hook_wrapper_x64_windows_avxfpu_patch_1_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_2
raw_hook_wrapper_x64_windows_avxfpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_2_end
raw_hook_wrapper_x64_windows_avxfpu_patch_2_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_3
raw_hook_wrapper_x64_windows_avxfpu_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_3_end
raw_hook_wrapper_x64_windows_avxfpu_patch_3_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_4
raw_hook_wrapper_x64_windows_avxfpu_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_4_end
raw_hook_wrapper_x64_windows_avxfpu_patch_4_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_5
raw_hook_wrapper_x64_windows_avxfpu_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_5_end
raw_hook_wrapper_x64_windows_avxfpu_patch_5_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_6
raw_hook_wrapper_x64_windows_avxfpu_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_6_end
raw_hook_wrapper_x64_windows_avxfpu_patch_6_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_7
raw_hook_wrapper_x64_windows_avxfpu_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_7_end
raw_hook_wrapper_x64_windows_avxfpu_patch_7_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_8
raw_hook_wrapper_x64_windows_avxfpu_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_8_end
raw_hook_wrapper_x64_windows_avxfpu_patch_8_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_9
raw_hook_wrapper_x64_windows_avxfpu_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_9_end
raw_hook_wrapper_x64_windows_avxfpu_patch_9_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_10
raw_hook_wrapper_x64_windows_avxfpu_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_10_end
raw_hook_wrapper_x64_windows_avxfpu_patch_10_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_11
raw_hook_wrapper_x64_windows_avxfpu_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_11_end
raw_hook_wrapper_x64_windows_avxfpu_patch_11_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_12
raw_hook_wrapper_x64_windows_avxfpu_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_12_end
raw_hook_wrapper_x64_windows_avxfpu_patch_12_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_13
raw_hook_wrapper_x64_windows_avxfpu_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_13_end
raw_hook_wrapper_x64_windows_avxfpu_patch_13_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_14
raw_hook_wrapper_x64_windows_avxfpu_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_14_end
raw_hook_wrapper_x64_windows_avxfpu_patch_14_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_15
raw_hook_wrapper_x64_windows_avxfpu_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_15_end
raw_hook_wrapper_x64_windows_avxfpu_patch_15_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_16
raw_hook_wrapper_x64_windows_avxfpu_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_16_end
raw_hook_wrapper_x64_windows_avxfpu_patch_16_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_17
raw_hook_wrapper_x64_windows_avxfpu_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_17_end
raw_hook_wrapper_x64_windows_avxfpu_patch_17_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_18
raw_hook_wrapper_x64_windows_avxfpu_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_18_end
raw_hook_wrapper_x64_windows_avxfpu_patch_18_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_19
raw_hook_wrapper_x64_windows_avxfpu_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_19_end
raw_hook_wrapper_x64_windows_avxfpu_patch_19_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_20
raw_hook_wrapper_x64_windows_avxfpu_patch_20:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_20_end
raw_hook_wrapper_x64_windows_avxfpu_patch_20_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_21
raw_hook_wrapper_x64_windows_avxfpu_patch_21:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_21_end
raw_hook_wrapper_x64_windows_avxfpu_patch_21_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_22
raw_hook_wrapper_x64_windows_avxfpu_patch_22:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_22_end
raw_hook_wrapper_x64_windows_avxfpu_patch_22_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_23
raw_hook_wrapper_x64_windows_avxfpu_patch_23:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_23_end
raw_hook_wrapper_x64_windows_avxfpu_patch_23_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_24
raw_hook_wrapper_x64_windows_avxfpu_patch_24:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_24_end
raw_hook_wrapper_x64_windows_avxfpu_patch_24_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_25
raw_hook_wrapper_x64_windows_avxfpu_patch_25:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_25_end
raw_hook_wrapper_x64_windows_avxfpu_patch_25_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_26
raw_hook_wrapper_x64_windows_avxfpu_patch_26:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_26_end
raw_hook_wrapper_x64_windows_avxfpu_patch_26_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_27
raw_hook_wrapper_x64_windows_avxfpu_patch_27:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_27_end
raw_hook_wrapper_x64_windows_avxfpu_patch_27_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_28
raw_hook_wrapper_x64_windows_avxfpu_patch_28:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_28_end
raw_hook_wrapper_x64_windows_avxfpu_patch_28_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_29
raw_hook_wrapper_x64_windows_avxfpu_patch_29:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_29_end
raw_hook_wrapper_x64_windows_avxfpu_patch_29_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_30
raw_hook_wrapper_x64_windows_avxfpu_patch_30:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_30_end
raw_hook_wrapper_x64_windows_avxfpu_patch_30_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_31
raw_hook_wrapper_x64_windows_avxfpu_patch_31:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_31_end
raw_hook_wrapper_x64_windows_avxfpu_patch_31_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_32
raw_hook_wrapper_x64_windows_avxfpu_patch_32:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_32_end
raw_hook_wrapper_x64_windows_avxfpu_patch_32_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_33
raw_hook_wrapper_x64_windows_avxfpu_patch_33:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_33_end
raw_hook_wrapper_x64_windows_avxfpu_patch_33_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_34
raw_hook_wrapper_x64_windows_avxfpu_patch_34:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_34_end
raw_hook_wrapper_x64_windows_avxfpu_patch_34_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_35
raw_hook_wrapper_x64_windows_avxfpu_patch_35:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_35_end
raw_hook_wrapper_x64_windows_avxfpu_patch_35_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_36
raw_hook_wrapper_x64_windows_avxfpu_patch_36:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_36_end
raw_hook_wrapper_x64_windows_avxfpu_patch_36_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_37
raw_hook_wrapper_x64_windows_avxfpu_patch_37:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_37_end
raw_hook_wrapper_x64_windows_avxfpu_patch_37_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_38
raw_hook_wrapper_x64_windows_avxfpu_patch_38:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_38_end
raw_hook_wrapper_x64_windows_avxfpu_patch_38_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_39
raw_hook_wrapper_x64_windows_avxfpu_patch_39:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_39_end
raw_hook_wrapper_x64_windows_avxfpu_patch_39_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_40
raw_hook_wrapper_x64_windows_avxfpu_patch_40:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_40_end
raw_hook_wrapper_x64_windows_avxfpu_patch_40_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_41
raw_hook_wrapper_x64_windows_avxfpu_patch_41:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_41_end
raw_hook_wrapper_x64_windows_avxfpu_patch_41_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_42
raw_hook_wrapper_x64_windows_avxfpu_patch_42:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_42_end
raw_hook_wrapper_x64_windows_avxfpu_patch_42_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_43
raw_hook_wrapper_x64_windows_avxfpu_patch_43:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_43_end
raw_hook_wrapper_x64_windows_avxfpu_patch_43_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_44
raw_hook_wrapper_x64_windows_avxfpu_patch_44:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm8
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_44_end
raw_hook_wrapper_x64_windows_avxfpu_patch_44_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_45
raw_hook_wrapper_x64_windows_avxfpu_patch_45:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm9
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_45_end
raw_hook_wrapper_x64_windows_avxfpu_patch_45_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_46
raw_hook_wrapper_x64_windows_avxfpu_patch_46:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm10
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_46_end
raw_hook_wrapper_x64_windows_avxfpu_patch_46_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_47
raw_hook_wrapper_x64_windows_avxfpu_patch_47:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm11
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_47_end
raw_hook_wrapper_x64_windows_avxfpu_patch_47_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_48
raw_hook_wrapper_x64_windows_avxfpu_patch_48:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm12
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_48_end
raw_hook_wrapper_x64_windows_avxfpu_patch_48_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_49
raw_hook_wrapper_x64_windows_avxfpu_patch_49:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm13
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_49_end
raw_hook_wrapper_x64_windows_avxfpu_patch_49_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_50
raw_hook_wrapper_x64_windows_avxfpu_patch_50:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm14
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_50_end
raw_hook_wrapper_x64_windows_avxfpu_patch_50_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_51
raw_hook_wrapper_x64_windows_avxfpu_patch_51:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm15
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_51_end
raw_hook_wrapper_x64_windows_avxfpu_patch_51_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_52
raw_hook_wrapper_x64_windows_avxfpu_patch_52:
	fsave [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_52_end
raw_hook_wrapper_x64_windows_avxfpu_patch_52_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_0
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_0_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_0_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_1
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_1_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_2
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_2_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_2_end:
	mov rcx, rsp
	sub rsp, 0x20
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_53
raw_hook_wrapper_x64_windows_avxfpu_patch_53:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_53_end
raw_hook_wrapper_x64_windows_avxfpu_patch_53_end:
	call rax
	add rsp, 0x20
	test al, al
	je raw_hook_wrapper_x64_windows_avxfpu_nothing_modified
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_54
raw_hook_wrapper_x64_windows_avxfpu_patch_54:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_54_end
raw_hook_wrapper_x64_windows_avxfpu_patch_54_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_55
raw_hook_wrapper_x64_windows_avxfpu_patch_55:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_55_end
raw_hook_wrapper_x64_windows_avxfpu_patch_55_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_56
raw_hook_wrapper_x64_windows_avxfpu_patch_56:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_56_end
raw_hook_wrapper_x64_windows_avxfpu_patch_56_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_57
raw_hook_wrapper_x64_windows_avxfpu_patch_57:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_57_end
raw_hook_wrapper_x64_windows_avxfpu_patch_57_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_58
raw_hook_wrapper_x64_windows_avxfpu_patch_58:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_58_end
raw_hook_wrapper_x64_windows_avxfpu_patch_58_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_59
raw_hook_wrapper_x64_windows_avxfpu_patch_59:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_59_end
raw_hook_wrapper_x64_windows_avxfpu_patch_59_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_60
raw_hook_wrapper_x64_windows_avxfpu_patch_60:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_60_end
raw_hook_wrapper_x64_windows_avxfpu_patch_60_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_61
raw_hook_wrapper_x64_windows_avxfpu_patch_61:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_61_end
raw_hook_wrapper_x64_windows_avxfpu_patch_61_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_62
raw_hook_wrapper_x64_windows_avxfpu_patch_62:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_62_end
raw_hook_wrapper_x64_windows_avxfpu_patch_62_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_63
raw_hook_wrapper_x64_windows_avxfpu_patch_63:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_63_end
raw_hook_wrapper_x64_windows_avxfpu_patch_63_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_64
raw_hook_wrapper_x64_windows_avxfpu_patch_64:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_64_end
raw_hook_wrapper_x64_windows_avxfpu_patch_64_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_65
raw_hook_wrapper_x64_windows_avxfpu_patch_65:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_65_end
raw_hook_wrapper_x64_windows_avxfpu_patch_65_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_66
raw_hook_wrapper_x64_windows_avxfpu_patch_66:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_66_end
raw_hook_wrapper_x64_windows_avxfpu_patch_66_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_67
raw_hook_wrapper_x64_windows_avxfpu_patch_67:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_67_end
raw_hook_wrapper_x64_windows_avxfpu_patch_67_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_68
raw_hook_wrapper_x64_windows_avxfpu_patch_68:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_68_end
raw_hook_wrapper_x64_windows_avxfpu_patch_68_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_69
raw_hook_wrapper_x64_windows_avxfpu_patch_69:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_69_end
raw_hook_wrapper_x64_windows_avxfpu_patch_69_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_70
raw_hook_wrapper_x64_windows_avxfpu_patch_70:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_70_end
raw_hook_wrapper_x64_windows_avxfpu_patch_70_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_71
raw_hook_wrapper_x64_windows_avxfpu_patch_71:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_71_end
raw_hook_wrapper_x64_windows_avxfpu_patch_71_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_72
raw_hook_wrapper_x64_windows_avxfpu_patch_72:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_72_end
raw_hook_wrapper_x64_windows_avxfpu_patch_72_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_73
raw_hook_wrapper_x64_windows_avxfpu_patch_73:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_73_end
raw_hook_wrapper_x64_windows_avxfpu_patch_73_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_74
raw_hook_wrapper_x64_windows_avxfpu_patch_74:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_74_end
raw_hook_wrapper_x64_windows_avxfpu_patch_74_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_75
raw_hook_wrapper_x64_windows_avxfpu_patch_75:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_75_end
raw_hook_wrapper_x64_windows_avxfpu_patch_75_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_76
raw_hook_wrapper_x64_windows_avxfpu_patch_76:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_76_end
raw_hook_wrapper_x64_windows_avxfpu_patch_76_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_77
raw_hook_wrapper_x64_windows_avxfpu_patch_77:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_77_end
raw_hook_wrapper_x64_windows_avxfpu_patch_77_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_78
raw_hook_wrapper_x64_windows_avxfpu_patch_78:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_78_end
raw_hook_wrapper_x64_windows_avxfpu_patch_78_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_79
raw_hook_wrapper_x64_windows_avxfpu_patch_79:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_79_end
raw_hook_wrapper_x64_windows_avxfpu_patch_79_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_80
raw_hook_wrapper_x64_windows_avxfpu_patch_80:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_80_end
raw_hook_wrapper_x64_windows_avxfpu_patch_80_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_81
raw_hook_wrapper_x64_windows_avxfpu_patch_81:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_81_end
raw_hook_wrapper_x64_windows_avxfpu_patch_81_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_82
raw_hook_wrapper_x64_windows_avxfpu_patch_82:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_82_end
raw_hook_wrapper_x64_windows_avxfpu_patch_82_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_83
raw_hook_wrapper_x64_windows_avxfpu_patch_83:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_83_end
raw_hook_wrapper_x64_windows_avxfpu_patch_83_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_84
raw_hook_wrapper_x64_windows_avxfpu_patch_84:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_84_end
raw_hook_wrapper_x64_windows_avxfpu_patch_84_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_85
raw_hook_wrapper_x64_windows_avxfpu_patch_85:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_85_end
raw_hook_wrapper_x64_windows_avxfpu_patch_85_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_86
raw_hook_wrapper_x64_windows_avxfpu_patch_86:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_86_end
raw_hook_wrapper_x64_windows_avxfpu_patch_86_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_87
raw_hook_wrapper_x64_windows_avxfpu_patch_87:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_87_end
raw_hook_wrapper_x64_windows_avxfpu_patch_87_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_89
raw_hook_wrapper_x64_windows_avxfpu_patch_89:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_89_end
raw_hook_wrapper_x64_windows_avxfpu_patch_89_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_90
raw_hook_wrapper_x64_windows_avxfpu_patch_90:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_90_end
raw_hook_wrapper_x64_windows_avxfpu_patch_90_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_91
raw_hook_wrapper_x64_windows_avxfpu_patch_91:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_91_end
raw_hook_wrapper_x64_windows_avxfpu_patch_91_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_92
raw_hook_wrapper_x64_windows_avxfpu_patch_92:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_92_end
raw_hook_wrapper_x64_windows_avxfpu_patch_92_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_93
raw_hook_wrapper_x64_windows_avxfpu_patch_93:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_93_end
raw_hook_wrapper_x64_windows_avxfpu_patch_93_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_94
raw_hook_wrapper_x64_windows_avxfpu_patch_94:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_94_end
raw_hook_wrapper_x64_windows_avxfpu_patch_94_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_95
raw_hook_wrapper_x64_windows_avxfpu_patch_95:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_95_end
raw_hook_wrapper_x64_windows_avxfpu_patch_95_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_96
raw_hook_wrapper_x64_windows_avxfpu_patch_96:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_96_end
raw_hook_wrapper_x64_windows_avxfpu_patch_96_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_97
raw_hook_wrapper_x64_windows_avxfpu_patch_97:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_97_end
raw_hook_wrapper_x64_windows_avxfpu_patch_97_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_98
raw_hook_wrapper_x64_windows_avxfpu_patch_98:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_98_end
raw_hook_wrapper_x64_windows_avxfpu_patch_98_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_99
raw_hook_wrapper_x64_windows_avxfpu_patch_99:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_99_end
raw_hook_wrapper_x64_windows_avxfpu_patch_99_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_100
raw_hook_wrapper_x64_windows_avxfpu_patch_100:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_100_end
raw_hook_wrapper_x64_windows_avxfpu_patch_100_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_3
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_3_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_windows_avxfpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_4
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_4_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_windows_avxfpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_5
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_5_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_windows_avxfpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_6
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_6_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_windows_avxfpu_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_avxfpu_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_avxfpu_redirect_return
raw_hook_wrapper_x64_windows_avxfpu_unsupported_stack:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_7
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_7_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_7_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_8
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_8_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_8_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_9
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_9_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_windows_avxfpu_direct_return:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_88
raw_hook_wrapper_x64_windows_avxfpu_patch_88:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_88_end
raw_hook_wrapper_x64_windows_avxfpu_patch_88_end:
	popfq
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_101
raw_hook_wrapper_x64_windows_avxfpu_patch_101:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_101_end
raw_hook_wrapper_x64_windows_avxfpu_patch_101_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_102
raw_hook_wrapper_x64_windows_avxfpu_patch_102:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_102_end
raw_hook_wrapper_x64_windows_avxfpu_patch_102_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_103
raw_hook_wrapper_x64_windows_avxfpu_patch_103:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_103_end
raw_hook_wrapper_x64_windows_avxfpu_patch_103_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_104
raw_hook_wrapper_x64_windows_avxfpu_patch_104:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_104_end
raw_hook_wrapper_x64_windows_avxfpu_patch_104_end:
	ret
raw_hook_wrapper_x64_windows_avxfpu_redirect_return:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_10
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_10_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_11
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_11_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_11_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_12
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_12_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_12_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_13
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_13_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_13_end:
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_14
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avxfpu_cet_patch_14_end
raw_hook_wrapper_x64_windows_avxfpu_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_windows_avxfpu_nothing_modified:
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_105
raw_hook_wrapper_x64_windows_avxfpu_patch_105:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avxfpu_patch_105_end
raw_hook_wrapper_x64_windows_avxfpu_patch_105_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 windows AVX
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_windows_avx
raw_hook_wrapper_x64_windows_avx:
.globl raw_hook_wrapper_x64_windows_avx_patch_0
raw_hook_wrapper_x64_windows_avx_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx_patch_0_end
raw_hook_wrapper_x64_windows_avx_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_windows_avx_patch_1
raw_hook_wrapper_x64_windows_avx_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_1_end
raw_hook_wrapper_x64_windows_avx_patch_1_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_2
raw_hook_wrapper_x64_windows_avx_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx_patch_2_end
raw_hook_wrapper_x64_windows_avx_patch_2_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_3
raw_hook_wrapper_x64_windows_avx_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_avx_patch_3_end
raw_hook_wrapper_x64_windows_avx_patch_3_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_4
raw_hook_wrapper_x64_windows_avx_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_windows_avx_patch_4_end
raw_hook_wrapper_x64_windows_avx_patch_4_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_5
raw_hook_wrapper_x64_windows_avx_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_windows_avx_patch_5_end
raw_hook_wrapper_x64_windows_avx_patch_5_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_6
raw_hook_wrapper_x64_windows_avx_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_windows_avx_patch_6_end
raw_hook_wrapper_x64_windows_avx_patch_6_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_7
raw_hook_wrapper_x64_windows_avx_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx_patch_7_end
raw_hook_wrapper_x64_windows_avx_patch_7_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_8
raw_hook_wrapper_x64_windows_avx_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_windows_avx_patch_8_end
raw_hook_wrapper_x64_windows_avx_patch_8_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_9
raw_hook_wrapper_x64_windows_avx_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_windows_avx_patch_9_end
raw_hook_wrapper_x64_windows_avx_patch_9_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_10
raw_hook_wrapper_x64_windows_avx_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_windows_avx_patch_10_end
raw_hook_wrapper_x64_windows_avx_patch_10_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_11
raw_hook_wrapper_x64_windows_avx_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_windows_avx_patch_11_end
raw_hook_wrapper_x64_windows_avx_patch_11_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_12
raw_hook_wrapper_x64_windows_avx_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_windows_avx_patch_12_end
raw_hook_wrapper_x64_windows_avx_patch_12_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_13
raw_hook_wrapper_x64_windows_avx_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_windows_avx_patch_13_end
raw_hook_wrapper_x64_windows_avx_patch_13_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_14
raw_hook_wrapper_x64_windows_avx_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_windows_avx_patch_14_end
raw_hook_wrapper_x64_windows_avx_patch_14_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_15
raw_hook_wrapper_x64_windows_avx_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_windows_avx_patch_15_end
raw_hook_wrapper_x64_windows_avx_patch_15_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_16
raw_hook_wrapper_x64_windows_avx_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_windows_avx_patch_16_end
raw_hook_wrapper_x64_windows_avx_patch_16_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_17
raw_hook_wrapper_x64_windows_avx_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_windows_avx_patch_17_end
raw_hook_wrapper_x64_windows_avx_patch_17_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_18
raw_hook_wrapper_x64_windows_avx_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_windows_avx_patch_18_end
raw_hook_wrapper_x64_windows_avx_patch_18_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_19
raw_hook_wrapper_x64_windows_avx_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_19_end
raw_hook_wrapper_x64_windows_avx_patch_19_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_20
raw_hook_wrapper_x64_windows_avx_patch_20:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_windows_avx_patch_20_end
raw_hook_wrapper_x64_windows_avx_patch_20_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_21
raw_hook_wrapper_x64_windows_avx_patch_21:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_windows_avx_patch_21_end
raw_hook_wrapper_x64_windows_avx_patch_21_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_22
raw_hook_wrapper_x64_windows_avx_patch_22:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_windows_avx_patch_22_end
raw_hook_wrapper_x64_windows_avx_patch_22_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_23
raw_hook_wrapper_x64_windows_avx_patch_23:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_windows_avx_patch_23_end
raw_hook_wrapper_x64_windows_avx_patch_23_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_24
raw_hook_wrapper_x64_windows_avx_patch_24:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_windows_avx_patch_24_end
raw_hook_wrapper_x64_windows_avx_patch_24_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_25
raw_hook_wrapper_x64_windows_avx_patch_25:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_windows_avx_patch_25_end
raw_hook_wrapper_x64_windows_avx_patch_25_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_26
raw_hook_wrapper_x64_windows_avx_patch_26:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_windows_avx_patch_26_end
raw_hook_wrapper_x64_windows_avx_patch_26_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_27
raw_hook_wrapper_x64_windows_avx_patch_27:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_windows_avx_patch_27_end
raw_hook_wrapper_x64_windows_avx_patch_27_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_28
raw_hook_wrapper_x64_windows_avx_patch_28:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_windows_avx_patch_28_end
raw_hook_wrapper_x64_windows_avx_patch_28_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_29
raw_hook_wrapper_x64_windows_avx_patch_29:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_windows_avx_patch_29_end
raw_hook_wrapper_x64_windows_avx_patch_29_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_30
raw_hook_wrapper_x64_windows_avx_patch_30:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_windows_avx_patch_30_end
raw_hook_wrapper_x64_windows_avx_patch_30_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_31
raw_hook_wrapper_x64_windows_avx_patch_31:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_windows_avx_patch_31_end
raw_hook_wrapper_x64_windows_avx_patch_31_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_32
raw_hook_wrapper_x64_windows_avx_patch_32:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_windows_avx_patch_32_end
raw_hook_wrapper_x64_windows_avx_patch_32_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_33
raw_hook_wrapper_x64_windows_avx_patch_33:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_windows_avx_patch_33_end
raw_hook_wrapper_x64_windows_avx_patch_33_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_34
raw_hook_wrapper_x64_windows_avx_patch_34:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_windows_avx_patch_34_end
raw_hook_wrapper_x64_windows_avx_patch_34_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_35
raw_hook_wrapper_x64_windows_avx_patch_35:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_windows_avx_patch_35_end
raw_hook_wrapper_x64_windows_avx_patch_35_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_36
raw_hook_wrapper_x64_windows_avx_patch_36:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x64_windows_avx_patch_36_end
raw_hook_wrapper_x64_windows_avx_patch_36_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_37
raw_hook_wrapper_x64_windows_avx_patch_37:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x64_windows_avx_patch_37_end
raw_hook_wrapper_x64_windows_avx_patch_37_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_38
raw_hook_wrapper_x64_windows_avx_patch_38:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x64_windows_avx_patch_38_end
raw_hook_wrapper_x64_windows_avx_patch_38_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_39
raw_hook_wrapper_x64_windows_avx_patch_39:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x64_windows_avx_patch_39_end
raw_hook_wrapper_x64_windows_avx_patch_39_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_40
raw_hook_wrapper_x64_windows_avx_patch_40:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x64_windows_avx_patch_40_end
raw_hook_wrapper_x64_windows_avx_patch_40_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_41
raw_hook_wrapper_x64_windows_avx_patch_41:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x64_windows_avx_patch_41_end
raw_hook_wrapper_x64_windows_avx_patch_41_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_42
raw_hook_wrapper_x64_windows_avx_patch_42:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x64_windows_avx_patch_42_end
raw_hook_wrapper_x64_windows_avx_patch_42_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_43
raw_hook_wrapper_x64_windows_avx_patch_43:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x64_windows_avx_patch_43_end
raw_hook_wrapper_x64_windows_avx_patch_43_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_44
raw_hook_wrapper_x64_windows_avx_patch_44:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm8
.globl raw_hook_wrapper_x64_windows_avx_patch_44_end
raw_hook_wrapper_x64_windows_avx_patch_44_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_45
raw_hook_wrapper_x64_windows_avx_patch_45:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm9
.globl raw_hook_wrapper_x64_windows_avx_patch_45_end
raw_hook_wrapper_x64_windows_avx_patch_45_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_46
raw_hook_wrapper_x64_windows_avx_patch_46:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm10
.globl raw_hook_wrapper_x64_windows_avx_patch_46_end
raw_hook_wrapper_x64_windows_avx_patch_46_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_47
raw_hook_wrapper_x64_windows_avx_patch_47:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm11
.globl raw_hook_wrapper_x64_windows_avx_patch_47_end
raw_hook_wrapper_x64_windows_avx_patch_47_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_48
raw_hook_wrapper_x64_windows_avx_patch_48:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm12
.globl raw_hook_wrapper_x64_windows_avx_patch_48_end
raw_hook_wrapper_x64_windows_avx_patch_48_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_49
raw_hook_wrapper_x64_windows_avx_patch_49:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm13
.globl raw_hook_wrapper_x64_windows_avx_patch_49_end
raw_hook_wrapper_x64_windows_avx_patch_49_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_50
raw_hook_wrapper_x64_windows_avx_patch_50:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm14
.globl raw_hook_wrapper_x64_windows_avx_patch_50_end
raw_hook_wrapper_x64_windows_avx_patch_50_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_51
raw_hook_wrapper_x64_windows_avx_patch_51:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm15
.globl raw_hook_wrapper_x64_windows_avx_patch_51_end
raw_hook_wrapper_x64_windows_avx_patch_51_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_0
raw_hook_wrapper_x64_windows_avx_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_0_end
raw_hook_wrapper_x64_windows_avx_cet_patch_0_end:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_1
raw_hook_wrapper_x64_windows_avx_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_1_end
raw_hook_wrapper_x64_windows_avx_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_2
raw_hook_wrapper_x64_windows_avx_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_2_end
raw_hook_wrapper_x64_windows_avx_cet_patch_2_end:
	mov rcx, rsp
	sub rsp, 0x20
.globl raw_hook_wrapper_x64_windows_avx_patch_52
raw_hook_wrapper_x64_windows_avx_patch_52:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_windows_avx_patch_52_end
raw_hook_wrapper_x64_windows_avx_patch_52_end:
	call rax
	add rsp, 0x20
	test al, al
	je raw_hook_wrapper_x64_windows_avx_nothing_modified
.globl raw_hook_wrapper_x64_windows_avx_patch_53
raw_hook_wrapper_x64_windows_avx_patch_53:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_53_end
raw_hook_wrapper_x64_windows_avx_patch_53_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_54
raw_hook_wrapper_x64_windows_avx_patch_54:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_54_end
raw_hook_wrapper_x64_windows_avx_patch_54_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_55
raw_hook_wrapper_x64_windows_avx_patch_55:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_55_end
raw_hook_wrapper_x64_windows_avx_patch_55_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_56
raw_hook_wrapper_x64_windows_avx_patch_56:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_56_end
raw_hook_wrapper_x64_windows_avx_patch_56_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_57
raw_hook_wrapper_x64_windows_avx_patch_57:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_57_end
raw_hook_wrapper_x64_windows_avx_patch_57_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_58
raw_hook_wrapper_x64_windows_avx_patch_58:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_58_end
raw_hook_wrapper_x64_windows_avx_patch_58_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_59
raw_hook_wrapper_x64_windows_avx_patch_59:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_59_end
raw_hook_wrapper_x64_windows_avx_patch_59_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_60
raw_hook_wrapper_x64_windows_avx_patch_60:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_60_end
raw_hook_wrapper_x64_windows_avx_patch_60_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_61
raw_hook_wrapper_x64_windows_avx_patch_61:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_61_end
raw_hook_wrapper_x64_windows_avx_patch_61_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_62
raw_hook_wrapper_x64_windows_avx_patch_62:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_62_end
raw_hook_wrapper_x64_windows_avx_patch_62_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_63
raw_hook_wrapper_x64_windows_avx_patch_63:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_63_end
raw_hook_wrapper_x64_windows_avx_patch_63_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_64
raw_hook_wrapper_x64_windows_avx_patch_64:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_64_end
raw_hook_wrapper_x64_windows_avx_patch_64_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_65
raw_hook_wrapper_x64_windows_avx_patch_65:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_65_end
raw_hook_wrapper_x64_windows_avx_patch_65_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_66
raw_hook_wrapper_x64_windows_avx_patch_66:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_66_end
raw_hook_wrapper_x64_windows_avx_patch_66_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_67
raw_hook_wrapper_x64_windows_avx_patch_67:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_67_end
raw_hook_wrapper_x64_windows_avx_patch_67_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_68
raw_hook_wrapper_x64_windows_avx_patch_68:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_68_end
raw_hook_wrapper_x64_windows_avx_patch_68_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_69
raw_hook_wrapper_x64_windows_avx_patch_69:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_69_end
raw_hook_wrapper_x64_windows_avx_patch_69_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_70
raw_hook_wrapper_x64_windows_avx_patch_70:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_70_end
raw_hook_wrapper_x64_windows_avx_patch_70_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_71
raw_hook_wrapper_x64_windows_avx_patch_71:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_71_end
raw_hook_wrapper_x64_windows_avx_patch_71_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_72
raw_hook_wrapper_x64_windows_avx_patch_72:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_72_end
raw_hook_wrapper_x64_windows_avx_patch_72_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_73
raw_hook_wrapper_x64_windows_avx_patch_73:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_73_end
raw_hook_wrapper_x64_windows_avx_patch_73_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_74
raw_hook_wrapper_x64_windows_avx_patch_74:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_74_end
raw_hook_wrapper_x64_windows_avx_patch_74_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_75
raw_hook_wrapper_x64_windows_avx_patch_75:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_75_end
raw_hook_wrapper_x64_windows_avx_patch_75_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_76
raw_hook_wrapper_x64_windows_avx_patch_76:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_76_end
raw_hook_wrapper_x64_windows_avx_patch_76_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_77
raw_hook_wrapper_x64_windows_avx_patch_77:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_77_end
raw_hook_wrapper_x64_windows_avx_patch_77_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_78
raw_hook_wrapper_x64_windows_avx_patch_78:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_78_end
raw_hook_wrapper_x64_windows_avx_patch_78_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_79
raw_hook_wrapper_x64_windows_avx_patch_79:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_79_end
raw_hook_wrapper_x64_windows_avx_patch_79_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_80
raw_hook_wrapper_x64_windows_avx_patch_80:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_80_end
raw_hook_wrapper_x64_windows_avx_patch_80_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_81
raw_hook_wrapper_x64_windows_avx_patch_81:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_81_end
raw_hook_wrapper_x64_windows_avx_patch_81_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_82
raw_hook_wrapper_x64_windows_avx_patch_82:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_82_end
raw_hook_wrapper_x64_windows_avx_patch_82_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_83
raw_hook_wrapper_x64_windows_avx_patch_83:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_83_end
raw_hook_wrapper_x64_windows_avx_patch_83_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_84
raw_hook_wrapper_x64_windows_avx_patch_84:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_84_end
raw_hook_wrapper_x64_windows_avx_patch_84_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_85
raw_hook_wrapper_x64_windows_avx_patch_85:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_85_end
raw_hook_wrapper_x64_windows_avx_patch_85_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_87
raw_hook_wrapper_x64_windows_avx_patch_87:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_87_end
raw_hook_wrapper_x64_windows_avx_patch_87_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_88
raw_hook_wrapper_x64_windows_avx_patch_88:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_88_end
raw_hook_wrapper_x64_windows_avx_patch_88_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_89
raw_hook_wrapper_x64_windows_avx_patch_89:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_89_end
raw_hook_wrapper_x64_windows_avx_patch_89_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_90
raw_hook_wrapper_x64_windows_avx_patch_90:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_90_end
raw_hook_wrapper_x64_windows_avx_patch_90_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_91
raw_hook_wrapper_x64_windows_avx_patch_91:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_91_end
raw_hook_wrapper_x64_windows_avx_patch_91_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_92
raw_hook_wrapper_x64_windows_avx_patch_92:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_92_end
raw_hook_wrapper_x64_windows_avx_patch_92_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_93
raw_hook_wrapper_x64_windows_avx_patch_93:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_93_end
raw_hook_wrapper_x64_windows_avx_patch_93_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_94
raw_hook_wrapper_x64_windows_avx_patch_94:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_94_end
raw_hook_wrapper_x64_windows_avx_patch_94_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_95
raw_hook_wrapper_x64_windows_avx_patch_95:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_95_end
raw_hook_wrapper_x64_windows_avx_patch_95_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_96
raw_hook_wrapper_x64_windows_avx_patch_96:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_96_end
raw_hook_wrapper_x64_windows_avx_patch_96_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_97
raw_hook_wrapper_x64_windows_avx_patch_97:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_97_end
raw_hook_wrapper_x64_windows_avx_patch_97_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_98
raw_hook_wrapper_x64_windows_avx_patch_98:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_98_end
raw_hook_wrapper_x64_windows_avx_patch_98_end:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_3
raw_hook_wrapper_x64_windows_avx_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_3_end
raw_hook_wrapper_x64_windows_avx_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_windows_avx_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_4
raw_hook_wrapper_x64_windows_avx_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_4_end
raw_hook_wrapper_x64_windows_avx_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_windows_avx_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_5
raw_hook_wrapper_x64_windows_avx_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_5_end
raw_hook_wrapper_x64_windows_avx_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_windows_avx_unsupported_stack
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_6
raw_hook_wrapper_x64_windows_avx_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_6_end
raw_hook_wrapper_x64_windows_avx_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_windows_avx_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_avx_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_avx_redirect_return
raw_hook_wrapper_x64_windows_avx_unsupported_stack:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_7
raw_hook_wrapper_x64_windows_avx_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_7_end
raw_hook_wrapper_x64_windows_avx_cet_patch_7_end:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_8
raw_hook_wrapper_x64_windows_avx_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_8_end
raw_hook_wrapper_x64_windows_avx_cet_patch_8_end:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_9
raw_hook_wrapper_x64_windows_avx_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_9_end
raw_hook_wrapper_x64_windows_avx_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_windows_avx_direct_return:
.globl raw_hook_wrapper_x64_windows_avx_patch_86
raw_hook_wrapper_x64_windows_avx_patch_86:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_86_end
raw_hook_wrapper_x64_windows_avx_patch_86_end:
	popfq
.globl raw_hook_wrapper_x64_windows_avx_patch_99
raw_hook_wrapper_x64_windows_avx_patch_99:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_99_end
raw_hook_wrapper_x64_windows_avx_patch_99_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_100
raw_hook_wrapper_x64_windows_avx_patch_100:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_100_end
raw_hook_wrapper_x64_windows_avx_patch_100_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_101
raw_hook_wrapper_x64_windows_avx_patch_101:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_101_end
raw_hook_wrapper_x64_windows_avx_patch_101_end:
.globl raw_hook_wrapper_x64_windows_avx_patch_102
raw_hook_wrapper_x64_windows_avx_patch_102:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_patch_102_end
raw_hook_wrapper_x64_windows_avx_patch_102_end:
	ret
raw_hook_wrapper_x64_windows_avx_redirect_return:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_10
raw_hook_wrapper_x64_windows_avx_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_10_end
raw_hook_wrapper_x64_windows_avx_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_11
raw_hook_wrapper_x64_windows_avx_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_11_end
raw_hook_wrapper_x64_windows_avx_cet_patch_11_end:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_12
raw_hook_wrapper_x64_windows_avx_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_12_end
raw_hook_wrapper_x64_windows_avx_cet_patch_12_end:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_13
raw_hook_wrapper_x64_windows_avx_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_13_end
raw_hook_wrapper_x64_windows_avx_cet_patch_13_end:
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_14
raw_hook_wrapper_x64_windows_avx_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_avx_cet_patch_14_end
raw_hook_wrapper_x64_windows_avx_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_windows_avx_nothing_modified:
.globl raw_hook_wrapper_x64_windows_avx_patch_103
raw_hook_wrapper_x64_windows_avx_patch_103:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_avx_patch_103_end
raw_hook_wrapper_x64_windows_avx_patch_103_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 windows SSEFPU
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_windows_ssefpu
raw_hook_wrapper_x64_windows_ssefpu:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_0
raw_hook_wrapper_x64_windows_ssefpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_0_end
raw_hook_wrapper_x64_windows_ssefpu_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_1
raw_hook_wrapper_x64_windows_ssefpu_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_1_end
raw_hook_wrapper_x64_windows_ssefpu_patch_1_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_2
raw_hook_wrapper_x64_windows_ssefpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_2_end
raw_hook_wrapper_x64_windows_ssefpu_patch_2_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_3
raw_hook_wrapper_x64_windows_ssefpu_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_3_end
raw_hook_wrapper_x64_windows_ssefpu_patch_3_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_4
raw_hook_wrapper_x64_windows_ssefpu_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_4_end
raw_hook_wrapper_x64_windows_ssefpu_patch_4_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_5
raw_hook_wrapper_x64_windows_ssefpu_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_5_end
raw_hook_wrapper_x64_windows_ssefpu_patch_5_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_6
raw_hook_wrapper_x64_windows_ssefpu_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_6_end
raw_hook_wrapper_x64_windows_ssefpu_patch_6_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_7
raw_hook_wrapper_x64_windows_ssefpu_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_7_end
raw_hook_wrapper_x64_windows_ssefpu_patch_7_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_8
raw_hook_wrapper_x64_windows_ssefpu_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_8_end
raw_hook_wrapper_x64_windows_ssefpu_patch_8_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_9
raw_hook_wrapper_x64_windows_ssefpu_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_9_end
raw_hook_wrapper_x64_windows_ssefpu_patch_9_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_10
raw_hook_wrapper_x64_windows_ssefpu_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_10_end
raw_hook_wrapper_x64_windows_ssefpu_patch_10_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_11
raw_hook_wrapper_x64_windows_ssefpu_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_11_end
raw_hook_wrapper_x64_windows_ssefpu_patch_11_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_12
raw_hook_wrapper_x64_windows_ssefpu_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_12_end
raw_hook_wrapper_x64_windows_ssefpu_patch_12_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_13
raw_hook_wrapper_x64_windows_ssefpu_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_13_end
raw_hook_wrapper_x64_windows_ssefpu_patch_13_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_14
raw_hook_wrapper_x64_windows_ssefpu_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_14_end
raw_hook_wrapper_x64_windows_ssefpu_patch_14_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_15
raw_hook_wrapper_x64_windows_ssefpu_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_15_end
raw_hook_wrapper_x64_windows_ssefpu_patch_15_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_16
raw_hook_wrapper_x64_windows_ssefpu_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_16_end
raw_hook_wrapper_x64_windows_ssefpu_patch_16_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_17
raw_hook_wrapper_x64_windows_ssefpu_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_17_end
raw_hook_wrapper_x64_windows_ssefpu_patch_17_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_18
raw_hook_wrapper_x64_windows_ssefpu_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_18_end
raw_hook_wrapper_x64_windows_ssefpu_patch_18_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_19
raw_hook_wrapper_x64_windows_ssefpu_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_19_end
raw_hook_wrapper_x64_windows_ssefpu_patch_19_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_20
raw_hook_wrapper_x64_windows_ssefpu_patch_20:
	movups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_20_end
raw_hook_wrapper_x64_windows_ssefpu_patch_20_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_21
raw_hook_wrapper_x64_windows_ssefpu_patch_21:
	movups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_21_end
raw_hook_wrapper_x64_windows_ssefpu_patch_21_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_22
raw_hook_wrapper_x64_windows_ssefpu_patch_22:
	movups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_22_end
raw_hook_wrapper_x64_windows_ssefpu_patch_22_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_23
raw_hook_wrapper_x64_windows_ssefpu_patch_23:
	movups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_23_end
raw_hook_wrapper_x64_windows_ssefpu_patch_23_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_24
raw_hook_wrapper_x64_windows_ssefpu_patch_24:
	movups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_24_end
raw_hook_wrapper_x64_windows_ssefpu_patch_24_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_25
raw_hook_wrapper_x64_windows_ssefpu_patch_25:
	movups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_25_end
raw_hook_wrapper_x64_windows_ssefpu_patch_25_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_26
raw_hook_wrapper_x64_windows_ssefpu_patch_26:
	movups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_26_end
raw_hook_wrapper_x64_windows_ssefpu_patch_26_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_27
raw_hook_wrapper_x64_windows_ssefpu_patch_27:
	movups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_27_end
raw_hook_wrapper_x64_windows_ssefpu_patch_27_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_28
raw_hook_wrapper_x64_windows_ssefpu_patch_28:
	movups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_28_end
raw_hook_wrapper_x64_windows_ssefpu_patch_28_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_29
raw_hook_wrapper_x64_windows_ssefpu_patch_29:
	movups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_29_end
raw_hook_wrapper_x64_windows_ssefpu_patch_29_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_30
raw_hook_wrapper_x64_windows_ssefpu_patch_30:
	movups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_30_end
raw_hook_wrapper_x64_windows_ssefpu_patch_30_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_31
raw_hook_wrapper_x64_windows_ssefpu_patch_31:
	movups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_31_end
raw_hook_wrapper_x64_windows_ssefpu_patch_31_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_32
raw_hook_wrapper_x64_windows_ssefpu_patch_32:
	movups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_32_end
raw_hook_wrapper_x64_windows_ssefpu_patch_32_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_33
raw_hook_wrapper_x64_windows_ssefpu_patch_33:
	movups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_33_end
raw_hook_wrapper_x64_windows_ssefpu_patch_33_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_34
raw_hook_wrapper_x64_windows_ssefpu_patch_34:
	movups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_34_end
raw_hook_wrapper_x64_windows_ssefpu_patch_34_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_35
raw_hook_wrapper_x64_windows_ssefpu_patch_35:
	movups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_35_end
raw_hook_wrapper_x64_windows_ssefpu_patch_35_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_36
raw_hook_wrapper_x64_windows_ssefpu_patch_36:
	fsave [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_36_end
raw_hook_wrapper_x64_windows_ssefpu_patch_36_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_0
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_0_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_0_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_1
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_1_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_2
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_2_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_2_end:
	mov rcx, rsp
	sub rsp, 0x20
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_37
raw_hook_wrapper_x64_windows_ssefpu_patch_37:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_37_end
raw_hook_wrapper_x64_windows_ssefpu_patch_37_end:
	call rax
	add rsp, 0x20
	test al, al
	je raw_hook_wrapper_x64_windows_ssefpu_nothing_modified
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_38
raw_hook_wrapper_x64_windows_ssefpu_patch_38:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_38_end
raw_hook_wrapper_x64_windows_ssefpu_patch_38_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_39
raw_hook_wrapper_x64_windows_ssefpu_patch_39:
	movups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_39_end
raw_hook_wrapper_x64_windows_ssefpu_patch_39_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_40
raw_hook_wrapper_x64_windows_ssefpu_patch_40:
	movups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_40_end
raw_hook_wrapper_x64_windows_ssefpu_patch_40_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_41
raw_hook_wrapper_x64_windows_ssefpu_patch_41:
	movups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_41_end
raw_hook_wrapper_x64_windows_ssefpu_patch_41_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_42
raw_hook_wrapper_x64_windows_ssefpu_patch_42:
	movups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_42_end
raw_hook_wrapper_x64_windows_ssefpu_patch_42_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_43
raw_hook_wrapper_x64_windows_ssefpu_patch_43:
	movups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_43_end
raw_hook_wrapper_x64_windows_ssefpu_patch_43_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_44
raw_hook_wrapper_x64_windows_ssefpu_patch_44:
	movups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_44_end
raw_hook_wrapper_x64_windows_ssefpu_patch_44_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_45
raw_hook_wrapper_x64_windows_ssefpu_patch_45:
	movups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_45_end
raw_hook_wrapper_x64_windows_ssefpu_patch_45_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_46
raw_hook_wrapper_x64_windows_ssefpu_patch_46:
	movups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_46_end
raw_hook_wrapper_x64_windows_ssefpu_patch_46_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_47
raw_hook_wrapper_x64_windows_ssefpu_patch_47:
	movups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_47_end
raw_hook_wrapper_x64_windows_ssefpu_patch_47_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_48
raw_hook_wrapper_x64_windows_ssefpu_patch_48:
	movups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_48_end
raw_hook_wrapper_x64_windows_ssefpu_patch_48_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_49
raw_hook_wrapper_x64_windows_ssefpu_patch_49:
	movups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_49_end
raw_hook_wrapper_x64_windows_ssefpu_patch_49_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_50
raw_hook_wrapper_x64_windows_ssefpu_patch_50:
	movups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_50_end
raw_hook_wrapper_x64_windows_ssefpu_patch_50_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_51
raw_hook_wrapper_x64_windows_ssefpu_patch_51:
	movups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_51_end
raw_hook_wrapper_x64_windows_ssefpu_patch_51_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_52
raw_hook_wrapper_x64_windows_ssefpu_patch_52:
	movups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_52_end
raw_hook_wrapper_x64_windows_ssefpu_patch_52_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_53
raw_hook_wrapper_x64_windows_ssefpu_patch_53:
	movups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_53_end
raw_hook_wrapper_x64_windows_ssefpu_patch_53_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_54
raw_hook_wrapper_x64_windows_ssefpu_patch_54:
	movups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_54_end
raw_hook_wrapper_x64_windows_ssefpu_patch_54_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_55
raw_hook_wrapper_x64_windows_ssefpu_patch_55:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_55_end
raw_hook_wrapper_x64_windows_ssefpu_patch_55_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_57
raw_hook_wrapper_x64_windows_ssefpu_patch_57:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_57_end
raw_hook_wrapper_x64_windows_ssefpu_patch_57_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_58
raw_hook_wrapper_x64_windows_ssefpu_patch_58:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_58_end
raw_hook_wrapper_x64_windows_ssefpu_patch_58_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_59
raw_hook_wrapper_x64_windows_ssefpu_patch_59:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_59_end
raw_hook_wrapper_x64_windows_ssefpu_patch_59_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_60
raw_hook_wrapper_x64_windows_ssefpu_patch_60:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_60_end
raw_hook_wrapper_x64_windows_ssefpu_patch_60_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_61
raw_hook_wrapper_x64_windows_ssefpu_patch_61:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_61_end
raw_hook_wrapper_x64_windows_ssefpu_patch_61_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_62
raw_hook_wrapper_x64_windows_ssefpu_patch_62:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_62_end
raw_hook_wrapper_x64_windows_ssefpu_patch_62_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_63
raw_hook_wrapper_x64_windows_ssefpu_patch_63:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_63_end
raw_hook_wrapper_x64_windows_ssefpu_patch_63_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_64
raw_hook_wrapper_x64_windows_ssefpu_patch_64:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_64_end
raw_hook_wrapper_x64_windows_ssefpu_patch_64_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_65
raw_hook_wrapper_x64_windows_ssefpu_patch_65:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_65_end
raw_hook_wrapper_x64_windows_ssefpu_patch_65_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_66
raw_hook_wrapper_x64_windows_ssefpu_patch_66:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_66_end
raw_hook_wrapper_x64_windows_ssefpu_patch_66_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_67
raw_hook_wrapper_x64_windows_ssefpu_patch_67:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_67_end
raw_hook_wrapper_x64_windows_ssefpu_patch_67_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_68
raw_hook_wrapper_x64_windows_ssefpu_patch_68:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_68_end
raw_hook_wrapper_x64_windows_ssefpu_patch_68_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_3
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_3_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_windows_ssefpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_4
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_4_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_windows_ssefpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_5
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_5_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_windows_ssefpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_6
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_6_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_windows_ssefpu_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_ssefpu_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_ssefpu_redirect_return
raw_hook_wrapper_x64_windows_ssefpu_unsupported_stack:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_7
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_7_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_7_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_8
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_8_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_8_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_9
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_9_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_windows_ssefpu_direct_return:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_56
raw_hook_wrapper_x64_windows_ssefpu_patch_56:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_56_end
raw_hook_wrapper_x64_windows_ssefpu_patch_56_end:
	popfq
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_69
raw_hook_wrapper_x64_windows_ssefpu_patch_69:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_69_end
raw_hook_wrapper_x64_windows_ssefpu_patch_69_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_70
raw_hook_wrapper_x64_windows_ssefpu_patch_70:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_70_end
raw_hook_wrapper_x64_windows_ssefpu_patch_70_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_71
raw_hook_wrapper_x64_windows_ssefpu_patch_71:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_71_end
raw_hook_wrapper_x64_windows_ssefpu_patch_71_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_72
raw_hook_wrapper_x64_windows_ssefpu_patch_72:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_72_end
raw_hook_wrapper_x64_windows_ssefpu_patch_72_end:
	ret
raw_hook_wrapper_x64_windows_ssefpu_redirect_return:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_10
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_10_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_11
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_11_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_11_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_12
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_12_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_12_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_13
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_13_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_13_end:
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_14
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_ssefpu_cet_patch_14_end
raw_hook_wrapper_x64_windows_ssefpu_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_windows_ssefpu_nothing_modified:
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_73
raw_hook_wrapper_x64_windows_ssefpu_patch_73:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_ssefpu_patch_73_end
raw_hook_wrapper_x64_windows_ssefpu_patch_73_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 windows SSE
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_windows_sse
raw_hook_wrapper_x64_windows_sse:
.globl raw_hook_wrapper_x64_windows_sse_patch_0
raw_hook_wrapper_x64_windows_sse_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_sse_patch_0_end
raw_hook_wrapper_x64_windows_sse_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_windows_sse_patch_1
raw_hook_wrapper_x64_windows_sse_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_1_end
raw_hook_wrapper_x64_windows_sse_patch_1_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_2
raw_hook_wrapper_x64_windows_sse_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_sse_patch_2_end
raw_hook_wrapper_x64_windows_sse_patch_2_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_3
raw_hook_wrapper_x64_windows_sse_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_sse_patch_3_end
raw_hook_wrapper_x64_windows_sse_patch_3_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_4
raw_hook_wrapper_x64_windows_sse_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_windows_sse_patch_4_end
raw_hook_wrapper_x64_windows_sse_patch_4_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_5
raw_hook_wrapper_x64_windows_sse_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_windows_sse_patch_5_end
raw_hook_wrapper_x64_windows_sse_patch_5_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_6
raw_hook_wrapper_x64_windows_sse_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_windows_sse_patch_6_end
raw_hook_wrapper_x64_windows_sse_patch_6_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_7
raw_hook_wrapper_x64_windows_sse_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_windows_sse_patch_7_end
raw_hook_wrapper_x64_windows_sse_patch_7_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_8
raw_hook_wrapper_x64_windows_sse_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_windows_sse_patch_8_end
raw_hook_wrapper_x64_windows_sse_patch_8_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_9
raw_hook_wrapper_x64_windows_sse_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_windows_sse_patch_9_end
raw_hook_wrapper_x64_windows_sse_patch_9_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_10
raw_hook_wrapper_x64_windows_sse_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_windows_sse_patch_10_end
raw_hook_wrapper_x64_windows_sse_patch_10_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_11
raw_hook_wrapper_x64_windows_sse_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_windows_sse_patch_11_end
raw_hook_wrapper_x64_windows_sse_patch_11_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_12
raw_hook_wrapper_x64_windows_sse_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_windows_sse_patch_12_end
raw_hook_wrapper_x64_windows_sse_patch_12_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_13
raw_hook_wrapper_x64_windows_sse_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_windows_sse_patch_13_end
raw_hook_wrapper_x64_windows_sse_patch_13_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_14
raw_hook_wrapper_x64_windows_sse_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_windows_sse_patch_14_end
raw_hook_wrapper_x64_windows_sse_patch_14_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_15
raw_hook_wrapper_x64_windows_sse_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_windows_sse_patch_15_end
raw_hook_wrapper_x64_windows_sse_patch_15_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_16
raw_hook_wrapper_x64_windows_sse_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_windows_sse_patch_16_end
raw_hook_wrapper_x64_windows_sse_patch_16_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_17
raw_hook_wrapper_x64_windows_sse_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_windows_sse_patch_17_end
raw_hook_wrapper_x64_windows_sse_patch_17_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_18
raw_hook_wrapper_x64_windows_sse_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_windows_sse_patch_18_end
raw_hook_wrapper_x64_windows_sse_patch_18_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_19
raw_hook_wrapper_x64_windows_sse_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_19_end
raw_hook_wrapper_x64_windows_sse_patch_19_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_20
raw_hook_wrapper_x64_windows_sse_patch_20:
	movups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_windows_sse_patch_20_end
raw_hook_wrapper_x64_windows_sse_patch_20_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_21
raw_hook_wrapper_x64_windows_sse_patch_21:
	movups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_windows_sse_patch_21_end
raw_hook_wrapper_x64_windows_sse_patch_21_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_22
raw_hook_wrapper_x64_windows_sse_patch_22:
	movups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_windows_sse_patch_22_end
raw_hook_wrapper_x64_windows_sse_patch_22_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_23
raw_hook_wrapper_x64_windows_sse_patch_23:
	movups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_windows_sse_patch_23_end
raw_hook_wrapper_x64_windows_sse_patch_23_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_24
raw_hook_wrapper_x64_windows_sse_patch_24:
	movups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_windows_sse_patch_24_end
raw_hook_wrapper_x64_windows_sse_patch_24_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_25
raw_hook_wrapper_x64_windows_sse_patch_25:
	movups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_windows_sse_patch_25_end
raw_hook_wrapper_x64_windows_sse_patch_25_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_26
raw_hook_wrapper_x64_windows_sse_patch_26:
	movups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_windows_sse_patch_26_end
raw_hook_wrapper_x64_windows_sse_patch_26_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_27
raw_hook_wrapper_x64_windows_sse_patch_27:
	movups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_windows_sse_patch_27_end
raw_hook_wrapper_x64_windows_sse_patch_27_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_28
raw_hook_wrapper_x64_windows_sse_patch_28:
	movups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_windows_sse_patch_28_end
raw_hook_wrapper_x64_windows_sse_patch_28_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_29
raw_hook_wrapper_x64_windows_sse_patch_29:
	movups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_windows_sse_patch_29_end
raw_hook_wrapper_x64_windows_sse_patch_29_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_30
raw_hook_wrapper_x64_windows_sse_patch_30:
	movups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_windows_sse_patch_30_end
raw_hook_wrapper_x64_windows_sse_patch_30_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_31
raw_hook_wrapper_x64_windows_sse_patch_31:
	movups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_windows_sse_patch_31_end
raw_hook_wrapper_x64_windows_sse_patch_31_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_32
raw_hook_wrapper_x64_windows_sse_patch_32:
	movups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_windows_sse_patch_32_end
raw_hook_wrapper_x64_windows_sse_patch_32_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_33
raw_hook_wrapper_x64_windows_sse_patch_33:
	movups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_windows_sse_patch_33_end
raw_hook_wrapper_x64_windows_sse_patch_33_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_34
raw_hook_wrapper_x64_windows_sse_patch_34:
	movups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_windows_sse_patch_34_end
raw_hook_wrapper_x64_windows_sse_patch_34_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_35
raw_hook_wrapper_x64_windows_sse_patch_35:
	movups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_windows_sse_patch_35_end
raw_hook_wrapper_x64_windows_sse_patch_35_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_0
raw_hook_wrapper_x64_windows_sse_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_0_end
raw_hook_wrapper_x64_windows_sse_cet_patch_0_end:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_1
raw_hook_wrapper_x64_windows_sse_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_1_end
raw_hook_wrapper_x64_windows_sse_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_2
raw_hook_wrapper_x64_windows_sse_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_2_end
raw_hook_wrapper_x64_windows_sse_cet_patch_2_end:
	mov rcx, rsp
	sub rsp, 0x20
.globl raw_hook_wrapper_x64_windows_sse_patch_36
raw_hook_wrapper_x64_windows_sse_patch_36:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_windows_sse_patch_36_end
raw_hook_wrapper_x64_windows_sse_patch_36_end:
	call rax
	add rsp, 0x20
	test al, al
	je raw_hook_wrapper_x64_windows_sse_nothing_modified
.globl raw_hook_wrapper_x64_windows_sse_patch_37
raw_hook_wrapper_x64_windows_sse_patch_37:
	movups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_37_end
raw_hook_wrapper_x64_windows_sse_patch_37_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_38
raw_hook_wrapper_x64_windows_sse_patch_38:
	movups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_38_end
raw_hook_wrapper_x64_windows_sse_patch_38_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_39
raw_hook_wrapper_x64_windows_sse_patch_39:
	movups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_39_end
raw_hook_wrapper_x64_windows_sse_patch_39_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_40
raw_hook_wrapper_x64_windows_sse_patch_40:
	movups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_40_end
raw_hook_wrapper_x64_windows_sse_patch_40_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_41
raw_hook_wrapper_x64_windows_sse_patch_41:
	movups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_41_end
raw_hook_wrapper_x64_windows_sse_patch_41_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_42
raw_hook_wrapper_x64_windows_sse_patch_42:
	movups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_42_end
raw_hook_wrapper_x64_windows_sse_patch_42_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_43
raw_hook_wrapper_x64_windows_sse_patch_43:
	movups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_43_end
raw_hook_wrapper_x64_windows_sse_patch_43_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_44
raw_hook_wrapper_x64_windows_sse_patch_44:
	movups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_44_end
raw_hook_wrapper_x64_windows_sse_patch_44_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_45
raw_hook_wrapper_x64_windows_sse_patch_45:
	movups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_45_end
raw_hook_wrapper_x64_windows_sse_patch_45_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_46
raw_hook_wrapper_x64_windows_sse_patch_46:
	movups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_46_end
raw_hook_wrapper_x64_windows_sse_patch_46_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_47
raw_hook_wrapper_x64_windows_sse_patch_47:
	movups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_47_end
raw_hook_wrapper_x64_windows_sse_patch_47_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_48
raw_hook_wrapper_x64_windows_sse_patch_48:
	movups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_48_end
raw_hook_wrapper_x64_windows_sse_patch_48_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_49
raw_hook_wrapper_x64_windows_sse_patch_49:
	movups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_49_end
raw_hook_wrapper_x64_windows_sse_patch_49_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_50
raw_hook_wrapper_x64_windows_sse_patch_50:
	movups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_50_end
raw_hook_wrapper_x64_windows_sse_patch_50_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_51
raw_hook_wrapper_x64_windows_sse_patch_51:
	movups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_51_end
raw_hook_wrapper_x64_windows_sse_patch_51_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_52
raw_hook_wrapper_x64_windows_sse_patch_52:
	movups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_52_end
raw_hook_wrapper_x64_windows_sse_patch_52_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_53
raw_hook_wrapper_x64_windows_sse_patch_53:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_53_end
raw_hook_wrapper_x64_windows_sse_patch_53_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_55
raw_hook_wrapper_x64_windows_sse_patch_55:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_55_end
raw_hook_wrapper_x64_windows_sse_patch_55_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_56
raw_hook_wrapper_x64_windows_sse_patch_56:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_56_end
raw_hook_wrapper_x64_windows_sse_patch_56_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_57
raw_hook_wrapper_x64_windows_sse_patch_57:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_57_end
raw_hook_wrapper_x64_windows_sse_patch_57_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_58
raw_hook_wrapper_x64_windows_sse_patch_58:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_58_end
raw_hook_wrapper_x64_windows_sse_patch_58_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_59
raw_hook_wrapper_x64_windows_sse_patch_59:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_59_end
raw_hook_wrapper_x64_windows_sse_patch_59_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_60
raw_hook_wrapper_x64_windows_sse_patch_60:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_60_end
raw_hook_wrapper_x64_windows_sse_patch_60_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_61
raw_hook_wrapper_x64_windows_sse_patch_61:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_61_end
raw_hook_wrapper_x64_windows_sse_patch_61_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_62
raw_hook_wrapper_x64_windows_sse_patch_62:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_62_end
raw_hook_wrapper_x64_windows_sse_patch_62_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_63
raw_hook_wrapper_x64_windows_sse_patch_63:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_63_end
raw_hook_wrapper_x64_windows_sse_patch_63_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_64
raw_hook_wrapper_x64_windows_sse_patch_64:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_64_end
raw_hook_wrapper_x64_windows_sse_patch_64_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_65
raw_hook_wrapper_x64_windows_sse_patch_65:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_65_end
raw_hook_wrapper_x64_windows_sse_patch_65_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_66
raw_hook_wrapper_x64_windows_sse_patch_66:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_66_end
raw_hook_wrapper_x64_windows_sse_patch_66_end:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_3
raw_hook_wrapper_x64_windows_sse_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_3_end
raw_hook_wrapper_x64_windows_sse_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_windows_sse_unsupported_stack
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_4
raw_hook_wrapper_x64_windows_sse_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_4_end
raw_hook_wrapper_x64_windows_sse_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_windows_sse_unsupported_stack
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_5
raw_hook_wrapper_x64_windows_sse_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_5_end
raw_hook_wrapper_x64_windows_sse_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_windows_sse_unsupported_stack
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_6
raw_hook_wrapper_x64_windows_sse_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_6_end
raw_hook_wrapper_x64_windows_sse_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_windows_sse_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_sse_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_sse_redirect_return
raw_hook_wrapper_x64_windows_sse_unsupported_stack:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_7
raw_hook_wrapper_x64_windows_sse_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_7_end
raw_hook_wrapper_x64_windows_sse_cet_patch_7_end:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_8
raw_hook_wrapper_x64_windows_sse_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_8_end
raw_hook_wrapper_x64_windows_sse_cet_patch_8_end:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_9
raw_hook_wrapper_x64_windows_sse_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_9_end
raw_hook_wrapper_x64_windows_sse_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_windows_sse_direct_return:
.globl raw_hook_wrapper_x64_windows_sse_patch_54
raw_hook_wrapper_x64_windows_sse_patch_54:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_54_end
raw_hook_wrapper_x64_windows_sse_patch_54_end:
	popfq
.globl raw_hook_wrapper_x64_windows_sse_patch_67
raw_hook_wrapper_x64_windows_sse_patch_67:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_67_end
raw_hook_wrapper_x64_windows_sse_patch_67_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_68
raw_hook_wrapper_x64_windows_sse_patch_68:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_68_end
raw_hook_wrapper_x64_windows_sse_patch_68_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_69
raw_hook_wrapper_x64_windows_sse_patch_69:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_69_end
raw_hook_wrapper_x64_windows_sse_patch_69_end:
.globl raw_hook_wrapper_x64_windows_sse_patch_70
raw_hook_wrapper_x64_windows_sse_patch_70:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_patch_70_end
raw_hook_wrapper_x64_windows_sse_patch_70_end:
	ret
raw_hook_wrapper_x64_windows_sse_redirect_return:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_10
raw_hook_wrapper_x64_windows_sse_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_10_end
raw_hook_wrapper_x64_windows_sse_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_11
raw_hook_wrapper_x64_windows_sse_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_11_end
raw_hook_wrapper_x64_windows_sse_cet_patch_11_end:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_12
raw_hook_wrapper_x64_windows_sse_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_12_end
raw_hook_wrapper_x64_windows_sse_cet_patch_12_end:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_13
raw_hook_wrapper_x64_windows_sse_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_13_end
raw_hook_wrapper_x64_windows_sse_cet_patch_13_end:
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_14
raw_hook_wrapper_x64_windows_sse_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_sse_cet_patch_14_end
raw_hook_wrapper_x64_windows_sse_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_windows_sse_nothing_modified:
.globl raw_hook_wrapper_x64_windows_sse_patch_71
raw_hook_wrapper_x64_windows_sse_patch_71:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_sse_patch_71_end
raw_hook_wrapper_x64_windows_sse_patch_71_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 windows FPU
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_windows_fpu
raw_hook_wrapper_x64_windows_fpu:
.globl raw_hook_wrapper_x64_windows_fpu_patch_0
raw_hook_wrapper_x64_windows_fpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_fpu_patch_0_end
raw_hook_wrapper_x64_windows_fpu_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_windows_fpu_patch_1
raw_hook_wrapper_x64_windows_fpu_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_1_end
raw_hook_wrapper_x64_windows_fpu_patch_1_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_2
raw_hook_wrapper_x64_windows_fpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_fpu_patch_2_end
raw_hook_wrapper_x64_windows_fpu_patch_2_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_3
raw_hook_wrapper_x64_windows_fpu_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_fpu_patch_3_end
raw_hook_wrapper_x64_windows_fpu_patch_3_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_4
raw_hook_wrapper_x64_windows_fpu_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_windows_fpu_patch_4_end
raw_hook_wrapper_x64_windows_fpu_patch_4_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_5
raw_hook_wrapper_x64_windows_fpu_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_windows_fpu_patch_5_end
raw_hook_wrapper_x64_windows_fpu_patch_5_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_6
raw_hook_wrapper_x64_windows_fpu_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_windows_fpu_patch_6_end
raw_hook_wrapper_x64_windows_fpu_patch_6_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_7
raw_hook_wrapper_x64_windows_fpu_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_windows_fpu_patch_7_end
raw_hook_wrapper_x64_windows_fpu_patch_7_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_8
raw_hook_wrapper_x64_windows_fpu_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_windows_fpu_patch_8_end
raw_hook_wrapper_x64_windows_fpu_patch_8_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_9
raw_hook_wrapper_x64_windows_fpu_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_windows_fpu_patch_9_end
raw_hook_wrapper_x64_windows_fpu_patch_9_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_10
raw_hook_wrapper_x64_windows_fpu_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_windows_fpu_patch_10_end
raw_hook_wrapper_x64_windows_fpu_patch_10_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_11
raw_hook_wrapper_x64_windows_fpu_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_windows_fpu_patch_11_end
raw_hook_wrapper_x64_windows_fpu_patch_11_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_12
raw_hook_wrapper_x64_windows_fpu_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_windows_fpu_patch_12_end
raw_hook_wrapper_x64_windows_fpu_patch_12_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_13
raw_hook_wrapper_x64_windows_fpu_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_windows_fpu_patch_13_end
raw_hook_wrapper_x64_windows_fpu_patch_13_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_14
raw_hook_wrapper_x64_windows_fpu_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_windows_fpu_patch_14_end
raw_hook_wrapper_x64_windows_fpu_patch_14_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_15
raw_hook_wrapper_x64_windows_fpu_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_windows_fpu_patch_15_end
raw_hook_wrapper_x64_windows_fpu_patch_15_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_16
raw_hook_wrapper_x64_windows_fpu_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_windows_fpu_patch_16_end
raw_hook_wrapper_x64_windows_fpu_patch_16_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_17
raw_hook_wrapper_x64_windows_fpu_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_windows_fpu_patch_17_end
raw_hook_wrapper_x64_windows_fpu_patch_17_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_18
raw_hook_wrapper_x64_windows_fpu_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_windows_fpu_patch_18_end
raw_hook_wrapper_x64_windows_fpu_patch_18_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_19
raw_hook_wrapper_x64_windows_fpu_patch_19:
	fsave [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_19_end
raw_hook_wrapper_x64_windows_fpu_patch_19_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_0
raw_hook_wrapper_x64_windows_fpu_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_0_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_0_end:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_1
raw_hook_wrapper_x64_windows_fpu_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_1_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_2
raw_hook_wrapper_x64_windows_fpu_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_2_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_2_end:
	mov rcx, rsp
	sub rsp, 0x20
.globl raw_hook_wrapper_x64_windows_fpu_patch_20
raw_hook_wrapper_x64_windows_fpu_patch_20:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_windows_fpu_patch_20_end
raw_hook_wrapper_x64_windows_fpu_patch_20_end:
	call rax
	add rsp, 0x20
	test al, al
	je raw_hook_wrapper_x64_windows_fpu_nothing_modified
.globl raw_hook_wrapper_x64_windows_fpu_patch_21
raw_hook_wrapper_x64_windows_fpu_patch_21:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_21_end
raw_hook_wrapper_x64_windows_fpu_patch_21_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_23
raw_hook_wrapper_x64_windows_fpu_patch_23:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_23_end
raw_hook_wrapper_x64_windows_fpu_patch_23_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_24
raw_hook_wrapper_x64_windows_fpu_patch_24:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_24_end
raw_hook_wrapper_x64_windows_fpu_patch_24_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_25
raw_hook_wrapper_x64_windows_fpu_patch_25:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_25_end
raw_hook_wrapper_x64_windows_fpu_patch_25_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_26
raw_hook_wrapper_x64_windows_fpu_patch_26:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_26_end
raw_hook_wrapper_x64_windows_fpu_patch_26_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_27
raw_hook_wrapper_x64_windows_fpu_patch_27:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_27_end
raw_hook_wrapper_x64_windows_fpu_patch_27_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_28
raw_hook_wrapper_x64_windows_fpu_patch_28:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_28_end
raw_hook_wrapper_x64_windows_fpu_patch_28_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_29
raw_hook_wrapper_x64_windows_fpu_patch_29:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_29_end
raw_hook_wrapper_x64_windows_fpu_patch_29_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_30
raw_hook_wrapper_x64_windows_fpu_patch_30:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_30_end
raw_hook_wrapper_x64_windows_fpu_patch_30_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_31
raw_hook_wrapper_x64_windows_fpu_patch_31:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_31_end
raw_hook_wrapper_x64_windows_fpu_patch_31_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_32
raw_hook_wrapper_x64_windows_fpu_patch_32:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_32_end
raw_hook_wrapper_x64_windows_fpu_patch_32_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_33
raw_hook_wrapper_x64_windows_fpu_patch_33:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_33_end
raw_hook_wrapper_x64_windows_fpu_patch_33_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_34
raw_hook_wrapper_x64_windows_fpu_patch_34:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_34_end
raw_hook_wrapper_x64_windows_fpu_patch_34_end:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_3
raw_hook_wrapper_x64_windows_fpu_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_3_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_windows_fpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_4
raw_hook_wrapper_x64_windows_fpu_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_4_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_windows_fpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_5
raw_hook_wrapper_x64_windows_fpu_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_5_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_windows_fpu_unsupported_stack
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_6
raw_hook_wrapper_x64_windows_fpu_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_6_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_windows_fpu_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_fpu_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_fpu_redirect_return
raw_hook_wrapper_x64_windows_fpu_unsupported_stack:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_7
raw_hook_wrapper_x64_windows_fpu_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_7_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_7_end:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_8
raw_hook_wrapper_x64_windows_fpu_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_8_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_8_end:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_9
raw_hook_wrapper_x64_windows_fpu_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_9_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_windows_fpu_direct_return:
.globl raw_hook_wrapper_x64_windows_fpu_patch_22
raw_hook_wrapper_x64_windows_fpu_patch_22:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_22_end
raw_hook_wrapper_x64_windows_fpu_patch_22_end:
	popfq
.globl raw_hook_wrapper_x64_windows_fpu_patch_35
raw_hook_wrapper_x64_windows_fpu_patch_35:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_35_end
raw_hook_wrapper_x64_windows_fpu_patch_35_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_36
raw_hook_wrapper_x64_windows_fpu_patch_36:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_36_end
raw_hook_wrapper_x64_windows_fpu_patch_36_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_37
raw_hook_wrapper_x64_windows_fpu_patch_37:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_37_end
raw_hook_wrapper_x64_windows_fpu_patch_37_end:
.globl raw_hook_wrapper_x64_windows_fpu_patch_38
raw_hook_wrapper_x64_windows_fpu_patch_38:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_patch_38_end
raw_hook_wrapper_x64_windows_fpu_patch_38_end:
	ret
raw_hook_wrapper_x64_windows_fpu_redirect_return:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_10
raw_hook_wrapper_x64_windows_fpu_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_10_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_11
raw_hook_wrapper_x64_windows_fpu_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_11_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_11_end:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_12
raw_hook_wrapper_x64_windows_fpu_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_12_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_12_end:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_13
raw_hook_wrapper_x64_windows_fpu_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_13_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_13_end:
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_14
raw_hook_wrapper_x64_windows_fpu_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_fpu_cet_patch_14_end
raw_hook_wrapper_x64_windows_fpu_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_windows_fpu_nothing_modified:
.globl raw_hook_wrapper_x64_windows_fpu_patch_39
raw_hook_wrapper_x64_windows_fpu_patch_39:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_fpu_patch_39_end
raw_hook_wrapper_x64_windows_fpu_patch_39_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 windows Native
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_windows_native
raw_hook_wrapper_x64_windows_native:
.globl raw_hook_wrapper_x64_windows_native_patch_0
raw_hook_wrapper_x64_windows_native_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_native_patch_0_end
raw_hook_wrapper_x64_windows_native_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_windows_native_patch_1
raw_hook_wrapper_x64_windows_native_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_1_end
raw_hook_wrapper_x64_windows_native_patch_1_end:
.globl raw_hook_wrapper_x64_windows_native_patch_2
raw_hook_wrapper_x64_windows_native_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_native_patch_2_end
raw_hook_wrapper_x64_windows_native_patch_2_end:
.globl raw_hook_wrapper_x64_windows_native_patch_3
raw_hook_wrapper_x64_windows_native_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_native_patch_3_end
raw_hook_wrapper_x64_windows_native_patch_3_end:
.globl raw_hook_wrapper_x64_windows_native_patch_4
raw_hook_wrapper_x64_windows_native_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_windows_native_patch_4_end
raw_hook_wrapper_x64_windows_native_patch_4_end:
.globl raw_hook_wrapper_x64_windows_native_patch_5
raw_hook_wrapper_x64_windows_native_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_windows_native_patch_5_end
raw_hook_wrapper_x64_windows_native_patch_5_end:
.globl raw_hook_wrapper_x64_windows_native_patch_6
raw_hook_wrapper_x64_windows_native_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_windows_native_patch_6_end
raw_hook_wrapper_x64_windows_native_patch_6_end:
.globl raw_hook_wrapper_x64_windows_native_patch_7
raw_hook_wrapper_x64_windows_native_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_windows_native_patch_7_end
raw_hook_wrapper_x64_windows_native_patch_7_end:
.globl raw_hook_wrapper_x64_windows_native_patch_8
raw_hook_wrapper_x64_windows_native_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_windows_native_patch_8_end
raw_hook_wrapper_x64_windows_native_patch_8_end:
.globl raw_hook_wrapper_x64_windows_native_patch_9
raw_hook_wrapper_x64_windows_native_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_windows_native_patch_9_end
raw_hook_wrapper_x64_windows_native_patch_9_end:
.globl raw_hook_wrapper_x64_windows_native_patch_10
raw_hook_wrapper_x64_windows_native_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_windows_native_patch_10_end
raw_hook_wrapper_x64_windows_native_patch_10_end:
.globl raw_hook_wrapper_x64_windows_native_patch_11
raw_hook_wrapper_x64_windows_native_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_windows_native_patch_11_end
raw_hook_wrapper_x64_windows_native_patch_11_end:
.globl raw_hook_wrapper_x64_windows_native_patch_12
raw_hook_wrapper_x64_windows_native_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_windows_native_patch_12_end
raw_hook_wrapper_x64_windows_native_patch_12_end:
.globl raw_hook_wrapper_x64_windows_native_patch_13
raw_hook_wrapper_x64_windows_native_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_windows_native_patch_13_end
raw_hook_wrapper_x64_windows_native_patch_13_end:
.globl raw_hook_wrapper_x64_windows_native_patch_14
raw_hook_wrapper_x64_windows_native_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_windows_native_patch_14_end
raw_hook_wrapper_x64_windows_native_patch_14_end:
.globl raw_hook_wrapper_x64_windows_native_patch_15
raw_hook_wrapper_x64_windows_native_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_windows_native_patch_15_end
raw_hook_wrapper_x64_windows_native_patch_15_end:
.globl raw_hook_wrapper_x64_windows_native_patch_16
raw_hook_wrapper_x64_windows_native_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_windows_native_patch_16_end
raw_hook_wrapper_x64_windows_native_patch_16_end:
.globl raw_hook_wrapper_x64_windows_native_patch_17
raw_hook_wrapper_x64_windows_native_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_windows_native_patch_17_end
raw_hook_wrapper_x64_windows_native_patch_17_end:
.globl raw_hook_wrapper_x64_windows_native_patch_18
raw_hook_wrapper_x64_windows_native_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_windows_native_patch_18_end
raw_hook_wrapper_x64_windows_native_patch_18_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_windows_native_cet_patch_0
raw_hook_wrapper_x64_windows_native_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_native_cet_patch_0_end
raw_hook_wrapper_x64_windows_native_cet_patch_0_end:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_1
raw_hook_wrapper_x64_windows_native_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_native_cet_patch_1_end
raw_hook_wrapper_x64_windows_native_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_2
raw_hook_wrapper_x64_windows_native_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_windows_native_cet_patch_2_end
raw_hook_wrapper_x64_windows_native_cet_patch_2_end:
	mov rcx, rsp
	sub rsp, 0x20
.globl raw_hook_wrapper_x64_windows_native_patch_19
raw_hook_wrapper_x64_windows_native_patch_19:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_windows_native_patch_19_end
raw_hook_wrapper_x64_windows_native_patch_19_end:
	call rax
	add rsp, 0x20
	test al, al
	je raw_hook_wrapper_x64_windows_native_nothing_modified
.globl raw_hook_wrapper_x64_windows_native_patch_21
raw_hook_wrapper_x64_windows_native_patch_21:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_21_end
raw_hook_wrapper_x64_windows_native_patch_21_end:
.globl raw_hook_wrapper_x64_windows_native_patch_22
raw_hook_wrapper_x64_windows_native_patch_22:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_22_end
raw_hook_wrapper_x64_windows_native_patch_22_end:
.globl raw_hook_wrapper_x64_windows_native_patch_23
raw_hook_wrapper_x64_windows_native_patch_23:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_23_end
raw_hook_wrapper_x64_windows_native_patch_23_end:
.globl raw_hook_wrapper_x64_windows_native_patch_24
raw_hook_wrapper_x64_windows_native_patch_24:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_24_end
raw_hook_wrapper_x64_windows_native_patch_24_end:
.globl raw_hook_wrapper_x64_windows_native_patch_25
raw_hook_wrapper_x64_windows_native_patch_25:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_25_end
raw_hook_wrapper_x64_windows_native_patch_25_end:
.globl raw_hook_wrapper_x64_windows_native_patch_26
raw_hook_wrapper_x64_windows_native_patch_26:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_26_end
raw_hook_wrapper_x64_windows_native_patch_26_end:
.globl raw_hook_wrapper_x64_windows_native_patch_27
raw_hook_wrapper_x64_windows_native_patch_27:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_27_end
raw_hook_wrapper_x64_windows_native_patch_27_end:
.globl raw_hook_wrapper_x64_windows_native_patch_28
raw_hook_wrapper_x64_windows_native_patch_28:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_28_end
raw_hook_wrapper_x64_windows_native_patch_28_end:
.globl raw_hook_wrapper_x64_windows_native_patch_29
raw_hook_wrapper_x64_windows_native_patch_29:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_29_end
raw_hook_wrapper_x64_windows_native_patch_29_end:
.globl raw_hook_wrapper_x64_windows_native_patch_30
raw_hook_wrapper_x64_windows_native_patch_30:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_30_end
raw_hook_wrapper_x64_windows_native_patch_30_end:
.globl raw_hook_wrapper_x64_windows_native_patch_31
raw_hook_wrapper_x64_windows_native_patch_31:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_31_end
raw_hook_wrapper_x64_windows_native_patch_31_end:
.globl raw_hook_wrapper_x64_windows_native_patch_32
raw_hook_wrapper_x64_windows_native_patch_32:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_32_end
raw_hook_wrapper_x64_windows_native_patch_32_end:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_3
raw_hook_wrapper_x64_windows_native_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_3_end
raw_hook_wrapper_x64_windows_native_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_windows_native_unsupported_stack
.globl raw_hook_wrapper_x64_windows_native_cet_patch_4
raw_hook_wrapper_x64_windows_native_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_4_end
raw_hook_wrapper_x64_windows_native_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_windows_native_unsupported_stack
.globl raw_hook_wrapper_x64_windows_native_cet_patch_5
raw_hook_wrapper_x64_windows_native_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_5_end
raw_hook_wrapper_x64_windows_native_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_windows_native_unsupported_stack
.globl raw_hook_wrapper_x64_windows_native_cet_patch_6
raw_hook_wrapper_x64_windows_native_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_6_end
raw_hook_wrapper_x64_windows_native_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_windows_native_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_native_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_windows_native_redirect_return
raw_hook_wrapper_x64_windows_native_unsupported_stack:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_7
raw_hook_wrapper_x64_windows_native_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_7_end
raw_hook_wrapper_x64_windows_native_cet_patch_7_end:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_8
raw_hook_wrapper_x64_windows_native_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_windows_native_cet_patch_8_end
raw_hook_wrapper_x64_windows_native_cet_patch_8_end:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_9
raw_hook_wrapper_x64_windows_native_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_9_end
raw_hook_wrapper_x64_windows_native_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_windows_native_direct_return:
.globl raw_hook_wrapper_x64_windows_native_patch_20
raw_hook_wrapper_x64_windows_native_patch_20:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_20_end
raw_hook_wrapper_x64_windows_native_patch_20_end:
	popfq
.globl raw_hook_wrapper_x64_windows_native_patch_33
raw_hook_wrapper_x64_windows_native_patch_33:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_33_end
raw_hook_wrapper_x64_windows_native_patch_33_end:
.globl raw_hook_wrapper_x64_windows_native_patch_34
raw_hook_wrapper_x64_windows_native_patch_34:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_34_end
raw_hook_wrapper_x64_windows_native_patch_34_end:
.globl raw_hook_wrapper_x64_windows_native_patch_35
raw_hook_wrapper_x64_windows_native_patch_35:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_35_end
raw_hook_wrapper_x64_windows_native_patch_35_end:
.globl raw_hook_wrapper_x64_windows_native_patch_36
raw_hook_wrapper_x64_windows_native_patch_36:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_patch_36_end
raw_hook_wrapper_x64_windows_native_patch_36_end:
	ret
raw_hook_wrapper_x64_windows_native_redirect_return:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_10
raw_hook_wrapper_x64_windows_native_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_10_end
raw_hook_wrapper_x64_windows_native_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_windows_native_cet_patch_11
raw_hook_wrapper_x64_windows_native_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_11_end
raw_hook_wrapper_x64_windows_native_cet_patch_11_end:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_12
raw_hook_wrapper_x64_windows_native_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_12_end
raw_hook_wrapper_x64_windows_native_cet_patch_12_end:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_13
raw_hook_wrapper_x64_windows_native_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_13_end
raw_hook_wrapper_x64_windows_native_cet_patch_13_end:
.globl raw_hook_wrapper_x64_windows_native_cet_patch_14
raw_hook_wrapper_x64_windows_native_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_windows_native_cet_patch_14_end
raw_hook_wrapper_x64_windows_native_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_windows_native_nothing_modified:
.globl raw_hook_wrapper_x64_windows_native_patch_37
raw_hook_wrapper_x64_windows_native_patch_37:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_windows_native_patch_37_end
raw_hook_wrapper_x64_windows_native_patch_37_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 systemv AVX512FPU
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_systemv_avx512fpu
raw_hook_wrapper_x64_systemv_avx512fpu:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_0
raw_hook_wrapper_x64_systemv_avx512fpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_0_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_1
raw_hook_wrapper_x64_systemv_avx512fpu_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_1_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_1_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_2
raw_hook_wrapper_x64_systemv_avx512fpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_2_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_2_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_3
raw_hook_wrapper_x64_systemv_avx512fpu_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_3_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_3_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_4
raw_hook_wrapper_x64_systemv_avx512fpu_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_4_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_4_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_5
raw_hook_wrapper_x64_systemv_avx512fpu_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_5_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_5_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_6
raw_hook_wrapper_x64_systemv_avx512fpu_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_6_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_6_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_7
raw_hook_wrapper_x64_systemv_avx512fpu_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_7_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_8
raw_hook_wrapper_x64_systemv_avx512fpu_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_8_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_9
raw_hook_wrapper_x64_systemv_avx512fpu_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_9_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_9_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_10
raw_hook_wrapper_x64_systemv_avx512fpu_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_10_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_10_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_11
raw_hook_wrapper_x64_systemv_avx512fpu_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_11_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_12
raw_hook_wrapper_x64_systemv_avx512fpu_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_12_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_13
raw_hook_wrapper_x64_systemv_avx512fpu_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_13_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_14
raw_hook_wrapper_x64_systemv_avx512fpu_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_14_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_14_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_15
raw_hook_wrapper_x64_systemv_avx512fpu_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_15_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_15_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_16
raw_hook_wrapper_x64_systemv_avx512fpu_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_16_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_16_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_17
raw_hook_wrapper_x64_systemv_avx512fpu_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_17_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_17_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_18
raw_hook_wrapper_x64_systemv_avx512fpu_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_18_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_18_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_19
raw_hook_wrapper_x64_systemv_avx512fpu_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_19_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_19_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_20
raw_hook_wrapper_x64_systemv_avx512fpu_patch_20:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_20_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_20_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_21
raw_hook_wrapper_x64_systemv_avx512fpu_patch_21:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_21_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_21_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_22
raw_hook_wrapper_x64_systemv_avx512fpu_patch_22:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_22_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_22_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_23
raw_hook_wrapper_x64_systemv_avx512fpu_patch_23:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_23_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_23_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_24
raw_hook_wrapper_x64_systemv_avx512fpu_patch_24:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_24_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_24_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_25
raw_hook_wrapper_x64_systemv_avx512fpu_patch_25:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_25_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_25_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_26
raw_hook_wrapper_x64_systemv_avx512fpu_patch_26:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_26_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_26_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_27
raw_hook_wrapper_x64_systemv_avx512fpu_patch_27:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_27_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_27_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_28
raw_hook_wrapper_x64_systemv_avx512fpu_patch_28:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_28_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_28_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_29
raw_hook_wrapper_x64_systemv_avx512fpu_patch_29:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_29_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_29_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_30
raw_hook_wrapper_x64_systemv_avx512fpu_patch_30:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_30_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_30_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_31
raw_hook_wrapper_x64_systemv_avx512fpu_patch_31:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_31_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_31_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_32
raw_hook_wrapper_x64_systemv_avx512fpu_patch_32:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_32_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_32_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_33
raw_hook_wrapper_x64_systemv_avx512fpu_patch_33:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_33_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_33_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_34
raw_hook_wrapper_x64_systemv_avx512fpu_patch_34:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_34_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_34_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_35
raw_hook_wrapper_x64_systemv_avx512fpu_patch_35:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_35_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_35_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_36
raw_hook_wrapper_x64_systemv_avx512fpu_patch_36:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_36_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_36_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_37
raw_hook_wrapper_x64_systemv_avx512fpu_patch_37:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_37_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_37_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_38
raw_hook_wrapper_x64_systemv_avx512fpu_patch_38:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_38_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_38_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_39
raw_hook_wrapper_x64_systemv_avx512fpu_patch_39:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_39_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_39_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_40
raw_hook_wrapper_x64_systemv_avx512fpu_patch_40:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_40_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_40_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_41
raw_hook_wrapper_x64_systemv_avx512fpu_patch_41:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_41_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_41_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_42
raw_hook_wrapper_x64_systemv_avx512fpu_patch_42:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_42_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_42_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_43
raw_hook_wrapper_x64_systemv_avx512fpu_patch_43:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_43_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_43_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_44
raw_hook_wrapper_x64_systemv_avx512fpu_patch_44:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm8
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_44_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_44_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_45
raw_hook_wrapper_x64_systemv_avx512fpu_patch_45:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm9
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_45_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_45_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_46
raw_hook_wrapper_x64_systemv_avx512fpu_patch_46:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm10
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_46_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_46_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_47
raw_hook_wrapper_x64_systemv_avx512fpu_patch_47:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm11
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_47_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_47_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_48
raw_hook_wrapper_x64_systemv_avx512fpu_patch_48:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm12
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_48_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_48_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_49
raw_hook_wrapper_x64_systemv_avx512fpu_patch_49:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm13
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_49_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_49_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_50
raw_hook_wrapper_x64_systemv_avx512fpu_patch_50:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm14
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_50_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_50_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_51
raw_hook_wrapper_x64_systemv_avx512fpu_patch_51:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm15
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_51_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_51_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_52
raw_hook_wrapper_x64_systemv_avx512fpu_patch_52:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm0
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_52_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_52_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_53
raw_hook_wrapper_x64_systemv_avx512fpu_patch_53:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm1
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_53_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_53_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_54
raw_hook_wrapper_x64_systemv_avx512fpu_patch_54:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm2
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_54_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_54_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_55
raw_hook_wrapper_x64_systemv_avx512fpu_patch_55:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm3
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_55_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_55_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_56
raw_hook_wrapper_x64_systemv_avx512fpu_patch_56:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm4
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_56_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_56_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_57
raw_hook_wrapper_x64_systemv_avx512fpu_patch_57:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm5
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_57_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_57_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_58
raw_hook_wrapper_x64_systemv_avx512fpu_patch_58:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm6
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_58_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_58_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_59
raw_hook_wrapper_x64_systemv_avx512fpu_patch_59:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm7
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_59_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_59_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_60
raw_hook_wrapper_x64_systemv_avx512fpu_patch_60:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm8
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_60_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_60_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_61
raw_hook_wrapper_x64_systemv_avx512fpu_patch_61:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm9
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_61_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_61_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_62
raw_hook_wrapper_x64_systemv_avx512fpu_patch_62:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm10
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_62_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_62_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_63
raw_hook_wrapper_x64_systemv_avx512fpu_patch_63:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm11
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_63_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_63_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_64
raw_hook_wrapper_x64_systemv_avx512fpu_patch_64:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm12
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_64_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_64_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_65
raw_hook_wrapper_x64_systemv_avx512fpu_patch_65:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm13
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_65_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_65_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_66
raw_hook_wrapper_x64_systemv_avx512fpu_patch_66:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm14
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_66_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_66_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_67
raw_hook_wrapper_x64_systemv_avx512fpu_patch_67:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm15
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_67_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_67_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_68
raw_hook_wrapper_x64_systemv_avx512fpu_patch_68:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm16
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_68_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_68_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_69
raw_hook_wrapper_x64_systemv_avx512fpu_patch_69:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm17
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_69_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_69_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_70
raw_hook_wrapper_x64_systemv_avx512fpu_patch_70:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm18
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_70_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_70_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_71
raw_hook_wrapper_x64_systemv_avx512fpu_patch_71:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm19
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_71_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_71_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_72
raw_hook_wrapper_x64_systemv_avx512fpu_patch_72:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm20
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_72_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_72_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_73
raw_hook_wrapper_x64_systemv_avx512fpu_patch_73:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm21
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_73_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_73_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_74
raw_hook_wrapper_x64_systemv_avx512fpu_patch_74:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm22
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_74_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_74_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_75
raw_hook_wrapper_x64_systemv_avx512fpu_patch_75:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm23
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_75_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_75_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_76
raw_hook_wrapper_x64_systemv_avx512fpu_patch_76:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm24
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_76_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_76_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_77
raw_hook_wrapper_x64_systemv_avx512fpu_patch_77:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm25
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_77_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_77_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_78
raw_hook_wrapper_x64_systemv_avx512fpu_patch_78:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm26
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_78_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_78_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_79
raw_hook_wrapper_x64_systemv_avx512fpu_patch_79:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm27
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_79_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_79_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_80
raw_hook_wrapper_x64_systemv_avx512fpu_patch_80:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm28
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_80_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_80_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_81
raw_hook_wrapper_x64_systemv_avx512fpu_patch_81:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm29
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_81_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_81_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_82
raw_hook_wrapper_x64_systemv_avx512fpu_patch_82:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm30
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_82_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_82_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_83
raw_hook_wrapper_x64_systemv_avx512fpu_patch_83:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm31
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_83_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_83_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_84
raw_hook_wrapper_x64_systemv_avx512fpu_patch_84:
	fsave [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_84_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_84_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_0
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_0_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_0_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_1
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_1_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_2
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_2_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_2_end:
	mov rdi, rsp
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_85
raw_hook_wrapper_x64_systemv_avx512fpu_patch_85:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_85_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_85_end:
	call rax
	test al, al
	je raw_hook_wrapper_x64_systemv_avx512fpu_nothing_modified
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_86
raw_hook_wrapper_x64_systemv_avx512fpu_patch_86:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_86_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_86_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_87
raw_hook_wrapper_x64_systemv_avx512fpu_patch_87:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_87_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_87_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_88
raw_hook_wrapper_x64_systemv_avx512fpu_patch_88:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_88_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_88_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_89
raw_hook_wrapper_x64_systemv_avx512fpu_patch_89:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_89_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_89_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_90
raw_hook_wrapper_x64_systemv_avx512fpu_patch_90:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_90_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_90_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_91
raw_hook_wrapper_x64_systemv_avx512fpu_patch_91:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_91_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_91_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_92
raw_hook_wrapper_x64_systemv_avx512fpu_patch_92:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_92_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_92_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_93
raw_hook_wrapper_x64_systemv_avx512fpu_patch_93:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_93_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_93_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_94
raw_hook_wrapper_x64_systemv_avx512fpu_patch_94:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_94_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_94_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_95
raw_hook_wrapper_x64_systemv_avx512fpu_patch_95:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_95_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_95_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_96
raw_hook_wrapper_x64_systemv_avx512fpu_patch_96:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_96_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_96_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_97
raw_hook_wrapper_x64_systemv_avx512fpu_patch_97:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_97_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_97_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_98
raw_hook_wrapper_x64_systemv_avx512fpu_patch_98:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_98_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_98_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_99
raw_hook_wrapper_x64_systemv_avx512fpu_patch_99:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_99_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_99_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_100
raw_hook_wrapper_x64_systemv_avx512fpu_patch_100:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_100_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_100_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_101
raw_hook_wrapper_x64_systemv_avx512fpu_patch_101:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_101_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_101_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_102
raw_hook_wrapper_x64_systemv_avx512fpu_patch_102:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_102_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_102_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_103
raw_hook_wrapper_x64_systemv_avx512fpu_patch_103:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_103_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_103_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_104
raw_hook_wrapper_x64_systemv_avx512fpu_patch_104:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_104_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_104_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_105
raw_hook_wrapper_x64_systemv_avx512fpu_patch_105:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_105_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_105_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_106
raw_hook_wrapper_x64_systemv_avx512fpu_patch_106:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_106_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_106_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_107
raw_hook_wrapper_x64_systemv_avx512fpu_patch_107:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_107_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_107_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_108
raw_hook_wrapper_x64_systemv_avx512fpu_patch_108:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_108_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_108_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_109
raw_hook_wrapper_x64_systemv_avx512fpu_patch_109:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_109_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_109_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_110
raw_hook_wrapper_x64_systemv_avx512fpu_patch_110:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_110_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_110_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_111
raw_hook_wrapper_x64_systemv_avx512fpu_patch_111:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_111_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_111_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_112
raw_hook_wrapper_x64_systemv_avx512fpu_patch_112:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_112_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_112_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_113
raw_hook_wrapper_x64_systemv_avx512fpu_patch_113:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_113_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_113_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_114
raw_hook_wrapper_x64_systemv_avx512fpu_patch_114:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_114_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_114_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_115
raw_hook_wrapper_x64_systemv_avx512fpu_patch_115:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_115_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_115_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_116
raw_hook_wrapper_x64_systemv_avx512fpu_patch_116:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_116_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_116_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_117
raw_hook_wrapper_x64_systemv_avx512fpu_patch_117:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_117_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_117_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_118
raw_hook_wrapper_x64_systemv_avx512fpu_patch_118:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_118_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_118_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_119
raw_hook_wrapper_x64_systemv_avx512fpu_patch_119:
	vmovups zmm0, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_119_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_119_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_120
raw_hook_wrapper_x64_systemv_avx512fpu_patch_120:
	vmovups zmm1, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_120_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_120_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_121
raw_hook_wrapper_x64_systemv_avx512fpu_patch_121:
	vmovups zmm2, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_121_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_121_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_122
raw_hook_wrapper_x64_systemv_avx512fpu_patch_122:
	vmovups zmm3, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_122_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_122_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_123
raw_hook_wrapper_x64_systemv_avx512fpu_patch_123:
	vmovups zmm4, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_123_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_123_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_124
raw_hook_wrapper_x64_systemv_avx512fpu_patch_124:
	vmovups zmm5, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_124_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_124_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_125
raw_hook_wrapper_x64_systemv_avx512fpu_patch_125:
	vmovups zmm6, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_125_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_125_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_126
raw_hook_wrapper_x64_systemv_avx512fpu_patch_126:
	vmovups zmm7, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_126_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_126_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_127
raw_hook_wrapper_x64_systemv_avx512fpu_patch_127:
	vmovups zmm8, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_127_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_127_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_128
raw_hook_wrapper_x64_systemv_avx512fpu_patch_128:
	vmovups zmm9, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_128_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_128_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_129
raw_hook_wrapper_x64_systemv_avx512fpu_patch_129:
	vmovups zmm10, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_129_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_129_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_130
raw_hook_wrapper_x64_systemv_avx512fpu_patch_130:
	vmovups zmm11, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_130_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_130_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_131
raw_hook_wrapper_x64_systemv_avx512fpu_patch_131:
	vmovups zmm12, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_131_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_131_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_132
raw_hook_wrapper_x64_systemv_avx512fpu_patch_132:
	vmovups zmm13, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_132_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_132_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_133
raw_hook_wrapper_x64_systemv_avx512fpu_patch_133:
	vmovups zmm14, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_133_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_133_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_134
raw_hook_wrapper_x64_systemv_avx512fpu_patch_134:
	vmovups zmm15, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_134_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_134_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_135
raw_hook_wrapper_x64_systemv_avx512fpu_patch_135:
	vmovups zmm16, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_135_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_135_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_136
raw_hook_wrapper_x64_systemv_avx512fpu_patch_136:
	vmovups zmm17, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_136_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_136_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_137
raw_hook_wrapper_x64_systemv_avx512fpu_patch_137:
	vmovups zmm18, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_137_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_137_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_138
raw_hook_wrapper_x64_systemv_avx512fpu_patch_138:
	vmovups zmm19, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_138_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_138_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_139
raw_hook_wrapper_x64_systemv_avx512fpu_patch_139:
	vmovups zmm20, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_139_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_139_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_140
raw_hook_wrapper_x64_systemv_avx512fpu_patch_140:
	vmovups zmm21, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_140_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_140_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_141
raw_hook_wrapper_x64_systemv_avx512fpu_patch_141:
	vmovups zmm22, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_141_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_141_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_142
raw_hook_wrapper_x64_systemv_avx512fpu_patch_142:
	vmovups zmm23, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_142_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_142_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_143
raw_hook_wrapper_x64_systemv_avx512fpu_patch_143:
	vmovups zmm24, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_143_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_143_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_144
raw_hook_wrapper_x64_systemv_avx512fpu_patch_144:
	vmovups zmm25, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_144_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_144_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_145
raw_hook_wrapper_x64_systemv_avx512fpu_patch_145:
	vmovups zmm26, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_145_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_145_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_146
raw_hook_wrapper_x64_systemv_avx512fpu_patch_146:
	vmovups zmm27, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_146_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_146_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_147
raw_hook_wrapper_x64_systemv_avx512fpu_patch_147:
	vmovups zmm28, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_147_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_147_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_148
raw_hook_wrapper_x64_systemv_avx512fpu_patch_148:
	vmovups zmm29, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_148_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_148_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_149
raw_hook_wrapper_x64_systemv_avx512fpu_patch_149:
	vmovups zmm30, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_149_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_149_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_150
raw_hook_wrapper_x64_systemv_avx512fpu_patch_150:
	vmovups zmm31, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_150_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_150_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_151
raw_hook_wrapper_x64_systemv_avx512fpu_patch_151:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_151_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_151_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_153
raw_hook_wrapper_x64_systemv_avx512fpu_patch_153:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_153_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_153_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_154
raw_hook_wrapper_x64_systemv_avx512fpu_patch_154:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_154_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_154_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_155
raw_hook_wrapper_x64_systemv_avx512fpu_patch_155:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_155_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_155_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_156
raw_hook_wrapper_x64_systemv_avx512fpu_patch_156:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_156_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_156_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_157
raw_hook_wrapper_x64_systemv_avx512fpu_patch_157:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_157_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_157_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_158
raw_hook_wrapper_x64_systemv_avx512fpu_patch_158:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_158_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_158_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_159
raw_hook_wrapper_x64_systemv_avx512fpu_patch_159:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_159_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_159_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_160
raw_hook_wrapper_x64_systemv_avx512fpu_patch_160:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_160_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_160_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_161
raw_hook_wrapper_x64_systemv_avx512fpu_patch_161:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_161_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_161_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_162
raw_hook_wrapper_x64_systemv_avx512fpu_patch_162:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_162_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_162_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_163
raw_hook_wrapper_x64_systemv_avx512fpu_patch_163:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_163_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_163_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_164
raw_hook_wrapper_x64_systemv_avx512fpu_patch_164:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_164_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_164_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_3
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_3_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_systemv_avx512fpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_4
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_4_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_systemv_avx512fpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_5
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_5_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_systemv_avx512fpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_6
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_6_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_systemv_avx512fpu_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_avx512fpu_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_avx512fpu_redirect_return
raw_hook_wrapper_x64_systemv_avx512fpu_unsupported_stack:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_7
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_7_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_8
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_8_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_9
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_9_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_systemv_avx512fpu_direct_return:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_152
raw_hook_wrapper_x64_systemv_avx512fpu_patch_152:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_152_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_152_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_165
raw_hook_wrapper_x64_systemv_avx512fpu_patch_165:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_165_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_165_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_166
raw_hook_wrapper_x64_systemv_avx512fpu_patch_166:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_166_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_166_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_167
raw_hook_wrapper_x64_systemv_avx512fpu_patch_167:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_167_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_167_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_168
raw_hook_wrapper_x64_systemv_avx512fpu_patch_168:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_168_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_168_end:
	ret
raw_hook_wrapper_x64_systemv_avx512fpu_redirect_return:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_10
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_10_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_11
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_11_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_12
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_12_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_13
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_13_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_14
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_14_end
raw_hook_wrapper_x64_systemv_avx512fpu_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_systemv_avx512fpu_nothing_modified:
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_169
raw_hook_wrapper_x64_systemv_avx512fpu_patch_169:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx512fpu_patch_169_end
raw_hook_wrapper_x64_systemv_avx512fpu_patch_169_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 systemv AVX512
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_systemv_avx512
raw_hook_wrapper_x64_systemv_avx512:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_0
raw_hook_wrapper_x64_systemv_avx512_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx512_patch_0_end
raw_hook_wrapper_x64_systemv_avx512_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_systemv_avx512_patch_1
raw_hook_wrapper_x64_systemv_avx512_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_1_end
raw_hook_wrapper_x64_systemv_avx512_patch_1_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_2
raw_hook_wrapper_x64_systemv_avx512_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx512_patch_2_end
raw_hook_wrapper_x64_systemv_avx512_patch_2_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_3
raw_hook_wrapper_x64_systemv_avx512_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_avx512_patch_3_end
raw_hook_wrapper_x64_systemv_avx512_patch_3_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_4
raw_hook_wrapper_x64_systemv_avx512_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_systemv_avx512_patch_4_end
raw_hook_wrapper_x64_systemv_avx512_patch_4_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_5
raw_hook_wrapper_x64_systemv_avx512_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_systemv_avx512_patch_5_end
raw_hook_wrapper_x64_systemv_avx512_patch_5_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_6
raw_hook_wrapper_x64_systemv_avx512_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_systemv_avx512_patch_6_end
raw_hook_wrapper_x64_systemv_avx512_patch_6_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_7
raw_hook_wrapper_x64_systemv_avx512_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx512_patch_7_end
raw_hook_wrapper_x64_systemv_avx512_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_8
raw_hook_wrapper_x64_systemv_avx512_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_systemv_avx512_patch_8_end
raw_hook_wrapper_x64_systemv_avx512_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_9
raw_hook_wrapper_x64_systemv_avx512_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_systemv_avx512_patch_9_end
raw_hook_wrapper_x64_systemv_avx512_patch_9_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_10
raw_hook_wrapper_x64_systemv_avx512_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_systemv_avx512_patch_10_end
raw_hook_wrapper_x64_systemv_avx512_patch_10_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_11
raw_hook_wrapper_x64_systemv_avx512_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_systemv_avx512_patch_11_end
raw_hook_wrapper_x64_systemv_avx512_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_12
raw_hook_wrapper_x64_systemv_avx512_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_systemv_avx512_patch_12_end
raw_hook_wrapper_x64_systemv_avx512_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_13
raw_hook_wrapper_x64_systemv_avx512_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_systemv_avx512_patch_13_end
raw_hook_wrapper_x64_systemv_avx512_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_14
raw_hook_wrapper_x64_systemv_avx512_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_systemv_avx512_patch_14_end
raw_hook_wrapper_x64_systemv_avx512_patch_14_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_15
raw_hook_wrapper_x64_systemv_avx512_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_systemv_avx512_patch_15_end
raw_hook_wrapper_x64_systemv_avx512_patch_15_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_16
raw_hook_wrapper_x64_systemv_avx512_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_systemv_avx512_patch_16_end
raw_hook_wrapper_x64_systemv_avx512_patch_16_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_17
raw_hook_wrapper_x64_systemv_avx512_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_systemv_avx512_patch_17_end
raw_hook_wrapper_x64_systemv_avx512_patch_17_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_18
raw_hook_wrapper_x64_systemv_avx512_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_systemv_avx512_patch_18_end
raw_hook_wrapper_x64_systemv_avx512_patch_18_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_19
raw_hook_wrapper_x64_systemv_avx512_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_19_end
raw_hook_wrapper_x64_systemv_avx512_patch_19_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_20
raw_hook_wrapper_x64_systemv_avx512_patch_20:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_systemv_avx512_patch_20_end
raw_hook_wrapper_x64_systemv_avx512_patch_20_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_21
raw_hook_wrapper_x64_systemv_avx512_patch_21:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_systemv_avx512_patch_21_end
raw_hook_wrapper_x64_systemv_avx512_patch_21_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_22
raw_hook_wrapper_x64_systemv_avx512_patch_22:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_systemv_avx512_patch_22_end
raw_hook_wrapper_x64_systemv_avx512_patch_22_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_23
raw_hook_wrapper_x64_systemv_avx512_patch_23:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_systemv_avx512_patch_23_end
raw_hook_wrapper_x64_systemv_avx512_patch_23_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_24
raw_hook_wrapper_x64_systemv_avx512_patch_24:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_systemv_avx512_patch_24_end
raw_hook_wrapper_x64_systemv_avx512_patch_24_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_25
raw_hook_wrapper_x64_systemv_avx512_patch_25:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_systemv_avx512_patch_25_end
raw_hook_wrapper_x64_systemv_avx512_patch_25_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_26
raw_hook_wrapper_x64_systemv_avx512_patch_26:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_systemv_avx512_patch_26_end
raw_hook_wrapper_x64_systemv_avx512_patch_26_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_27
raw_hook_wrapper_x64_systemv_avx512_patch_27:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_systemv_avx512_patch_27_end
raw_hook_wrapper_x64_systemv_avx512_patch_27_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_28
raw_hook_wrapper_x64_systemv_avx512_patch_28:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_systemv_avx512_patch_28_end
raw_hook_wrapper_x64_systemv_avx512_patch_28_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_29
raw_hook_wrapper_x64_systemv_avx512_patch_29:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_systemv_avx512_patch_29_end
raw_hook_wrapper_x64_systemv_avx512_patch_29_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_30
raw_hook_wrapper_x64_systemv_avx512_patch_30:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_systemv_avx512_patch_30_end
raw_hook_wrapper_x64_systemv_avx512_patch_30_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_31
raw_hook_wrapper_x64_systemv_avx512_patch_31:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_systemv_avx512_patch_31_end
raw_hook_wrapper_x64_systemv_avx512_patch_31_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_32
raw_hook_wrapper_x64_systemv_avx512_patch_32:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_systemv_avx512_patch_32_end
raw_hook_wrapper_x64_systemv_avx512_patch_32_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_33
raw_hook_wrapper_x64_systemv_avx512_patch_33:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_systemv_avx512_patch_33_end
raw_hook_wrapper_x64_systemv_avx512_patch_33_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_34
raw_hook_wrapper_x64_systemv_avx512_patch_34:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_systemv_avx512_patch_34_end
raw_hook_wrapper_x64_systemv_avx512_patch_34_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_35
raw_hook_wrapper_x64_systemv_avx512_patch_35:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_systemv_avx512_patch_35_end
raw_hook_wrapper_x64_systemv_avx512_patch_35_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_36
raw_hook_wrapper_x64_systemv_avx512_patch_36:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x64_systemv_avx512_patch_36_end
raw_hook_wrapper_x64_systemv_avx512_patch_36_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_37
raw_hook_wrapper_x64_systemv_avx512_patch_37:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x64_systemv_avx512_patch_37_end
raw_hook_wrapper_x64_systemv_avx512_patch_37_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_38
raw_hook_wrapper_x64_systemv_avx512_patch_38:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x64_systemv_avx512_patch_38_end
raw_hook_wrapper_x64_systemv_avx512_patch_38_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_39
raw_hook_wrapper_x64_systemv_avx512_patch_39:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x64_systemv_avx512_patch_39_end
raw_hook_wrapper_x64_systemv_avx512_patch_39_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_40
raw_hook_wrapper_x64_systemv_avx512_patch_40:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x64_systemv_avx512_patch_40_end
raw_hook_wrapper_x64_systemv_avx512_patch_40_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_41
raw_hook_wrapper_x64_systemv_avx512_patch_41:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x64_systemv_avx512_patch_41_end
raw_hook_wrapper_x64_systemv_avx512_patch_41_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_42
raw_hook_wrapper_x64_systemv_avx512_patch_42:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x64_systemv_avx512_patch_42_end
raw_hook_wrapper_x64_systemv_avx512_patch_42_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_43
raw_hook_wrapper_x64_systemv_avx512_patch_43:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x64_systemv_avx512_patch_43_end
raw_hook_wrapper_x64_systemv_avx512_patch_43_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_44
raw_hook_wrapper_x64_systemv_avx512_patch_44:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm8
.globl raw_hook_wrapper_x64_systemv_avx512_patch_44_end
raw_hook_wrapper_x64_systemv_avx512_patch_44_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_45
raw_hook_wrapper_x64_systemv_avx512_patch_45:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm9
.globl raw_hook_wrapper_x64_systemv_avx512_patch_45_end
raw_hook_wrapper_x64_systemv_avx512_patch_45_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_46
raw_hook_wrapper_x64_systemv_avx512_patch_46:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm10
.globl raw_hook_wrapper_x64_systemv_avx512_patch_46_end
raw_hook_wrapper_x64_systemv_avx512_patch_46_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_47
raw_hook_wrapper_x64_systemv_avx512_patch_47:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm11
.globl raw_hook_wrapper_x64_systemv_avx512_patch_47_end
raw_hook_wrapper_x64_systemv_avx512_patch_47_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_48
raw_hook_wrapper_x64_systemv_avx512_patch_48:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm12
.globl raw_hook_wrapper_x64_systemv_avx512_patch_48_end
raw_hook_wrapper_x64_systemv_avx512_patch_48_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_49
raw_hook_wrapper_x64_systemv_avx512_patch_49:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm13
.globl raw_hook_wrapper_x64_systemv_avx512_patch_49_end
raw_hook_wrapper_x64_systemv_avx512_patch_49_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_50
raw_hook_wrapper_x64_systemv_avx512_patch_50:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm14
.globl raw_hook_wrapper_x64_systemv_avx512_patch_50_end
raw_hook_wrapper_x64_systemv_avx512_patch_50_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_51
raw_hook_wrapper_x64_systemv_avx512_patch_51:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm15
.globl raw_hook_wrapper_x64_systemv_avx512_patch_51_end
raw_hook_wrapper_x64_systemv_avx512_patch_51_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_52
raw_hook_wrapper_x64_systemv_avx512_patch_52:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm0
.globl raw_hook_wrapper_x64_systemv_avx512_patch_52_end
raw_hook_wrapper_x64_systemv_avx512_patch_52_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_53
raw_hook_wrapper_x64_systemv_avx512_patch_53:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm1
.globl raw_hook_wrapper_x64_systemv_avx512_patch_53_end
raw_hook_wrapper_x64_systemv_avx512_patch_53_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_54
raw_hook_wrapper_x64_systemv_avx512_patch_54:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm2
.globl raw_hook_wrapper_x64_systemv_avx512_patch_54_end
raw_hook_wrapper_x64_systemv_avx512_patch_54_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_55
raw_hook_wrapper_x64_systemv_avx512_patch_55:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm3
.globl raw_hook_wrapper_x64_systemv_avx512_patch_55_end
raw_hook_wrapper_x64_systemv_avx512_patch_55_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_56
raw_hook_wrapper_x64_systemv_avx512_patch_56:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm4
.globl raw_hook_wrapper_x64_systemv_avx512_patch_56_end
raw_hook_wrapper_x64_systemv_avx512_patch_56_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_57
raw_hook_wrapper_x64_systemv_avx512_patch_57:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm5
.globl raw_hook_wrapper_x64_systemv_avx512_patch_57_end
raw_hook_wrapper_x64_systemv_avx512_patch_57_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_58
raw_hook_wrapper_x64_systemv_avx512_patch_58:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm6
.globl raw_hook_wrapper_x64_systemv_avx512_patch_58_end
raw_hook_wrapper_x64_systemv_avx512_patch_58_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_59
raw_hook_wrapper_x64_systemv_avx512_patch_59:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm7
.globl raw_hook_wrapper_x64_systemv_avx512_patch_59_end
raw_hook_wrapper_x64_systemv_avx512_patch_59_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_60
raw_hook_wrapper_x64_systemv_avx512_patch_60:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm8
.globl raw_hook_wrapper_x64_systemv_avx512_patch_60_end
raw_hook_wrapper_x64_systemv_avx512_patch_60_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_61
raw_hook_wrapper_x64_systemv_avx512_patch_61:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm9
.globl raw_hook_wrapper_x64_systemv_avx512_patch_61_end
raw_hook_wrapper_x64_systemv_avx512_patch_61_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_62
raw_hook_wrapper_x64_systemv_avx512_patch_62:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm10
.globl raw_hook_wrapper_x64_systemv_avx512_patch_62_end
raw_hook_wrapper_x64_systemv_avx512_patch_62_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_63
raw_hook_wrapper_x64_systemv_avx512_patch_63:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm11
.globl raw_hook_wrapper_x64_systemv_avx512_patch_63_end
raw_hook_wrapper_x64_systemv_avx512_patch_63_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_64
raw_hook_wrapper_x64_systemv_avx512_patch_64:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm12
.globl raw_hook_wrapper_x64_systemv_avx512_patch_64_end
raw_hook_wrapper_x64_systemv_avx512_patch_64_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_65
raw_hook_wrapper_x64_systemv_avx512_patch_65:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm13
.globl raw_hook_wrapper_x64_systemv_avx512_patch_65_end
raw_hook_wrapper_x64_systemv_avx512_patch_65_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_66
raw_hook_wrapper_x64_systemv_avx512_patch_66:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm14
.globl raw_hook_wrapper_x64_systemv_avx512_patch_66_end
raw_hook_wrapper_x64_systemv_avx512_patch_66_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_67
raw_hook_wrapper_x64_systemv_avx512_patch_67:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm15
.globl raw_hook_wrapper_x64_systemv_avx512_patch_67_end
raw_hook_wrapper_x64_systemv_avx512_patch_67_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_68
raw_hook_wrapper_x64_systemv_avx512_patch_68:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm16
.globl raw_hook_wrapper_x64_systemv_avx512_patch_68_end
raw_hook_wrapper_x64_systemv_avx512_patch_68_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_69
raw_hook_wrapper_x64_systemv_avx512_patch_69:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm17
.globl raw_hook_wrapper_x64_systemv_avx512_patch_69_end
raw_hook_wrapper_x64_systemv_avx512_patch_69_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_70
raw_hook_wrapper_x64_systemv_avx512_patch_70:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm18
.globl raw_hook_wrapper_x64_systemv_avx512_patch_70_end
raw_hook_wrapper_x64_systemv_avx512_patch_70_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_71
raw_hook_wrapper_x64_systemv_avx512_patch_71:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm19
.globl raw_hook_wrapper_x64_systemv_avx512_patch_71_end
raw_hook_wrapper_x64_systemv_avx512_patch_71_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_72
raw_hook_wrapper_x64_systemv_avx512_patch_72:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm20
.globl raw_hook_wrapper_x64_systemv_avx512_patch_72_end
raw_hook_wrapper_x64_systemv_avx512_patch_72_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_73
raw_hook_wrapper_x64_systemv_avx512_patch_73:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm21
.globl raw_hook_wrapper_x64_systemv_avx512_patch_73_end
raw_hook_wrapper_x64_systemv_avx512_patch_73_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_74
raw_hook_wrapper_x64_systemv_avx512_patch_74:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm22
.globl raw_hook_wrapper_x64_systemv_avx512_patch_74_end
raw_hook_wrapper_x64_systemv_avx512_patch_74_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_75
raw_hook_wrapper_x64_systemv_avx512_patch_75:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm23
.globl raw_hook_wrapper_x64_systemv_avx512_patch_75_end
raw_hook_wrapper_x64_systemv_avx512_patch_75_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_76
raw_hook_wrapper_x64_systemv_avx512_patch_76:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm24
.globl raw_hook_wrapper_x64_systemv_avx512_patch_76_end
raw_hook_wrapper_x64_systemv_avx512_patch_76_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_77
raw_hook_wrapper_x64_systemv_avx512_patch_77:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm25
.globl raw_hook_wrapper_x64_systemv_avx512_patch_77_end
raw_hook_wrapper_x64_systemv_avx512_patch_77_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_78
raw_hook_wrapper_x64_systemv_avx512_patch_78:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm26
.globl raw_hook_wrapper_x64_systemv_avx512_patch_78_end
raw_hook_wrapper_x64_systemv_avx512_patch_78_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_79
raw_hook_wrapper_x64_systemv_avx512_patch_79:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm27
.globl raw_hook_wrapper_x64_systemv_avx512_patch_79_end
raw_hook_wrapper_x64_systemv_avx512_patch_79_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_80
raw_hook_wrapper_x64_systemv_avx512_patch_80:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm28
.globl raw_hook_wrapper_x64_systemv_avx512_patch_80_end
raw_hook_wrapper_x64_systemv_avx512_patch_80_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_81
raw_hook_wrapper_x64_systemv_avx512_patch_81:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm29
.globl raw_hook_wrapper_x64_systemv_avx512_patch_81_end
raw_hook_wrapper_x64_systemv_avx512_patch_81_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_82
raw_hook_wrapper_x64_systemv_avx512_patch_82:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm30
.globl raw_hook_wrapper_x64_systemv_avx512_patch_82_end
raw_hook_wrapper_x64_systemv_avx512_patch_82_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_83
raw_hook_wrapper_x64_systemv_avx512_patch_83:
	vmovups zmmword ptr [rsp + 0x7fffffff], zmm31
.globl raw_hook_wrapper_x64_systemv_avx512_patch_83_end
raw_hook_wrapper_x64_systemv_avx512_patch_83_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_0
raw_hook_wrapper_x64_systemv_avx512_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_0_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_0_end:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_1
raw_hook_wrapper_x64_systemv_avx512_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_1_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_2
raw_hook_wrapper_x64_systemv_avx512_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_2_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_2_end:
	mov rdi, rsp
.globl raw_hook_wrapper_x64_systemv_avx512_patch_84
raw_hook_wrapper_x64_systemv_avx512_patch_84:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_systemv_avx512_patch_84_end
raw_hook_wrapper_x64_systemv_avx512_patch_84_end:
	call rax
	test al, al
	je raw_hook_wrapper_x64_systemv_avx512_nothing_modified
.globl raw_hook_wrapper_x64_systemv_avx512_patch_85
raw_hook_wrapper_x64_systemv_avx512_patch_85:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_85_end
raw_hook_wrapper_x64_systemv_avx512_patch_85_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_86
raw_hook_wrapper_x64_systemv_avx512_patch_86:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_86_end
raw_hook_wrapper_x64_systemv_avx512_patch_86_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_87
raw_hook_wrapper_x64_systemv_avx512_patch_87:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_87_end
raw_hook_wrapper_x64_systemv_avx512_patch_87_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_88
raw_hook_wrapper_x64_systemv_avx512_patch_88:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_88_end
raw_hook_wrapper_x64_systemv_avx512_patch_88_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_89
raw_hook_wrapper_x64_systemv_avx512_patch_89:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_89_end
raw_hook_wrapper_x64_systemv_avx512_patch_89_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_90
raw_hook_wrapper_x64_systemv_avx512_patch_90:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_90_end
raw_hook_wrapper_x64_systemv_avx512_patch_90_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_91
raw_hook_wrapper_x64_systemv_avx512_patch_91:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_91_end
raw_hook_wrapper_x64_systemv_avx512_patch_91_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_92
raw_hook_wrapper_x64_systemv_avx512_patch_92:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_92_end
raw_hook_wrapper_x64_systemv_avx512_patch_92_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_93
raw_hook_wrapper_x64_systemv_avx512_patch_93:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_93_end
raw_hook_wrapper_x64_systemv_avx512_patch_93_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_94
raw_hook_wrapper_x64_systemv_avx512_patch_94:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_94_end
raw_hook_wrapper_x64_systemv_avx512_patch_94_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_95
raw_hook_wrapper_x64_systemv_avx512_patch_95:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_95_end
raw_hook_wrapper_x64_systemv_avx512_patch_95_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_96
raw_hook_wrapper_x64_systemv_avx512_patch_96:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_96_end
raw_hook_wrapper_x64_systemv_avx512_patch_96_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_97
raw_hook_wrapper_x64_systemv_avx512_patch_97:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_97_end
raw_hook_wrapper_x64_systemv_avx512_patch_97_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_98
raw_hook_wrapper_x64_systemv_avx512_patch_98:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_98_end
raw_hook_wrapper_x64_systemv_avx512_patch_98_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_99
raw_hook_wrapper_x64_systemv_avx512_patch_99:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_99_end
raw_hook_wrapper_x64_systemv_avx512_patch_99_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_100
raw_hook_wrapper_x64_systemv_avx512_patch_100:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_100_end
raw_hook_wrapper_x64_systemv_avx512_patch_100_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_101
raw_hook_wrapper_x64_systemv_avx512_patch_101:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_101_end
raw_hook_wrapper_x64_systemv_avx512_patch_101_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_102
raw_hook_wrapper_x64_systemv_avx512_patch_102:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_102_end
raw_hook_wrapper_x64_systemv_avx512_patch_102_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_103
raw_hook_wrapper_x64_systemv_avx512_patch_103:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_103_end
raw_hook_wrapper_x64_systemv_avx512_patch_103_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_104
raw_hook_wrapper_x64_systemv_avx512_patch_104:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_104_end
raw_hook_wrapper_x64_systemv_avx512_patch_104_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_105
raw_hook_wrapper_x64_systemv_avx512_patch_105:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_105_end
raw_hook_wrapper_x64_systemv_avx512_patch_105_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_106
raw_hook_wrapper_x64_systemv_avx512_patch_106:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_106_end
raw_hook_wrapper_x64_systemv_avx512_patch_106_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_107
raw_hook_wrapper_x64_systemv_avx512_patch_107:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_107_end
raw_hook_wrapper_x64_systemv_avx512_patch_107_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_108
raw_hook_wrapper_x64_systemv_avx512_patch_108:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_108_end
raw_hook_wrapper_x64_systemv_avx512_patch_108_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_109
raw_hook_wrapper_x64_systemv_avx512_patch_109:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_109_end
raw_hook_wrapper_x64_systemv_avx512_patch_109_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_110
raw_hook_wrapper_x64_systemv_avx512_patch_110:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_110_end
raw_hook_wrapper_x64_systemv_avx512_patch_110_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_111
raw_hook_wrapper_x64_systemv_avx512_patch_111:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_111_end
raw_hook_wrapper_x64_systemv_avx512_patch_111_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_112
raw_hook_wrapper_x64_systemv_avx512_patch_112:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_112_end
raw_hook_wrapper_x64_systemv_avx512_patch_112_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_113
raw_hook_wrapper_x64_systemv_avx512_patch_113:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_113_end
raw_hook_wrapper_x64_systemv_avx512_patch_113_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_114
raw_hook_wrapper_x64_systemv_avx512_patch_114:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_114_end
raw_hook_wrapper_x64_systemv_avx512_patch_114_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_115
raw_hook_wrapper_x64_systemv_avx512_patch_115:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_115_end
raw_hook_wrapper_x64_systemv_avx512_patch_115_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_116
raw_hook_wrapper_x64_systemv_avx512_patch_116:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_116_end
raw_hook_wrapper_x64_systemv_avx512_patch_116_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_117
raw_hook_wrapper_x64_systemv_avx512_patch_117:
	vmovups zmm0, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_117_end
raw_hook_wrapper_x64_systemv_avx512_patch_117_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_118
raw_hook_wrapper_x64_systemv_avx512_patch_118:
	vmovups zmm1, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_118_end
raw_hook_wrapper_x64_systemv_avx512_patch_118_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_119
raw_hook_wrapper_x64_systemv_avx512_patch_119:
	vmovups zmm2, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_119_end
raw_hook_wrapper_x64_systemv_avx512_patch_119_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_120
raw_hook_wrapper_x64_systemv_avx512_patch_120:
	vmovups zmm3, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_120_end
raw_hook_wrapper_x64_systemv_avx512_patch_120_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_121
raw_hook_wrapper_x64_systemv_avx512_patch_121:
	vmovups zmm4, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_121_end
raw_hook_wrapper_x64_systemv_avx512_patch_121_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_122
raw_hook_wrapper_x64_systemv_avx512_patch_122:
	vmovups zmm5, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_122_end
raw_hook_wrapper_x64_systemv_avx512_patch_122_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_123
raw_hook_wrapper_x64_systemv_avx512_patch_123:
	vmovups zmm6, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_123_end
raw_hook_wrapper_x64_systemv_avx512_patch_123_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_124
raw_hook_wrapper_x64_systemv_avx512_patch_124:
	vmovups zmm7, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_124_end
raw_hook_wrapper_x64_systemv_avx512_patch_124_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_125
raw_hook_wrapper_x64_systemv_avx512_patch_125:
	vmovups zmm8, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_125_end
raw_hook_wrapper_x64_systemv_avx512_patch_125_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_126
raw_hook_wrapper_x64_systemv_avx512_patch_126:
	vmovups zmm9, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_126_end
raw_hook_wrapper_x64_systemv_avx512_patch_126_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_127
raw_hook_wrapper_x64_systemv_avx512_patch_127:
	vmovups zmm10, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_127_end
raw_hook_wrapper_x64_systemv_avx512_patch_127_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_128
raw_hook_wrapper_x64_systemv_avx512_patch_128:
	vmovups zmm11, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_128_end
raw_hook_wrapper_x64_systemv_avx512_patch_128_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_129
raw_hook_wrapper_x64_systemv_avx512_patch_129:
	vmovups zmm12, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_129_end
raw_hook_wrapper_x64_systemv_avx512_patch_129_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_130
raw_hook_wrapper_x64_systemv_avx512_patch_130:
	vmovups zmm13, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_130_end
raw_hook_wrapper_x64_systemv_avx512_patch_130_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_131
raw_hook_wrapper_x64_systemv_avx512_patch_131:
	vmovups zmm14, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_131_end
raw_hook_wrapper_x64_systemv_avx512_patch_131_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_132
raw_hook_wrapper_x64_systemv_avx512_patch_132:
	vmovups zmm15, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_132_end
raw_hook_wrapper_x64_systemv_avx512_patch_132_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_133
raw_hook_wrapper_x64_systemv_avx512_patch_133:
	vmovups zmm16, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_133_end
raw_hook_wrapper_x64_systemv_avx512_patch_133_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_134
raw_hook_wrapper_x64_systemv_avx512_patch_134:
	vmovups zmm17, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_134_end
raw_hook_wrapper_x64_systemv_avx512_patch_134_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_135
raw_hook_wrapper_x64_systemv_avx512_patch_135:
	vmovups zmm18, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_135_end
raw_hook_wrapper_x64_systemv_avx512_patch_135_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_136
raw_hook_wrapper_x64_systemv_avx512_patch_136:
	vmovups zmm19, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_136_end
raw_hook_wrapper_x64_systemv_avx512_patch_136_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_137
raw_hook_wrapper_x64_systemv_avx512_patch_137:
	vmovups zmm20, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_137_end
raw_hook_wrapper_x64_systemv_avx512_patch_137_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_138
raw_hook_wrapper_x64_systemv_avx512_patch_138:
	vmovups zmm21, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_138_end
raw_hook_wrapper_x64_systemv_avx512_patch_138_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_139
raw_hook_wrapper_x64_systemv_avx512_patch_139:
	vmovups zmm22, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_139_end
raw_hook_wrapper_x64_systemv_avx512_patch_139_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_140
raw_hook_wrapper_x64_systemv_avx512_patch_140:
	vmovups zmm23, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_140_end
raw_hook_wrapper_x64_systemv_avx512_patch_140_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_141
raw_hook_wrapper_x64_systemv_avx512_patch_141:
	vmovups zmm24, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_141_end
raw_hook_wrapper_x64_systemv_avx512_patch_141_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_142
raw_hook_wrapper_x64_systemv_avx512_patch_142:
	vmovups zmm25, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_142_end
raw_hook_wrapper_x64_systemv_avx512_patch_142_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_143
raw_hook_wrapper_x64_systemv_avx512_patch_143:
	vmovups zmm26, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_143_end
raw_hook_wrapper_x64_systemv_avx512_patch_143_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_144
raw_hook_wrapper_x64_systemv_avx512_patch_144:
	vmovups zmm27, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_144_end
raw_hook_wrapper_x64_systemv_avx512_patch_144_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_145
raw_hook_wrapper_x64_systemv_avx512_patch_145:
	vmovups zmm28, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_145_end
raw_hook_wrapper_x64_systemv_avx512_patch_145_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_146
raw_hook_wrapper_x64_systemv_avx512_patch_146:
	vmovups zmm29, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_146_end
raw_hook_wrapper_x64_systemv_avx512_patch_146_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_147
raw_hook_wrapper_x64_systemv_avx512_patch_147:
	vmovups zmm30, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_147_end
raw_hook_wrapper_x64_systemv_avx512_patch_147_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_148
raw_hook_wrapper_x64_systemv_avx512_patch_148:
	vmovups zmm31, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_148_end
raw_hook_wrapper_x64_systemv_avx512_patch_148_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_149
raw_hook_wrapper_x64_systemv_avx512_patch_149:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_149_end
raw_hook_wrapper_x64_systemv_avx512_patch_149_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_151
raw_hook_wrapper_x64_systemv_avx512_patch_151:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_151_end
raw_hook_wrapper_x64_systemv_avx512_patch_151_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_152
raw_hook_wrapper_x64_systemv_avx512_patch_152:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_152_end
raw_hook_wrapper_x64_systemv_avx512_patch_152_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_153
raw_hook_wrapper_x64_systemv_avx512_patch_153:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_153_end
raw_hook_wrapper_x64_systemv_avx512_patch_153_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_154
raw_hook_wrapper_x64_systemv_avx512_patch_154:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_154_end
raw_hook_wrapper_x64_systemv_avx512_patch_154_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_155
raw_hook_wrapper_x64_systemv_avx512_patch_155:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_155_end
raw_hook_wrapper_x64_systemv_avx512_patch_155_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_156
raw_hook_wrapper_x64_systemv_avx512_patch_156:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_156_end
raw_hook_wrapper_x64_systemv_avx512_patch_156_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_157
raw_hook_wrapper_x64_systemv_avx512_patch_157:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_157_end
raw_hook_wrapper_x64_systemv_avx512_patch_157_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_158
raw_hook_wrapper_x64_systemv_avx512_patch_158:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_158_end
raw_hook_wrapper_x64_systemv_avx512_patch_158_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_159
raw_hook_wrapper_x64_systemv_avx512_patch_159:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_159_end
raw_hook_wrapper_x64_systemv_avx512_patch_159_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_160
raw_hook_wrapper_x64_systemv_avx512_patch_160:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_160_end
raw_hook_wrapper_x64_systemv_avx512_patch_160_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_161
raw_hook_wrapper_x64_systemv_avx512_patch_161:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_161_end
raw_hook_wrapper_x64_systemv_avx512_patch_161_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_162
raw_hook_wrapper_x64_systemv_avx512_patch_162:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_162_end
raw_hook_wrapper_x64_systemv_avx512_patch_162_end:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_3
raw_hook_wrapper_x64_systemv_avx512_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_3_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_systemv_avx512_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_4
raw_hook_wrapper_x64_systemv_avx512_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_4_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_systemv_avx512_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_5
raw_hook_wrapper_x64_systemv_avx512_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_5_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_systemv_avx512_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_6
raw_hook_wrapper_x64_systemv_avx512_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_6_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_systemv_avx512_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_avx512_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_avx512_redirect_return
raw_hook_wrapper_x64_systemv_avx512_unsupported_stack:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_7
raw_hook_wrapper_x64_systemv_avx512_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_7_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_8
raw_hook_wrapper_x64_systemv_avx512_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_8_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_9
raw_hook_wrapper_x64_systemv_avx512_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_9_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_systemv_avx512_direct_return:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_150
raw_hook_wrapper_x64_systemv_avx512_patch_150:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_150_end
raw_hook_wrapper_x64_systemv_avx512_patch_150_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_avx512_patch_163
raw_hook_wrapper_x64_systemv_avx512_patch_163:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_163_end
raw_hook_wrapper_x64_systemv_avx512_patch_163_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_164
raw_hook_wrapper_x64_systemv_avx512_patch_164:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_164_end
raw_hook_wrapper_x64_systemv_avx512_patch_164_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_165
raw_hook_wrapper_x64_systemv_avx512_patch_165:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_165_end
raw_hook_wrapper_x64_systemv_avx512_patch_165_end:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_166
raw_hook_wrapper_x64_systemv_avx512_patch_166:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_patch_166_end
raw_hook_wrapper_x64_systemv_avx512_patch_166_end:
	ret
raw_hook_wrapper_x64_systemv_avx512_redirect_return:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_10
raw_hook_wrapper_x64_systemv_avx512_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_10_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_11
raw_hook_wrapper_x64_systemv_avx512_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_11_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_12
raw_hook_wrapper_x64_systemv_avx512_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_12_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_13
raw_hook_wrapper_x64_systemv_avx512_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_13_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_14
raw_hook_wrapper_x64_systemv_avx512_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx512_cet_patch_14_end
raw_hook_wrapper_x64_systemv_avx512_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_systemv_avx512_nothing_modified:
.globl raw_hook_wrapper_x64_systemv_avx512_patch_167
raw_hook_wrapper_x64_systemv_avx512_patch_167:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx512_patch_167_end
raw_hook_wrapper_x64_systemv_avx512_patch_167_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 systemv AVXFPU
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_systemv_avxfpu
raw_hook_wrapper_x64_systemv_avxfpu:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_0
raw_hook_wrapper_x64_systemv_avxfpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_0_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_1
raw_hook_wrapper_x64_systemv_avxfpu_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_1_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_1_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_2
raw_hook_wrapper_x64_systemv_avxfpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_2_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_2_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_3
raw_hook_wrapper_x64_systemv_avxfpu_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_3_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_3_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_4
raw_hook_wrapper_x64_systemv_avxfpu_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_4_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_4_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_5
raw_hook_wrapper_x64_systemv_avxfpu_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_5_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_5_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_6
raw_hook_wrapper_x64_systemv_avxfpu_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_6_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_6_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_7
raw_hook_wrapper_x64_systemv_avxfpu_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_7_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_8
raw_hook_wrapper_x64_systemv_avxfpu_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_8_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_9
raw_hook_wrapper_x64_systemv_avxfpu_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_9_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_9_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_10
raw_hook_wrapper_x64_systemv_avxfpu_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_10_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_10_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_11
raw_hook_wrapper_x64_systemv_avxfpu_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_11_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_12
raw_hook_wrapper_x64_systemv_avxfpu_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_12_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_13
raw_hook_wrapper_x64_systemv_avxfpu_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_13_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_14
raw_hook_wrapper_x64_systemv_avxfpu_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_14_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_14_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_15
raw_hook_wrapper_x64_systemv_avxfpu_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_15_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_15_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_16
raw_hook_wrapper_x64_systemv_avxfpu_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_16_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_16_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_17
raw_hook_wrapper_x64_systemv_avxfpu_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_17_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_17_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_18
raw_hook_wrapper_x64_systemv_avxfpu_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_18_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_18_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_19
raw_hook_wrapper_x64_systemv_avxfpu_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_19_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_19_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_20
raw_hook_wrapper_x64_systemv_avxfpu_patch_20:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_20_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_20_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_21
raw_hook_wrapper_x64_systemv_avxfpu_patch_21:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_21_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_21_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_22
raw_hook_wrapper_x64_systemv_avxfpu_patch_22:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_22_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_22_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_23
raw_hook_wrapper_x64_systemv_avxfpu_patch_23:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_23_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_23_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_24
raw_hook_wrapper_x64_systemv_avxfpu_patch_24:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_24_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_24_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_25
raw_hook_wrapper_x64_systemv_avxfpu_patch_25:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_25_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_25_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_26
raw_hook_wrapper_x64_systemv_avxfpu_patch_26:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_26_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_26_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_27
raw_hook_wrapper_x64_systemv_avxfpu_patch_27:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_27_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_27_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_28
raw_hook_wrapper_x64_systemv_avxfpu_patch_28:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_28_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_28_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_29
raw_hook_wrapper_x64_systemv_avxfpu_patch_29:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_29_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_29_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_30
raw_hook_wrapper_x64_systemv_avxfpu_patch_30:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_30_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_30_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_31
raw_hook_wrapper_x64_systemv_avxfpu_patch_31:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_31_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_31_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_32
raw_hook_wrapper_x64_systemv_avxfpu_patch_32:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_32_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_32_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_33
raw_hook_wrapper_x64_systemv_avxfpu_patch_33:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_33_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_33_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_34
raw_hook_wrapper_x64_systemv_avxfpu_patch_34:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_34_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_34_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_35
raw_hook_wrapper_x64_systemv_avxfpu_patch_35:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_35_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_35_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_36
raw_hook_wrapper_x64_systemv_avxfpu_patch_36:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_36_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_36_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_37
raw_hook_wrapper_x64_systemv_avxfpu_patch_37:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_37_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_37_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_38
raw_hook_wrapper_x64_systemv_avxfpu_patch_38:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_38_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_38_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_39
raw_hook_wrapper_x64_systemv_avxfpu_patch_39:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_39_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_39_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_40
raw_hook_wrapper_x64_systemv_avxfpu_patch_40:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_40_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_40_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_41
raw_hook_wrapper_x64_systemv_avxfpu_patch_41:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_41_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_41_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_42
raw_hook_wrapper_x64_systemv_avxfpu_patch_42:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_42_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_42_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_43
raw_hook_wrapper_x64_systemv_avxfpu_patch_43:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_43_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_43_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_44
raw_hook_wrapper_x64_systemv_avxfpu_patch_44:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm8
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_44_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_44_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_45
raw_hook_wrapper_x64_systemv_avxfpu_patch_45:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm9
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_45_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_45_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_46
raw_hook_wrapper_x64_systemv_avxfpu_patch_46:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm10
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_46_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_46_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_47
raw_hook_wrapper_x64_systemv_avxfpu_patch_47:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm11
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_47_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_47_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_48
raw_hook_wrapper_x64_systemv_avxfpu_patch_48:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm12
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_48_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_48_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_49
raw_hook_wrapper_x64_systemv_avxfpu_patch_49:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm13
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_49_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_49_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_50
raw_hook_wrapper_x64_systemv_avxfpu_patch_50:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm14
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_50_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_50_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_51
raw_hook_wrapper_x64_systemv_avxfpu_patch_51:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm15
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_51_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_51_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_52
raw_hook_wrapper_x64_systemv_avxfpu_patch_52:
	fsave [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_52_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_52_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_0
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_0_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_0_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_1
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_1_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_2
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_2_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_2_end:
	mov rdi, rsp
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_53
raw_hook_wrapper_x64_systemv_avxfpu_patch_53:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_53_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_53_end:
	call rax
	test al, al
	je raw_hook_wrapper_x64_systemv_avxfpu_nothing_modified
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_54
raw_hook_wrapper_x64_systemv_avxfpu_patch_54:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_54_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_54_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_55
raw_hook_wrapper_x64_systemv_avxfpu_patch_55:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_55_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_55_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_56
raw_hook_wrapper_x64_systemv_avxfpu_patch_56:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_56_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_56_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_57
raw_hook_wrapper_x64_systemv_avxfpu_patch_57:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_57_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_57_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_58
raw_hook_wrapper_x64_systemv_avxfpu_patch_58:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_58_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_58_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_59
raw_hook_wrapper_x64_systemv_avxfpu_patch_59:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_59_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_59_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_60
raw_hook_wrapper_x64_systemv_avxfpu_patch_60:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_60_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_60_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_61
raw_hook_wrapper_x64_systemv_avxfpu_patch_61:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_61_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_61_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_62
raw_hook_wrapper_x64_systemv_avxfpu_patch_62:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_62_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_62_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_63
raw_hook_wrapper_x64_systemv_avxfpu_patch_63:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_63_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_63_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_64
raw_hook_wrapper_x64_systemv_avxfpu_patch_64:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_64_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_64_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_65
raw_hook_wrapper_x64_systemv_avxfpu_patch_65:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_65_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_65_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_66
raw_hook_wrapper_x64_systemv_avxfpu_patch_66:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_66_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_66_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_67
raw_hook_wrapper_x64_systemv_avxfpu_patch_67:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_67_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_67_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_68
raw_hook_wrapper_x64_systemv_avxfpu_patch_68:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_68_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_68_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_69
raw_hook_wrapper_x64_systemv_avxfpu_patch_69:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_69_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_69_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_70
raw_hook_wrapper_x64_systemv_avxfpu_patch_70:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_70_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_70_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_71
raw_hook_wrapper_x64_systemv_avxfpu_patch_71:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_71_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_71_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_72
raw_hook_wrapper_x64_systemv_avxfpu_patch_72:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_72_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_72_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_73
raw_hook_wrapper_x64_systemv_avxfpu_patch_73:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_73_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_73_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_74
raw_hook_wrapper_x64_systemv_avxfpu_patch_74:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_74_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_74_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_75
raw_hook_wrapper_x64_systemv_avxfpu_patch_75:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_75_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_75_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_76
raw_hook_wrapper_x64_systemv_avxfpu_patch_76:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_76_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_76_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_77
raw_hook_wrapper_x64_systemv_avxfpu_patch_77:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_77_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_77_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_78
raw_hook_wrapper_x64_systemv_avxfpu_patch_78:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_78_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_78_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_79
raw_hook_wrapper_x64_systemv_avxfpu_patch_79:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_79_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_79_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_80
raw_hook_wrapper_x64_systemv_avxfpu_patch_80:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_80_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_80_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_81
raw_hook_wrapper_x64_systemv_avxfpu_patch_81:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_81_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_81_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_82
raw_hook_wrapper_x64_systemv_avxfpu_patch_82:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_82_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_82_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_83
raw_hook_wrapper_x64_systemv_avxfpu_patch_83:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_83_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_83_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_84
raw_hook_wrapper_x64_systemv_avxfpu_patch_84:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_84_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_84_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_85
raw_hook_wrapper_x64_systemv_avxfpu_patch_85:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_85_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_85_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_86
raw_hook_wrapper_x64_systemv_avxfpu_patch_86:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_86_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_86_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_87
raw_hook_wrapper_x64_systemv_avxfpu_patch_87:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_87_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_87_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_89
raw_hook_wrapper_x64_systemv_avxfpu_patch_89:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_89_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_89_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_90
raw_hook_wrapper_x64_systemv_avxfpu_patch_90:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_90_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_90_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_91
raw_hook_wrapper_x64_systemv_avxfpu_patch_91:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_91_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_91_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_92
raw_hook_wrapper_x64_systemv_avxfpu_patch_92:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_92_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_92_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_93
raw_hook_wrapper_x64_systemv_avxfpu_patch_93:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_93_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_93_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_94
raw_hook_wrapper_x64_systemv_avxfpu_patch_94:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_94_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_94_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_95
raw_hook_wrapper_x64_systemv_avxfpu_patch_95:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_95_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_95_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_96
raw_hook_wrapper_x64_systemv_avxfpu_patch_96:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_96_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_96_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_97
raw_hook_wrapper_x64_systemv_avxfpu_patch_97:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_97_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_97_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_98
raw_hook_wrapper_x64_systemv_avxfpu_patch_98:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_98_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_98_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_99
raw_hook_wrapper_x64_systemv_avxfpu_patch_99:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_99_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_99_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_100
raw_hook_wrapper_x64_systemv_avxfpu_patch_100:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_100_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_100_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_3
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_3_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_systemv_avxfpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_4
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_4_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_systemv_avxfpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_5
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_5_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_systemv_avxfpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_6
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_6_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_systemv_avxfpu_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_avxfpu_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_avxfpu_redirect_return
raw_hook_wrapper_x64_systemv_avxfpu_unsupported_stack:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_7
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_7_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_8
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_8_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_9
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_9_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_systemv_avxfpu_direct_return:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_88
raw_hook_wrapper_x64_systemv_avxfpu_patch_88:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_88_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_88_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_101
raw_hook_wrapper_x64_systemv_avxfpu_patch_101:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_101_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_101_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_102
raw_hook_wrapper_x64_systemv_avxfpu_patch_102:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_102_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_102_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_103
raw_hook_wrapper_x64_systemv_avxfpu_patch_103:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_103_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_103_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_104
raw_hook_wrapper_x64_systemv_avxfpu_patch_104:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_104_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_104_end:
	ret
raw_hook_wrapper_x64_systemv_avxfpu_redirect_return:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_10
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_10_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_11
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_11_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_12
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_12_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_13
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_13_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_14
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_14_end
raw_hook_wrapper_x64_systemv_avxfpu_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_systemv_avxfpu_nothing_modified:
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_105
raw_hook_wrapper_x64_systemv_avxfpu_patch_105:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avxfpu_patch_105_end
raw_hook_wrapper_x64_systemv_avxfpu_patch_105_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 systemv AVX
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_systemv_avx
raw_hook_wrapper_x64_systemv_avx:
.globl raw_hook_wrapper_x64_systemv_avx_patch_0
raw_hook_wrapper_x64_systemv_avx_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx_patch_0_end
raw_hook_wrapper_x64_systemv_avx_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_systemv_avx_patch_1
raw_hook_wrapper_x64_systemv_avx_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_1_end
raw_hook_wrapper_x64_systemv_avx_patch_1_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_2
raw_hook_wrapper_x64_systemv_avx_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx_patch_2_end
raw_hook_wrapper_x64_systemv_avx_patch_2_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_3
raw_hook_wrapper_x64_systemv_avx_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_avx_patch_3_end
raw_hook_wrapper_x64_systemv_avx_patch_3_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_4
raw_hook_wrapper_x64_systemv_avx_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_systemv_avx_patch_4_end
raw_hook_wrapper_x64_systemv_avx_patch_4_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_5
raw_hook_wrapper_x64_systemv_avx_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_systemv_avx_patch_5_end
raw_hook_wrapper_x64_systemv_avx_patch_5_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_6
raw_hook_wrapper_x64_systemv_avx_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_systemv_avx_patch_6_end
raw_hook_wrapper_x64_systemv_avx_patch_6_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_7
raw_hook_wrapper_x64_systemv_avx_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx_patch_7_end
raw_hook_wrapper_x64_systemv_avx_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_8
raw_hook_wrapper_x64_systemv_avx_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_systemv_avx_patch_8_end
raw_hook_wrapper_x64_systemv_avx_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_9
raw_hook_wrapper_x64_systemv_avx_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_systemv_avx_patch_9_end
raw_hook_wrapper_x64_systemv_avx_patch_9_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_10
raw_hook_wrapper_x64_systemv_avx_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_systemv_avx_patch_10_end
raw_hook_wrapper_x64_systemv_avx_patch_10_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_11
raw_hook_wrapper_x64_systemv_avx_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_systemv_avx_patch_11_end
raw_hook_wrapper_x64_systemv_avx_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_12
raw_hook_wrapper_x64_systemv_avx_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_systemv_avx_patch_12_end
raw_hook_wrapper_x64_systemv_avx_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_13
raw_hook_wrapper_x64_systemv_avx_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_systemv_avx_patch_13_end
raw_hook_wrapper_x64_systemv_avx_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_14
raw_hook_wrapper_x64_systemv_avx_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_systemv_avx_patch_14_end
raw_hook_wrapper_x64_systemv_avx_patch_14_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_15
raw_hook_wrapper_x64_systemv_avx_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_systemv_avx_patch_15_end
raw_hook_wrapper_x64_systemv_avx_patch_15_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_16
raw_hook_wrapper_x64_systemv_avx_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_systemv_avx_patch_16_end
raw_hook_wrapper_x64_systemv_avx_patch_16_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_17
raw_hook_wrapper_x64_systemv_avx_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_systemv_avx_patch_17_end
raw_hook_wrapper_x64_systemv_avx_patch_17_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_18
raw_hook_wrapper_x64_systemv_avx_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_systemv_avx_patch_18_end
raw_hook_wrapper_x64_systemv_avx_patch_18_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_19
raw_hook_wrapper_x64_systemv_avx_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_19_end
raw_hook_wrapper_x64_systemv_avx_patch_19_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_20
raw_hook_wrapper_x64_systemv_avx_patch_20:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_systemv_avx_patch_20_end
raw_hook_wrapper_x64_systemv_avx_patch_20_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_21
raw_hook_wrapper_x64_systemv_avx_patch_21:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_systemv_avx_patch_21_end
raw_hook_wrapper_x64_systemv_avx_patch_21_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_22
raw_hook_wrapper_x64_systemv_avx_patch_22:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_systemv_avx_patch_22_end
raw_hook_wrapper_x64_systemv_avx_patch_22_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_23
raw_hook_wrapper_x64_systemv_avx_patch_23:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_systemv_avx_patch_23_end
raw_hook_wrapper_x64_systemv_avx_patch_23_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_24
raw_hook_wrapper_x64_systemv_avx_patch_24:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_systemv_avx_patch_24_end
raw_hook_wrapper_x64_systemv_avx_patch_24_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_25
raw_hook_wrapper_x64_systemv_avx_patch_25:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_systemv_avx_patch_25_end
raw_hook_wrapper_x64_systemv_avx_patch_25_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_26
raw_hook_wrapper_x64_systemv_avx_patch_26:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_systemv_avx_patch_26_end
raw_hook_wrapper_x64_systemv_avx_patch_26_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_27
raw_hook_wrapper_x64_systemv_avx_patch_27:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_systemv_avx_patch_27_end
raw_hook_wrapper_x64_systemv_avx_patch_27_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_28
raw_hook_wrapper_x64_systemv_avx_patch_28:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_systemv_avx_patch_28_end
raw_hook_wrapper_x64_systemv_avx_patch_28_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_29
raw_hook_wrapper_x64_systemv_avx_patch_29:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_systemv_avx_patch_29_end
raw_hook_wrapper_x64_systemv_avx_patch_29_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_30
raw_hook_wrapper_x64_systemv_avx_patch_30:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_systemv_avx_patch_30_end
raw_hook_wrapper_x64_systemv_avx_patch_30_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_31
raw_hook_wrapper_x64_systemv_avx_patch_31:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_systemv_avx_patch_31_end
raw_hook_wrapper_x64_systemv_avx_patch_31_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_32
raw_hook_wrapper_x64_systemv_avx_patch_32:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_systemv_avx_patch_32_end
raw_hook_wrapper_x64_systemv_avx_patch_32_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_33
raw_hook_wrapper_x64_systemv_avx_patch_33:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_systemv_avx_patch_33_end
raw_hook_wrapper_x64_systemv_avx_patch_33_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_34
raw_hook_wrapper_x64_systemv_avx_patch_34:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_systemv_avx_patch_34_end
raw_hook_wrapper_x64_systemv_avx_patch_34_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_35
raw_hook_wrapper_x64_systemv_avx_patch_35:
	vmovups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_systemv_avx_patch_35_end
raw_hook_wrapper_x64_systemv_avx_patch_35_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_36
raw_hook_wrapper_x64_systemv_avx_patch_36:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm0
.globl raw_hook_wrapper_x64_systemv_avx_patch_36_end
raw_hook_wrapper_x64_systemv_avx_patch_36_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_37
raw_hook_wrapper_x64_systemv_avx_patch_37:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm1
.globl raw_hook_wrapper_x64_systemv_avx_patch_37_end
raw_hook_wrapper_x64_systemv_avx_patch_37_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_38
raw_hook_wrapper_x64_systemv_avx_patch_38:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm2
.globl raw_hook_wrapper_x64_systemv_avx_patch_38_end
raw_hook_wrapper_x64_systemv_avx_patch_38_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_39
raw_hook_wrapper_x64_systemv_avx_patch_39:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm3
.globl raw_hook_wrapper_x64_systemv_avx_patch_39_end
raw_hook_wrapper_x64_systemv_avx_patch_39_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_40
raw_hook_wrapper_x64_systemv_avx_patch_40:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm4
.globl raw_hook_wrapper_x64_systemv_avx_patch_40_end
raw_hook_wrapper_x64_systemv_avx_patch_40_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_41
raw_hook_wrapper_x64_systemv_avx_patch_41:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm5
.globl raw_hook_wrapper_x64_systemv_avx_patch_41_end
raw_hook_wrapper_x64_systemv_avx_patch_41_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_42
raw_hook_wrapper_x64_systemv_avx_patch_42:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm6
.globl raw_hook_wrapper_x64_systemv_avx_patch_42_end
raw_hook_wrapper_x64_systemv_avx_patch_42_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_43
raw_hook_wrapper_x64_systemv_avx_patch_43:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm7
.globl raw_hook_wrapper_x64_systemv_avx_patch_43_end
raw_hook_wrapper_x64_systemv_avx_patch_43_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_44
raw_hook_wrapper_x64_systemv_avx_patch_44:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm8
.globl raw_hook_wrapper_x64_systemv_avx_patch_44_end
raw_hook_wrapper_x64_systemv_avx_patch_44_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_45
raw_hook_wrapper_x64_systemv_avx_patch_45:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm9
.globl raw_hook_wrapper_x64_systemv_avx_patch_45_end
raw_hook_wrapper_x64_systemv_avx_patch_45_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_46
raw_hook_wrapper_x64_systemv_avx_patch_46:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm10
.globl raw_hook_wrapper_x64_systemv_avx_patch_46_end
raw_hook_wrapper_x64_systemv_avx_patch_46_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_47
raw_hook_wrapper_x64_systemv_avx_patch_47:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm11
.globl raw_hook_wrapper_x64_systemv_avx_patch_47_end
raw_hook_wrapper_x64_systemv_avx_patch_47_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_48
raw_hook_wrapper_x64_systemv_avx_patch_48:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm12
.globl raw_hook_wrapper_x64_systemv_avx_patch_48_end
raw_hook_wrapper_x64_systemv_avx_patch_48_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_49
raw_hook_wrapper_x64_systemv_avx_patch_49:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm13
.globl raw_hook_wrapper_x64_systemv_avx_patch_49_end
raw_hook_wrapper_x64_systemv_avx_patch_49_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_50
raw_hook_wrapper_x64_systemv_avx_patch_50:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm14
.globl raw_hook_wrapper_x64_systemv_avx_patch_50_end
raw_hook_wrapper_x64_systemv_avx_patch_50_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_51
raw_hook_wrapper_x64_systemv_avx_patch_51:
	vmovups ymmword ptr [rsp + 0x7fffffff], ymm15
.globl raw_hook_wrapper_x64_systemv_avx_patch_51_end
raw_hook_wrapper_x64_systemv_avx_patch_51_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_0
raw_hook_wrapper_x64_systemv_avx_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_0_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_0_end:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_1
raw_hook_wrapper_x64_systemv_avx_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_1_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_2
raw_hook_wrapper_x64_systemv_avx_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_2_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_2_end:
	mov rdi, rsp
.globl raw_hook_wrapper_x64_systemv_avx_patch_52
raw_hook_wrapper_x64_systemv_avx_patch_52:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_systemv_avx_patch_52_end
raw_hook_wrapper_x64_systemv_avx_patch_52_end:
	call rax
	test al, al
	je raw_hook_wrapper_x64_systemv_avx_nothing_modified
.globl raw_hook_wrapper_x64_systemv_avx_patch_53
raw_hook_wrapper_x64_systemv_avx_patch_53:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_53_end
raw_hook_wrapper_x64_systemv_avx_patch_53_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_54
raw_hook_wrapper_x64_systemv_avx_patch_54:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_54_end
raw_hook_wrapper_x64_systemv_avx_patch_54_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_55
raw_hook_wrapper_x64_systemv_avx_patch_55:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_55_end
raw_hook_wrapper_x64_systemv_avx_patch_55_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_56
raw_hook_wrapper_x64_systemv_avx_patch_56:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_56_end
raw_hook_wrapper_x64_systemv_avx_patch_56_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_57
raw_hook_wrapper_x64_systemv_avx_patch_57:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_57_end
raw_hook_wrapper_x64_systemv_avx_patch_57_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_58
raw_hook_wrapper_x64_systemv_avx_patch_58:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_58_end
raw_hook_wrapper_x64_systemv_avx_patch_58_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_59
raw_hook_wrapper_x64_systemv_avx_patch_59:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_59_end
raw_hook_wrapper_x64_systemv_avx_patch_59_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_60
raw_hook_wrapper_x64_systemv_avx_patch_60:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_60_end
raw_hook_wrapper_x64_systemv_avx_patch_60_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_61
raw_hook_wrapper_x64_systemv_avx_patch_61:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_61_end
raw_hook_wrapper_x64_systemv_avx_patch_61_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_62
raw_hook_wrapper_x64_systemv_avx_patch_62:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_62_end
raw_hook_wrapper_x64_systemv_avx_patch_62_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_63
raw_hook_wrapper_x64_systemv_avx_patch_63:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_63_end
raw_hook_wrapper_x64_systemv_avx_patch_63_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_64
raw_hook_wrapper_x64_systemv_avx_patch_64:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_64_end
raw_hook_wrapper_x64_systemv_avx_patch_64_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_65
raw_hook_wrapper_x64_systemv_avx_patch_65:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_65_end
raw_hook_wrapper_x64_systemv_avx_patch_65_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_66
raw_hook_wrapper_x64_systemv_avx_patch_66:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_66_end
raw_hook_wrapper_x64_systemv_avx_patch_66_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_67
raw_hook_wrapper_x64_systemv_avx_patch_67:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_67_end
raw_hook_wrapper_x64_systemv_avx_patch_67_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_68
raw_hook_wrapper_x64_systemv_avx_patch_68:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_68_end
raw_hook_wrapper_x64_systemv_avx_patch_68_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_69
raw_hook_wrapper_x64_systemv_avx_patch_69:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_69_end
raw_hook_wrapper_x64_systemv_avx_patch_69_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_70
raw_hook_wrapper_x64_systemv_avx_patch_70:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_70_end
raw_hook_wrapper_x64_systemv_avx_patch_70_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_71
raw_hook_wrapper_x64_systemv_avx_patch_71:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_71_end
raw_hook_wrapper_x64_systemv_avx_patch_71_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_72
raw_hook_wrapper_x64_systemv_avx_patch_72:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_72_end
raw_hook_wrapper_x64_systemv_avx_patch_72_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_73
raw_hook_wrapper_x64_systemv_avx_patch_73:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_73_end
raw_hook_wrapper_x64_systemv_avx_patch_73_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_74
raw_hook_wrapper_x64_systemv_avx_patch_74:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_74_end
raw_hook_wrapper_x64_systemv_avx_patch_74_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_75
raw_hook_wrapper_x64_systemv_avx_patch_75:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_75_end
raw_hook_wrapper_x64_systemv_avx_patch_75_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_76
raw_hook_wrapper_x64_systemv_avx_patch_76:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_76_end
raw_hook_wrapper_x64_systemv_avx_patch_76_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_77
raw_hook_wrapper_x64_systemv_avx_patch_77:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_77_end
raw_hook_wrapper_x64_systemv_avx_patch_77_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_78
raw_hook_wrapper_x64_systemv_avx_patch_78:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_78_end
raw_hook_wrapper_x64_systemv_avx_patch_78_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_79
raw_hook_wrapper_x64_systemv_avx_patch_79:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_79_end
raw_hook_wrapper_x64_systemv_avx_patch_79_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_80
raw_hook_wrapper_x64_systemv_avx_patch_80:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_80_end
raw_hook_wrapper_x64_systemv_avx_patch_80_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_81
raw_hook_wrapper_x64_systemv_avx_patch_81:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_81_end
raw_hook_wrapper_x64_systemv_avx_patch_81_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_82
raw_hook_wrapper_x64_systemv_avx_patch_82:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_82_end
raw_hook_wrapper_x64_systemv_avx_patch_82_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_83
raw_hook_wrapper_x64_systemv_avx_patch_83:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_83_end
raw_hook_wrapper_x64_systemv_avx_patch_83_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_84
raw_hook_wrapper_x64_systemv_avx_patch_84:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_84_end
raw_hook_wrapper_x64_systemv_avx_patch_84_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_85
raw_hook_wrapper_x64_systemv_avx_patch_85:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_85_end
raw_hook_wrapper_x64_systemv_avx_patch_85_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_87
raw_hook_wrapper_x64_systemv_avx_patch_87:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_87_end
raw_hook_wrapper_x64_systemv_avx_patch_87_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_88
raw_hook_wrapper_x64_systemv_avx_patch_88:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_88_end
raw_hook_wrapper_x64_systemv_avx_patch_88_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_89
raw_hook_wrapper_x64_systemv_avx_patch_89:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_89_end
raw_hook_wrapper_x64_systemv_avx_patch_89_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_90
raw_hook_wrapper_x64_systemv_avx_patch_90:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_90_end
raw_hook_wrapper_x64_systemv_avx_patch_90_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_91
raw_hook_wrapper_x64_systemv_avx_patch_91:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_91_end
raw_hook_wrapper_x64_systemv_avx_patch_91_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_92
raw_hook_wrapper_x64_systemv_avx_patch_92:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_92_end
raw_hook_wrapper_x64_systemv_avx_patch_92_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_93
raw_hook_wrapper_x64_systemv_avx_patch_93:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_93_end
raw_hook_wrapper_x64_systemv_avx_patch_93_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_94
raw_hook_wrapper_x64_systemv_avx_patch_94:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_94_end
raw_hook_wrapper_x64_systemv_avx_patch_94_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_95
raw_hook_wrapper_x64_systemv_avx_patch_95:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_95_end
raw_hook_wrapper_x64_systemv_avx_patch_95_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_96
raw_hook_wrapper_x64_systemv_avx_patch_96:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_96_end
raw_hook_wrapper_x64_systemv_avx_patch_96_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_97
raw_hook_wrapper_x64_systemv_avx_patch_97:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_97_end
raw_hook_wrapper_x64_systemv_avx_patch_97_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_98
raw_hook_wrapper_x64_systemv_avx_patch_98:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_98_end
raw_hook_wrapper_x64_systemv_avx_patch_98_end:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_3
raw_hook_wrapper_x64_systemv_avx_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_3_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_systemv_avx_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_4
raw_hook_wrapper_x64_systemv_avx_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_4_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_systemv_avx_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_5
raw_hook_wrapper_x64_systemv_avx_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_5_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_systemv_avx_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_6
raw_hook_wrapper_x64_systemv_avx_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_6_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_systemv_avx_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_avx_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_avx_redirect_return
raw_hook_wrapper_x64_systemv_avx_unsupported_stack:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_7
raw_hook_wrapper_x64_systemv_avx_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_7_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_8
raw_hook_wrapper_x64_systemv_avx_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_8_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_9
raw_hook_wrapper_x64_systemv_avx_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_9_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_systemv_avx_direct_return:
.globl raw_hook_wrapper_x64_systemv_avx_patch_86
raw_hook_wrapper_x64_systemv_avx_patch_86:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_86_end
raw_hook_wrapper_x64_systemv_avx_patch_86_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_avx_patch_99
raw_hook_wrapper_x64_systemv_avx_patch_99:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_99_end
raw_hook_wrapper_x64_systemv_avx_patch_99_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_100
raw_hook_wrapper_x64_systemv_avx_patch_100:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_100_end
raw_hook_wrapper_x64_systemv_avx_patch_100_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_101
raw_hook_wrapper_x64_systemv_avx_patch_101:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_101_end
raw_hook_wrapper_x64_systemv_avx_patch_101_end:
.globl raw_hook_wrapper_x64_systemv_avx_patch_102
raw_hook_wrapper_x64_systemv_avx_patch_102:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_patch_102_end
raw_hook_wrapper_x64_systemv_avx_patch_102_end:
	ret
raw_hook_wrapper_x64_systemv_avx_redirect_return:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_10
raw_hook_wrapper_x64_systemv_avx_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_10_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_11
raw_hook_wrapper_x64_systemv_avx_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_11_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_12
raw_hook_wrapper_x64_systemv_avx_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_12_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_13
raw_hook_wrapper_x64_systemv_avx_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_13_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_14
raw_hook_wrapper_x64_systemv_avx_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_avx_cet_patch_14_end
raw_hook_wrapper_x64_systemv_avx_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_systemv_avx_nothing_modified:
.globl raw_hook_wrapper_x64_systemv_avx_patch_103
raw_hook_wrapper_x64_systemv_avx_patch_103:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_avx_patch_103_end
raw_hook_wrapper_x64_systemv_avx_patch_103_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 systemv SSEFPU
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_systemv_ssefpu
raw_hook_wrapper_x64_systemv_ssefpu:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_0
raw_hook_wrapper_x64_systemv_ssefpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_0_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_1
raw_hook_wrapper_x64_systemv_ssefpu_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_1_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_1_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_2
raw_hook_wrapper_x64_systemv_ssefpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_2_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_2_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_3
raw_hook_wrapper_x64_systemv_ssefpu_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_3_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_3_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_4
raw_hook_wrapper_x64_systemv_ssefpu_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_4_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_4_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_5
raw_hook_wrapper_x64_systemv_ssefpu_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_5_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_5_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_6
raw_hook_wrapper_x64_systemv_ssefpu_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_6_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_6_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_7
raw_hook_wrapper_x64_systemv_ssefpu_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_7_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_8
raw_hook_wrapper_x64_systemv_ssefpu_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_8_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_9
raw_hook_wrapper_x64_systemv_ssefpu_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_9_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_9_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_10
raw_hook_wrapper_x64_systemv_ssefpu_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_10_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_10_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_11
raw_hook_wrapper_x64_systemv_ssefpu_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_11_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_12
raw_hook_wrapper_x64_systemv_ssefpu_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_12_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_13
raw_hook_wrapper_x64_systemv_ssefpu_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_13_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_14
raw_hook_wrapper_x64_systemv_ssefpu_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_14_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_14_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_15
raw_hook_wrapper_x64_systemv_ssefpu_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_15_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_15_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_16
raw_hook_wrapper_x64_systemv_ssefpu_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_16_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_16_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_17
raw_hook_wrapper_x64_systemv_ssefpu_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_17_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_17_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_18
raw_hook_wrapper_x64_systemv_ssefpu_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_18_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_18_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_19
raw_hook_wrapper_x64_systemv_ssefpu_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_19_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_19_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_20
raw_hook_wrapper_x64_systemv_ssefpu_patch_20:
	movups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_20_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_20_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_21
raw_hook_wrapper_x64_systemv_ssefpu_patch_21:
	movups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_21_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_21_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_22
raw_hook_wrapper_x64_systemv_ssefpu_patch_22:
	movups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_22_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_22_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_23
raw_hook_wrapper_x64_systemv_ssefpu_patch_23:
	movups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_23_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_23_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_24
raw_hook_wrapper_x64_systemv_ssefpu_patch_24:
	movups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_24_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_24_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_25
raw_hook_wrapper_x64_systemv_ssefpu_patch_25:
	movups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_25_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_25_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_26
raw_hook_wrapper_x64_systemv_ssefpu_patch_26:
	movups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_26_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_26_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_27
raw_hook_wrapper_x64_systemv_ssefpu_patch_27:
	movups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_27_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_27_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_28
raw_hook_wrapper_x64_systemv_ssefpu_patch_28:
	movups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_28_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_28_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_29
raw_hook_wrapper_x64_systemv_ssefpu_patch_29:
	movups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_29_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_29_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_30
raw_hook_wrapper_x64_systemv_ssefpu_patch_30:
	movups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_30_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_30_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_31
raw_hook_wrapper_x64_systemv_ssefpu_patch_31:
	movups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_31_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_31_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_32
raw_hook_wrapper_x64_systemv_ssefpu_patch_32:
	movups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_32_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_32_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_33
raw_hook_wrapper_x64_systemv_ssefpu_patch_33:
	movups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_33_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_33_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_34
raw_hook_wrapper_x64_systemv_ssefpu_patch_34:
	movups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_34_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_34_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_35
raw_hook_wrapper_x64_systemv_ssefpu_patch_35:
	movups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_35_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_35_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_36
raw_hook_wrapper_x64_systemv_ssefpu_patch_36:
	fsave [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_36_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_36_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_0
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_0_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_0_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_1
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_1_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_2
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_2_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_2_end:
	mov rdi, rsp
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_37
raw_hook_wrapper_x64_systemv_ssefpu_patch_37:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_37_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_37_end:
	call rax
	test al, al
	je raw_hook_wrapper_x64_systemv_ssefpu_nothing_modified
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_38
raw_hook_wrapper_x64_systemv_ssefpu_patch_38:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_38_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_38_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_39
raw_hook_wrapper_x64_systemv_ssefpu_patch_39:
	movups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_39_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_39_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_40
raw_hook_wrapper_x64_systemv_ssefpu_patch_40:
	movups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_40_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_40_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_41
raw_hook_wrapper_x64_systemv_ssefpu_patch_41:
	movups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_41_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_41_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_42
raw_hook_wrapper_x64_systemv_ssefpu_patch_42:
	movups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_42_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_42_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_43
raw_hook_wrapper_x64_systemv_ssefpu_patch_43:
	movups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_43_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_43_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_44
raw_hook_wrapper_x64_systemv_ssefpu_patch_44:
	movups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_44_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_44_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_45
raw_hook_wrapper_x64_systemv_ssefpu_patch_45:
	movups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_45_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_45_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_46
raw_hook_wrapper_x64_systemv_ssefpu_patch_46:
	movups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_46_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_46_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_47
raw_hook_wrapper_x64_systemv_ssefpu_patch_47:
	movups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_47_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_47_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_48
raw_hook_wrapper_x64_systemv_ssefpu_patch_48:
	movups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_48_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_48_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_49
raw_hook_wrapper_x64_systemv_ssefpu_patch_49:
	movups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_49_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_49_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_50
raw_hook_wrapper_x64_systemv_ssefpu_patch_50:
	movups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_50_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_50_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_51
raw_hook_wrapper_x64_systemv_ssefpu_patch_51:
	movups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_51_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_51_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_52
raw_hook_wrapper_x64_systemv_ssefpu_patch_52:
	movups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_52_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_52_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_53
raw_hook_wrapper_x64_systemv_ssefpu_patch_53:
	movups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_53_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_53_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_54
raw_hook_wrapper_x64_systemv_ssefpu_patch_54:
	movups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_54_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_54_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_55
raw_hook_wrapper_x64_systemv_ssefpu_patch_55:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_55_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_55_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_57
raw_hook_wrapper_x64_systemv_ssefpu_patch_57:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_57_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_57_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_58
raw_hook_wrapper_x64_systemv_ssefpu_patch_58:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_58_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_58_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_59
raw_hook_wrapper_x64_systemv_ssefpu_patch_59:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_59_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_59_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_60
raw_hook_wrapper_x64_systemv_ssefpu_patch_60:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_60_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_60_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_61
raw_hook_wrapper_x64_systemv_ssefpu_patch_61:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_61_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_61_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_62
raw_hook_wrapper_x64_systemv_ssefpu_patch_62:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_62_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_62_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_63
raw_hook_wrapper_x64_systemv_ssefpu_patch_63:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_63_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_63_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_64
raw_hook_wrapper_x64_systemv_ssefpu_patch_64:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_64_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_64_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_65
raw_hook_wrapper_x64_systemv_ssefpu_patch_65:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_65_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_65_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_66
raw_hook_wrapper_x64_systemv_ssefpu_patch_66:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_66_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_66_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_67
raw_hook_wrapper_x64_systemv_ssefpu_patch_67:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_67_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_67_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_68
raw_hook_wrapper_x64_systemv_ssefpu_patch_68:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_68_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_68_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_3
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_3_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_systemv_ssefpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_4
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_4_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_systemv_ssefpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_5
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_5_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_systemv_ssefpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_6
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_6_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_systemv_ssefpu_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_ssefpu_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_ssefpu_redirect_return
raw_hook_wrapper_x64_systemv_ssefpu_unsupported_stack:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_7
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_7_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_8
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_8_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_9
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_9_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_systemv_ssefpu_direct_return:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_56
raw_hook_wrapper_x64_systemv_ssefpu_patch_56:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_56_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_56_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_69
raw_hook_wrapper_x64_systemv_ssefpu_patch_69:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_69_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_69_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_70
raw_hook_wrapper_x64_systemv_ssefpu_patch_70:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_70_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_70_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_71
raw_hook_wrapper_x64_systemv_ssefpu_patch_71:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_71_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_71_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_72
raw_hook_wrapper_x64_systemv_ssefpu_patch_72:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_72_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_72_end:
	ret
raw_hook_wrapper_x64_systemv_ssefpu_redirect_return:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_10
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_10_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_11
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_11_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_12
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_12_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_13
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_13_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_14
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_14_end
raw_hook_wrapper_x64_systemv_ssefpu_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_systemv_ssefpu_nothing_modified:
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_73
raw_hook_wrapper_x64_systemv_ssefpu_patch_73:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_ssefpu_patch_73_end
raw_hook_wrapper_x64_systemv_ssefpu_patch_73_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 systemv SSE
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_systemv_sse
raw_hook_wrapper_x64_systemv_sse:
.globl raw_hook_wrapper_x64_systemv_sse_patch_0
raw_hook_wrapper_x64_systemv_sse_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_sse_patch_0_end
raw_hook_wrapper_x64_systemv_sse_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_systemv_sse_patch_1
raw_hook_wrapper_x64_systemv_sse_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_1_end
raw_hook_wrapper_x64_systemv_sse_patch_1_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_2
raw_hook_wrapper_x64_systemv_sse_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_sse_patch_2_end
raw_hook_wrapper_x64_systemv_sse_patch_2_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_3
raw_hook_wrapper_x64_systemv_sse_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_sse_patch_3_end
raw_hook_wrapper_x64_systemv_sse_patch_3_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_4
raw_hook_wrapper_x64_systemv_sse_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_systemv_sse_patch_4_end
raw_hook_wrapper_x64_systemv_sse_patch_4_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_5
raw_hook_wrapper_x64_systemv_sse_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_systemv_sse_patch_5_end
raw_hook_wrapper_x64_systemv_sse_patch_5_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_6
raw_hook_wrapper_x64_systemv_sse_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_systemv_sse_patch_6_end
raw_hook_wrapper_x64_systemv_sse_patch_6_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_7
raw_hook_wrapper_x64_systemv_sse_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_sse_patch_7_end
raw_hook_wrapper_x64_systemv_sse_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_8
raw_hook_wrapper_x64_systemv_sse_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_systemv_sse_patch_8_end
raw_hook_wrapper_x64_systemv_sse_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_9
raw_hook_wrapper_x64_systemv_sse_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_systemv_sse_patch_9_end
raw_hook_wrapper_x64_systemv_sse_patch_9_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_10
raw_hook_wrapper_x64_systemv_sse_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_systemv_sse_patch_10_end
raw_hook_wrapper_x64_systemv_sse_patch_10_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_11
raw_hook_wrapper_x64_systemv_sse_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_systemv_sse_patch_11_end
raw_hook_wrapper_x64_systemv_sse_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_12
raw_hook_wrapper_x64_systemv_sse_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_systemv_sse_patch_12_end
raw_hook_wrapper_x64_systemv_sse_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_13
raw_hook_wrapper_x64_systemv_sse_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_systemv_sse_patch_13_end
raw_hook_wrapper_x64_systemv_sse_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_14
raw_hook_wrapper_x64_systemv_sse_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_systemv_sse_patch_14_end
raw_hook_wrapper_x64_systemv_sse_patch_14_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_15
raw_hook_wrapper_x64_systemv_sse_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_systemv_sse_patch_15_end
raw_hook_wrapper_x64_systemv_sse_patch_15_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_16
raw_hook_wrapper_x64_systemv_sse_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_systemv_sse_patch_16_end
raw_hook_wrapper_x64_systemv_sse_patch_16_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_17
raw_hook_wrapper_x64_systemv_sse_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_systemv_sse_patch_17_end
raw_hook_wrapper_x64_systemv_sse_patch_17_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_18
raw_hook_wrapper_x64_systemv_sse_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_systemv_sse_patch_18_end
raw_hook_wrapper_x64_systemv_sse_patch_18_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_19
raw_hook_wrapper_x64_systemv_sse_patch_19:
	stmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_19_end
raw_hook_wrapper_x64_systemv_sse_patch_19_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_20
raw_hook_wrapper_x64_systemv_sse_patch_20:
	movups xmmword ptr [rsp + 0x7fffffff], xmm0
.globl raw_hook_wrapper_x64_systemv_sse_patch_20_end
raw_hook_wrapper_x64_systemv_sse_patch_20_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_21
raw_hook_wrapper_x64_systemv_sse_patch_21:
	movups xmmword ptr [rsp + 0x7fffffff], xmm1
.globl raw_hook_wrapper_x64_systemv_sse_patch_21_end
raw_hook_wrapper_x64_systemv_sse_patch_21_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_22
raw_hook_wrapper_x64_systemv_sse_patch_22:
	movups xmmword ptr [rsp + 0x7fffffff], xmm2
.globl raw_hook_wrapper_x64_systemv_sse_patch_22_end
raw_hook_wrapper_x64_systemv_sse_patch_22_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_23
raw_hook_wrapper_x64_systemv_sse_patch_23:
	movups xmmword ptr [rsp + 0x7fffffff], xmm3
.globl raw_hook_wrapper_x64_systemv_sse_patch_23_end
raw_hook_wrapper_x64_systemv_sse_patch_23_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_24
raw_hook_wrapper_x64_systemv_sse_patch_24:
	movups xmmword ptr [rsp + 0x7fffffff], xmm4
.globl raw_hook_wrapper_x64_systemv_sse_patch_24_end
raw_hook_wrapper_x64_systemv_sse_patch_24_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_25
raw_hook_wrapper_x64_systemv_sse_patch_25:
	movups xmmword ptr [rsp + 0x7fffffff], xmm5
.globl raw_hook_wrapper_x64_systemv_sse_patch_25_end
raw_hook_wrapper_x64_systemv_sse_patch_25_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_26
raw_hook_wrapper_x64_systemv_sse_patch_26:
	movups xmmword ptr [rsp + 0x7fffffff], xmm6
.globl raw_hook_wrapper_x64_systemv_sse_patch_26_end
raw_hook_wrapper_x64_systemv_sse_patch_26_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_27
raw_hook_wrapper_x64_systemv_sse_patch_27:
	movups xmmword ptr [rsp + 0x7fffffff], xmm7
.globl raw_hook_wrapper_x64_systemv_sse_patch_27_end
raw_hook_wrapper_x64_systemv_sse_patch_27_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_28
raw_hook_wrapper_x64_systemv_sse_patch_28:
	movups xmmword ptr [rsp + 0x7fffffff], xmm8
.globl raw_hook_wrapper_x64_systemv_sse_patch_28_end
raw_hook_wrapper_x64_systemv_sse_patch_28_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_29
raw_hook_wrapper_x64_systemv_sse_patch_29:
	movups xmmword ptr [rsp + 0x7fffffff], xmm9
.globl raw_hook_wrapper_x64_systemv_sse_patch_29_end
raw_hook_wrapper_x64_systemv_sse_patch_29_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_30
raw_hook_wrapper_x64_systemv_sse_patch_30:
	movups xmmword ptr [rsp + 0x7fffffff], xmm10
.globl raw_hook_wrapper_x64_systemv_sse_patch_30_end
raw_hook_wrapper_x64_systemv_sse_patch_30_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_31
raw_hook_wrapper_x64_systemv_sse_patch_31:
	movups xmmword ptr [rsp + 0x7fffffff], xmm11
.globl raw_hook_wrapper_x64_systemv_sse_patch_31_end
raw_hook_wrapper_x64_systemv_sse_patch_31_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_32
raw_hook_wrapper_x64_systemv_sse_patch_32:
	movups xmmword ptr [rsp + 0x7fffffff], xmm12
.globl raw_hook_wrapper_x64_systemv_sse_patch_32_end
raw_hook_wrapper_x64_systemv_sse_patch_32_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_33
raw_hook_wrapper_x64_systemv_sse_patch_33:
	movups xmmword ptr [rsp + 0x7fffffff], xmm13
.globl raw_hook_wrapper_x64_systemv_sse_patch_33_end
raw_hook_wrapper_x64_systemv_sse_patch_33_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_34
raw_hook_wrapper_x64_systemv_sse_patch_34:
	movups xmmword ptr [rsp + 0x7fffffff], xmm14
.globl raw_hook_wrapper_x64_systemv_sse_patch_34_end
raw_hook_wrapper_x64_systemv_sse_patch_34_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_35
raw_hook_wrapper_x64_systemv_sse_patch_35:
	movups xmmword ptr [rsp + 0x7fffffff], xmm15
.globl raw_hook_wrapper_x64_systemv_sse_patch_35_end
raw_hook_wrapper_x64_systemv_sse_patch_35_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_0
raw_hook_wrapper_x64_systemv_sse_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_0_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_0_end:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_1
raw_hook_wrapper_x64_systemv_sse_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_1_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_2
raw_hook_wrapper_x64_systemv_sse_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_2_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_2_end:
	mov rdi, rsp
.globl raw_hook_wrapper_x64_systemv_sse_patch_36
raw_hook_wrapper_x64_systemv_sse_patch_36:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_systemv_sse_patch_36_end
raw_hook_wrapper_x64_systemv_sse_patch_36_end:
	call rax
	test al, al
	je raw_hook_wrapper_x64_systemv_sse_nothing_modified
.globl raw_hook_wrapper_x64_systemv_sse_patch_37
raw_hook_wrapper_x64_systemv_sse_patch_37:
	movups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_37_end
raw_hook_wrapper_x64_systemv_sse_patch_37_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_38
raw_hook_wrapper_x64_systemv_sse_patch_38:
	movups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_38_end
raw_hook_wrapper_x64_systemv_sse_patch_38_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_39
raw_hook_wrapper_x64_systemv_sse_patch_39:
	movups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_39_end
raw_hook_wrapper_x64_systemv_sse_patch_39_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_40
raw_hook_wrapper_x64_systemv_sse_patch_40:
	movups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_40_end
raw_hook_wrapper_x64_systemv_sse_patch_40_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_41
raw_hook_wrapper_x64_systemv_sse_patch_41:
	movups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_41_end
raw_hook_wrapper_x64_systemv_sse_patch_41_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_42
raw_hook_wrapper_x64_systemv_sse_patch_42:
	movups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_42_end
raw_hook_wrapper_x64_systemv_sse_patch_42_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_43
raw_hook_wrapper_x64_systemv_sse_patch_43:
	movups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_43_end
raw_hook_wrapper_x64_systemv_sse_patch_43_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_44
raw_hook_wrapper_x64_systemv_sse_patch_44:
	movups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_44_end
raw_hook_wrapper_x64_systemv_sse_patch_44_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_45
raw_hook_wrapper_x64_systemv_sse_patch_45:
	movups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_45_end
raw_hook_wrapper_x64_systemv_sse_patch_45_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_46
raw_hook_wrapper_x64_systemv_sse_patch_46:
	movups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_46_end
raw_hook_wrapper_x64_systemv_sse_patch_46_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_47
raw_hook_wrapper_x64_systemv_sse_patch_47:
	movups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_47_end
raw_hook_wrapper_x64_systemv_sse_patch_47_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_48
raw_hook_wrapper_x64_systemv_sse_patch_48:
	movups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_48_end
raw_hook_wrapper_x64_systemv_sse_patch_48_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_49
raw_hook_wrapper_x64_systemv_sse_patch_49:
	movups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_49_end
raw_hook_wrapper_x64_systemv_sse_patch_49_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_50
raw_hook_wrapper_x64_systemv_sse_patch_50:
	movups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_50_end
raw_hook_wrapper_x64_systemv_sse_patch_50_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_51
raw_hook_wrapper_x64_systemv_sse_patch_51:
	movups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_51_end
raw_hook_wrapper_x64_systemv_sse_patch_51_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_52
raw_hook_wrapper_x64_systemv_sse_patch_52:
	movups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_52_end
raw_hook_wrapper_x64_systemv_sse_patch_52_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_53
raw_hook_wrapper_x64_systemv_sse_patch_53:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_53_end
raw_hook_wrapper_x64_systemv_sse_patch_53_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_55
raw_hook_wrapper_x64_systemv_sse_patch_55:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_55_end
raw_hook_wrapper_x64_systemv_sse_patch_55_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_56
raw_hook_wrapper_x64_systemv_sse_patch_56:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_56_end
raw_hook_wrapper_x64_systemv_sse_patch_56_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_57
raw_hook_wrapper_x64_systemv_sse_patch_57:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_57_end
raw_hook_wrapper_x64_systemv_sse_patch_57_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_58
raw_hook_wrapper_x64_systemv_sse_patch_58:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_58_end
raw_hook_wrapper_x64_systemv_sse_patch_58_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_59
raw_hook_wrapper_x64_systemv_sse_patch_59:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_59_end
raw_hook_wrapper_x64_systemv_sse_patch_59_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_60
raw_hook_wrapper_x64_systemv_sse_patch_60:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_60_end
raw_hook_wrapper_x64_systemv_sse_patch_60_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_61
raw_hook_wrapper_x64_systemv_sse_patch_61:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_61_end
raw_hook_wrapper_x64_systemv_sse_patch_61_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_62
raw_hook_wrapper_x64_systemv_sse_patch_62:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_62_end
raw_hook_wrapper_x64_systemv_sse_patch_62_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_63
raw_hook_wrapper_x64_systemv_sse_patch_63:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_63_end
raw_hook_wrapper_x64_systemv_sse_patch_63_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_64
raw_hook_wrapper_x64_systemv_sse_patch_64:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_64_end
raw_hook_wrapper_x64_systemv_sse_patch_64_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_65
raw_hook_wrapper_x64_systemv_sse_patch_65:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_65_end
raw_hook_wrapper_x64_systemv_sse_patch_65_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_66
raw_hook_wrapper_x64_systemv_sse_patch_66:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_66_end
raw_hook_wrapper_x64_systemv_sse_patch_66_end:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_3
raw_hook_wrapper_x64_systemv_sse_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_3_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_systemv_sse_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_4
raw_hook_wrapper_x64_systemv_sse_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_4_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_systemv_sse_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_5
raw_hook_wrapper_x64_systemv_sse_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_5_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_systemv_sse_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_6
raw_hook_wrapper_x64_systemv_sse_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_6_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_systemv_sse_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_sse_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_sse_redirect_return
raw_hook_wrapper_x64_systemv_sse_unsupported_stack:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_7
raw_hook_wrapper_x64_systemv_sse_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_7_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_8
raw_hook_wrapper_x64_systemv_sse_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_8_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_9
raw_hook_wrapper_x64_systemv_sse_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_9_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_systemv_sse_direct_return:
.globl raw_hook_wrapper_x64_systemv_sse_patch_54
raw_hook_wrapper_x64_systemv_sse_patch_54:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_54_end
raw_hook_wrapper_x64_systemv_sse_patch_54_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_sse_patch_67
raw_hook_wrapper_x64_systemv_sse_patch_67:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_67_end
raw_hook_wrapper_x64_systemv_sse_patch_67_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_68
raw_hook_wrapper_x64_systemv_sse_patch_68:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_68_end
raw_hook_wrapper_x64_systemv_sse_patch_68_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_69
raw_hook_wrapper_x64_systemv_sse_patch_69:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_69_end
raw_hook_wrapper_x64_systemv_sse_patch_69_end:
.globl raw_hook_wrapper_x64_systemv_sse_patch_70
raw_hook_wrapper_x64_systemv_sse_patch_70:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_patch_70_end
raw_hook_wrapper_x64_systemv_sse_patch_70_end:
	ret
raw_hook_wrapper_x64_systemv_sse_redirect_return:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_10
raw_hook_wrapper_x64_systemv_sse_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_10_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_11
raw_hook_wrapper_x64_systemv_sse_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_11_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_12
raw_hook_wrapper_x64_systemv_sse_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_12_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_13
raw_hook_wrapper_x64_systemv_sse_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_13_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_14
raw_hook_wrapper_x64_systemv_sse_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_sse_cet_patch_14_end
raw_hook_wrapper_x64_systemv_sse_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_systemv_sse_nothing_modified:
.globl raw_hook_wrapper_x64_systemv_sse_patch_71
raw_hook_wrapper_x64_systemv_sse_patch_71:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_sse_patch_71_end
raw_hook_wrapper_x64_systemv_sse_patch_71_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 systemv FPU
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_systemv_fpu
raw_hook_wrapper_x64_systemv_fpu:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_0
raw_hook_wrapper_x64_systemv_fpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_fpu_patch_0_end
raw_hook_wrapper_x64_systemv_fpu_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_systemv_fpu_patch_1
raw_hook_wrapper_x64_systemv_fpu_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_1_end
raw_hook_wrapper_x64_systemv_fpu_patch_1_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_2
raw_hook_wrapper_x64_systemv_fpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_fpu_patch_2_end
raw_hook_wrapper_x64_systemv_fpu_patch_2_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_3
raw_hook_wrapper_x64_systemv_fpu_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_fpu_patch_3_end
raw_hook_wrapper_x64_systemv_fpu_patch_3_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_4
raw_hook_wrapper_x64_systemv_fpu_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_systemv_fpu_patch_4_end
raw_hook_wrapper_x64_systemv_fpu_patch_4_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_5
raw_hook_wrapper_x64_systemv_fpu_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_systemv_fpu_patch_5_end
raw_hook_wrapper_x64_systemv_fpu_patch_5_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_6
raw_hook_wrapper_x64_systemv_fpu_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_systemv_fpu_patch_6_end
raw_hook_wrapper_x64_systemv_fpu_patch_6_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_7
raw_hook_wrapper_x64_systemv_fpu_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_fpu_patch_7_end
raw_hook_wrapper_x64_systemv_fpu_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_8
raw_hook_wrapper_x64_systemv_fpu_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_systemv_fpu_patch_8_end
raw_hook_wrapper_x64_systemv_fpu_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_9
raw_hook_wrapper_x64_systemv_fpu_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_systemv_fpu_patch_9_end
raw_hook_wrapper_x64_systemv_fpu_patch_9_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_10
raw_hook_wrapper_x64_systemv_fpu_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_systemv_fpu_patch_10_end
raw_hook_wrapper_x64_systemv_fpu_patch_10_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_11
raw_hook_wrapper_x64_systemv_fpu_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_systemv_fpu_patch_11_end
raw_hook_wrapper_x64_systemv_fpu_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_12
raw_hook_wrapper_x64_systemv_fpu_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_systemv_fpu_patch_12_end
raw_hook_wrapper_x64_systemv_fpu_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_13
raw_hook_wrapper_x64_systemv_fpu_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_systemv_fpu_patch_13_end
raw_hook_wrapper_x64_systemv_fpu_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_14
raw_hook_wrapper_x64_systemv_fpu_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_systemv_fpu_patch_14_end
raw_hook_wrapper_x64_systemv_fpu_patch_14_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_15
raw_hook_wrapper_x64_systemv_fpu_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_systemv_fpu_patch_15_end
raw_hook_wrapper_x64_systemv_fpu_patch_15_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_16
raw_hook_wrapper_x64_systemv_fpu_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_systemv_fpu_patch_16_end
raw_hook_wrapper_x64_systemv_fpu_patch_16_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_17
raw_hook_wrapper_x64_systemv_fpu_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_systemv_fpu_patch_17_end
raw_hook_wrapper_x64_systemv_fpu_patch_17_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_18
raw_hook_wrapper_x64_systemv_fpu_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_systemv_fpu_patch_18_end
raw_hook_wrapper_x64_systemv_fpu_patch_18_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_19
raw_hook_wrapper_x64_systemv_fpu_patch_19:
	fsave [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_19_end
raw_hook_wrapper_x64_systemv_fpu_patch_19_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_0
raw_hook_wrapper_x64_systemv_fpu_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_0_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_0_end:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_1
raw_hook_wrapper_x64_systemv_fpu_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_1_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_2
raw_hook_wrapper_x64_systemv_fpu_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_2_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_2_end:
	mov rdi, rsp
.globl raw_hook_wrapper_x64_systemv_fpu_patch_20
raw_hook_wrapper_x64_systemv_fpu_patch_20:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_systemv_fpu_patch_20_end
raw_hook_wrapper_x64_systemv_fpu_patch_20_end:
	call rax
	test al, al
	je raw_hook_wrapper_x64_systemv_fpu_nothing_modified
.globl raw_hook_wrapper_x64_systemv_fpu_patch_21
raw_hook_wrapper_x64_systemv_fpu_patch_21:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_21_end
raw_hook_wrapper_x64_systemv_fpu_patch_21_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_23
raw_hook_wrapper_x64_systemv_fpu_patch_23:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_23_end
raw_hook_wrapper_x64_systemv_fpu_patch_23_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_24
raw_hook_wrapper_x64_systemv_fpu_patch_24:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_24_end
raw_hook_wrapper_x64_systemv_fpu_patch_24_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_25
raw_hook_wrapper_x64_systemv_fpu_patch_25:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_25_end
raw_hook_wrapper_x64_systemv_fpu_patch_25_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_26
raw_hook_wrapper_x64_systemv_fpu_patch_26:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_26_end
raw_hook_wrapper_x64_systemv_fpu_patch_26_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_27
raw_hook_wrapper_x64_systemv_fpu_patch_27:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_27_end
raw_hook_wrapper_x64_systemv_fpu_patch_27_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_28
raw_hook_wrapper_x64_systemv_fpu_patch_28:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_28_end
raw_hook_wrapper_x64_systemv_fpu_patch_28_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_29
raw_hook_wrapper_x64_systemv_fpu_patch_29:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_29_end
raw_hook_wrapper_x64_systemv_fpu_patch_29_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_30
raw_hook_wrapper_x64_systemv_fpu_patch_30:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_30_end
raw_hook_wrapper_x64_systemv_fpu_patch_30_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_31
raw_hook_wrapper_x64_systemv_fpu_patch_31:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_31_end
raw_hook_wrapper_x64_systemv_fpu_patch_31_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_32
raw_hook_wrapper_x64_systemv_fpu_patch_32:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_32_end
raw_hook_wrapper_x64_systemv_fpu_patch_32_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_33
raw_hook_wrapper_x64_systemv_fpu_patch_33:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_33_end
raw_hook_wrapper_x64_systemv_fpu_patch_33_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_34
raw_hook_wrapper_x64_systemv_fpu_patch_34:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_34_end
raw_hook_wrapper_x64_systemv_fpu_patch_34_end:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_3
raw_hook_wrapper_x64_systemv_fpu_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_3_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_systemv_fpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_4
raw_hook_wrapper_x64_systemv_fpu_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_4_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_systemv_fpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_5
raw_hook_wrapper_x64_systemv_fpu_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_5_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_systemv_fpu_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_6
raw_hook_wrapper_x64_systemv_fpu_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_6_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_systemv_fpu_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_fpu_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_fpu_redirect_return
raw_hook_wrapper_x64_systemv_fpu_unsupported_stack:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_7
raw_hook_wrapper_x64_systemv_fpu_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_7_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_8
raw_hook_wrapper_x64_systemv_fpu_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_8_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_9
raw_hook_wrapper_x64_systemv_fpu_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_9_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_systemv_fpu_direct_return:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_22
raw_hook_wrapper_x64_systemv_fpu_patch_22:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_22_end
raw_hook_wrapper_x64_systemv_fpu_patch_22_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_fpu_patch_35
raw_hook_wrapper_x64_systemv_fpu_patch_35:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_35_end
raw_hook_wrapper_x64_systemv_fpu_patch_35_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_36
raw_hook_wrapper_x64_systemv_fpu_patch_36:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_36_end
raw_hook_wrapper_x64_systemv_fpu_patch_36_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_37
raw_hook_wrapper_x64_systemv_fpu_patch_37:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_37_end
raw_hook_wrapper_x64_systemv_fpu_patch_37_end:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_38
raw_hook_wrapper_x64_systemv_fpu_patch_38:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_patch_38_end
raw_hook_wrapper_x64_systemv_fpu_patch_38_end:
	ret
raw_hook_wrapper_x64_systemv_fpu_redirect_return:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_10
raw_hook_wrapper_x64_systemv_fpu_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_10_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_11
raw_hook_wrapper_x64_systemv_fpu_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_11_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_12
raw_hook_wrapper_x64_systemv_fpu_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_12_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_13
raw_hook_wrapper_x64_systemv_fpu_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_13_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_14
raw_hook_wrapper_x64_systemv_fpu_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_fpu_cet_patch_14_end
raw_hook_wrapper_x64_systemv_fpu_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_systemv_fpu_nothing_modified:
.globl raw_hook_wrapper_x64_systemv_fpu_patch_39
raw_hook_wrapper_x64_systemv_fpu_patch_39:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_fpu_patch_39_end
raw_hook_wrapper_x64_systemv_fpu_patch_39_end:

# ----------------------------------------------------------------
# RawHook wrapper: x64 systemv Native
# ----------------------------------------------------------------
.intel_syntax noprefix
.text
.globl raw_hook_wrapper_x64_systemv_native
raw_hook_wrapper_x64_systemv_native:
.globl raw_hook_wrapper_x64_systemv_native_patch_0
raw_hook_wrapper_x64_systemv_native_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_native_patch_0_end
raw_hook_wrapper_x64_systemv_native_patch_0_end:
	pushfq
.globl raw_hook_wrapper_x64_systemv_native_patch_1
raw_hook_wrapper_x64_systemv_native_patch_1:
	pop qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_1_end
raw_hook_wrapper_x64_systemv_native_patch_1_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_2
raw_hook_wrapper_x64_systemv_native_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_native_patch_2_end
raw_hook_wrapper_x64_systemv_native_patch_2_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_3
raw_hook_wrapper_x64_systemv_native_patch_3:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_native_patch_3_end
raw_hook_wrapper_x64_systemv_native_patch_3_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_4
raw_hook_wrapper_x64_systemv_native_patch_4:
	mov qword ptr [rsp + 0x7fffffff], rdx
.globl raw_hook_wrapper_x64_systemv_native_patch_4_end
raw_hook_wrapper_x64_systemv_native_patch_4_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_5
raw_hook_wrapper_x64_systemv_native_patch_5:
	mov qword ptr [rsp + 0x7fffffff], rbx
.globl raw_hook_wrapper_x64_systemv_native_patch_5_end
raw_hook_wrapper_x64_systemv_native_patch_5_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_6
raw_hook_wrapper_x64_systemv_native_patch_6:
	mov qword ptr [rsp + 0x7fffffff], rsp
.globl raw_hook_wrapper_x64_systemv_native_patch_6_end
raw_hook_wrapper_x64_systemv_native_patch_6_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_7
raw_hook_wrapper_x64_systemv_native_patch_7:
	add qword ptr [rsp + 0x7fffffff], 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_native_patch_7_end
raw_hook_wrapper_x64_systemv_native_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_8
raw_hook_wrapper_x64_systemv_native_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rbp
.globl raw_hook_wrapper_x64_systemv_native_patch_8_end
raw_hook_wrapper_x64_systemv_native_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_9
raw_hook_wrapper_x64_systemv_native_patch_9:
	mov qword ptr [rsp + 0x7fffffff], rsi
.globl raw_hook_wrapper_x64_systemv_native_patch_9_end
raw_hook_wrapper_x64_systemv_native_patch_9_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_10
raw_hook_wrapper_x64_systemv_native_patch_10:
	mov qword ptr [rsp + 0x7fffffff], rdi
.globl raw_hook_wrapper_x64_systemv_native_patch_10_end
raw_hook_wrapper_x64_systemv_native_patch_10_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_11
raw_hook_wrapper_x64_systemv_native_patch_11:
	mov qword ptr [rsp + 0x7fffffff], r8
.globl raw_hook_wrapper_x64_systemv_native_patch_11_end
raw_hook_wrapper_x64_systemv_native_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_12
raw_hook_wrapper_x64_systemv_native_patch_12:
	mov qword ptr [rsp + 0x7fffffff], r9
.globl raw_hook_wrapper_x64_systemv_native_patch_12_end
raw_hook_wrapper_x64_systemv_native_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_13
raw_hook_wrapper_x64_systemv_native_patch_13:
	mov qword ptr [rsp + 0x7fffffff], r10
.globl raw_hook_wrapper_x64_systemv_native_patch_13_end
raw_hook_wrapper_x64_systemv_native_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_14
raw_hook_wrapper_x64_systemv_native_patch_14:
	mov qword ptr [rsp + 0x7fffffff], r11
.globl raw_hook_wrapper_x64_systemv_native_patch_14_end
raw_hook_wrapper_x64_systemv_native_patch_14_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_15
raw_hook_wrapper_x64_systemv_native_patch_15:
	mov qword ptr [rsp + 0x7fffffff], r12
.globl raw_hook_wrapper_x64_systemv_native_patch_15_end
raw_hook_wrapper_x64_systemv_native_patch_15_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_16
raw_hook_wrapper_x64_systemv_native_patch_16:
	mov qword ptr [rsp + 0x7fffffff], r13
.globl raw_hook_wrapper_x64_systemv_native_patch_16_end
raw_hook_wrapper_x64_systemv_native_patch_16_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_17
raw_hook_wrapper_x64_systemv_native_patch_17:
	mov qword ptr [rsp + 0x7fffffff], r14
.globl raw_hook_wrapper_x64_systemv_native_patch_17_end
raw_hook_wrapper_x64_systemv_native_patch_17_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_18
raw_hook_wrapper_x64_systemv_native_patch_18:
	mov qword ptr [rsp + 0x7fffffff], r15
.globl raw_hook_wrapper_x64_systemv_native_patch_18_end
raw_hook_wrapper_x64_systemv_native_patch_18_end:
	mov rax, rsp
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_0
raw_hook_wrapper_x64_systemv_native_cet_patch_0:
	add rax, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_0_end
raw_hook_wrapper_x64_systemv_native_cet_patch_0_end:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_1
raw_hook_wrapper_x64_systemv_native_cet_patch_1:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_1_end
raw_hook_wrapper_x64_systemv_native_cet_patch_1_end:
	mov rax, qword ptr [rax]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_2
raw_hook_wrapper_x64_systemv_native_cet_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_2_end
raw_hook_wrapper_x64_systemv_native_cet_patch_2_end:
	mov rdi, rsp
.globl raw_hook_wrapper_x64_systemv_native_patch_19
raw_hook_wrapper_x64_systemv_native_patch_19:
	mov rax, 0x7fffffffffffffff
.globl raw_hook_wrapper_x64_systemv_native_patch_19_end
raw_hook_wrapper_x64_systemv_native_patch_19_end:
	call rax
	test al, al
	je raw_hook_wrapper_x64_systemv_native_nothing_modified
.globl raw_hook_wrapper_x64_systemv_native_patch_21
raw_hook_wrapper_x64_systemv_native_patch_21:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_21_end
raw_hook_wrapper_x64_systemv_native_patch_21_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_22
raw_hook_wrapper_x64_systemv_native_patch_22:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_22_end
raw_hook_wrapper_x64_systemv_native_patch_22_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_23
raw_hook_wrapper_x64_systemv_native_patch_23:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_23_end
raw_hook_wrapper_x64_systemv_native_patch_23_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_24
raw_hook_wrapper_x64_systemv_native_patch_24:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_24_end
raw_hook_wrapper_x64_systemv_native_patch_24_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_25
raw_hook_wrapper_x64_systemv_native_patch_25:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_25_end
raw_hook_wrapper_x64_systemv_native_patch_25_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_26
raw_hook_wrapper_x64_systemv_native_patch_26:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_26_end
raw_hook_wrapper_x64_systemv_native_patch_26_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_27
raw_hook_wrapper_x64_systemv_native_patch_27:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_27_end
raw_hook_wrapper_x64_systemv_native_patch_27_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_28
raw_hook_wrapper_x64_systemv_native_patch_28:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_28_end
raw_hook_wrapper_x64_systemv_native_patch_28_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_29
raw_hook_wrapper_x64_systemv_native_patch_29:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_29_end
raw_hook_wrapper_x64_systemv_native_patch_29_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_30
raw_hook_wrapper_x64_systemv_native_patch_30:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_30_end
raw_hook_wrapper_x64_systemv_native_patch_30_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_31
raw_hook_wrapper_x64_systemv_native_patch_31:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_31_end
raw_hook_wrapper_x64_systemv_native_patch_31_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_32
raw_hook_wrapper_x64_systemv_native_patch_32:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_32_end
raw_hook_wrapper_x64_systemv_native_patch_32_end:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_3
raw_hook_wrapper_x64_systemv_native_cet_patch_3:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_3_end
raw_hook_wrapper_x64_systemv_native_cet_patch_3_end:
	test rax, 0x7
	jne raw_hook_wrapper_x64_systemv_native_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_4
raw_hook_wrapper_x64_systemv_native_cet_patch_4:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_4_end
raw_hook_wrapper_x64_systemv_native_cet_patch_4_end:
	cmp rax, rcx
	jb raw_hook_wrapper_x64_systemv_native_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_5
raw_hook_wrapper_x64_systemv_native_cet_patch_5:
	lea rcx, [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_5_end
raw_hook_wrapper_x64_systemv_native_cet_patch_5_end:
	cmp rax, rcx
	ja raw_hook_wrapper_x64_systemv_native_unsupported_stack
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_6
raw_hook_wrapper_x64_systemv_native_cet_patch_6:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_6_end
raw_hook_wrapper_x64_systemv_native_cet_patch_6_end:
	cmp qword ptr [rcx], rdx
	jne raw_hook_wrapper_x64_systemv_native_unsupported_stack
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_native_direct_return
	lea rax, [rax + 0x8]
	cmp rax, rcx
	je raw_hook_wrapper_x64_systemv_native_redirect_return
raw_hook_wrapper_x64_systemv_native_unsupported_stack:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_7
raw_hook_wrapper_x64_systemv_native_cet_patch_7:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_7_end
raw_hook_wrapper_x64_systemv_native_cet_patch_7_end:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_8
raw_hook_wrapper_x64_systemv_native_cet_patch_8:
	mov qword ptr [rsp + 0x7fffffff], rcx
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_8_end
raw_hook_wrapper_x64_systemv_native_cet_patch_8_end:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_9
raw_hook_wrapper_x64_systemv_native_cet_patch_9:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_9_end
raw_hook_wrapper_x64_systemv_native_cet_patch_9_end:
	mov qword ptr [rcx], rdx
raw_hook_wrapper_x64_systemv_native_direct_return:
.globl raw_hook_wrapper_x64_systemv_native_patch_20
raw_hook_wrapper_x64_systemv_native_patch_20:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_20_end
raw_hook_wrapper_x64_systemv_native_patch_20_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_native_patch_33
raw_hook_wrapper_x64_systemv_native_patch_33:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_33_end
raw_hook_wrapper_x64_systemv_native_patch_33_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_34
raw_hook_wrapper_x64_systemv_native_patch_34:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_34_end
raw_hook_wrapper_x64_systemv_native_patch_34_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_35
raw_hook_wrapper_x64_systemv_native_patch_35:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_35_end
raw_hook_wrapper_x64_systemv_native_patch_35_end:
.globl raw_hook_wrapper_x64_systemv_native_patch_36
raw_hook_wrapper_x64_systemv_native_patch_36:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_patch_36_end
raw_hook_wrapper_x64_systemv_native_patch_36_end:
	ret
raw_hook_wrapper_x64_systemv_native_redirect_return:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_10
raw_hook_wrapper_x64_systemv_native_cet_patch_10:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_10_end
raw_hook_wrapper_x64_systemv_native_cet_patch_10_end:
	popfq
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_11
raw_hook_wrapper_x64_systemv_native_cet_patch_11:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_11_end
raw_hook_wrapper_x64_systemv_native_cet_patch_11_end:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_12
raw_hook_wrapper_x64_systemv_native_cet_patch_12:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_12_end
raw_hook_wrapper_x64_systemv_native_cet_patch_12_end:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_13
raw_hook_wrapper_x64_systemv_native_cet_patch_13:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_13_end
raw_hook_wrapper_x64_systemv_native_cet_patch_13_end:
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_14
raw_hook_wrapper_x64_systemv_native_cet_patch_14:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_wrapper_x64_systemv_native_cet_patch_14_end
raw_hook_wrapper_x64_systemv_native_cet_patch_14_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]
raw_hook_wrapper_x64_systemv_native_nothing_modified:
.globl raw_hook_wrapper_x64_systemv_native_patch_37
raw_hook_wrapper_x64_systemv_native_patch_37:
	add rsp, 0x7fffffff
.globl raw_hook_wrapper_x64_systemv_native_patch_37_end
raw_hook_wrapper_x64_systemv_native_patch_37_end:

# RawHook restore: x64 AVX512FPU
.intel_syntax noprefix
.text
.globl raw_hook_restore_x64_avx512fpu
raw_hook_restore_x64_avx512fpu:
.globl raw_hook_restore_x64_avx512fpu_patch_0
raw_hook_restore_x64_avx512fpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_restore_x64_avx512fpu_patch_0_end
raw_hook_restore_x64_avx512fpu_patch_0_end:
.globl raw_hook_restore_x64_avx512fpu_patch_1
raw_hook_restore_x64_avx512fpu_patch_1:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_1_end
raw_hook_restore_x64_avx512fpu_patch_1_end:
	sub rax, 0x8
.globl raw_hook_restore_x64_avx512fpu_patch_2
raw_hook_restore_x64_avx512fpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_restore_x64_avx512fpu_patch_2_end
raw_hook_restore_x64_avx512fpu_patch_2_end:
.globl raw_hook_restore_x64_avx512fpu_patch_3
raw_hook_restore_x64_avx512fpu_patch_3:
	mov rdx, 0x7fffffffffffffff
.globl raw_hook_restore_x64_avx512fpu_patch_3_end
raw_hook_restore_x64_avx512fpu_patch_3_end:
	mov qword ptr [rax], rdx
.globl raw_hook_restore_x64_avx512fpu_patch_4
raw_hook_restore_x64_avx512fpu_patch_4:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_4_end
raw_hook_restore_x64_avx512fpu_patch_4_end:
.globl raw_hook_restore_x64_avx512fpu_patch_5
raw_hook_restore_x64_avx512fpu_patch_5:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_5_end
raw_hook_restore_x64_avx512fpu_patch_5_end:
.globl raw_hook_restore_x64_avx512fpu_patch_6
raw_hook_restore_x64_avx512fpu_patch_6:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_6_end
raw_hook_restore_x64_avx512fpu_patch_6_end:
.globl raw_hook_restore_x64_avx512fpu_patch_7
raw_hook_restore_x64_avx512fpu_patch_7:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_7_end
raw_hook_restore_x64_avx512fpu_patch_7_end:
.globl raw_hook_restore_x64_avx512fpu_patch_8
raw_hook_restore_x64_avx512fpu_patch_8:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_8_end
raw_hook_restore_x64_avx512fpu_patch_8_end:
.globl raw_hook_restore_x64_avx512fpu_patch_9
raw_hook_restore_x64_avx512fpu_patch_9:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_9_end
raw_hook_restore_x64_avx512fpu_patch_9_end:
.globl raw_hook_restore_x64_avx512fpu_patch_10
raw_hook_restore_x64_avx512fpu_patch_10:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_10_end
raw_hook_restore_x64_avx512fpu_patch_10_end:
.globl raw_hook_restore_x64_avx512fpu_patch_11
raw_hook_restore_x64_avx512fpu_patch_11:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_11_end
raw_hook_restore_x64_avx512fpu_patch_11_end:
.globl raw_hook_restore_x64_avx512fpu_patch_12
raw_hook_restore_x64_avx512fpu_patch_12:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_12_end
raw_hook_restore_x64_avx512fpu_patch_12_end:
.globl raw_hook_restore_x64_avx512fpu_patch_13
raw_hook_restore_x64_avx512fpu_patch_13:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_13_end
raw_hook_restore_x64_avx512fpu_patch_13_end:
.globl raw_hook_restore_x64_avx512fpu_patch_14
raw_hook_restore_x64_avx512fpu_patch_14:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_14_end
raw_hook_restore_x64_avx512fpu_patch_14_end:
.globl raw_hook_restore_x64_avx512fpu_patch_15
raw_hook_restore_x64_avx512fpu_patch_15:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_15_end
raw_hook_restore_x64_avx512fpu_patch_15_end:
.globl raw_hook_restore_x64_avx512fpu_patch_16
raw_hook_restore_x64_avx512fpu_patch_16:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_16_end
raw_hook_restore_x64_avx512fpu_patch_16_end:
.globl raw_hook_restore_x64_avx512fpu_patch_17
raw_hook_restore_x64_avx512fpu_patch_17:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_17_end
raw_hook_restore_x64_avx512fpu_patch_17_end:
.globl raw_hook_restore_x64_avx512fpu_patch_18
raw_hook_restore_x64_avx512fpu_patch_18:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_18_end
raw_hook_restore_x64_avx512fpu_patch_18_end:
.globl raw_hook_restore_x64_avx512fpu_patch_19
raw_hook_restore_x64_avx512fpu_patch_19:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_19_end
raw_hook_restore_x64_avx512fpu_patch_19_end:
.globl raw_hook_restore_x64_avx512fpu_patch_20
raw_hook_restore_x64_avx512fpu_patch_20:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_20_end
raw_hook_restore_x64_avx512fpu_patch_20_end:
.globl raw_hook_restore_x64_avx512fpu_patch_21
raw_hook_restore_x64_avx512fpu_patch_21:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_21_end
raw_hook_restore_x64_avx512fpu_patch_21_end:
.globl raw_hook_restore_x64_avx512fpu_patch_22
raw_hook_restore_x64_avx512fpu_patch_22:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_22_end
raw_hook_restore_x64_avx512fpu_patch_22_end:
.globl raw_hook_restore_x64_avx512fpu_patch_23
raw_hook_restore_x64_avx512fpu_patch_23:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_23_end
raw_hook_restore_x64_avx512fpu_patch_23_end:
.globl raw_hook_restore_x64_avx512fpu_patch_24
raw_hook_restore_x64_avx512fpu_patch_24:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_24_end
raw_hook_restore_x64_avx512fpu_patch_24_end:
.globl raw_hook_restore_x64_avx512fpu_patch_25
raw_hook_restore_x64_avx512fpu_patch_25:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_25_end
raw_hook_restore_x64_avx512fpu_patch_25_end:
.globl raw_hook_restore_x64_avx512fpu_patch_26
raw_hook_restore_x64_avx512fpu_patch_26:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_26_end
raw_hook_restore_x64_avx512fpu_patch_26_end:
.globl raw_hook_restore_x64_avx512fpu_patch_27
raw_hook_restore_x64_avx512fpu_patch_27:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_27_end
raw_hook_restore_x64_avx512fpu_patch_27_end:
.globl raw_hook_restore_x64_avx512fpu_patch_28
raw_hook_restore_x64_avx512fpu_patch_28:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_28_end
raw_hook_restore_x64_avx512fpu_patch_28_end:
.globl raw_hook_restore_x64_avx512fpu_patch_29
raw_hook_restore_x64_avx512fpu_patch_29:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_29_end
raw_hook_restore_x64_avx512fpu_patch_29_end:
.globl raw_hook_restore_x64_avx512fpu_patch_30
raw_hook_restore_x64_avx512fpu_patch_30:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_30_end
raw_hook_restore_x64_avx512fpu_patch_30_end:
.globl raw_hook_restore_x64_avx512fpu_patch_31
raw_hook_restore_x64_avx512fpu_patch_31:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_31_end
raw_hook_restore_x64_avx512fpu_patch_31_end:
.globl raw_hook_restore_x64_avx512fpu_patch_32
raw_hook_restore_x64_avx512fpu_patch_32:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_32_end
raw_hook_restore_x64_avx512fpu_patch_32_end:
.globl raw_hook_restore_x64_avx512fpu_patch_33
raw_hook_restore_x64_avx512fpu_patch_33:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_33_end
raw_hook_restore_x64_avx512fpu_patch_33_end:
.globl raw_hook_restore_x64_avx512fpu_patch_34
raw_hook_restore_x64_avx512fpu_patch_34:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_34_end
raw_hook_restore_x64_avx512fpu_patch_34_end:
.globl raw_hook_restore_x64_avx512fpu_patch_35
raw_hook_restore_x64_avx512fpu_patch_35:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_35_end
raw_hook_restore_x64_avx512fpu_patch_35_end:
.globl raw_hook_restore_x64_avx512fpu_patch_36
raw_hook_restore_x64_avx512fpu_patch_36:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_36_end
raw_hook_restore_x64_avx512fpu_patch_36_end:
.globl raw_hook_restore_x64_avx512fpu_patch_37
raw_hook_restore_x64_avx512fpu_patch_37:
	vmovups zmm0, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_37_end
raw_hook_restore_x64_avx512fpu_patch_37_end:
.globl raw_hook_restore_x64_avx512fpu_patch_38
raw_hook_restore_x64_avx512fpu_patch_38:
	vmovups zmm1, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_38_end
raw_hook_restore_x64_avx512fpu_patch_38_end:
.globl raw_hook_restore_x64_avx512fpu_patch_39
raw_hook_restore_x64_avx512fpu_patch_39:
	vmovups zmm2, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_39_end
raw_hook_restore_x64_avx512fpu_patch_39_end:
.globl raw_hook_restore_x64_avx512fpu_patch_40
raw_hook_restore_x64_avx512fpu_patch_40:
	vmovups zmm3, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_40_end
raw_hook_restore_x64_avx512fpu_patch_40_end:
.globl raw_hook_restore_x64_avx512fpu_patch_41
raw_hook_restore_x64_avx512fpu_patch_41:
	vmovups zmm4, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_41_end
raw_hook_restore_x64_avx512fpu_patch_41_end:
.globl raw_hook_restore_x64_avx512fpu_patch_42
raw_hook_restore_x64_avx512fpu_patch_42:
	vmovups zmm5, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_42_end
raw_hook_restore_x64_avx512fpu_patch_42_end:
.globl raw_hook_restore_x64_avx512fpu_patch_43
raw_hook_restore_x64_avx512fpu_patch_43:
	vmovups zmm6, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_43_end
raw_hook_restore_x64_avx512fpu_patch_43_end:
.globl raw_hook_restore_x64_avx512fpu_patch_44
raw_hook_restore_x64_avx512fpu_patch_44:
	vmovups zmm7, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_44_end
raw_hook_restore_x64_avx512fpu_patch_44_end:
.globl raw_hook_restore_x64_avx512fpu_patch_45
raw_hook_restore_x64_avx512fpu_patch_45:
	vmovups zmm8, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_45_end
raw_hook_restore_x64_avx512fpu_patch_45_end:
.globl raw_hook_restore_x64_avx512fpu_patch_46
raw_hook_restore_x64_avx512fpu_patch_46:
	vmovups zmm9, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_46_end
raw_hook_restore_x64_avx512fpu_patch_46_end:
.globl raw_hook_restore_x64_avx512fpu_patch_47
raw_hook_restore_x64_avx512fpu_patch_47:
	vmovups zmm10, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_47_end
raw_hook_restore_x64_avx512fpu_patch_47_end:
.globl raw_hook_restore_x64_avx512fpu_patch_48
raw_hook_restore_x64_avx512fpu_patch_48:
	vmovups zmm11, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_48_end
raw_hook_restore_x64_avx512fpu_patch_48_end:
.globl raw_hook_restore_x64_avx512fpu_patch_49
raw_hook_restore_x64_avx512fpu_patch_49:
	vmovups zmm12, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_49_end
raw_hook_restore_x64_avx512fpu_patch_49_end:
.globl raw_hook_restore_x64_avx512fpu_patch_50
raw_hook_restore_x64_avx512fpu_patch_50:
	vmovups zmm13, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_50_end
raw_hook_restore_x64_avx512fpu_patch_50_end:
.globl raw_hook_restore_x64_avx512fpu_patch_51
raw_hook_restore_x64_avx512fpu_patch_51:
	vmovups zmm14, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_51_end
raw_hook_restore_x64_avx512fpu_patch_51_end:
.globl raw_hook_restore_x64_avx512fpu_patch_52
raw_hook_restore_x64_avx512fpu_patch_52:
	vmovups zmm15, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_52_end
raw_hook_restore_x64_avx512fpu_patch_52_end:
.globl raw_hook_restore_x64_avx512fpu_patch_53
raw_hook_restore_x64_avx512fpu_patch_53:
	vmovups zmm16, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_53_end
raw_hook_restore_x64_avx512fpu_patch_53_end:
.globl raw_hook_restore_x64_avx512fpu_patch_54
raw_hook_restore_x64_avx512fpu_patch_54:
	vmovups zmm17, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_54_end
raw_hook_restore_x64_avx512fpu_patch_54_end:
.globl raw_hook_restore_x64_avx512fpu_patch_55
raw_hook_restore_x64_avx512fpu_patch_55:
	vmovups zmm18, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_55_end
raw_hook_restore_x64_avx512fpu_patch_55_end:
.globl raw_hook_restore_x64_avx512fpu_patch_56
raw_hook_restore_x64_avx512fpu_patch_56:
	vmovups zmm19, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_56_end
raw_hook_restore_x64_avx512fpu_patch_56_end:
.globl raw_hook_restore_x64_avx512fpu_patch_57
raw_hook_restore_x64_avx512fpu_patch_57:
	vmovups zmm20, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_57_end
raw_hook_restore_x64_avx512fpu_patch_57_end:
.globl raw_hook_restore_x64_avx512fpu_patch_58
raw_hook_restore_x64_avx512fpu_patch_58:
	vmovups zmm21, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_58_end
raw_hook_restore_x64_avx512fpu_patch_58_end:
.globl raw_hook_restore_x64_avx512fpu_patch_59
raw_hook_restore_x64_avx512fpu_patch_59:
	vmovups zmm22, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_59_end
raw_hook_restore_x64_avx512fpu_patch_59_end:
.globl raw_hook_restore_x64_avx512fpu_patch_60
raw_hook_restore_x64_avx512fpu_patch_60:
	vmovups zmm23, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_60_end
raw_hook_restore_x64_avx512fpu_patch_60_end:
.globl raw_hook_restore_x64_avx512fpu_patch_61
raw_hook_restore_x64_avx512fpu_patch_61:
	vmovups zmm24, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_61_end
raw_hook_restore_x64_avx512fpu_patch_61_end:
.globl raw_hook_restore_x64_avx512fpu_patch_62
raw_hook_restore_x64_avx512fpu_patch_62:
	vmovups zmm25, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_62_end
raw_hook_restore_x64_avx512fpu_patch_62_end:
.globl raw_hook_restore_x64_avx512fpu_patch_63
raw_hook_restore_x64_avx512fpu_patch_63:
	vmovups zmm26, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_63_end
raw_hook_restore_x64_avx512fpu_patch_63_end:
.globl raw_hook_restore_x64_avx512fpu_patch_64
raw_hook_restore_x64_avx512fpu_patch_64:
	vmovups zmm27, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_64_end
raw_hook_restore_x64_avx512fpu_patch_64_end:
.globl raw_hook_restore_x64_avx512fpu_patch_65
raw_hook_restore_x64_avx512fpu_patch_65:
	vmovups zmm28, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_65_end
raw_hook_restore_x64_avx512fpu_patch_65_end:
.globl raw_hook_restore_x64_avx512fpu_patch_66
raw_hook_restore_x64_avx512fpu_patch_66:
	vmovups zmm29, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_66_end
raw_hook_restore_x64_avx512fpu_patch_66_end:
.globl raw_hook_restore_x64_avx512fpu_patch_67
raw_hook_restore_x64_avx512fpu_patch_67:
	vmovups zmm30, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_67_end
raw_hook_restore_x64_avx512fpu_patch_67_end:
.globl raw_hook_restore_x64_avx512fpu_patch_68
raw_hook_restore_x64_avx512fpu_patch_68:
	vmovups zmm31, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_68_end
raw_hook_restore_x64_avx512fpu_patch_68_end:
.globl raw_hook_restore_x64_avx512fpu_patch_69
raw_hook_restore_x64_avx512fpu_patch_69:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_69_end
raw_hook_restore_x64_avx512fpu_patch_69_end:
.globl raw_hook_restore_x64_avx512fpu_patch_70
raw_hook_restore_x64_avx512fpu_patch_70:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_70_end
raw_hook_restore_x64_avx512fpu_patch_70_end:
	popfq
.globl raw_hook_restore_x64_avx512fpu_patch_71
raw_hook_restore_x64_avx512fpu_patch_71:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_71_end
raw_hook_restore_x64_avx512fpu_patch_71_end:
.globl raw_hook_restore_x64_avx512fpu_patch_72
raw_hook_restore_x64_avx512fpu_patch_72:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_72_end
raw_hook_restore_x64_avx512fpu_patch_72_end:
.globl raw_hook_restore_x64_avx512fpu_patch_73
raw_hook_restore_x64_avx512fpu_patch_73:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_73_end
raw_hook_restore_x64_avx512fpu_patch_73_end:
.globl raw_hook_restore_x64_avx512fpu_patch_74
raw_hook_restore_x64_avx512fpu_patch_74:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_74_end
raw_hook_restore_x64_avx512fpu_patch_74_end:
.globl raw_hook_restore_x64_avx512fpu_patch_75
raw_hook_restore_x64_avx512fpu_patch_75:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_75_end
raw_hook_restore_x64_avx512fpu_patch_75_end:
.globl raw_hook_restore_x64_avx512fpu_patch_76
raw_hook_restore_x64_avx512fpu_patch_76:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_76_end
raw_hook_restore_x64_avx512fpu_patch_76_end:
.globl raw_hook_restore_x64_avx512fpu_patch_77
raw_hook_restore_x64_avx512fpu_patch_77:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_77_end
raw_hook_restore_x64_avx512fpu_patch_77_end:
.globl raw_hook_restore_x64_avx512fpu_patch_78
raw_hook_restore_x64_avx512fpu_patch_78:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_78_end
raw_hook_restore_x64_avx512fpu_patch_78_end:
.globl raw_hook_restore_x64_avx512fpu_patch_79
raw_hook_restore_x64_avx512fpu_patch_79:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_79_end
raw_hook_restore_x64_avx512fpu_patch_79_end:
.globl raw_hook_restore_x64_avx512fpu_patch_80
raw_hook_restore_x64_avx512fpu_patch_80:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_80_end
raw_hook_restore_x64_avx512fpu_patch_80_end:
.globl raw_hook_restore_x64_avx512fpu_patch_81
raw_hook_restore_x64_avx512fpu_patch_81:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_81_end
raw_hook_restore_x64_avx512fpu_patch_81_end:
.globl raw_hook_restore_x64_avx512fpu_patch_82
raw_hook_restore_x64_avx512fpu_patch_82:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_82_end
raw_hook_restore_x64_avx512fpu_patch_82_end:
.globl raw_hook_restore_x64_avx512fpu_patch_83
raw_hook_restore_x64_avx512fpu_patch_83:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_83_end
raw_hook_restore_x64_avx512fpu_patch_83_end:
.globl raw_hook_restore_x64_avx512fpu_patch_84
raw_hook_restore_x64_avx512fpu_patch_84:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_84_end
raw_hook_restore_x64_avx512fpu_patch_84_end:
.globl raw_hook_restore_x64_avx512fpu_patch_85
raw_hook_restore_x64_avx512fpu_patch_85:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_85_end
raw_hook_restore_x64_avx512fpu_patch_85_end:
.globl raw_hook_restore_x64_avx512fpu_patch_86
raw_hook_restore_x64_avx512fpu_patch_86:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512fpu_patch_86_end
raw_hook_restore_x64_avx512fpu_patch_86_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]

# RawHook restore: x64 AVX512
.intel_syntax noprefix
.text
.globl raw_hook_restore_x64_avx512
raw_hook_restore_x64_avx512:
.globl raw_hook_restore_x64_avx512_patch_0
raw_hook_restore_x64_avx512_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_restore_x64_avx512_patch_0_end
raw_hook_restore_x64_avx512_patch_0_end:
.globl raw_hook_restore_x64_avx512_patch_1
raw_hook_restore_x64_avx512_patch_1:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_1_end
raw_hook_restore_x64_avx512_patch_1_end:
	sub rax, 0x8
.globl raw_hook_restore_x64_avx512_patch_2
raw_hook_restore_x64_avx512_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_restore_x64_avx512_patch_2_end
raw_hook_restore_x64_avx512_patch_2_end:
.globl raw_hook_restore_x64_avx512_patch_3
raw_hook_restore_x64_avx512_patch_3:
	mov rdx, 0x7fffffffffffffff
.globl raw_hook_restore_x64_avx512_patch_3_end
raw_hook_restore_x64_avx512_patch_3_end:
	mov qword ptr [rax], rdx
.globl raw_hook_restore_x64_avx512_patch_4
raw_hook_restore_x64_avx512_patch_4:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_4_end
raw_hook_restore_x64_avx512_patch_4_end:
.globl raw_hook_restore_x64_avx512_patch_5
raw_hook_restore_x64_avx512_patch_5:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_5_end
raw_hook_restore_x64_avx512_patch_5_end:
.globl raw_hook_restore_x64_avx512_patch_6
raw_hook_restore_x64_avx512_patch_6:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_6_end
raw_hook_restore_x64_avx512_patch_6_end:
.globl raw_hook_restore_x64_avx512_patch_7
raw_hook_restore_x64_avx512_patch_7:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_7_end
raw_hook_restore_x64_avx512_patch_7_end:
.globl raw_hook_restore_x64_avx512_patch_8
raw_hook_restore_x64_avx512_patch_8:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_8_end
raw_hook_restore_x64_avx512_patch_8_end:
.globl raw_hook_restore_x64_avx512_patch_9
raw_hook_restore_x64_avx512_patch_9:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_9_end
raw_hook_restore_x64_avx512_patch_9_end:
.globl raw_hook_restore_x64_avx512_patch_10
raw_hook_restore_x64_avx512_patch_10:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_10_end
raw_hook_restore_x64_avx512_patch_10_end:
.globl raw_hook_restore_x64_avx512_patch_11
raw_hook_restore_x64_avx512_patch_11:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_11_end
raw_hook_restore_x64_avx512_patch_11_end:
.globl raw_hook_restore_x64_avx512_patch_12
raw_hook_restore_x64_avx512_patch_12:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_12_end
raw_hook_restore_x64_avx512_patch_12_end:
.globl raw_hook_restore_x64_avx512_patch_13
raw_hook_restore_x64_avx512_patch_13:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_13_end
raw_hook_restore_x64_avx512_patch_13_end:
.globl raw_hook_restore_x64_avx512_patch_14
raw_hook_restore_x64_avx512_patch_14:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_14_end
raw_hook_restore_x64_avx512_patch_14_end:
.globl raw_hook_restore_x64_avx512_patch_15
raw_hook_restore_x64_avx512_patch_15:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_15_end
raw_hook_restore_x64_avx512_patch_15_end:
.globl raw_hook_restore_x64_avx512_patch_16
raw_hook_restore_x64_avx512_patch_16:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_16_end
raw_hook_restore_x64_avx512_patch_16_end:
.globl raw_hook_restore_x64_avx512_patch_17
raw_hook_restore_x64_avx512_patch_17:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_17_end
raw_hook_restore_x64_avx512_patch_17_end:
.globl raw_hook_restore_x64_avx512_patch_18
raw_hook_restore_x64_avx512_patch_18:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_18_end
raw_hook_restore_x64_avx512_patch_18_end:
.globl raw_hook_restore_x64_avx512_patch_19
raw_hook_restore_x64_avx512_patch_19:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_19_end
raw_hook_restore_x64_avx512_patch_19_end:
.globl raw_hook_restore_x64_avx512_patch_20
raw_hook_restore_x64_avx512_patch_20:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_20_end
raw_hook_restore_x64_avx512_patch_20_end:
.globl raw_hook_restore_x64_avx512_patch_21
raw_hook_restore_x64_avx512_patch_21:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_21_end
raw_hook_restore_x64_avx512_patch_21_end:
.globl raw_hook_restore_x64_avx512_patch_22
raw_hook_restore_x64_avx512_patch_22:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_22_end
raw_hook_restore_x64_avx512_patch_22_end:
.globl raw_hook_restore_x64_avx512_patch_23
raw_hook_restore_x64_avx512_patch_23:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_23_end
raw_hook_restore_x64_avx512_patch_23_end:
.globl raw_hook_restore_x64_avx512_patch_24
raw_hook_restore_x64_avx512_patch_24:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_24_end
raw_hook_restore_x64_avx512_patch_24_end:
.globl raw_hook_restore_x64_avx512_patch_25
raw_hook_restore_x64_avx512_patch_25:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_25_end
raw_hook_restore_x64_avx512_patch_25_end:
.globl raw_hook_restore_x64_avx512_patch_26
raw_hook_restore_x64_avx512_patch_26:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_26_end
raw_hook_restore_x64_avx512_patch_26_end:
.globl raw_hook_restore_x64_avx512_patch_27
raw_hook_restore_x64_avx512_patch_27:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_27_end
raw_hook_restore_x64_avx512_patch_27_end:
.globl raw_hook_restore_x64_avx512_patch_28
raw_hook_restore_x64_avx512_patch_28:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_28_end
raw_hook_restore_x64_avx512_patch_28_end:
.globl raw_hook_restore_x64_avx512_patch_29
raw_hook_restore_x64_avx512_patch_29:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_29_end
raw_hook_restore_x64_avx512_patch_29_end:
.globl raw_hook_restore_x64_avx512_patch_30
raw_hook_restore_x64_avx512_patch_30:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_30_end
raw_hook_restore_x64_avx512_patch_30_end:
.globl raw_hook_restore_x64_avx512_patch_31
raw_hook_restore_x64_avx512_patch_31:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_31_end
raw_hook_restore_x64_avx512_patch_31_end:
.globl raw_hook_restore_x64_avx512_patch_32
raw_hook_restore_x64_avx512_patch_32:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_32_end
raw_hook_restore_x64_avx512_patch_32_end:
.globl raw_hook_restore_x64_avx512_patch_33
raw_hook_restore_x64_avx512_patch_33:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_33_end
raw_hook_restore_x64_avx512_patch_33_end:
.globl raw_hook_restore_x64_avx512_patch_34
raw_hook_restore_x64_avx512_patch_34:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_34_end
raw_hook_restore_x64_avx512_patch_34_end:
.globl raw_hook_restore_x64_avx512_patch_35
raw_hook_restore_x64_avx512_patch_35:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_35_end
raw_hook_restore_x64_avx512_patch_35_end:
.globl raw_hook_restore_x64_avx512_patch_36
raw_hook_restore_x64_avx512_patch_36:
	vmovups zmm0, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_36_end
raw_hook_restore_x64_avx512_patch_36_end:
.globl raw_hook_restore_x64_avx512_patch_37
raw_hook_restore_x64_avx512_patch_37:
	vmovups zmm1, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_37_end
raw_hook_restore_x64_avx512_patch_37_end:
.globl raw_hook_restore_x64_avx512_patch_38
raw_hook_restore_x64_avx512_patch_38:
	vmovups zmm2, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_38_end
raw_hook_restore_x64_avx512_patch_38_end:
.globl raw_hook_restore_x64_avx512_patch_39
raw_hook_restore_x64_avx512_patch_39:
	vmovups zmm3, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_39_end
raw_hook_restore_x64_avx512_patch_39_end:
.globl raw_hook_restore_x64_avx512_patch_40
raw_hook_restore_x64_avx512_patch_40:
	vmovups zmm4, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_40_end
raw_hook_restore_x64_avx512_patch_40_end:
.globl raw_hook_restore_x64_avx512_patch_41
raw_hook_restore_x64_avx512_patch_41:
	vmovups zmm5, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_41_end
raw_hook_restore_x64_avx512_patch_41_end:
.globl raw_hook_restore_x64_avx512_patch_42
raw_hook_restore_x64_avx512_patch_42:
	vmovups zmm6, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_42_end
raw_hook_restore_x64_avx512_patch_42_end:
.globl raw_hook_restore_x64_avx512_patch_43
raw_hook_restore_x64_avx512_patch_43:
	vmovups zmm7, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_43_end
raw_hook_restore_x64_avx512_patch_43_end:
.globl raw_hook_restore_x64_avx512_patch_44
raw_hook_restore_x64_avx512_patch_44:
	vmovups zmm8, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_44_end
raw_hook_restore_x64_avx512_patch_44_end:
.globl raw_hook_restore_x64_avx512_patch_45
raw_hook_restore_x64_avx512_patch_45:
	vmovups zmm9, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_45_end
raw_hook_restore_x64_avx512_patch_45_end:
.globl raw_hook_restore_x64_avx512_patch_46
raw_hook_restore_x64_avx512_patch_46:
	vmovups zmm10, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_46_end
raw_hook_restore_x64_avx512_patch_46_end:
.globl raw_hook_restore_x64_avx512_patch_47
raw_hook_restore_x64_avx512_patch_47:
	vmovups zmm11, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_47_end
raw_hook_restore_x64_avx512_patch_47_end:
.globl raw_hook_restore_x64_avx512_patch_48
raw_hook_restore_x64_avx512_patch_48:
	vmovups zmm12, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_48_end
raw_hook_restore_x64_avx512_patch_48_end:
.globl raw_hook_restore_x64_avx512_patch_49
raw_hook_restore_x64_avx512_patch_49:
	vmovups zmm13, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_49_end
raw_hook_restore_x64_avx512_patch_49_end:
.globl raw_hook_restore_x64_avx512_patch_50
raw_hook_restore_x64_avx512_patch_50:
	vmovups zmm14, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_50_end
raw_hook_restore_x64_avx512_patch_50_end:
.globl raw_hook_restore_x64_avx512_patch_51
raw_hook_restore_x64_avx512_patch_51:
	vmovups zmm15, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_51_end
raw_hook_restore_x64_avx512_patch_51_end:
.globl raw_hook_restore_x64_avx512_patch_52
raw_hook_restore_x64_avx512_patch_52:
	vmovups zmm16, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_52_end
raw_hook_restore_x64_avx512_patch_52_end:
.globl raw_hook_restore_x64_avx512_patch_53
raw_hook_restore_x64_avx512_patch_53:
	vmovups zmm17, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_53_end
raw_hook_restore_x64_avx512_patch_53_end:
.globl raw_hook_restore_x64_avx512_patch_54
raw_hook_restore_x64_avx512_patch_54:
	vmovups zmm18, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_54_end
raw_hook_restore_x64_avx512_patch_54_end:
.globl raw_hook_restore_x64_avx512_patch_55
raw_hook_restore_x64_avx512_patch_55:
	vmovups zmm19, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_55_end
raw_hook_restore_x64_avx512_patch_55_end:
.globl raw_hook_restore_x64_avx512_patch_56
raw_hook_restore_x64_avx512_patch_56:
	vmovups zmm20, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_56_end
raw_hook_restore_x64_avx512_patch_56_end:
.globl raw_hook_restore_x64_avx512_patch_57
raw_hook_restore_x64_avx512_patch_57:
	vmovups zmm21, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_57_end
raw_hook_restore_x64_avx512_patch_57_end:
.globl raw_hook_restore_x64_avx512_patch_58
raw_hook_restore_x64_avx512_patch_58:
	vmovups zmm22, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_58_end
raw_hook_restore_x64_avx512_patch_58_end:
.globl raw_hook_restore_x64_avx512_patch_59
raw_hook_restore_x64_avx512_patch_59:
	vmovups zmm23, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_59_end
raw_hook_restore_x64_avx512_patch_59_end:
.globl raw_hook_restore_x64_avx512_patch_60
raw_hook_restore_x64_avx512_patch_60:
	vmovups zmm24, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_60_end
raw_hook_restore_x64_avx512_patch_60_end:
.globl raw_hook_restore_x64_avx512_patch_61
raw_hook_restore_x64_avx512_patch_61:
	vmovups zmm25, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_61_end
raw_hook_restore_x64_avx512_patch_61_end:
.globl raw_hook_restore_x64_avx512_patch_62
raw_hook_restore_x64_avx512_patch_62:
	vmovups zmm26, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_62_end
raw_hook_restore_x64_avx512_patch_62_end:
.globl raw_hook_restore_x64_avx512_patch_63
raw_hook_restore_x64_avx512_patch_63:
	vmovups zmm27, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_63_end
raw_hook_restore_x64_avx512_patch_63_end:
.globl raw_hook_restore_x64_avx512_patch_64
raw_hook_restore_x64_avx512_patch_64:
	vmovups zmm28, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_64_end
raw_hook_restore_x64_avx512_patch_64_end:
.globl raw_hook_restore_x64_avx512_patch_65
raw_hook_restore_x64_avx512_patch_65:
	vmovups zmm29, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_65_end
raw_hook_restore_x64_avx512_patch_65_end:
.globl raw_hook_restore_x64_avx512_patch_66
raw_hook_restore_x64_avx512_patch_66:
	vmovups zmm30, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_66_end
raw_hook_restore_x64_avx512_patch_66_end:
.globl raw_hook_restore_x64_avx512_patch_67
raw_hook_restore_x64_avx512_patch_67:
	vmovups zmm31, zmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_67_end
raw_hook_restore_x64_avx512_patch_67_end:
.globl raw_hook_restore_x64_avx512_patch_68
raw_hook_restore_x64_avx512_patch_68:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_68_end
raw_hook_restore_x64_avx512_patch_68_end:
.globl raw_hook_restore_x64_avx512_patch_69
raw_hook_restore_x64_avx512_patch_69:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_69_end
raw_hook_restore_x64_avx512_patch_69_end:
	popfq
.globl raw_hook_restore_x64_avx512_patch_70
raw_hook_restore_x64_avx512_patch_70:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_70_end
raw_hook_restore_x64_avx512_patch_70_end:
.globl raw_hook_restore_x64_avx512_patch_71
raw_hook_restore_x64_avx512_patch_71:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_71_end
raw_hook_restore_x64_avx512_patch_71_end:
.globl raw_hook_restore_x64_avx512_patch_72
raw_hook_restore_x64_avx512_patch_72:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_72_end
raw_hook_restore_x64_avx512_patch_72_end:
.globl raw_hook_restore_x64_avx512_patch_73
raw_hook_restore_x64_avx512_patch_73:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_73_end
raw_hook_restore_x64_avx512_patch_73_end:
.globl raw_hook_restore_x64_avx512_patch_74
raw_hook_restore_x64_avx512_patch_74:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_74_end
raw_hook_restore_x64_avx512_patch_74_end:
.globl raw_hook_restore_x64_avx512_patch_75
raw_hook_restore_x64_avx512_patch_75:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_75_end
raw_hook_restore_x64_avx512_patch_75_end:
.globl raw_hook_restore_x64_avx512_patch_76
raw_hook_restore_x64_avx512_patch_76:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_76_end
raw_hook_restore_x64_avx512_patch_76_end:
.globl raw_hook_restore_x64_avx512_patch_77
raw_hook_restore_x64_avx512_patch_77:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_77_end
raw_hook_restore_x64_avx512_patch_77_end:
.globl raw_hook_restore_x64_avx512_patch_78
raw_hook_restore_x64_avx512_patch_78:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_78_end
raw_hook_restore_x64_avx512_patch_78_end:
.globl raw_hook_restore_x64_avx512_patch_79
raw_hook_restore_x64_avx512_patch_79:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_79_end
raw_hook_restore_x64_avx512_patch_79_end:
.globl raw_hook_restore_x64_avx512_patch_80
raw_hook_restore_x64_avx512_patch_80:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_80_end
raw_hook_restore_x64_avx512_patch_80_end:
.globl raw_hook_restore_x64_avx512_patch_81
raw_hook_restore_x64_avx512_patch_81:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_81_end
raw_hook_restore_x64_avx512_patch_81_end:
.globl raw_hook_restore_x64_avx512_patch_82
raw_hook_restore_x64_avx512_patch_82:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_82_end
raw_hook_restore_x64_avx512_patch_82_end:
.globl raw_hook_restore_x64_avx512_patch_83
raw_hook_restore_x64_avx512_patch_83:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_83_end
raw_hook_restore_x64_avx512_patch_83_end:
.globl raw_hook_restore_x64_avx512_patch_84
raw_hook_restore_x64_avx512_patch_84:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_84_end
raw_hook_restore_x64_avx512_patch_84_end:
.globl raw_hook_restore_x64_avx512_patch_85
raw_hook_restore_x64_avx512_patch_85:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx512_patch_85_end
raw_hook_restore_x64_avx512_patch_85_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]

# RawHook restore: x64 AVXFPU
.intel_syntax noprefix
.text
.globl raw_hook_restore_x64_avxfpu
raw_hook_restore_x64_avxfpu:
.globl raw_hook_restore_x64_avxfpu_patch_0
raw_hook_restore_x64_avxfpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_restore_x64_avxfpu_patch_0_end
raw_hook_restore_x64_avxfpu_patch_0_end:
.globl raw_hook_restore_x64_avxfpu_patch_1
raw_hook_restore_x64_avxfpu_patch_1:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_1_end
raw_hook_restore_x64_avxfpu_patch_1_end:
	sub rax, 0x8
.globl raw_hook_restore_x64_avxfpu_patch_2
raw_hook_restore_x64_avxfpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_restore_x64_avxfpu_patch_2_end
raw_hook_restore_x64_avxfpu_patch_2_end:
.globl raw_hook_restore_x64_avxfpu_patch_3
raw_hook_restore_x64_avxfpu_patch_3:
	mov rdx, 0x7fffffffffffffff
.globl raw_hook_restore_x64_avxfpu_patch_3_end
raw_hook_restore_x64_avxfpu_patch_3_end:
	mov qword ptr [rax], rdx
.globl raw_hook_restore_x64_avxfpu_patch_4
raw_hook_restore_x64_avxfpu_patch_4:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_4_end
raw_hook_restore_x64_avxfpu_patch_4_end:
.globl raw_hook_restore_x64_avxfpu_patch_5
raw_hook_restore_x64_avxfpu_patch_5:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_5_end
raw_hook_restore_x64_avxfpu_patch_5_end:
.globl raw_hook_restore_x64_avxfpu_patch_6
raw_hook_restore_x64_avxfpu_patch_6:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_6_end
raw_hook_restore_x64_avxfpu_patch_6_end:
.globl raw_hook_restore_x64_avxfpu_patch_7
raw_hook_restore_x64_avxfpu_patch_7:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_7_end
raw_hook_restore_x64_avxfpu_patch_7_end:
.globl raw_hook_restore_x64_avxfpu_patch_8
raw_hook_restore_x64_avxfpu_patch_8:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_8_end
raw_hook_restore_x64_avxfpu_patch_8_end:
.globl raw_hook_restore_x64_avxfpu_patch_9
raw_hook_restore_x64_avxfpu_patch_9:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_9_end
raw_hook_restore_x64_avxfpu_patch_9_end:
.globl raw_hook_restore_x64_avxfpu_patch_10
raw_hook_restore_x64_avxfpu_patch_10:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_10_end
raw_hook_restore_x64_avxfpu_patch_10_end:
.globl raw_hook_restore_x64_avxfpu_patch_11
raw_hook_restore_x64_avxfpu_patch_11:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_11_end
raw_hook_restore_x64_avxfpu_patch_11_end:
.globl raw_hook_restore_x64_avxfpu_patch_12
raw_hook_restore_x64_avxfpu_patch_12:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_12_end
raw_hook_restore_x64_avxfpu_patch_12_end:
.globl raw_hook_restore_x64_avxfpu_patch_13
raw_hook_restore_x64_avxfpu_patch_13:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_13_end
raw_hook_restore_x64_avxfpu_patch_13_end:
.globl raw_hook_restore_x64_avxfpu_patch_14
raw_hook_restore_x64_avxfpu_patch_14:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_14_end
raw_hook_restore_x64_avxfpu_patch_14_end:
.globl raw_hook_restore_x64_avxfpu_patch_15
raw_hook_restore_x64_avxfpu_patch_15:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_15_end
raw_hook_restore_x64_avxfpu_patch_15_end:
.globl raw_hook_restore_x64_avxfpu_patch_16
raw_hook_restore_x64_avxfpu_patch_16:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_16_end
raw_hook_restore_x64_avxfpu_patch_16_end:
.globl raw_hook_restore_x64_avxfpu_patch_17
raw_hook_restore_x64_avxfpu_patch_17:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_17_end
raw_hook_restore_x64_avxfpu_patch_17_end:
.globl raw_hook_restore_x64_avxfpu_patch_18
raw_hook_restore_x64_avxfpu_patch_18:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_18_end
raw_hook_restore_x64_avxfpu_patch_18_end:
.globl raw_hook_restore_x64_avxfpu_patch_19
raw_hook_restore_x64_avxfpu_patch_19:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_19_end
raw_hook_restore_x64_avxfpu_patch_19_end:
.globl raw_hook_restore_x64_avxfpu_patch_20
raw_hook_restore_x64_avxfpu_patch_20:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_20_end
raw_hook_restore_x64_avxfpu_patch_20_end:
.globl raw_hook_restore_x64_avxfpu_patch_21
raw_hook_restore_x64_avxfpu_patch_21:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_21_end
raw_hook_restore_x64_avxfpu_patch_21_end:
.globl raw_hook_restore_x64_avxfpu_patch_22
raw_hook_restore_x64_avxfpu_patch_22:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_22_end
raw_hook_restore_x64_avxfpu_patch_22_end:
.globl raw_hook_restore_x64_avxfpu_patch_23
raw_hook_restore_x64_avxfpu_patch_23:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_23_end
raw_hook_restore_x64_avxfpu_patch_23_end:
.globl raw_hook_restore_x64_avxfpu_patch_24
raw_hook_restore_x64_avxfpu_patch_24:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_24_end
raw_hook_restore_x64_avxfpu_patch_24_end:
.globl raw_hook_restore_x64_avxfpu_patch_25
raw_hook_restore_x64_avxfpu_patch_25:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_25_end
raw_hook_restore_x64_avxfpu_patch_25_end:
.globl raw_hook_restore_x64_avxfpu_patch_26
raw_hook_restore_x64_avxfpu_patch_26:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_26_end
raw_hook_restore_x64_avxfpu_patch_26_end:
.globl raw_hook_restore_x64_avxfpu_patch_27
raw_hook_restore_x64_avxfpu_patch_27:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_27_end
raw_hook_restore_x64_avxfpu_patch_27_end:
.globl raw_hook_restore_x64_avxfpu_patch_28
raw_hook_restore_x64_avxfpu_patch_28:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_28_end
raw_hook_restore_x64_avxfpu_patch_28_end:
.globl raw_hook_restore_x64_avxfpu_patch_29
raw_hook_restore_x64_avxfpu_patch_29:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_29_end
raw_hook_restore_x64_avxfpu_patch_29_end:
.globl raw_hook_restore_x64_avxfpu_patch_30
raw_hook_restore_x64_avxfpu_patch_30:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_30_end
raw_hook_restore_x64_avxfpu_patch_30_end:
.globl raw_hook_restore_x64_avxfpu_patch_31
raw_hook_restore_x64_avxfpu_patch_31:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_31_end
raw_hook_restore_x64_avxfpu_patch_31_end:
.globl raw_hook_restore_x64_avxfpu_patch_32
raw_hook_restore_x64_avxfpu_patch_32:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_32_end
raw_hook_restore_x64_avxfpu_patch_32_end:
.globl raw_hook_restore_x64_avxfpu_patch_33
raw_hook_restore_x64_avxfpu_patch_33:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_33_end
raw_hook_restore_x64_avxfpu_patch_33_end:
.globl raw_hook_restore_x64_avxfpu_patch_34
raw_hook_restore_x64_avxfpu_patch_34:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_34_end
raw_hook_restore_x64_avxfpu_patch_34_end:
.globl raw_hook_restore_x64_avxfpu_patch_35
raw_hook_restore_x64_avxfpu_patch_35:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_35_end
raw_hook_restore_x64_avxfpu_patch_35_end:
.globl raw_hook_restore_x64_avxfpu_patch_36
raw_hook_restore_x64_avxfpu_patch_36:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_36_end
raw_hook_restore_x64_avxfpu_patch_36_end:
.globl raw_hook_restore_x64_avxfpu_patch_37
raw_hook_restore_x64_avxfpu_patch_37:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_37_end
raw_hook_restore_x64_avxfpu_patch_37_end:
.globl raw_hook_restore_x64_avxfpu_patch_38
raw_hook_restore_x64_avxfpu_patch_38:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_38_end
raw_hook_restore_x64_avxfpu_patch_38_end:
	popfq
.globl raw_hook_restore_x64_avxfpu_patch_39
raw_hook_restore_x64_avxfpu_patch_39:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_39_end
raw_hook_restore_x64_avxfpu_patch_39_end:
.globl raw_hook_restore_x64_avxfpu_patch_40
raw_hook_restore_x64_avxfpu_patch_40:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_40_end
raw_hook_restore_x64_avxfpu_patch_40_end:
.globl raw_hook_restore_x64_avxfpu_patch_41
raw_hook_restore_x64_avxfpu_patch_41:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_41_end
raw_hook_restore_x64_avxfpu_patch_41_end:
.globl raw_hook_restore_x64_avxfpu_patch_42
raw_hook_restore_x64_avxfpu_patch_42:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_42_end
raw_hook_restore_x64_avxfpu_patch_42_end:
.globl raw_hook_restore_x64_avxfpu_patch_43
raw_hook_restore_x64_avxfpu_patch_43:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_43_end
raw_hook_restore_x64_avxfpu_patch_43_end:
.globl raw_hook_restore_x64_avxfpu_patch_44
raw_hook_restore_x64_avxfpu_patch_44:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_44_end
raw_hook_restore_x64_avxfpu_patch_44_end:
.globl raw_hook_restore_x64_avxfpu_patch_45
raw_hook_restore_x64_avxfpu_patch_45:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_45_end
raw_hook_restore_x64_avxfpu_patch_45_end:
.globl raw_hook_restore_x64_avxfpu_patch_46
raw_hook_restore_x64_avxfpu_patch_46:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_46_end
raw_hook_restore_x64_avxfpu_patch_46_end:
.globl raw_hook_restore_x64_avxfpu_patch_47
raw_hook_restore_x64_avxfpu_patch_47:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_47_end
raw_hook_restore_x64_avxfpu_patch_47_end:
.globl raw_hook_restore_x64_avxfpu_patch_48
raw_hook_restore_x64_avxfpu_patch_48:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_48_end
raw_hook_restore_x64_avxfpu_patch_48_end:
.globl raw_hook_restore_x64_avxfpu_patch_49
raw_hook_restore_x64_avxfpu_patch_49:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_49_end
raw_hook_restore_x64_avxfpu_patch_49_end:
.globl raw_hook_restore_x64_avxfpu_patch_50
raw_hook_restore_x64_avxfpu_patch_50:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_50_end
raw_hook_restore_x64_avxfpu_patch_50_end:
.globl raw_hook_restore_x64_avxfpu_patch_51
raw_hook_restore_x64_avxfpu_patch_51:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_51_end
raw_hook_restore_x64_avxfpu_patch_51_end:
.globl raw_hook_restore_x64_avxfpu_patch_52
raw_hook_restore_x64_avxfpu_patch_52:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_52_end
raw_hook_restore_x64_avxfpu_patch_52_end:
.globl raw_hook_restore_x64_avxfpu_patch_53
raw_hook_restore_x64_avxfpu_patch_53:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_53_end
raw_hook_restore_x64_avxfpu_patch_53_end:
.globl raw_hook_restore_x64_avxfpu_patch_54
raw_hook_restore_x64_avxfpu_patch_54:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avxfpu_patch_54_end
raw_hook_restore_x64_avxfpu_patch_54_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]

# RawHook restore: x64 AVX
.intel_syntax noprefix
.text
.globl raw_hook_restore_x64_avx
raw_hook_restore_x64_avx:
.globl raw_hook_restore_x64_avx_patch_0
raw_hook_restore_x64_avx_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_restore_x64_avx_patch_0_end
raw_hook_restore_x64_avx_patch_0_end:
.globl raw_hook_restore_x64_avx_patch_1
raw_hook_restore_x64_avx_patch_1:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_1_end
raw_hook_restore_x64_avx_patch_1_end:
	sub rax, 0x8
.globl raw_hook_restore_x64_avx_patch_2
raw_hook_restore_x64_avx_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_restore_x64_avx_patch_2_end
raw_hook_restore_x64_avx_patch_2_end:
.globl raw_hook_restore_x64_avx_patch_3
raw_hook_restore_x64_avx_patch_3:
	mov rdx, 0x7fffffffffffffff
.globl raw_hook_restore_x64_avx_patch_3_end
raw_hook_restore_x64_avx_patch_3_end:
	mov qword ptr [rax], rdx
.globl raw_hook_restore_x64_avx_patch_4
raw_hook_restore_x64_avx_patch_4:
	vmovups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_4_end
raw_hook_restore_x64_avx_patch_4_end:
.globl raw_hook_restore_x64_avx_patch_5
raw_hook_restore_x64_avx_patch_5:
	vmovups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_5_end
raw_hook_restore_x64_avx_patch_5_end:
.globl raw_hook_restore_x64_avx_patch_6
raw_hook_restore_x64_avx_patch_6:
	vmovups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_6_end
raw_hook_restore_x64_avx_patch_6_end:
.globl raw_hook_restore_x64_avx_patch_7
raw_hook_restore_x64_avx_patch_7:
	vmovups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_7_end
raw_hook_restore_x64_avx_patch_7_end:
.globl raw_hook_restore_x64_avx_patch_8
raw_hook_restore_x64_avx_patch_8:
	vmovups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_8_end
raw_hook_restore_x64_avx_patch_8_end:
.globl raw_hook_restore_x64_avx_patch_9
raw_hook_restore_x64_avx_patch_9:
	vmovups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_9_end
raw_hook_restore_x64_avx_patch_9_end:
.globl raw_hook_restore_x64_avx_patch_10
raw_hook_restore_x64_avx_patch_10:
	vmovups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_10_end
raw_hook_restore_x64_avx_patch_10_end:
.globl raw_hook_restore_x64_avx_patch_11
raw_hook_restore_x64_avx_patch_11:
	vmovups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_11_end
raw_hook_restore_x64_avx_patch_11_end:
.globl raw_hook_restore_x64_avx_patch_12
raw_hook_restore_x64_avx_patch_12:
	vmovups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_12_end
raw_hook_restore_x64_avx_patch_12_end:
.globl raw_hook_restore_x64_avx_patch_13
raw_hook_restore_x64_avx_patch_13:
	vmovups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_13_end
raw_hook_restore_x64_avx_patch_13_end:
.globl raw_hook_restore_x64_avx_patch_14
raw_hook_restore_x64_avx_patch_14:
	vmovups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_14_end
raw_hook_restore_x64_avx_patch_14_end:
.globl raw_hook_restore_x64_avx_patch_15
raw_hook_restore_x64_avx_patch_15:
	vmovups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_15_end
raw_hook_restore_x64_avx_patch_15_end:
.globl raw_hook_restore_x64_avx_patch_16
raw_hook_restore_x64_avx_patch_16:
	vmovups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_16_end
raw_hook_restore_x64_avx_patch_16_end:
.globl raw_hook_restore_x64_avx_patch_17
raw_hook_restore_x64_avx_patch_17:
	vmovups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_17_end
raw_hook_restore_x64_avx_patch_17_end:
.globl raw_hook_restore_x64_avx_patch_18
raw_hook_restore_x64_avx_patch_18:
	vmovups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_18_end
raw_hook_restore_x64_avx_patch_18_end:
.globl raw_hook_restore_x64_avx_patch_19
raw_hook_restore_x64_avx_patch_19:
	vmovups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_19_end
raw_hook_restore_x64_avx_patch_19_end:
.globl raw_hook_restore_x64_avx_patch_20
raw_hook_restore_x64_avx_patch_20:
	vmovups ymm0, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_20_end
raw_hook_restore_x64_avx_patch_20_end:
.globl raw_hook_restore_x64_avx_patch_21
raw_hook_restore_x64_avx_patch_21:
	vmovups ymm1, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_21_end
raw_hook_restore_x64_avx_patch_21_end:
.globl raw_hook_restore_x64_avx_patch_22
raw_hook_restore_x64_avx_patch_22:
	vmovups ymm2, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_22_end
raw_hook_restore_x64_avx_patch_22_end:
.globl raw_hook_restore_x64_avx_patch_23
raw_hook_restore_x64_avx_patch_23:
	vmovups ymm3, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_23_end
raw_hook_restore_x64_avx_patch_23_end:
.globl raw_hook_restore_x64_avx_patch_24
raw_hook_restore_x64_avx_patch_24:
	vmovups ymm4, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_24_end
raw_hook_restore_x64_avx_patch_24_end:
.globl raw_hook_restore_x64_avx_patch_25
raw_hook_restore_x64_avx_patch_25:
	vmovups ymm5, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_25_end
raw_hook_restore_x64_avx_patch_25_end:
.globl raw_hook_restore_x64_avx_patch_26
raw_hook_restore_x64_avx_patch_26:
	vmovups ymm6, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_26_end
raw_hook_restore_x64_avx_patch_26_end:
.globl raw_hook_restore_x64_avx_patch_27
raw_hook_restore_x64_avx_patch_27:
	vmovups ymm7, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_27_end
raw_hook_restore_x64_avx_patch_27_end:
.globl raw_hook_restore_x64_avx_patch_28
raw_hook_restore_x64_avx_patch_28:
	vmovups ymm8, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_28_end
raw_hook_restore_x64_avx_patch_28_end:
.globl raw_hook_restore_x64_avx_patch_29
raw_hook_restore_x64_avx_patch_29:
	vmovups ymm9, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_29_end
raw_hook_restore_x64_avx_patch_29_end:
.globl raw_hook_restore_x64_avx_patch_30
raw_hook_restore_x64_avx_patch_30:
	vmovups ymm10, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_30_end
raw_hook_restore_x64_avx_patch_30_end:
.globl raw_hook_restore_x64_avx_patch_31
raw_hook_restore_x64_avx_patch_31:
	vmovups ymm11, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_31_end
raw_hook_restore_x64_avx_patch_31_end:
.globl raw_hook_restore_x64_avx_patch_32
raw_hook_restore_x64_avx_patch_32:
	vmovups ymm12, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_32_end
raw_hook_restore_x64_avx_patch_32_end:
.globl raw_hook_restore_x64_avx_patch_33
raw_hook_restore_x64_avx_patch_33:
	vmovups ymm13, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_33_end
raw_hook_restore_x64_avx_patch_33_end:
.globl raw_hook_restore_x64_avx_patch_34
raw_hook_restore_x64_avx_patch_34:
	vmovups ymm14, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_34_end
raw_hook_restore_x64_avx_patch_34_end:
.globl raw_hook_restore_x64_avx_patch_35
raw_hook_restore_x64_avx_patch_35:
	vmovups ymm15, ymmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_35_end
raw_hook_restore_x64_avx_patch_35_end:
.globl raw_hook_restore_x64_avx_patch_36
raw_hook_restore_x64_avx_patch_36:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_36_end
raw_hook_restore_x64_avx_patch_36_end:
.globl raw_hook_restore_x64_avx_patch_37
raw_hook_restore_x64_avx_patch_37:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_37_end
raw_hook_restore_x64_avx_patch_37_end:
	popfq
.globl raw_hook_restore_x64_avx_patch_38
raw_hook_restore_x64_avx_patch_38:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_38_end
raw_hook_restore_x64_avx_patch_38_end:
.globl raw_hook_restore_x64_avx_patch_39
raw_hook_restore_x64_avx_patch_39:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_39_end
raw_hook_restore_x64_avx_patch_39_end:
.globl raw_hook_restore_x64_avx_patch_40
raw_hook_restore_x64_avx_patch_40:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_40_end
raw_hook_restore_x64_avx_patch_40_end:
.globl raw_hook_restore_x64_avx_patch_41
raw_hook_restore_x64_avx_patch_41:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_41_end
raw_hook_restore_x64_avx_patch_41_end:
.globl raw_hook_restore_x64_avx_patch_42
raw_hook_restore_x64_avx_patch_42:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_42_end
raw_hook_restore_x64_avx_patch_42_end:
.globl raw_hook_restore_x64_avx_patch_43
raw_hook_restore_x64_avx_patch_43:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_43_end
raw_hook_restore_x64_avx_patch_43_end:
.globl raw_hook_restore_x64_avx_patch_44
raw_hook_restore_x64_avx_patch_44:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_44_end
raw_hook_restore_x64_avx_patch_44_end:
.globl raw_hook_restore_x64_avx_patch_45
raw_hook_restore_x64_avx_patch_45:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_45_end
raw_hook_restore_x64_avx_patch_45_end:
.globl raw_hook_restore_x64_avx_patch_46
raw_hook_restore_x64_avx_patch_46:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_46_end
raw_hook_restore_x64_avx_patch_46_end:
.globl raw_hook_restore_x64_avx_patch_47
raw_hook_restore_x64_avx_patch_47:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_47_end
raw_hook_restore_x64_avx_patch_47_end:
.globl raw_hook_restore_x64_avx_patch_48
raw_hook_restore_x64_avx_patch_48:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_48_end
raw_hook_restore_x64_avx_patch_48_end:
.globl raw_hook_restore_x64_avx_patch_49
raw_hook_restore_x64_avx_patch_49:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_49_end
raw_hook_restore_x64_avx_patch_49_end:
.globl raw_hook_restore_x64_avx_patch_50
raw_hook_restore_x64_avx_patch_50:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_50_end
raw_hook_restore_x64_avx_patch_50_end:
.globl raw_hook_restore_x64_avx_patch_51
raw_hook_restore_x64_avx_patch_51:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_51_end
raw_hook_restore_x64_avx_patch_51_end:
.globl raw_hook_restore_x64_avx_patch_52
raw_hook_restore_x64_avx_patch_52:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_52_end
raw_hook_restore_x64_avx_patch_52_end:
.globl raw_hook_restore_x64_avx_patch_53
raw_hook_restore_x64_avx_patch_53:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_avx_patch_53_end
raw_hook_restore_x64_avx_patch_53_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]

# RawHook restore: x64 SSEFPU
.intel_syntax noprefix
.text
.globl raw_hook_restore_x64_ssefpu
raw_hook_restore_x64_ssefpu:
.globl raw_hook_restore_x64_ssefpu_patch_0
raw_hook_restore_x64_ssefpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_restore_x64_ssefpu_patch_0_end
raw_hook_restore_x64_ssefpu_patch_0_end:
.globl raw_hook_restore_x64_ssefpu_patch_1
raw_hook_restore_x64_ssefpu_patch_1:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_1_end
raw_hook_restore_x64_ssefpu_patch_1_end:
	sub rax, 0x8
.globl raw_hook_restore_x64_ssefpu_patch_2
raw_hook_restore_x64_ssefpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_restore_x64_ssefpu_patch_2_end
raw_hook_restore_x64_ssefpu_patch_2_end:
.globl raw_hook_restore_x64_ssefpu_patch_3
raw_hook_restore_x64_ssefpu_patch_3:
	mov rdx, 0x7fffffffffffffff
.globl raw_hook_restore_x64_ssefpu_patch_3_end
raw_hook_restore_x64_ssefpu_patch_3_end:
	mov qword ptr [rax], rdx
.globl raw_hook_restore_x64_ssefpu_patch_4
raw_hook_restore_x64_ssefpu_patch_4:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_4_end
raw_hook_restore_x64_ssefpu_patch_4_end:
.globl raw_hook_restore_x64_ssefpu_patch_5
raw_hook_restore_x64_ssefpu_patch_5:
	movups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_5_end
raw_hook_restore_x64_ssefpu_patch_5_end:
.globl raw_hook_restore_x64_ssefpu_patch_6
raw_hook_restore_x64_ssefpu_patch_6:
	movups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_6_end
raw_hook_restore_x64_ssefpu_patch_6_end:
.globl raw_hook_restore_x64_ssefpu_patch_7
raw_hook_restore_x64_ssefpu_patch_7:
	movups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_7_end
raw_hook_restore_x64_ssefpu_patch_7_end:
.globl raw_hook_restore_x64_ssefpu_patch_8
raw_hook_restore_x64_ssefpu_patch_8:
	movups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_8_end
raw_hook_restore_x64_ssefpu_patch_8_end:
.globl raw_hook_restore_x64_ssefpu_patch_9
raw_hook_restore_x64_ssefpu_patch_9:
	movups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_9_end
raw_hook_restore_x64_ssefpu_patch_9_end:
.globl raw_hook_restore_x64_ssefpu_patch_10
raw_hook_restore_x64_ssefpu_patch_10:
	movups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_10_end
raw_hook_restore_x64_ssefpu_patch_10_end:
.globl raw_hook_restore_x64_ssefpu_patch_11
raw_hook_restore_x64_ssefpu_patch_11:
	movups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_11_end
raw_hook_restore_x64_ssefpu_patch_11_end:
.globl raw_hook_restore_x64_ssefpu_patch_12
raw_hook_restore_x64_ssefpu_patch_12:
	movups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_12_end
raw_hook_restore_x64_ssefpu_patch_12_end:
.globl raw_hook_restore_x64_ssefpu_patch_13
raw_hook_restore_x64_ssefpu_patch_13:
	movups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_13_end
raw_hook_restore_x64_ssefpu_patch_13_end:
.globl raw_hook_restore_x64_ssefpu_patch_14
raw_hook_restore_x64_ssefpu_patch_14:
	movups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_14_end
raw_hook_restore_x64_ssefpu_patch_14_end:
.globl raw_hook_restore_x64_ssefpu_patch_15
raw_hook_restore_x64_ssefpu_patch_15:
	movups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_15_end
raw_hook_restore_x64_ssefpu_patch_15_end:
.globl raw_hook_restore_x64_ssefpu_patch_16
raw_hook_restore_x64_ssefpu_patch_16:
	movups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_16_end
raw_hook_restore_x64_ssefpu_patch_16_end:
.globl raw_hook_restore_x64_ssefpu_patch_17
raw_hook_restore_x64_ssefpu_patch_17:
	movups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_17_end
raw_hook_restore_x64_ssefpu_patch_17_end:
.globl raw_hook_restore_x64_ssefpu_patch_18
raw_hook_restore_x64_ssefpu_patch_18:
	movups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_18_end
raw_hook_restore_x64_ssefpu_patch_18_end:
.globl raw_hook_restore_x64_ssefpu_patch_19
raw_hook_restore_x64_ssefpu_patch_19:
	movups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_19_end
raw_hook_restore_x64_ssefpu_patch_19_end:
.globl raw_hook_restore_x64_ssefpu_patch_20
raw_hook_restore_x64_ssefpu_patch_20:
	movups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_20_end
raw_hook_restore_x64_ssefpu_patch_20_end:
.globl raw_hook_restore_x64_ssefpu_patch_21
raw_hook_restore_x64_ssefpu_patch_21:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_21_end
raw_hook_restore_x64_ssefpu_patch_21_end:
.globl raw_hook_restore_x64_ssefpu_patch_22
raw_hook_restore_x64_ssefpu_patch_22:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_22_end
raw_hook_restore_x64_ssefpu_patch_22_end:
	popfq
.globl raw_hook_restore_x64_ssefpu_patch_23
raw_hook_restore_x64_ssefpu_patch_23:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_23_end
raw_hook_restore_x64_ssefpu_patch_23_end:
.globl raw_hook_restore_x64_ssefpu_patch_24
raw_hook_restore_x64_ssefpu_patch_24:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_24_end
raw_hook_restore_x64_ssefpu_patch_24_end:
.globl raw_hook_restore_x64_ssefpu_patch_25
raw_hook_restore_x64_ssefpu_patch_25:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_25_end
raw_hook_restore_x64_ssefpu_patch_25_end:
.globl raw_hook_restore_x64_ssefpu_patch_26
raw_hook_restore_x64_ssefpu_patch_26:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_26_end
raw_hook_restore_x64_ssefpu_patch_26_end:
.globl raw_hook_restore_x64_ssefpu_patch_27
raw_hook_restore_x64_ssefpu_patch_27:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_27_end
raw_hook_restore_x64_ssefpu_patch_27_end:
.globl raw_hook_restore_x64_ssefpu_patch_28
raw_hook_restore_x64_ssefpu_patch_28:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_28_end
raw_hook_restore_x64_ssefpu_patch_28_end:
.globl raw_hook_restore_x64_ssefpu_patch_29
raw_hook_restore_x64_ssefpu_patch_29:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_29_end
raw_hook_restore_x64_ssefpu_patch_29_end:
.globl raw_hook_restore_x64_ssefpu_patch_30
raw_hook_restore_x64_ssefpu_patch_30:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_30_end
raw_hook_restore_x64_ssefpu_patch_30_end:
.globl raw_hook_restore_x64_ssefpu_patch_31
raw_hook_restore_x64_ssefpu_patch_31:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_31_end
raw_hook_restore_x64_ssefpu_patch_31_end:
.globl raw_hook_restore_x64_ssefpu_patch_32
raw_hook_restore_x64_ssefpu_patch_32:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_32_end
raw_hook_restore_x64_ssefpu_patch_32_end:
.globl raw_hook_restore_x64_ssefpu_patch_33
raw_hook_restore_x64_ssefpu_patch_33:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_33_end
raw_hook_restore_x64_ssefpu_patch_33_end:
.globl raw_hook_restore_x64_ssefpu_patch_34
raw_hook_restore_x64_ssefpu_patch_34:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_34_end
raw_hook_restore_x64_ssefpu_patch_34_end:
.globl raw_hook_restore_x64_ssefpu_patch_35
raw_hook_restore_x64_ssefpu_patch_35:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_35_end
raw_hook_restore_x64_ssefpu_patch_35_end:
.globl raw_hook_restore_x64_ssefpu_patch_36
raw_hook_restore_x64_ssefpu_patch_36:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_36_end
raw_hook_restore_x64_ssefpu_patch_36_end:
.globl raw_hook_restore_x64_ssefpu_patch_37
raw_hook_restore_x64_ssefpu_patch_37:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_37_end
raw_hook_restore_x64_ssefpu_patch_37_end:
.globl raw_hook_restore_x64_ssefpu_patch_38
raw_hook_restore_x64_ssefpu_patch_38:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_ssefpu_patch_38_end
raw_hook_restore_x64_ssefpu_patch_38_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]

# RawHook restore: x64 SSE
.intel_syntax noprefix
.text
.globl raw_hook_restore_x64_sse
raw_hook_restore_x64_sse:
.globl raw_hook_restore_x64_sse_patch_0
raw_hook_restore_x64_sse_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_restore_x64_sse_patch_0_end
raw_hook_restore_x64_sse_patch_0_end:
.globl raw_hook_restore_x64_sse_patch_1
raw_hook_restore_x64_sse_patch_1:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_1_end
raw_hook_restore_x64_sse_patch_1_end:
	sub rax, 0x8
.globl raw_hook_restore_x64_sse_patch_2
raw_hook_restore_x64_sse_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_restore_x64_sse_patch_2_end
raw_hook_restore_x64_sse_patch_2_end:
.globl raw_hook_restore_x64_sse_patch_3
raw_hook_restore_x64_sse_patch_3:
	mov rdx, 0x7fffffffffffffff
.globl raw_hook_restore_x64_sse_patch_3_end
raw_hook_restore_x64_sse_patch_3_end:
	mov qword ptr [rax], rdx
.globl raw_hook_restore_x64_sse_patch_4
raw_hook_restore_x64_sse_patch_4:
	movups xmm0, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_4_end
raw_hook_restore_x64_sse_patch_4_end:
.globl raw_hook_restore_x64_sse_patch_5
raw_hook_restore_x64_sse_patch_5:
	movups xmm1, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_5_end
raw_hook_restore_x64_sse_patch_5_end:
.globl raw_hook_restore_x64_sse_patch_6
raw_hook_restore_x64_sse_patch_6:
	movups xmm2, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_6_end
raw_hook_restore_x64_sse_patch_6_end:
.globl raw_hook_restore_x64_sse_patch_7
raw_hook_restore_x64_sse_patch_7:
	movups xmm3, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_7_end
raw_hook_restore_x64_sse_patch_7_end:
.globl raw_hook_restore_x64_sse_patch_8
raw_hook_restore_x64_sse_patch_8:
	movups xmm4, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_8_end
raw_hook_restore_x64_sse_patch_8_end:
.globl raw_hook_restore_x64_sse_patch_9
raw_hook_restore_x64_sse_patch_9:
	movups xmm5, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_9_end
raw_hook_restore_x64_sse_patch_9_end:
.globl raw_hook_restore_x64_sse_patch_10
raw_hook_restore_x64_sse_patch_10:
	movups xmm6, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_10_end
raw_hook_restore_x64_sse_patch_10_end:
.globl raw_hook_restore_x64_sse_patch_11
raw_hook_restore_x64_sse_patch_11:
	movups xmm7, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_11_end
raw_hook_restore_x64_sse_patch_11_end:
.globl raw_hook_restore_x64_sse_patch_12
raw_hook_restore_x64_sse_patch_12:
	movups xmm8, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_12_end
raw_hook_restore_x64_sse_patch_12_end:
.globl raw_hook_restore_x64_sse_patch_13
raw_hook_restore_x64_sse_patch_13:
	movups xmm9, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_13_end
raw_hook_restore_x64_sse_patch_13_end:
.globl raw_hook_restore_x64_sse_patch_14
raw_hook_restore_x64_sse_patch_14:
	movups xmm10, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_14_end
raw_hook_restore_x64_sse_patch_14_end:
.globl raw_hook_restore_x64_sse_patch_15
raw_hook_restore_x64_sse_patch_15:
	movups xmm11, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_15_end
raw_hook_restore_x64_sse_patch_15_end:
.globl raw_hook_restore_x64_sse_patch_16
raw_hook_restore_x64_sse_patch_16:
	movups xmm12, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_16_end
raw_hook_restore_x64_sse_patch_16_end:
.globl raw_hook_restore_x64_sse_patch_17
raw_hook_restore_x64_sse_patch_17:
	movups xmm13, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_17_end
raw_hook_restore_x64_sse_patch_17_end:
.globl raw_hook_restore_x64_sse_patch_18
raw_hook_restore_x64_sse_patch_18:
	movups xmm14, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_18_end
raw_hook_restore_x64_sse_patch_18_end:
.globl raw_hook_restore_x64_sse_patch_19
raw_hook_restore_x64_sse_patch_19:
	movups xmm15, xmmword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_19_end
raw_hook_restore_x64_sse_patch_19_end:
.globl raw_hook_restore_x64_sse_patch_20
raw_hook_restore_x64_sse_patch_20:
	ldmxcsr dword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_20_end
raw_hook_restore_x64_sse_patch_20_end:
.globl raw_hook_restore_x64_sse_patch_21
raw_hook_restore_x64_sse_patch_21:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_21_end
raw_hook_restore_x64_sse_patch_21_end:
	popfq
.globl raw_hook_restore_x64_sse_patch_22
raw_hook_restore_x64_sse_patch_22:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_22_end
raw_hook_restore_x64_sse_patch_22_end:
.globl raw_hook_restore_x64_sse_patch_23
raw_hook_restore_x64_sse_patch_23:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_23_end
raw_hook_restore_x64_sse_patch_23_end:
.globl raw_hook_restore_x64_sse_patch_24
raw_hook_restore_x64_sse_patch_24:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_24_end
raw_hook_restore_x64_sse_patch_24_end:
.globl raw_hook_restore_x64_sse_patch_25
raw_hook_restore_x64_sse_patch_25:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_25_end
raw_hook_restore_x64_sse_patch_25_end:
.globl raw_hook_restore_x64_sse_patch_26
raw_hook_restore_x64_sse_patch_26:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_26_end
raw_hook_restore_x64_sse_patch_26_end:
.globl raw_hook_restore_x64_sse_patch_27
raw_hook_restore_x64_sse_patch_27:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_27_end
raw_hook_restore_x64_sse_patch_27_end:
.globl raw_hook_restore_x64_sse_patch_28
raw_hook_restore_x64_sse_patch_28:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_28_end
raw_hook_restore_x64_sse_patch_28_end:
.globl raw_hook_restore_x64_sse_patch_29
raw_hook_restore_x64_sse_patch_29:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_29_end
raw_hook_restore_x64_sse_patch_29_end:
.globl raw_hook_restore_x64_sse_patch_30
raw_hook_restore_x64_sse_patch_30:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_30_end
raw_hook_restore_x64_sse_patch_30_end:
.globl raw_hook_restore_x64_sse_patch_31
raw_hook_restore_x64_sse_patch_31:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_31_end
raw_hook_restore_x64_sse_patch_31_end:
.globl raw_hook_restore_x64_sse_patch_32
raw_hook_restore_x64_sse_patch_32:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_32_end
raw_hook_restore_x64_sse_patch_32_end:
.globl raw_hook_restore_x64_sse_patch_33
raw_hook_restore_x64_sse_patch_33:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_33_end
raw_hook_restore_x64_sse_patch_33_end:
.globl raw_hook_restore_x64_sse_patch_34
raw_hook_restore_x64_sse_patch_34:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_34_end
raw_hook_restore_x64_sse_patch_34_end:
.globl raw_hook_restore_x64_sse_patch_35
raw_hook_restore_x64_sse_patch_35:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_35_end
raw_hook_restore_x64_sse_patch_35_end:
.globl raw_hook_restore_x64_sse_patch_36
raw_hook_restore_x64_sse_patch_36:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_36_end
raw_hook_restore_x64_sse_patch_36_end:
.globl raw_hook_restore_x64_sse_patch_37
raw_hook_restore_x64_sse_patch_37:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_sse_patch_37_end
raw_hook_restore_x64_sse_patch_37_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]

# RawHook restore: x64 FPU
.intel_syntax noprefix
.text
.globl raw_hook_restore_x64_fpu
raw_hook_restore_x64_fpu:
.globl raw_hook_restore_x64_fpu_patch_0
raw_hook_restore_x64_fpu_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_restore_x64_fpu_patch_0_end
raw_hook_restore_x64_fpu_patch_0_end:
.globl raw_hook_restore_x64_fpu_patch_1
raw_hook_restore_x64_fpu_patch_1:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_1_end
raw_hook_restore_x64_fpu_patch_1_end:
	sub rax, 0x8
.globl raw_hook_restore_x64_fpu_patch_2
raw_hook_restore_x64_fpu_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_restore_x64_fpu_patch_2_end
raw_hook_restore_x64_fpu_patch_2_end:
.globl raw_hook_restore_x64_fpu_patch_3
raw_hook_restore_x64_fpu_patch_3:
	mov rdx, 0x7fffffffffffffff
.globl raw_hook_restore_x64_fpu_patch_3_end
raw_hook_restore_x64_fpu_patch_3_end:
	mov qword ptr [rax], rdx
.globl raw_hook_restore_x64_fpu_patch_4
raw_hook_restore_x64_fpu_patch_4:
	frstor [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_4_end
raw_hook_restore_x64_fpu_patch_4_end:
.globl raw_hook_restore_x64_fpu_patch_5
raw_hook_restore_x64_fpu_patch_5:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_5_end
raw_hook_restore_x64_fpu_patch_5_end:
	popfq
.globl raw_hook_restore_x64_fpu_patch_6
raw_hook_restore_x64_fpu_patch_6:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_6_end
raw_hook_restore_x64_fpu_patch_6_end:
.globl raw_hook_restore_x64_fpu_patch_7
raw_hook_restore_x64_fpu_patch_7:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_7_end
raw_hook_restore_x64_fpu_patch_7_end:
.globl raw_hook_restore_x64_fpu_patch_8
raw_hook_restore_x64_fpu_patch_8:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_8_end
raw_hook_restore_x64_fpu_patch_8_end:
.globl raw_hook_restore_x64_fpu_patch_9
raw_hook_restore_x64_fpu_patch_9:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_9_end
raw_hook_restore_x64_fpu_patch_9_end:
.globl raw_hook_restore_x64_fpu_patch_10
raw_hook_restore_x64_fpu_patch_10:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_10_end
raw_hook_restore_x64_fpu_patch_10_end:
.globl raw_hook_restore_x64_fpu_patch_11
raw_hook_restore_x64_fpu_patch_11:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_11_end
raw_hook_restore_x64_fpu_patch_11_end:
.globl raw_hook_restore_x64_fpu_patch_12
raw_hook_restore_x64_fpu_patch_12:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_12_end
raw_hook_restore_x64_fpu_patch_12_end:
.globl raw_hook_restore_x64_fpu_patch_13
raw_hook_restore_x64_fpu_patch_13:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_13_end
raw_hook_restore_x64_fpu_patch_13_end:
.globl raw_hook_restore_x64_fpu_patch_14
raw_hook_restore_x64_fpu_patch_14:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_14_end
raw_hook_restore_x64_fpu_patch_14_end:
.globl raw_hook_restore_x64_fpu_patch_15
raw_hook_restore_x64_fpu_patch_15:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_15_end
raw_hook_restore_x64_fpu_patch_15_end:
.globl raw_hook_restore_x64_fpu_patch_16
raw_hook_restore_x64_fpu_patch_16:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_16_end
raw_hook_restore_x64_fpu_patch_16_end:
.globl raw_hook_restore_x64_fpu_patch_17
raw_hook_restore_x64_fpu_patch_17:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_17_end
raw_hook_restore_x64_fpu_patch_17_end:
.globl raw_hook_restore_x64_fpu_patch_18
raw_hook_restore_x64_fpu_patch_18:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_18_end
raw_hook_restore_x64_fpu_patch_18_end:
.globl raw_hook_restore_x64_fpu_patch_19
raw_hook_restore_x64_fpu_patch_19:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_19_end
raw_hook_restore_x64_fpu_patch_19_end:
.globl raw_hook_restore_x64_fpu_patch_20
raw_hook_restore_x64_fpu_patch_20:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_20_end
raw_hook_restore_x64_fpu_patch_20_end:
.globl raw_hook_restore_x64_fpu_patch_21
raw_hook_restore_x64_fpu_patch_21:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_fpu_patch_21_end
raw_hook_restore_x64_fpu_patch_21_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]

# RawHook restore: x64 Native
.intel_syntax noprefix
.text
.globl raw_hook_restore_x64_native
raw_hook_restore_x64_native:
.globl raw_hook_restore_x64_native_patch_0
raw_hook_restore_x64_native_patch_0:
	sub rsp, 0x7fffffff
.globl raw_hook_restore_x64_native_patch_0_end
raw_hook_restore_x64_native_patch_0_end:
.globl raw_hook_restore_x64_native_patch_1
raw_hook_restore_x64_native_patch_1:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_1_end
raw_hook_restore_x64_native_patch_1_end:
	sub rax, 0x8
.globl raw_hook_restore_x64_native_patch_2
raw_hook_restore_x64_native_patch_2:
	mov qword ptr [rsp + 0x7fffffff], rax
.globl raw_hook_restore_x64_native_patch_2_end
raw_hook_restore_x64_native_patch_2_end:
.globl raw_hook_restore_x64_native_patch_3
raw_hook_restore_x64_native_patch_3:
	mov rdx, 0x7fffffffffffffff
.globl raw_hook_restore_x64_native_patch_3_end
raw_hook_restore_x64_native_patch_3_end:
	mov qword ptr [rax], rdx
.globl raw_hook_restore_x64_native_patch_4
raw_hook_restore_x64_native_patch_4:
	push qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_4_end
raw_hook_restore_x64_native_patch_4_end:
	popfq
.globl raw_hook_restore_x64_native_patch_5
raw_hook_restore_x64_native_patch_5:
	mov r15, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_5_end
raw_hook_restore_x64_native_patch_5_end:
.globl raw_hook_restore_x64_native_patch_6
raw_hook_restore_x64_native_patch_6:
	mov r14, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_6_end
raw_hook_restore_x64_native_patch_6_end:
.globl raw_hook_restore_x64_native_patch_7
raw_hook_restore_x64_native_patch_7:
	mov r13, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_7_end
raw_hook_restore_x64_native_patch_7_end:
.globl raw_hook_restore_x64_native_patch_8
raw_hook_restore_x64_native_patch_8:
	mov r12, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_8_end
raw_hook_restore_x64_native_patch_8_end:
.globl raw_hook_restore_x64_native_patch_9
raw_hook_restore_x64_native_patch_9:
	mov r11, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_9_end
raw_hook_restore_x64_native_patch_9_end:
.globl raw_hook_restore_x64_native_patch_10
raw_hook_restore_x64_native_patch_10:
	mov r10, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_10_end
raw_hook_restore_x64_native_patch_10_end:
.globl raw_hook_restore_x64_native_patch_11
raw_hook_restore_x64_native_patch_11:
	mov r9, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_11_end
raw_hook_restore_x64_native_patch_11_end:
.globl raw_hook_restore_x64_native_patch_12
raw_hook_restore_x64_native_patch_12:
	mov r8, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_12_end
raw_hook_restore_x64_native_patch_12_end:
.globl raw_hook_restore_x64_native_patch_13
raw_hook_restore_x64_native_patch_13:
	mov rdi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_13_end
raw_hook_restore_x64_native_patch_13_end:
.globl raw_hook_restore_x64_native_patch_14
raw_hook_restore_x64_native_patch_14:
	mov rsi, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_14_end
raw_hook_restore_x64_native_patch_14_end:
.globl raw_hook_restore_x64_native_patch_15
raw_hook_restore_x64_native_patch_15:
	mov rbp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_15_end
raw_hook_restore_x64_native_patch_15_end:
.globl raw_hook_restore_x64_native_patch_16
raw_hook_restore_x64_native_patch_16:
	mov rbx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_16_end
raw_hook_restore_x64_native_patch_16_end:
.globl raw_hook_restore_x64_native_patch_17
raw_hook_restore_x64_native_patch_17:
	mov rdx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_17_end
raw_hook_restore_x64_native_patch_17_end:
.globl raw_hook_restore_x64_native_patch_18
raw_hook_restore_x64_native_patch_18:
	mov rcx, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_18_end
raw_hook_restore_x64_native_patch_18_end:
.globl raw_hook_restore_x64_native_patch_19
raw_hook_restore_x64_native_patch_19:
	mov rax, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_19_end
raw_hook_restore_x64_native_patch_19_end:
.globl raw_hook_restore_x64_native_patch_20
raw_hook_restore_x64_native_patch_20:
	mov rsp, qword ptr [rsp + 0x7fffffff]
.globl raw_hook_restore_x64_native_patch_20_end
raw_hook_restore_x64_native_patch_20_end:
	lea rsp, [rsp + 0x8]
	jmp qword ptr [rsp - 0x8]

# GetCurrentContext: x64 windows AVX512FPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_windows_avx512fpu
raw_get_current_context_x64_windows_avx512fpu:
	pushfq
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
	mov r11, qword ptr [rsp + 0x68]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_0
raw_get_current_context_x64_windows_avx512fpu_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_0_end
raw_get_current_context_x64_windows_avx512fpu_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_1
raw_get_current_context_x64_windows_avx512fpu_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_1_end
raw_get_current_context_x64_windows_avx512fpu_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_2
raw_get_current_context_x64_windows_avx512fpu_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_2_end
raw_get_current_context_x64_windows_avx512fpu_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_3
raw_get_current_context_x64_windows_avx512fpu_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_3_end
raw_get_current_context_x64_windows_avx512fpu_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_4
raw_get_current_context_x64_windows_avx512fpu_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_4_end
raw_get_current_context_x64_windows_avx512fpu_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_5
raw_get_current_context_x64_windows_avx512fpu_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_5_end
raw_get_current_context_x64_windows_avx512fpu_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_6
raw_get_current_context_x64_windows_avx512fpu_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_6_end
raw_get_current_context_x64_windows_avx512fpu_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_7
raw_get_current_context_x64_windows_avx512fpu_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_7_end
raw_get_current_context_x64_windows_avx512fpu_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_8
raw_get_current_context_x64_windows_avx512fpu_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_8_end
raw_get_current_context_x64_windows_avx512fpu_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_9
raw_get_current_context_x64_windows_avx512fpu_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_9_end
raw_get_current_context_x64_windows_avx512fpu_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_10
raw_get_current_context_x64_windows_avx512fpu_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_10_end
raw_get_current_context_x64_windows_avx512fpu_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_11
raw_get_current_context_x64_windows_avx512fpu_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_11_end
raw_get_current_context_x64_windows_avx512fpu_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_12
raw_get_current_context_x64_windows_avx512fpu_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_12_end
raw_get_current_context_x64_windows_avx512fpu_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_13
raw_get_current_context_x64_windows_avx512fpu_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_13_end
raw_get_current_context_x64_windows_avx512fpu_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_14
raw_get_current_context_x64_windows_avx512fpu_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_14_end
raw_get_current_context_x64_windows_avx512fpu_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_15
raw_get_current_context_x64_windows_avx512fpu_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_15_end
raw_get_current_context_x64_windows_avx512fpu_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_16
raw_get_current_context_x64_windows_avx512fpu_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_16_end
raw_get_current_context_x64_windows_avx512fpu_patch_16_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_17
raw_get_current_context_x64_windows_avx512fpu_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_17_end
raw_get_current_context_x64_windows_avx512fpu_patch_17_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_18
raw_get_current_context_x64_windows_avx512fpu_patch_18:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_windows_avx512fpu_patch_18_end
raw_get_current_context_x64_windows_avx512fpu_patch_18_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_19
raw_get_current_context_x64_windows_avx512fpu_patch_19:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_windows_avx512fpu_patch_19_end
raw_get_current_context_x64_windows_avx512fpu_patch_19_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_20
raw_get_current_context_x64_windows_avx512fpu_patch_20:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_windows_avx512fpu_patch_20_end
raw_get_current_context_x64_windows_avx512fpu_patch_20_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_21
raw_get_current_context_x64_windows_avx512fpu_patch_21:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_windows_avx512fpu_patch_21_end
raw_get_current_context_x64_windows_avx512fpu_patch_21_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_22
raw_get_current_context_x64_windows_avx512fpu_patch_22:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_windows_avx512fpu_patch_22_end
raw_get_current_context_x64_windows_avx512fpu_patch_22_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_23
raw_get_current_context_x64_windows_avx512fpu_patch_23:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_windows_avx512fpu_patch_23_end
raw_get_current_context_x64_windows_avx512fpu_patch_23_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_24
raw_get_current_context_x64_windows_avx512fpu_patch_24:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_windows_avx512fpu_patch_24_end
raw_get_current_context_x64_windows_avx512fpu_patch_24_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_25
raw_get_current_context_x64_windows_avx512fpu_patch_25:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_windows_avx512fpu_patch_25_end
raw_get_current_context_x64_windows_avx512fpu_patch_25_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_26
raw_get_current_context_x64_windows_avx512fpu_patch_26:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_windows_avx512fpu_patch_26_end
raw_get_current_context_x64_windows_avx512fpu_patch_26_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_27
raw_get_current_context_x64_windows_avx512fpu_patch_27:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_windows_avx512fpu_patch_27_end
raw_get_current_context_x64_windows_avx512fpu_patch_27_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_28
raw_get_current_context_x64_windows_avx512fpu_patch_28:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_28_end
raw_get_current_context_x64_windows_avx512fpu_patch_28_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_29
raw_get_current_context_x64_windows_avx512fpu_patch_29:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_windows_avx512fpu_patch_29_end
raw_get_current_context_x64_windows_avx512fpu_patch_29_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_30
raw_get_current_context_x64_windows_avx512fpu_patch_30:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_windows_avx512fpu_patch_30_end
raw_get_current_context_x64_windows_avx512fpu_patch_30_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_31
raw_get_current_context_x64_windows_avx512fpu_patch_31:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_windows_avx512fpu_patch_31_end
raw_get_current_context_x64_windows_avx512fpu_patch_31_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_32
raw_get_current_context_x64_windows_avx512fpu_patch_32:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_windows_avx512fpu_patch_32_end
raw_get_current_context_x64_windows_avx512fpu_patch_32_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_33
raw_get_current_context_x64_windows_avx512fpu_patch_33:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_windows_avx512fpu_patch_33_end
raw_get_current_context_x64_windows_avx512fpu_patch_33_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_34
raw_get_current_context_x64_windows_avx512fpu_patch_34:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm0
.globl raw_get_current_context_x64_windows_avx512fpu_patch_34_end
raw_get_current_context_x64_windows_avx512fpu_patch_34_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_35
raw_get_current_context_x64_windows_avx512fpu_patch_35:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm1
.globl raw_get_current_context_x64_windows_avx512fpu_patch_35_end
raw_get_current_context_x64_windows_avx512fpu_patch_35_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_36
raw_get_current_context_x64_windows_avx512fpu_patch_36:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm2
.globl raw_get_current_context_x64_windows_avx512fpu_patch_36_end
raw_get_current_context_x64_windows_avx512fpu_patch_36_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_37
raw_get_current_context_x64_windows_avx512fpu_patch_37:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm3
.globl raw_get_current_context_x64_windows_avx512fpu_patch_37_end
raw_get_current_context_x64_windows_avx512fpu_patch_37_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_38
raw_get_current_context_x64_windows_avx512fpu_patch_38:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm4
.globl raw_get_current_context_x64_windows_avx512fpu_patch_38_end
raw_get_current_context_x64_windows_avx512fpu_patch_38_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_39
raw_get_current_context_x64_windows_avx512fpu_patch_39:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm5
.globl raw_get_current_context_x64_windows_avx512fpu_patch_39_end
raw_get_current_context_x64_windows_avx512fpu_patch_39_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_40
raw_get_current_context_x64_windows_avx512fpu_patch_40:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm6
.globl raw_get_current_context_x64_windows_avx512fpu_patch_40_end
raw_get_current_context_x64_windows_avx512fpu_patch_40_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_41
raw_get_current_context_x64_windows_avx512fpu_patch_41:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm7
.globl raw_get_current_context_x64_windows_avx512fpu_patch_41_end
raw_get_current_context_x64_windows_avx512fpu_patch_41_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_42
raw_get_current_context_x64_windows_avx512fpu_patch_42:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm8
.globl raw_get_current_context_x64_windows_avx512fpu_patch_42_end
raw_get_current_context_x64_windows_avx512fpu_patch_42_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_43
raw_get_current_context_x64_windows_avx512fpu_patch_43:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm9
.globl raw_get_current_context_x64_windows_avx512fpu_patch_43_end
raw_get_current_context_x64_windows_avx512fpu_patch_43_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_44
raw_get_current_context_x64_windows_avx512fpu_patch_44:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_44_end
raw_get_current_context_x64_windows_avx512fpu_patch_44_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_45
raw_get_current_context_x64_windows_avx512fpu_patch_45:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm11
.globl raw_get_current_context_x64_windows_avx512fpu_patch_45_end
raw_get_current_context_x64_windows_avx512fpu_patch_45_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_46
raw_get_current_context_x64_windows_avx512fpu_patch_46:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm12
.globl raw_get_current_context_x64_windows_avx512fpu_patch_46_end
raw_get_current_context_x64_windows_avx512fpu_patch_46_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_47
raw_get_current_context_x64_windows_avx512fpu_patch_47:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm13
.globl raw_get_current_context_x64_windows_avx512fpu_patch_47_end
raw_get_current_context_x64_windows_avx512fpu_patch_47_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_48
raw_get_current_context_x64_windows_avx512fpu_patch_48:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm14
.globl raw_get_current_context_x64_windows_avx512fpu_patch_48_end
raw_get_current_context_x64_windows_avx512fpu_patch_48_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_49
raw_get_current_context_x64_windows_avx512fpu_patch_49:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm15
.globl raw_get_current_context_x64_windows_avx512fpu_patch_49_end
raw_get_current_context_x64_windows_avx512fpu_patch_49_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_50
raw_get_current_context_x64_windows_avx512fpu_patch_50:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm0
.globl raw_get_current_context_x64_windows_avx512fpu_patch_50_end
raw_get_current_context_x64_windows_avx512fpu_patch_50_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_51
raw_get_current_context_x64_windows_avx512fpu_patch_51:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm1
.globl raw_get_current_context_x64_windows_avx512fpu_patch_51_end
raw_get_current_context_x64_windows_avx512fpu_patch_51_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_52
raw_get_current_context_x64_windows_avx512fpu_patch_52:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm2
.globl raw_get_current_context_x64_windows_avx512fpu_patch_52_end
raw_get_current_context_x64_windows_avx512fpu_patch_52_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_53
raw_get_current_context_x64_windows_avx512fpu_patch_53:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm3
.globl raw_get_current_context_x64_windows_avx512fpu_patch_53_end
raw_get_current_context_x64_windows_avx512fpu_patch_53_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_54
raw_get_current_context_x64_windows_avx512fpu_patch_54:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm4
.globl raw_get_current_context_x64_windows_avx512fpu_patch_54_end
raw_get_current_context_x64_windows_avx512fpu_patch_54_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_55
raw_get_current_context_x64_windows_avx512fpu_patch_55:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm5
.globl raw_get_current_context_x64_windows_avx512fpu_patch_55_end
raw_get_current_context_x64_windows_avx512fpu_patch_55_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_56
raw_get_current_context_x64_windows_avx512fpu_patch_56:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm6
.globl raw_get_current_context_x64_windows_avx512fpu_patch_56_end
raw_get_current_context_x64_windows_avx512fpu_patch_56_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_57
raw_get_current_context_x64_windows_avx512fpu_patch_57:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm7
.globl raw_get_current_context_x64_windows_avx512fpu_patch_57_end
raw_get_current_context_x64_windows_avx512fpu_patch_57_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_58
raw_get_current_context_x64_windows_avx512fpu_patch_58:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm8
.globl raw_get_current_context_x64_windows_avx512fpu_patch_58_end
raw_get_current_context_x64_windows_avx512fpu_patch_58_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_59
raw_get_current_context_x64_windows_avx512fpu_patch_59:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm9
.globl raw_get_current_context_x64_windows_avx512fpu_patch_59_end
raw_get_current_context_x64_windows_avx512fpu_patch_59_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_60
raw_get_current_context_x64_windows_avx512fpu_patch_60:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm10
.globl raw_get_current_context_x64_windows_avx512fpu_patch_60_end
raw_get_current_context_x64_windows_avx512fpu_patch_60_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_61
raw_get_current_context_x64_windows_avx512fpu_patch_61:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm11
.globl raw_get_current_context_x64_windows_avx512fpu_patch_61_end
raw_get_current_context_x64_windows_avx512fpu_patch_61_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_62
raw_get_current_context_x64_windows_avx512fpu_patch_62:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm12
.globl raw_get_current_context_x64_windows_avx512fpu_patch_62_end
raw_get_current_context_x64_windows_avx512fpu_patch_62_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_63
raw_get_current_context_x64_windows_avx512fpu_patch_63:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm13
.globl raw_get_current_context_x64_windows_avx512fpu_patch_63_end
raw_get_current_context_x64_windows_avx512fpu_patch_63_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_64
raw_get_current_context_x64_windows_avx512fpu_patch_64:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm14
.globl raw_get_current_context_x64_windows_avx512fpu_patch_64_end
raw_get_current_context_x64_windows_avx512fpu_patch_64_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_65
raw_get_current_context_x64_windows_avx512fpu_patch_65:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm15
.globl raw_get_current_context_x64_windows_avx512fpu_patch_65_end
raw_get_current_context_x64_windows_avx512fpu_patch_65_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_66
raw_get_current_context_x64_windows_avx512fpu_patch_66:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm16
.globl raw_get_current_context_x64_windows_avx512fpu_patch_66_end
raw_get_current_context_x64_windows_avx512fpu_patch_66_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_67
raw_get_current_context_x64_windows_avx512fpu_patch_67:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm17
.globl raw_get_current_context_x64_windows_avx512fpu_patch_67_end
raw_get_current_context_x64_windows_avx512fpu_patch_67_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_68
raw_get_current_context_x64_windows_avx512fpu_patch_68:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm18
.globl raw_get_current_context_x64_windows_avx512fpu_patch_68_end
raw_get_current_context_x64_windows_avx512fpu_patch_68_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_69
raw_get_current_context_x64_windows_avx512fpu_patch_69:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm19
.globl raw_get_current_context_x64_windows_avx512fpu_patch_69_end
raw_get_current_context_x64_windows_avx512fpu_patch_69_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_70
raw_get_current_context_x64_windows_avx512fpu_patch_70:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm20
.globl raw_get_current_context_x64_windows_avx512fpu_patch_70_end
raw_get_current_context_x64_windows_avx512fpu_patch_70_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_71
raw_get_current_context_x64_windows_avx512fpu_patch_71:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm21
.globl raw_get_current_context_x64_windows_avx512fpu_patch_71_end
raw_get_current_context_x64_windows_avx512fpu_patch_71_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_72
raw_get_current_context_x64_windows_avx512fpu_patch_72:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm22
.globl raw_get_current_context_x64_windows_avx512fpu_patch_72_end
raw_get_current_context_x64_windows_avx512fpu_patch_72_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_73
raw_get_current_context_x64_windows_avx512fpu_patch_73:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm23
.globl raw_get_current_context_x64_windows_avx512fpu_patch_73_end
raw_get_current_context_x64_windows_avx512fpu_patch_73_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_74
raw_get_current_context_x64_windows_avx512fpu_patch_74:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm24
.globl raw_get_current_context_x64_windows_avx512fpu_patch_74_end
raw_get_current_context_x64_windows_avx512fpu_patch_74_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_75
raw_get_current_context_x64_windows_avx512fpu_patch_75:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm25
.globl raw_get_current_context_x64_windows_avx512fpu_patch_75_end
raw_get_current_context_x64_windows_avx512fpu_patch_75_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_76
raw_get_current_context_x64_windows_avx512fpu_patch_76:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm26
.globl raw_get_current_context_x64_windows_avx512fpu_patch_76_end
raw_get_current_context_x64_windows_avx512fpu_patch_76_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_77
raw_get_current_context_x64_windows_avx512fpu_patch_77:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm27
.globl raw_get_current_context_x64_windows_avx512fpu_patch_77_end
raw_get_current_context_x64_windows_avx512fpu_patch_77_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_78
raw_get_current_context_x64_windows_avx512fpu_patch_78:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm28
.globl raw_get_current_context_x64_windows_avx512fpu_patch_78_end
raw_get_current_context_x64_windows_avx512fpu_patch_78_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_79
raw_get_current_context_x64_windows_avx512fpu_patch_79:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm29
.globl raw_get_current_context_x64_windows_avx512fpu_patch_79_end
raw_get_current_context_x64_windows_avx512fpu_patch_79_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_80
raw_get_current_context_x64_windows_avx512fpu_patch_80:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm30
.globl raw_get_current_context_x64_windows_avx512fpu_patch_80_end
raw_get_current_context_x64_windows_avx512fpu_patch_80_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_81
raw_get_current_context_x64_windows_avx512fpu_patch_81:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm31
.globl raw_get_current_context_x64_windows_avx512fpu_patch_81_end
raw_get_current_context_x64_windows_avx512fpu_patch_81_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_82
raw_get_current_context_x64_windows_avx512fpu_patch_82:
	fsave [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_82_end
raw_get_current_context_x64_windows_avx512fpu_patch_82_end:
.globl raw_get_current_context_x64_windows_avx512fpu_patch_83
raw_get_current_context_x64_windows_avx512fpu_patch_83:
	frstor [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_avx512fpu_patch_83_end
raw_get_current_context_x64_windows_avx512fpu_patch_83_end:
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
	popfq
	ret

# GetCurrentContext: x64 windows AVX512
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_windows_avx512
raw_get_current_context_x64_windows_avx512:
	pushfq
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
	mov r11, qword ptr [rsp + 0x68]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_windows_avx512_patch_0
raw_get_current_context_x64_windows_avx512_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_0_end
raw_get_current_context_x64_windows_avx512_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_windows_avx512_patch_1
raw_get_current_context_x64_windows_avx512_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_1_end
raw_get_current_context_x64_windows_avx512_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_windows_avx512_patch_2
raw_get_current_context_x64_windows_avx512_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_2_end
raw_get_current_context_x64_windows_avx512_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_windows_avx512_patch_3
raw_get_current_context_x64_windows_avx512_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_3_end
raw_get_current_context_x64_windows_avx512_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_windows_avx512_patch_4
raw_get_current_context_x64_windows_avx512_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_4_end
raw_get_current_context_x64_windows_avx512_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_windows_avx512_patch_5
raw_get_current_context_x64_windows_avx512_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_5_end
raw_get_current_context_x64_windows_avx512_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_windows_avx512_patch_6
raw_get_current_context_x64_windows_avx512_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_6_end
raw_get_current_context_x64_windows_avx512_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_windows_avx512_patch_7
raw_get_current_context_x64_windows_avx512_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_7_end
raw_get_current_context_x64_windows_avx512_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_windows_avx512_patch_8
raw_get_current_context_x64_windows_avx512_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_8_end
raw_get_current_context_x64_windows_avx512_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_windows_avx512_patch_9
raw_get_current_context_x64_windows_avx512_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_9_end
raw_get_current_context_x64_windows_avx512_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_windows_avx512_patch_10
raw_get_current_context_x64_windows_avx512_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_10_end
raw_get_current_context_x64_windows_avx512_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_windows_avx512_patch_11
raw_get_current_context_x64_windows_avx512_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_11_end
raw_get_current_context_x64_windows_avx512_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_windows_avx512_patch_12
raw_get_current_context_x64_windows_avx512_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_12_end
raw_get_current_context_x64_windows_avx512_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_windows_avx512_patch_13
raw_get_current_context_x64_windows_avx512_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_13_end
raw_get_current_context_x64_windows_avx512_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_windows_avx512_patch_14
raw_get_current_context_x64_windows_avx512_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_14_end
raw_get_current_context_x64_windows_avx512_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_windows_avx512_patch_15
raw_get_current_context_x64_windows_avx512_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_15_end
raw_get_current_context_x64_windows_avx512_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_windows_avx512_patch_16
raw_get_current_context_x64_windows_avx512_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx512_patch_16_end
raw_get_current_context_x64_windows_avx512_patch_16_end:
.globl raw_get_current_context_x64_windows_avx512_patch_17
raw_get_current_context_x64_windows_avx512_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_avx512_patch_17_end
raw_get_current_context_x64_windows_avx512_patch_17_end:
.globl raw_get_current_context_x64_windows_avx512_patch_18
raw_get_current_context_x64_windows_avx512_patch_18:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_windows_avx512_patch_18_end
raw_get_current_context_x64_windows_avx512_patch_18_end:
.globl raw_get_current_context_x64_windows_avx512_patch_19
raw_get_current_context_x64_windows_avx512_patch_19:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_windows_avx512_patch_19_end
raw_get_current_context_x64_windows_avx512_patch_19_end:
.globl raw_get_current_context_x64_windows_avx512_patch_20
raw_get_current_context_x64_windows_avx512_patch_20:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_windows_avx512_patch_20_end
raw_get_current_context_x64_windows_avx512_patch_20_end:
.globl raw_get_current_context_x64_windows_avx512_patch_21
raw_get_current_context_x64_windows_avx512_patch_21:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_windows_avx512_patch_21_end
raw_get_current_context_x64_windows_avx512_patch_21_end:
.globl raw_get_current_context_x64_windows_avx512_patch_22
raw_get_current_context_x64_windows_avx512_patch_22:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_windows_avx512_patch_22_end
raw_get_current_context_x64_windows_avx512_patch_22_end:
.globl raw_get_current_context_x64_windows_avx512_patch_23
raw_get_current_context_x64_windows_avx512_patch_23:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_windows_avx512_patch_23_end
raw_get_current_context_x64_windows_avx512_patch_23_end:
.globl raw_get_current_context_x64_windows_avx512_patch_24
raw_get_current_context_x64_windows_avx512_patch_24:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_windows_avx512_patch_24_end
raw_get_current_context_x64_windows_avx512_patch_24_end:
.globl raw_get_current_context_x64_windows_avx512_patch_25
raw_get_current_context_x64_windows_avx512_patch_25:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_windows_avx512_patch_25_end
raw_get_current_context_x64_windows_avx512_patch_25_end:
.globl raw_get_current_context_x64_windows_avx512_patch_26
raw_get_current_context_x64_windows_avx512_patch_26:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_windows_avx512_patch_26_end
raw_get_current_context_x64_windows_avx512_patch_26_end:
.globl raw_get_current_context_x64_windows_avx512_patch_27
raw_get_current_context_x64_windows_avx512_patch_27:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_windows_avx512_patch_27_end
raw_get_current_context_x64_windows_avx512_patch_27_end:
.globl raw_get_current_context_x64_windows_avx512_patch_28
raw_get_current_context_x64_windows_avx512_patch_28:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_windows_avx512_patch_28_end
raw_get_current_context_x64_windows_avx512_patch_28_end:
.globl raw_get_current_context_x64_windows_avx512_patch_29
raw_get_current_context_x64_windows_avx512_patch_29:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_windows_avx512_patch_29_end
raw_get_current_context_x64_windows_avx512_patch_29_end:
.globl raw_get_current_context_x64_windows_avx512_patch_30
raw_get_current_context_x64_windows_avx512_patch_30:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_windows_avx512_patch_30_end
raw_get_current_context_x64_windows_avx512_patch_30_end:
.globl raw_get_current_context_x64_windows_avx512_patch_31
raw_get_current_context_x64_windows_avx512_patch_31:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_windows_avx512_patch_31_end
raw_get_current_context_x64_windows_avx512_patch_31_end:
.globl raw_get_current_context_x64_windows_avx512_patch_32
raw_get_current_context_x64_windows_avx512_patch_32:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_windows_avx512_patch_32_end
raw_get_current_context_x64_windows_avx512_patch_32_end:
.globl raw_get_current_context_x64_windows_avx512_patch_33
raw_get_current_context_x64_windows_avx512_patch_33:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_windows_avx512_patch_33_end
raw_get_current_context_x64_windows_avx512_patch_33_end:
.globl raw_get_current_context_x64_windows_avx512_patch_34
raw_get_current_context_x64_windows_avx512_patch_34:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm0
.globl raw_get_current_context_x64_windows_avx512_patch_34_end
raw_get_current_context_x64_windows_avx512_patch_34_end:
.globl raw_get_current_context_x64_windows_avx512_patch_35
raw_get_current_context_x64_windows_avx512_patch_35:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm1
.globl raw_get_current_context_x64_windows_avx512_patch_35_end
raw_get_current_context_x64_windows_avx512_patch_35_end:
.globl raw_get_current_context_x64_windows_avx512_patch_36
raw_get_current_context_x64_windows_avx512_patch_36:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm2
.globl raw_get_current_context_x64_windows_avx512_patch_36_end
raw_get_current_context_x64_windows_avx512_patch_36_end:
.globl raw_get_current_context_x64_windows_avx512_patch_37
raw_get_current_context_x64_windows_avx512_patch_37:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm3
.globl raw_get_current_context_x64_windows_avx512_patch_37_end
raw_get_current_context_x64_windows_avx512_patch_37_end:
.globl raw_get_current_context_x64_windows_avx512_patch_38
raw_get_current_context_x64_windows_avx512_patch_38:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm4
.globl raw_get_current_context_x64_windows_avx512_patch_38_end
raw_get_current_context_x64_windows_avx512_patch_38_end:
.globl raw_get_current_context_x64_windows_avx512_patch_39
raw_get_current_context_x64_windows_avx512_patch_39:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm5
.globl raw_get_current_context_x64_windows_avx512_patch_39_end
raw_get_current_context_x64_windows_avx512_patch_39_end:
.globl raw_get_current_context_x64_windows_avx512_patch_40
raw_get_current_context_x64_windows_avx512_patch_40:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm6
.globl raw_get_current_context_x64_windows_avx512_patch_40_end
raw_get_current_context_x64_windows_avx512_patch_40_end:
.globl raw_get_current_context_x64_windows_avx512_patch_41
raw_get_current_context_x64_windows_avx512_patch_41:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm7
.globl raw_get_current_context_x64_windows_avx512_patch_41_end
raw_get_current_context_x64_windows_avx512_patch_41_end:
.globl raw_get_current_context_x64_windows_avx512_patch_42
raw_get_current_context_x64_windows_avx512_patch_42:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm8
.globl raw_get_current_context_x64_windows_avx512_patch_42_end
raw_get_current_context_x64_windows_avx512_patch_42_end:
.globl raw_get_current_context_x64_windows_avx512_patch_43
raw_get_current_context_x64_windows_avx512_patch_43:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm9
.globl raw_get_current_context_x64_windows_avx512_patch_43_end
raw_get_current_context_x64_windows_avx512_patch_43_end:
.globl raw_get_current_context_x64_windows_avx512_patch_44
raw_get_current_context_x64_windows_avx512_patch_44:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm10
.globl raw_get_current_context_x64_windows_avx512_patch_44_end
raw_get_current_context_x64_windows_avx512_patch_44_end:
.globl raw_get_current_context_x64_windows_avx512_patch_45
raw_get_current_context_x64_windows_avx512_patch_45:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm11
.globl raw_get_current_context_x64_windows_avx512_patch_45_end
raw_get_current_context_x64_windows_avx512_patch_45_end:
.globl raw_get_current_context_x64_windows_avx512_patch_46
raw_get_current_context_x64_windows_avx512_patch_46:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm12
.globl raw_get_current_context_x64_windows_avx512_patch_46_end
raw_get_current_context_x64_windows_avx512_patch_46_end:
.globl raw_get_current_context_x64_windows_avx512_patch_47
raw_get_current_context_x64_windows_avx512_patch_47:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm13
.globl raw_get_current_context_x64_windows_avx512_patch_47_end
raw_get_current_context_x64_windows_avx512_patch_47_end:
.globl raw_get_current_context_x64_windows_avx512_patch_48
raw_get_current_context_x64_windows_avx512_patch_48:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm14
.globl raw_get_current_context_x64_windows_avx512_patch_48_end
raw_get_current_context_x64_windows_avx512_patch_48_end:
.globl raw_get_current_context_x64_windows_avx512_patch_49
raw_get_current_context_x64_windows_avx512_patch_49:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm15
.globl raw_get_current_context_x64_windows_avx512_patch_49_end
raw_get_current_context_x64_windows_avx512_patch_49_end:
.globl raw_get_current_context_x64_windows_avx512_patch_50
raw_get_current_context_x64_windows_avx512_patch_50:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm0
.globl raw_get_current_context_x64_windows_avx512_patch_50_end
raw_get_current_context_x64_windows_avx512_patch_50_end:
.globl raw_get_current_context_x64_windows_avx512_patch_51
raw_get_current_context_x64_windows_avx512_patch_51:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm1
.globl raw_get_current_context_x64_windows_avx512_patch_51_end
raw_get_current_context_x64_windows_avx512_patch_51_end:
.globl raw_get_current_context_x64_windows_avx512_patch_52
raw_get_current_context_x64_windows_avx512_patch_52:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm2
.globl raw_get_current_context_x64_windows_avx512_patch_52_end
raw_get_current_context_x64_windows_avx512_patch_52_end:
.globl raw_get_current_context_x64_windows_avx512_patch_53
raw_get_current_context_x64_windows_avx512_patch_53:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm3
.globl raw_get_current_context_x64_windows_avx512_patch_53_end
raw_get_current_context_x64_windows_avx512_patch_53_end:
.globl raw_get_current_context_x64_windows_avx512_patch_54
raw_get_current_context_x64_windows_avx512_patch_54:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm4
.globl raw_get_current_context_x64_windows_avx512_patch_54_end
raw_get_current_context_x64_windows_avx512_patch_54_end:
.globl raw_get_current_context_x64_windows_avx512_patch_55
raw_get_current_context_x64_windows_avx512_patch_55:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm5
.globl raw_get_current_context_x64_windows_avx512_patch_55_end
raw_get_current_context_x64_windows_avx512_patch_55_end:
.globl raw_get_current_context_x64_windows_avx512_patch_56
raw_get_current_context_x64_windows_avx512_patch_56:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm6
.globl raw_get_current_context_x64_windows_avx512_patch_56_end
raw_get_current_context_x64_windows_avx512_patch_56_end:
.globl raw_get_current_context_x64_windows_avx512_patch_57
raw_get_current_context_x64_windows_avx512_patch_57:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm7
.globl raw_get_current_context_x64_windows_avx512_patch_57_end
raw_get_current_context_x64_windows_avx512_patch_57_end:
.globl raw_get_current_context_x64_windows_avx512_patch_58
raw_get_current_context_x64_windows_avx512_patch_58:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm8
.globl raw_get_current_context_x64_windows_avx512_patch_58_end
raw_get_current_context_x64_windows_avx512_patch_58_end:
.globl raw_get_current_context_x64_windows_avx512_patch_59
raw_get_current_context_x64_windows_avx512_patch_59:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm9
.globl raw_get_current_context_x64_windows_avx512_patch_59_end
raw_get_current_context_x64_windows_avx512_patch_59_end:
.globl raw_get_current_context_x64_windows_avx512_patch_60
raw_get_current_context_x64_windows_avx512_patch_60:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm10
.globl raw_get_current_context_x64_windows_avx512_patch_60_end
raw_get_current_context_x64_windows_avx512_patch_60_end:
.globl raw_get_current_context_x64_windows_avx512_patch_61
raw_get_current_context_x64_windows_avx512_patch_61:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm11
.globl raw_get_current_context_x64_windows_avx512_patch_61_end
raw_get_current_context_x64_windows_avx512_patch_61_end:
.globl raw_get_current_context_x64_windows_avx512_patch_62
raw_get_current_context_x64_windows_avx512_patch_62:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm12
.globl raw_get_current_context_x64_windows_avx512_patch_62_end
raw_get_current_context_x64_windows_avx512_patch_62_end:
.globl raw_get_current_context_x64_windows_avx512_patch_63
raw_get_current_context_x64_windows_avx512_patch_63:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm13
.globl raw_get_current_context_x64_windows_avx512_patch_63_end
raw_get_current_context_x64_windows_avx512_patch_63_end:
.globl raw_get_current_context_x64_windows_avx512_patch_64
raw_get_current_context_x64_windows_avx512_patch_64:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm14
.globl raw_get_current_context_x64_windows_avx512_patch_64_end
raw_get_current_context_x64_windows_avx512_patch_64_end:
.globl raw_get_current_context_x64_windows_avx512_patch_65
raw_get_current_context_x64_windows_avx512_patch_65:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm15
.globl raw_get_current_context_x64_windows_avx512_patch_65_end
raw_get_current_context_x64_windows_avx512_patch_65_end:
.globl raw_get_current_context_x64_windows_avx512_patch_66
raw_get_current_context_x64_windows_avx512_patch_66:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm16
.globl raw_get_current_context_x64_windows_avx512_patch_66_end
raw_get_current_context_x64_windows_avx512_patch_66_end:
.globl raw_get_current_context_x64_windows_avx512_patch_67
raw_get_current_context_x64_windows_avx512_patch_67:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm17
.globl raw_get_current_context_x64_windows_avx512_patch_67_end
raw_get_current_context_x64_windows_avx512_patch_67_end:
.globl raw_get_current_context_x64_windows_avx512_patch_68
raw_get_current_context_x64_windows_avx512_patch_68:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm18
.globl raw_get_current_context_x64_windows_avx512_patch_68_end
raw_get_current_context_x64_windows_avx512_patch_68_end:
.globl raw_get_current_context_x64_windows_avx512_patch_69
raw_get_current_context_x64_windows_avx512_patch_69:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm19
.globl raw_get_current_context_x64_windows_avx512_patch_69_end
raw_get_current_context_x64_windows_avx512_patch_69_end:
.globl raw_get_current_context_x64_windows_avx512_patch_70
raw_get_current_context_x64_windows_avx512_patch_70:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm20
.globl raw_get_current_context_x64_windows_avx512_patch_70_end
raw_get_current_context_x64_windows_avx512_patch_70_end:
.globl raw_get_current_context_x64_windows_avx512_patch_71
raw_get_current_context_x64_windows_avx512_patch_71:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm21
.globl raw_get_current_context_x64_windows_avx512_patch_71_end
raw_get_current_context_x64_windows_avx512_patch_71_end:
.globl raw_get_current_context_x64_windows_avx512_patch_72
raw_get_current_context_x64_windows_avx512_patch_72:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm22
.globl raw_get_current_context_x64_windows_avx512_patch_72_end
raw_get_current_context_x64_windows_avx512_patch_72_end:
.globl raw_get_current_context_x64_windows_avx512_patch_73
raw_get_current_context_x64_windows_avx512_patch_73:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm23
.globl raw_get_current_context_x64_windows_avx512_patch_73_end
raw_get_current_context_x64_windows_avx512_patch_73_end:
.globl raw_get_current_context_x64_windows_avx512_patch_74
raw_get_current_context_x64_windows_avx512_patch_74:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm24
.globl raw_get_current_context_x64_windows_avx512_patch_74_end
raw_get_current_context_x64_windows_avx512_patch_74_end:
.globl raw_get_current_context_x64_windows_avx512_patch_75
raw_get_current_context_x64_windows_avx512_patch_75:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm25
.globl raw_get_current_context_x64_windows_avx512_patch_75_end
raw_get_current_context_x64_windows_avx512_patch_75_end:
.globl raw_get_current_context_x64_windows_avx512_patch_76
raw_get_current_context_x64_windows_avx512_patch_76:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm26
.globl raw_get_current_context_x64_windows_avx512_patch_76_end
raw_get_current_context_x64_windows_avx512_patch_76_end:
.globl raw_get_current_context_x64_windows_avx512_patch_77
raw_get_current_context_x64_windows_avx512_patch_77:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm27
.globl raw_get_current_context_x64_windows_avx512_patch_77_end
raw_get_current_context_x64_windows_avx512_patch_77_end:
.globl raw_get_current_context_x64_windows_avx512_patch_78
raw_get_current_context_x64_windows_avx512_patch_78:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm28
.globl raw_get_current_context_x64_windows_avx512_patch_78_end
raw_get_current_context_x64_windows_avx512_patch_78_end:
.globl raw_get_current_context_x64_windows_avx512_patch_79
raw_get_current_context_x64_windows_avx512_patch_79:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm29
.globl raw_get_current_context_x64_windows_avx512_patch_79_end
raw_get_current_context_x64_windows_avx512_patch_79_end:
.globl raw_get_current_context_x64_windows_avx512_patch_80
raw_get_current_context_x64_windows_avx512_patch_80:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm30
.globl raw_get_current_context_x64_windows_avx512_patch_80_end
raw_get_current_context_x64_windows_avx512_patch_80_end:
.globl raw_get_current_context_x64_windows_avx512_patch_81
raw_get_current_context_x64_windows_avx512_patch_81:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm31
.globl raw_get_current_context_x64_windows_avx512_patch_81_end
raw_get_current_context_x64_windows_avx512_patch_81_end:
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
	popfq
	ret

# GetCurrentContext: x64 windows AVXFPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_windows_avxfpu
raw_get_current_context_x64_windows_avxfpu:
	pushfq
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
	mov r11, qword ptr [rsp + 0x68]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_windows_avxfpu_patch_0
raw_get_current_context_x64_windows_avxfpu_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_0_end
raw_get_current_context_x64_windows_avxfpu_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_windows_avxfpu_patch_1
raw_get_current_context_x64_windows_avxfpu_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_1_end
raw_get_current_context_x64_windows_avxfpu_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_windows_avxfpu_patch_2
raw_get_current_context_x64_windows_avxfpu_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_2_end
raw_get_current_context_x64_windows_avxfpu_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_windows_avxfpu_patch_3
raw_get_current_context_x64_windows_avxfpu_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_3_end
raw_get_current_context_x64_windows_avxfpu_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_windows_avxfpu_patch_4
raw_get_current_context_x64_windows_avxfpu_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_4_end
raw_get_current_context_x64_windows_avxfpu_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_windows_avxfpu_patch_5
raw_get_current_context_x64_windows_avxfpu_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_5_end
raw_get_current_context_x64_windows_avxfpu_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_windows_avxfpu_patch_6
raw_get_current_context_x64_windows_avxfpu_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_6_end
raw_get_current_context_x64_windows_avxfpu_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_windows_avxfpu_patch_7
raw_get_current_context_x64_windows_avxfpu_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_7_end
raw_get_current_context_x64_windows_avxfpu_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_windows_avxfpu_patch_8
raw_get_current_context_x64_windows_avxfpu_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_8_end
raw_get_current_context_x64_windows_avxfpu_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_windows_avxfpu_patch_9
raw_get_current_context_x64_windows_avxfpu_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_9_end
raw_get_current_context_x64_windows_avxfpu_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_windows_avxfpu_patch_10
raw_get_current_context_x64_windows_avxfpu_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_10_end
raw_get_current_context_x64_windows_avxfpu_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_windows_avxfpu_patch_11
raw_get_current_context_x64_windows_avxfpu_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_11_end
raw_get_current_context_x64_windows_avxfpu_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_windows_avxfpu_patch_12
raw_get_current_context_x64_windows_avxfpu_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_12_end
raw_get_current_context_x64_windows_avxfpu_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_windows_avxfpu_patch_13
raw_get_current_context_x64_windows_avxfpu_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_13_end
raw_get_current_context_x64_windows_avxfpu_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_windows_avxfpu_patch_14
raw_get_current_context_x64_windows_avxfpu_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_14_end
raw_get_current_context_x64_windows_avxfpu_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_windows_avxfpu_patch_15
raw_get_current_context_x64_windows_avxfpu_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_15_end
raw_get_current_context_x64_windows_avxfpu_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_windows_avxfpu_patch_16
raw_get_current_context_x64_windows_avxfpu_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avxfpu_patch_16_end
raw_get_current_context_x64_windows_avxfpu_patch_16_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_17
raw_get_current_context_x64_windows_avxfpu_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_avxfpu_patch_17_end
raw_get_current_context_x64_windows_avxfpu_patch_17_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_18
raw_get_current_context_x64_windows_avxfpu_patch_18:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_windows_avxfpu_patch_18_end
raw_get_current_context_x64_windows_avxfpu_patch_18_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_19
raw_get_current_context_x64_windows_avxfpu_patch_19:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_windows_avxfpu_patch_19_end
raw_get_current_context_x64_windows_avxfpu_patch_19_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_20
raw_get_current_context_x64_windows_avxfpu_patch_20:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_windows_avxfpu_patch_20_end
raw_get_current_context_x64_windows_avxfpu_patch_20_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_21
raw_get_current_context_x64_windows_avxfpu_patch_21:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_windows_avxfpu_patch_21_end
raw_get_current_context_x64_windows_avxfpu_patch_21_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_22
raw_get_current_context_x64_windows_avxfpu_patch_22:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_windows_avxfpu_patch_22_end
raw_get_current_context_x64_windows_avxfpu_patch_22_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_23
raw_get_current_context_x64_windows_avxfpu_patch_23:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_windows_avxfpu_patch_23_end
raw_get_current_context_x64_windows_avxfpu_patch_23_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_24
raw_get_current_context_x64_windows_avxfpu_patch_24:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_windows_avxfpu_patch_24_end
raw_get_current_context_x64_windows_avxfpu_patch_24_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_25
raw_get_current_context_x64_windows_avxfpu_patch_25:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_windows_avxfpu_patch_25_end
raw_get_current_context_x64_windows_avxfpu_patch_25_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_26
raw_get_current_context_x64_windows_avxfpu_patch_26:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_windows_avxfpu_patch_26_end
raw_get_current_context_x64_windows_avxfpu_patch_26_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_27
raw_get_current_context_x64_windows_avxfpu_patch_27:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_windows_avxfpu_patch_27_end
raw_get_current_context_x64_windows_avxfpu_patch_27_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_28
raw_get_current_context_x64_windows_avxfpu_patch_28:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_windows_avxfpu_patch_28_end
raw_get_current_context_x64_windows_avxfpu_patch_28_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_29
raw_get_current_context_x64_windows_avxfpu_patch_29:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_windows_avxfpu_patch_29_end
raw_get_current_context_x64_windows_avxfpu_patch_29_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_30
raw_get_current_context_x64_windows_avxfpu_patch_30:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_windows_avxfpu_patch_30_end
raw_get_current_context_x64_windows_avxfpu_patch_30_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_31
raw_get_current_context_x64_windows_avxfpu_patch_31:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_windows_avxfpu_patch_31_end
raw_get_current_context_x64_windows_avxfpu_patch_31_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_32
raw_get_current_context_x64_windows_avxfpu_patch_32:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_windows_avxfpu_patch_32_end
raw_get_current_context_x64_windows_avxfpu_patch_32_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_33
raw_get_current_context_x64_windows_avxfpu_patch_33:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_windows_avxfpu_patch_33_end
raw_get_current_context_x64_windows_avxfpu_patch_33_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_34
raw_get_current_context_x64_windows_avxfpu_patch_34:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm0
.globl raw_get_current_context_x64_windows_avxfpu_patch_34_end
raw_get_current_context_x64_windows_avxfpu_patch_34_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_35
raw_get_current_context_x64_windows_avxfpu_patch_35:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm1
.globl raw_get_current_context_x64_windows_avxfpu_patch_35_end
raw_get_current_context_x64_windows_avxfpu_patch_35_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_36
raw_get_current_context_x64_windows_avxfpu_patch_36:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm2
.globl raw_get_current_context_x64_windows_avxfpu_patch_36_end
raw_get_current_context_x64_windows_avxfpu_patch_36_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_37
raw_get_current_context_x64_windows_avxfpu_patch_37:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm3
.globl raw_get_current_context_x64_windows_avxfpu_patch_37_end
raw_get_current_context_x64_windows_avxfpu_patch_37_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_38
raw_get_current_context_x64_windows_avxfpu_patch_38:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm4
.globl raw_get_current_context_x64_windows_avxfpu_patch_38_end
raw_get_current_context_x64_windows_avxfpu_patch_38_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_39
raw_get_current_context_x64_windows_avxfpu_patch_39:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm5
.globl raw_get_current_context_x64_windows_avxfpu_patch_39_end
raw_get_current_context_x64_windows_avxfpu_patch_39_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_40
raw_get_current_context_x64_windows_avxfpu_patch_40:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm6
.globl raw_get_current_context_x64_windows_avxfpu_patch_40_end
raw_get_current_context_x64_windows_avxfpu_patch_40_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_41
raw_get_current_context_x64_windows_avxfpu_patch_41:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm7
.globl raw_get_current_context_x64_windows_avxfpu_patch_41_end
raw_get_current_context_x64_windows_avxfpu_patch_41_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_42
raw_get_current_context_x64_windows_avxfpu_patch_42:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm8
.globl raw_get_current_context_x64_windows_avxfpu_patch_42_end
raw_get_current_context_x64_windows_avxfpu_patch_42_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_43
raw_get_current_context_x64_windows_avxfpu_patch_43:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm9
.globl raw_get_current_context_x64_windows_avxfpu_patch_43_end
raw_get_current_context_x64_windows_avxfpu_patch_43_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_44
raw_get_current_context_x64_windows_avxfpu_patch_44:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm10
.globl raw_get_current_context_x64_windows_avxfpu_patch_44_end
raw_get_current_context_x64_windows_avxfpu_patch_44_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_45
raw_get_current_context_x64_windows_avxfpu_patch_45:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm11
.globl raw_get_current_context_x64_windows_avxfpu_patch_45_end
raw_get_current_context_x64_windows_avxfpu_patch_45_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_46
raw_get_current_context_x64_windows_avxfpu_patch_46:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm12
.globl raw_get_current_context_x64_windows_avxfpu_patch_46_end
raw_get_current_context_x64_windows_avxfpu_patch_46_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_47
raw_get_current_context_x64_windows_avxfpu_patch_47:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm13
.globl raw_get_current_context_x64_windows_avxfpu_patch_47_end
raw_get_current_context_x64_windows_avxfpu_patch_47_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_48
raw_get_current_context_x64_windows_avxfpu_patch_48:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm14
.globl raw_get_current_context_x64_windows_avxfpu_patch_48_end
raw_get_current_context_x64_windows_avxfpu_patch_48_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_49
raw_get_current_context_x64_windows_avxfpu_patch_49:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm15
.globl raw_get_current_context_x64_windows_avxfpu_patch_49_end
raw_get_current_context_x64_windows_avxfpu_patch_49_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_50
raw_get_current_context_x64_windows_avxfpu_patch_50:
	fsave [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_avxfpu_patch_50_end
raw_get_current_context_x64_windows_avxfpu_patch_50_end:
.globl raw_get_current_context_x64_windows_avxfpu_patch_51
raw_get_current_context_x64_windows_avxfpu_patch_51:
	frstor [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_avxfpu_patch_51_end
raw_get_current_context_x64_windows_avxfpu_patch_51_end:
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
	popfq
	ret

# GetCurrentContext: x64 windows AVX
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_windows_avx
raw_get_current_context_x64_windows_avx:
	pushfq
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
	mov r11, qword ptr [rsp + 0x68]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_windows_avx_patch_0
raw_get_current_context_x64_windows_avx_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_0_end
raw_get_current_context_x64_windows_avx_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_windows_avx_patch_1
raw_get_current_context_x64_windows_avx_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_1_end
raw_get_current_context_x64_windows_avx_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_windows_avx_patch_2
raw_get_current_context_x64_windows_avx_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_2_end
raw_get_current_context_x64_windows_avx_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_windows_avx_patch_3
raw_get_current_context_x64_windows_avx_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_3_end
raw_get_current_context_x64_windows_avx_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_windows_avx_patch_4
raw_get_current_context_x64_windows_avx_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_4_end
raw_get_current_context_x64_windows_avx_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_windows_avx_patch_5
raw_get_current_context_x64_windows_avx_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_5_end
raw_get_current_context_x64_windows_avx_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_windows_avx_patch_6
raw_get_current_context_x64_windows_avx_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_6_end
raw_get_current_context_x64_windows_avx_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_windows_avx_patch_7
raw_get_current_context_x64_windows_avx_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_7_end
raw_get_current_context_x64_windows_avx_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_windows_avx_patch_8
raw_get_current_context_x64_windows_avx_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_8_end
raw_get_current_context_x64_windows_avx_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_windows_avx_patch_9
raw_get_current_context_x64_windows_avx_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_9_end
raw_get_current_context_x64_windows_avx_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_windows_avx_patch_10
raw_get_current_context_x64_windows_avx_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_10_end
raw_get_current_context_x64_windows_avx_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_windows_avx_patch_11
raw_get_current_context_x64_windows_avx_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_11_end
raw_get_current_context_x64_windows_avx_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_windows_avx_patch_12
raw_get_current_context_x64_windows_avx_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_12_end
raw_get_current_context_x64_windows_avx_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_windows_avx_patch_13
raw_get_current_context_x64_windows_avx_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_13_end
raw_get_current_context_x64_windows_avx_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_windows_avx_patch_14
raw_get_current_context_x64_windows_avx_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_14_end
raw_get_current_context_x64_windows_avx_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_windows_avx_patch_15
raw_get_current_context_x64_windows_avx_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_15_end
raw_get_current_context_x64_windows_avx_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_windows_avx_patch_16
raw_get_current_context_x64_windows_avx_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_avx_patch_16_end
raw_get_current_context_x64_windows_avx_patch_16_end:
.globl raw_get_current_context_x64_windows_avx_patch_17
raw_get_current_context_x64_windows_avx_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_avx_patch_17_end
raw_get_current_context_x64_windows_avx_patch_17_end:
.globl raw_get_current_context_x64_windows_avx_patch_18
raw_get_current_context_x64_windows_avx_patch_18:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_windows_avx_patch_18_end
raw_get_current_context_x64_windows_avx_patch_18_end:
.globl raw_get_current_context_x64_windows_avx_patch_19
raw_get_current_context_x64_windows_avx_patch_19:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_windows_avx_patch_19_end
raw_get_current_context_x64_windows_avx_patch_19_end:
.globl raw_get_current_context_x64_windows_avx_patch_20
raw_get_current_context_x64_windows_avx_patch_20:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_windows_avx_patch_20_end
raw_get_current_context_x64_windows_avx_patch_20_end:
.globl raw_get_current_context_x64_windows_avx_patch_21
raw_get_current_context_x64_windows_avx_patch_21:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_windows_avx_patch_21_end
raw_get_current_context_x64_windows_avx_patch_21_end:
.globl raw_get_current_context_x64_windows_avx_patch_22
raw_get_current_context_x64_windows_avx_patch_22:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_windows_avx_patch_22_end
raw_get_current_context_x64_windows_avx_patch_22_end:
.globl raw_get_current_context_x64_windows_avx_patch_23
raw_get_current_context_x64_windows_avx_patch_23:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_windows_avx_patch_23_end
raw_get_current_context_x64_windows_avx_patch_23_end:
.globl raw_get_current_context_x64_windows_avx_patch_24
raw_get_current_context_x64_windows_avx_patch_24:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_windows_avx_patch_24_end
raw_get_current_context_x64_windows_avx_patch_24_end:
.globl raw_get_current_context_x64_windows_avx_patch_25
raw_get_current_context_x64_windows_avx_patch_25:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_windows_avx_patch_25_end
raw_get_current_context_x64_windows_avx_patch_25_end:
.globl raw_get_current_context_x64_windows_avx_patch_26
raw_get_current_context_x64_windows_avx_patch_26:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_windows_avx_patch_26_end
raw_get_current_context_x64_windows_avx_patch_26_end:
.globl raw_get_current_context_x64_windows_avx_patch_27
raw_get_current_context_x64_windows_avx_patch_27:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_windows_avx_patch_27_end
raw_get_current_context_x64_windows_avx_patch_27_end:
.globl raw_get_current_context_x64_windows_avx_patch_28
raw_get_current_context_x64_windows_avx_patch_28:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_windows_avx_patch_28_end
raw_get_current_context_x64_windows_avx_patch_28_end:
.globl raw_get_current_context_x64_windows_avx_patch_29
raw_get_current_context_x64_windows_avx_patch_29:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_windows_avx_patch_29_end
raw_get_current_context_x64_windows_avx_patch_29_end:
.globl raw_get_current_context_x64_windows_avx_patch_30
raw_get_current_context_x64_windows_avx_patch_30:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_windows_avx_patch_30_end
raw_get_current_context_x64_windows_avx_patch_30_end:
.globl raw_get_current_context_x64_windows_avx_patch_31
raw_get_current_context_x64_windows_avx_patch_31:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_windows_avx_patch_31_end
raw_get_current_context_x64_windows_avx_patch_31_end:
.globl raw_get_current_context_x64_windows_avx_patch_32
raw_get_current_context_x64_windows_avx_patch_32:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_windows_avx_patch_32_end
raw_get_current_context_x64_windows_avx_patch_32_end:
.globl raw_get_current_context_x64_windows_avx_patch_33
raw_get_current_context_x64_windows_avx_patch_33:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_windows_avx_patch_33_end
raw_get_current_context_x64_windows_avx_patch_33_end:
.globl raw_get_current_context_x64_windows_avx_patch_34
raw_get_current_context_x64_windows_avx_patch_34:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm0
.globl raw_get_current_context_x64_windows_avx_patch_34_end
raw_get_current_context_x64_windows_avx_patch_34_end:
.globl raw_get_current_context_x64_windows_avx_patch_35
raw_get_current_context_x64_windows_avx_patch_35:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm1
.globl raw_get_current_context_x64_windows_avx_patch_35_end
raw_get_current_context_x64_windows_avx_patch_35_end:
.globl raw_get_current_context_x64_windows_avx_patch_36
raw_get_current_context_x64_windows_avx_patch_36:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm2
.globl raw_get_current_context_x64_windows_avx_patch_36_end
raw_get_current_context_x64_windows_avx_patch_36_end:
.globl raw_get_current_context_x64_windows_avx_patch_37
raw_get_current_context_x64_windows_avx_patch_37:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm3
.globl raw_get_current_context_x64_windows_avx_patch_37_end
raw_get_current_context_x64_windows_avx_patch_37_end:
.globl raw_get_current_context_x64_windows_avx_patch_38
raw_get_current_context_x64_windows_avx_patch_38:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm4
.globl raw_get_current_context_x64_windows_avx_patch_38_end
raw_get_current_context_x64_windows_avx_patch_38_end:
.globl raw_get_current_context_x64_windows_avx_patch_39
raw_get_current_context_x64_windows_avx_patch_39:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm5
.globl raw_get_current_context_x64_windows_avx_patch_39_end
raw_get_current_context_x64_windows_avx_patch_39_end:
.globl raw_get_current_context_x64_windows_avx_patch_40
raw_get_current_context_x64_windows_avx_patch_40:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm6
.globl raw_get_current_context_x64_windows_avx_patch_40_end
raw_get_current_context_x64_windows_avx_patch_40_end:
.globl raw_get_current_context_x64_windows_avx_patch_41
raw_get_current_context_x64_windows_avx_patch_41:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm7
.globl raw_get_current_context_x64_windows_avx_patch_41_end
raw_get_current_context_x64_windows_avx_patch_41_end:
.globl raw_get_current_context_x64_windows_avx_patch_42
raw_get_current_context_x64_windows_avx_patch_42:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm8
.globl raw_get_current_context_x64_windows_avx_patch_42_end
raw_get_current_context_x64_windows_avx_patch_42_end:
.globl raw_get_current_context_x64_windows_avx_patch_43
raw_get_current_context_x64_windows_avx_patch_43:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm9
.globl raw_get_current_context_x64_windows_avx_patch_43_end
raw_get_current_context_x64_windows_avx_patch_43_end:
.globl raw_get_current_context_x64_windows_avx_patch_44
raw_get_current_context_x64_windows_avx_patch_44:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm10
.globl raw_get_current_context_x64_windows_avx_patch_44_end
raw_get_current_context_x64_windows_avx_patch_44_end:
.globl raw_get_current_context_x64_windows_avx_patch_45
raw_get_current_context_x64_windows_avx_patch_45:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm11
.globl raw_get_current_context_x64_windows_avx_patch_45_end
raw_get_current_context_x64_windows_avx_patch_45_end:
.globl raw_get_current_context_x64_windows_avx_patch_46
raw_get_current_context_x64_windows_avx_patch_46:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm12
.globl raw_get_current_context_x64_windows_avx_patch_46_end
raw_get_current_context_x64_windows_avx_patch_46_end:
.globl raw_get_current_context_x64_windows_avx_patch_47
raw_get_current_context_x64_windows_avx_patch_47:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm13
.globl raw_get_current_context_x64_windows_avx_patch_47_end
raw_get_current_context_x64_windows_avx_patch_47_end:
.globl raw_get_current_context_x64_windows_avx_patch_48
raw_get_current_context_x64_windows_avx_patch_48:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm14
.globl raw_get_current_context_x64_windows_avx_patch_48_end
raw_get_current_context_x64_windows_avx_patch_48_end:
.globl raw_get_current_context_x64_windows_avx_patch_49
raw_get_current_context_x64_windows_avx_patch_49:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm15
.globl raw_get_current_context_x64_windows_avx_patch_49_end
raw_get_current_context_x64_windows_avx_patch_49_end:
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
	popfq
	ret

# GetCurrentContext: x64 windows SSEFPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_windows_ssefpu
raw_get_current_context_x64_windows_ssefpu:
	pushfq
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
	mov r11, qword ptr [rsp + 0x68]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_windows_ssefpu_patch_0
raw_get_current_context_x64_windows_ssefpu_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_0_end
raw_get_current_context_x64_windows_ssefpu_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_windows_ssefpu_patch_1
raw_get_current_context_x64_windows_ssefpu_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_1_end
raw_get_current_context_x64_windows_ssefpu_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_windows_ssefpu_patch_2
raw_get_current_context_x64_windows_ssefpu_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_2_end
raw_get_current_context_x64_windows_ssefpu_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_windows_ssefpu_patch_3
raw_get_current_context_x64_windows_ssefpu_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_3_end
raw_get_current_context_x64_windows_ssefpu_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_windows_ssefpu_patch_4
raw_get_current_context_x64_windows_ssefpu_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_4_end
raw_get_current_context_x64_windows_ssefpu_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_windows_ssefpu_patch_5
raw_get_current_context_x64_windows_ssefpu_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_5_end
raw_get_current_context_x64_windows_ssefpu_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_windows_ssefpu_patch_6
raw_get_current_context_x64_windows_ssefpu_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_6_end
raw_get_current_context_x64_windows_ssefpu_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_windows_ssefpu_patch_7
raw_get_current_context_x64_windows_ssefpu_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_7_end
raw_get_current_context_x64_windows_ssefpu_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_windows_ssefpu_patch_8
raw_get_current_context_x64_windows_ssefpu_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_8_end
raw_get_current_context_x64_windows_ssefpu_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_windows_ssefpu_patch_9
raw_get_current_context_x64_windows_ssefpu_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_9_end
raw_get_current_context_x64_windows_ssefpu_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_windows_ssefpu_patch_10
raw_get_current_context_x64_windows_ssefpu_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_10_end
raw_get_current_context_x64_windows_ssefpu_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_windows_ssefpu_patch_11
raw_get_current_context_x64_windows_ssefpu_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_11_end
raw_get_current_context_x64_windows_ssefpu_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_windows_ssefpu_patch_12
raw_get_current_context_x64_windows_ssefpu_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_12_end
raw_get_current_context_x64_windows_ssefpu_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_windows_ssefpu_patch_13
raw_get_current_context_x64_windows_ssefpu_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_13_end
raw_get_current_context_x64_windows_ssefpu_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_windows_ssefpu_patch_14
raw_get_current_context_x64_windows_ssefpu_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_14_end
raw_get_current_context_x64_windows_ssefpu_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_windows_ssefpu_patch_15
raw_get_current_context_x64_windows_ssefpu_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_15_end
raw_get_current_context_x64_windows_ssefpu_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_windows_ssefpu_patch_16
raw_get_current_context_x64_windows_ssefpu_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_ssefpu_patch_16_end
raw_get_current_context_x64_windows_ssefpu_patch_16_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_17
raw_get_current_context_x64_windows_ssefpu_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_ssefpu_patch_17_end
raw_get_current_context_x64_windows_ssefpu_patch_17_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_18
raw_get_current_context_x64_windows_ssefpu_patch_18:
	movups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_windows_ssefpu_patch_18_end
raw_get_current_context_x64_windows_ssefpu_patch_18_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_19
raw_get_current_context_x64_windows_ssefpu_patch_19:
	movups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_windows_ssefpu_patch_19_end
raw_get_current_context_x64_windows_ssefpu_patch_19_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_20
raw_get_current_context_x64_windows_ssefpu_patch_20:
	movups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_windows_ssefpu_patch_20_end
raw_get_current_context_x64_windows_ssefpu_patch_20_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_21
raw_get_current_context_x64_windows_ssefpu_patch_21:
	movups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_windows_ssefpu_patch_21_end
raw_get_current_context_x64_windows_ssefpu_patch_21_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_22
raw_get_current_context_x64_windows_ssefpu_patch_22:
	movups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_windows_ssefpu_patch_22_end
raw_get_current_context_x64_windows_ssefpu_patch_22_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_23
raw_get_current_context_x64_windows_ssefpu_patch_23:
	movups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_windows_ssefpu_patch_23_end
raw_get_current_context_x64_windows_ssefpu_patch_23_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_24
raw_get_current_context_x64_windows_ssefpu_patch_24:
	movups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_windows_ssefpu_patch_24_end
raw_get_current_context_x64_windows_ssefpu_patch_24_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_25
raw_get_current_context_x64_windows_ssefpu_patch_25:
	movups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_windows_ssefpu_patch_25_end
raw_get_current_context_x64_windows_ssefpu_patch_25_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_26
raw_get_current_context_x64_windows_ssefpu_patch_26:
	movups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_windows_ssefpu_patch_26_end
raw_get_current_context_x64_windows_ssefpu_patch_26_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_27
raw_get_current_context_x64_windows_ssefpu_patch_27:
	movups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_windows_ssefpu_patch_27_end
raw_get_current_context_x64_windows_ssefpu_patch_27_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_28
raw_get_current_context_x64_windows_ssefpu_patch_28:
	movups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_windows_ssefpu_patch_28_end
raw_get_current_context_x64_windows_ssefpu_patch_28_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_29
raw_get_current_context_x64_windows_ssefpu_patch_29:
	movups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_windows_ssefpu_patch_29_end
raw_get_current_context_x64_windows_ssefpu_patch_29_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_30
raw_get_current_context_x64_windows_ssefpu_patch_30:
	movups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_windows_ssefpu_patch_30_end
raw_get_current_context_x64_windows_ssefpu_patch_30_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_31
raw_get_current_context_x64_windows_ssefpu_patch_31:
	movups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_windows_ssefpu_patch_31_end
raw_get_current_context_x64_windows_ssefpu_patch_31_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_32
raw_get_current_context_x64_windows_ssefpu_patch_32:
	movups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_windows_ssefpu_patch_32_end
raw_get_current_context_x64_windows_ssefpu_patch_32_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_33
raw_get_current_context_x64_windows_ssefpu_patch_33:
	movups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_windows_ssefpu_patch_33_end
raw_get_current_context_x64_windows_ssefpu_patch_33_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_34
raw_get_current_context_x64_windows_ssefpu_patch_34:
	fsave [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_ssefpu_patch_34_end
raw_get_current_context_x64_windows_ssefpu_patch_34_end:
.globl raw_get_current_context_x64_windows_ssefpu_patch_35
raw_get_current_context_x64_windows_ssefpu_patch_35:
	frstor [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_ssefpu_patch_35_end
raw_get_current_context_x64_windows_ssefpu_patch_35_end:
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
	popfq
	ret

# GetCurrentContext: x64 windows SSE
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_windows_sse
raw_get_current_context_x64_windows_sse:
	pushfq
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
	mov r11, qword ptr [rsp + 0x68]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_windows_sse_patch_0
raw_get_current_context_x64_windows_sse_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_0_end
raw_get_current_context_x64_windows_sse_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_windows_sse_patch_1
raw_get_current_context_x64_windows_sse_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_1_end
raw_get_current_context_x64_windows_sse_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_windows_sse_patch_2
raw_get_current_context_x64_windows_sse_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_2_end
raw_get_current_context_x64_windows_sse_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_windows_sse_patch_3
raw_get_current_context_x64_windows_sse_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_3_end
raw_get_current_context_x64_windows_sse_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_windows_sse_patch_4
raw_get_current_context_x64_windows_sse_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_4_end
raw_get_current_context_x64_windows_sse_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_windows_sse_patch_5
raw_get_current_context_x64_windows_sse_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_5_end
raw_get_current_context_x64_windows_sse_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_windows_sse_patch_6
raw_get_current_context_x64_windows_sse_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_6_end
raw_get_current_context_x64_windows_sse_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_windows_sse_patch_7
raw_get_current_context_x64_windows_sse_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_7_end
raw_get_current_context_x64_windows_sse_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_windows_sse_patch_8
raw_get_current_context_x64_windows_sse_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_8_end
raw_get_current_context_x64_windows_sse_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_windows_sse_patch_9
raw_get_current_context_x64_windows_sse_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_9_end
raw_get_current_context_x64_windows_sse_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_windows_sse_patch_10
raw_get_current_context_x64_windows_sse_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_10_end
raw_get_current_context_x64_windows_sse_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_windows_sse_patch_11
raw_get_current_context_x64_windows_sse_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_11_end
raw_get_current_context_x64_windows_sse_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_windows_sse_patch_12
raw_get_current_context_x64_windows_sse_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_12_end
raw_get_current_context_x64_windows_sse_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_windows_sse_patch_13
raw_get_current_context_x64_windows_sse_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_13_end
raw_get_current_context_x64_windows_sse_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_windows_sse_patch_14
raw_get_current_context_x64_windows_sse_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_14_end
raw_get_current_context_x64_windows_sse_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_windows_sse_patch_15
raw_get_current_context_x64_windows_sse_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_15_end
raw_get_current_context_x64_windows_sse_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_windows_sse_patch_16
raw_get_current_context_x64_windows_sse_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_sse_patch_16_end
raw_get_current_context_x64_windows_sse_patch_16_end:
.globl raw_get_current_context_x64_windows_sse_patch_17
raw_get_current_context_x64_windows_sse_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_sse_patch_17_end
raw_get_current_context_x64_windows_sse_patch_17_end:
.globl raw_get_current_context_x64_windows_sse_patch_18
raw_get_current_context_x64_windows_sse_patch_18:
	movups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_windows_sse_patch_18_end
raw_get_current_context_x64_windows_sse_patch_18_end:
.globl raw_get_current_context_x64_windows_sse_patch_19
raw_get_current_context_x64_windows_sse_patch_19:
	movups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_windows_sse_patch_19_end
raw_get_current_context_x64_windows_sse_patch_19_end:
.globl raw_get_current_context_x64_windows_sse_patch_20
raw_get_current_context_x64_windows_sse_patch_20:
	movups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_windows_sse_patch_20_end
raw_get_current_context_x64_windows_sse_patch_20_end:
.globl raw_get_current_context_x64_windows_sse_patch_21
raw_get_current_context_x64_windows_sse_patch_21:
	movups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_windows_sse_patch_21_end
raw_get_current_context_x64_windows_sse_patch_21_end:
.globl raw_get_current_context_x64_windows_sse_patch_22
raw_get_current_context_x64_windows_sse_patch_22:
	movups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_windows_sse_patch_22_end
raw_get_current_context_x64_windows_sse_patch_22_end:
.globl raw_get_current_context_x64_windows_sse_patch_23
raw_get_current_context_x64_windows_sse_patch_23:
	movups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_windows_sse_patch_23_end
raw_get_current_context_x64_windows_sse_patch_23_end:
.globl raw_get_current_context_x64_windows_sse_patch_24
raw_get_current_context_x64_windows_sse_patch_24:
	movups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_windows_sse_patch_24_end
raw_get_current_context_x64_windows_sse_patch_24_end:
.globl raw_get_current_context_x64_windows_sse_patch_25
raw_get_current_context_x64_windows_sse_patch_25:
	movups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_windows_sse_patch_25_end
raw_get_current_context_x64_windows_sse_patch_25_end:
.globl raw_get_current_context_x64_windows_sse_patch_26
raw_get_current_context_x64_windows_sse_patch_26:
	movups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_windows_sse_patch_26_end
raw_get_current_context_x64_windows_sse_patch_26_end:
.globl raw_get_current_context_x64_windows_sse_patch_27
raw_get_current_context_x64_windows_sse_patch_27:
	movups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_windows_sse_patch_27_end
raw_get_current_context_x64_windows_sse_patch_27_end:
.globl raw_get_current_context_x64_windows_sse_patch_28
raw_get_current_context_x64_windows_sse_patch_28:
	movups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_windows_sse_patch_28_end
raw_get_current_context_x64_windows_sse_patch_28_end:
.globl raw_get_current_context_x64_windows_sse_patch_29
raw_get_current_context_x64_windows_sse_patch_29:
	movups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_windows_sse_patch_29_end
raw_get_current_context_x64_windows_sse_patch_29_end:
.globl raw_get_current_context_x64_windows_sse_patch_30
raw_get_current_context_x64_windows_sse_patch_30:
	movups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_windows_sse_patch_30_end
raw_get_current_context_x64_windows_sse_patch_30_end:
.globl raw_get_current_context_x64_windows_sse_patch_31
raw_get_current_context_x64_windows_sse_patch_31:
	movups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_windows_sse_patch_31_end
raw_get_current_context_x64_windows_sse_patch_31_end:
.globl raw_get_current_context_x64_windows_sse_patch_32
raw_get_current_context_x64_windows_sse_patch_32:
	movups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_windows_sse_patch_32_end
raw_get_current_context_x64_windows_sse_patch_32_end:
.globl raw_get_current_context_x64_windows_sse_patch_33
raw_get_current_context_x64_windows_sse_patch_33:
	movups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_windows_sse_patch_33_end
raw_get_current_context_x64_windows_sse_patch_33_end:
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
	popfq
	ret

# GetCurrentContext: x64 windows FPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_windows_fpu
raw_get_current_context_x64_windows_fpu:
	pushfq
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
	mov r11, qword ptr [rsp + 0x68]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_windows_fpu_patch_0
raw_get_current_context_x64_windows_fpu_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_0_end
raw_get_current_context_x64_windows_fpu_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_windows_fpu_patch_1
raw_get_current_context_x64_windows_fpu_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_1_end
raw_get_current_context_x64_windows_fpu_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_windows_fpu_patch_2
raw_get_current_context_x64_windows_fpu_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_2_end
raw_get_current_context_x64_windows_fpu_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_windows_fpu_patch_3
raw_get_current_context_x64_windows_fpu_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_3_end
raw_get_current_context_x64_windows_fpu_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_windows_fpu_patch_4
raw_get_current_context_x64_windows_fpu_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_4_end
raw_get_current_context_x64_windows_fpu_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_windows_fpu_patch_5
raw_get_current_context_x64_windows_fpu_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_5_end
raw_get_current_context_x64_windows_fpu_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_windows_fpu_patch_6
raw_get_current_context_x64_windows_fpu_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_6_end
raw_get_current_context_x64_windows_fpu_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_windows_fpu_patch_7
raw_get_current_context_x64_windows_fpu_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_7_end
raw_get_current_context_x64_windows_fpu_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_windows_fpu_patch_8
raw_get_current_context_x64_windows_fpu_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_8_end
raw_get_current_context_x64_windows_fpu_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_windows_fpu_patch_9
raw_get_current_context_x64_windows_fpu_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_9_end
raw_get_current_context_x64_windows_fpu_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_windows_fpu_patch_10
raw_get_current_context_x64_windows_fpu_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_10_end
raw_get_current_context_x64_windows_fpu_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_windows_fpu_patch_11
raw_get_current_context_x64_windows_fpu_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_11_end
raw_get_current_context_x64_windows_fpu_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_windows_fpu_patch_12
raw_get_current_context_x64_windows_fpu_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_12_end
raw_get_current_context_x64_windows_fpu_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_windows_fpu_patch_13
raw_get_current_context_x64_windows_fpu_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_13_end
raw_get_current_context_x64_windows_fpu_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_windows_fpu_patch_14
raw_get_current_context_x64_windows_fpu_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_14_end
raw_get_current_context_x64_windows_fpu_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_windows_fpu_patch_15
raw_get_current_context_x64_windows_fpu_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_15_end
raw_get_current_context_x64_windows_fpu_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_windows_fpu_patch_16
raw_get_current_context_x64_windows_fpu_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_fpu_patch_16_end
raw_get_current_context_x64_windows_fpu_patch_16_end:
.globl raw_get_current_context_x64_windows_fpu_patch_17
raw_get_current_context_x64_windows_fpu_patch_17:
	fsave [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_fpu_patch_17_end
raw_get_current_context_x64_windows_fpu_patch_17_end:
.globl raw_get_current_context_x64_windows_fpu_patch_18
raw_get_current_context_x64_windows_fpu_patch_18:
	frstor [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_windows_fpu_patch_18_end
raw_get_current_context_x64_windows_fpu_patch_18_end:
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
	popfq
	ret

# GetCurrentContext: x64 windows Native
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_windows_native
raw_get_current_context_x64_windows_native:
	pushfq
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
	mov r11, qword ptr [rsp + 0x68]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_windows_native_patch_0
raw_get_current_context_x64_windows_native_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_0_end
raw_get_current_context_x64_windows_native_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_windows_native_patch_1
raw_get_current_context_x64_windows_native_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_1_end
raw_get_current_context_x64_windows_native_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_windows_native_patch_2
raw_get_current_context_x64_windows_native_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_2_end
raw_get_current_context_x64_windows_native_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_windows_native_patch_3
raw_get_current_context_x64_windows_native_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_3_end
raw_get_current_context_x64_windows_native_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_windows_native_patch_4
raw_get_current_context_x64_windows_native_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_4_end
raw_get_current_context_x64_windows_native_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_windows_native_patch_5
raw_get_current_context_x64_windows_native_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_5_end
raw_get_current_context_x64_windows_native_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_windows_native_patch_6
raw_get_current_context_x64_windows_native_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_6_end
raw_get_current_context_x64_windows_native_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_windows_native_patch_7
raw_get_current_context_x64_windows_native_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_7_end
raw_get_current_context_x64_windows_native_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_windows_native_patch_8
raw_get_current_context_x64_windows_native_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_8_end
raw_get_current_context_x64_windows_native_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_windows_native_patch_9
raw_get_current_context_x64_windows_native_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_9_end
raw_get_current_context_x64_windows_native_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_windows_native_patch_10
raw_get_current_context_x64_windows_native_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_10_end
raw_get_current_context_x64_windows_native_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_windows_native_patch_11
raw_get_current_context_x64_windows_native_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_11_end
raw_get_current_context_x64_windows_native_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_windows_native_patch_12
raw_get_current_context_x64_windows_native_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_12_end
raw_get_current_context_x64_windows_native_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_windows_native_patch_13
raw_get_current_context_x64_windows_native_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_13_end
raw_get_current_context_x64_windows_native_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_windows_native_patch_14
raw_get_current_context_x64_windows_native_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_14_end
raw_get_current_context_x64_windows_native_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_windows_native_patch_15
raw_get_current_context_x64_windows_native_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_15_end
raw_get_current_context_x64_windows_native_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_windows_native_patch_16
raw_get_current_context_x64_windows_native_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_windows_native_patch_16_end
raw_get_current_context_x64_windows_native_patch_16_end:
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
	popfq
	ret

# GetCurrentContext: x64 systemv AVX512FPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_systemv_avx512fpu
raw_get_current_context_x64_systemv_avx512fpu:
	pushfq
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
	mov r11, qword ptr [rsp + 0x40]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_0
raw_get_current_context_x64_systemv_avx512fpu_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_0_end
raw_get_current_context_x64_systemv_avx512fpu_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_1
raw_get_current_context_x64_systemv_avx512fpu_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_1_end
raw_get_current_context_x64_systemv_avx512fpu_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_2
raw_get_current_context_x64_systemv_avx512fpu_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_2_end
raw_get_current_context_x64_systemv_avx512fpu_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_3
raw_get_current_context_x64_systemv_avx512fpu_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_3_end
raw_get_current_context_x64_systemv_avx512fpu_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_4
raw_get_current_context_x64_systemv_avx512fpu_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_4_end
raw_get_current_context_x64_systemv_avx512fpu_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_5
raw_get_current_context_x64_systemv_avx512fpu_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_5_end
raw_get_current_context_x64_systemv_avx512fpu_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_6
raw_get_current_context_x64_systemv_avx512fpu_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_6_end
raw_get_current_context_x64_systemv_avx512fpu_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_7
raw_get_current_context_x64_systemv_avx512fpu_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_7_end
raw_get_current_context_x64_systemv_avx512fpu_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_8
raw_get_current_context_x64_systemv_avx512fpu_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_8_end
raw_get_current_context_x64_systemv_avx512fpu_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_9
raw_get_current_context_x64_systemv_avx512fpu_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_9_end
raw_get_current_context_x64_systemv_avx512fpu_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_10
raw_get_current_context_x64_systemv_avx512fpu_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_10_end
raw_get_current_context_x64_systemv_avx512fpu_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_11
raw_get_current_context_x64_systemv_avx512fpu_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_11_end
raw_get_current_context_x64_systemv_avx512fpu_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_12
raw_get_current_context_x64_systemv_avx512fpu_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_12_end
raw_get_current_context_x64_systemv_avx512fpu_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_13
raw_get_current_context_x64_systemv_avx512fpu_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_13_end
raw_get_current_context_x64_systemv_avx512fpu_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_14
raw_get_current_context_x64_systemv_avx512fpu_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_14_end
raw_get_current_context_x64_systemv_avx512fpu_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_15
raw_get_current_context_x64_systemv_avx512fpu_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_15_end
raw_get_current_context_x64_systemv_avx512fpu_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_16
raw_get_current_context_x64_systemv_avx512fpu_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_16_end
raw_get_current_context_x64_systemv_avx512fpu_patch_16_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_17
raw_get_current_context_x64_systemv_avx512fpu_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_17_end
raw_get_current_context_x64_systemv_avx512fpu_patch_17_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_18
raw_get_current_context_x64_systemv_avx512fpu_patch_18:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_18_end
raw_get_current_context_x64_systemv_avx512fpu_patch_18_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_19
raw_get_current_context_x64_systemv_avx512fpu_patch_19:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_19_end
raw_get_current_context_x64_systemv_avx512fpu_patch_19_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_20
raw_get_current_context_x64_systemv_avx512fpu_patch_20:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_20_end
raw_get_current_context_x64_systemv_avx512fpu_patch_20_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_21
raw_get_current_context_x64_systemv_avx512fpu_patch_21:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_21_end
raw_get_current_context_x64_systemv_avx512fpu_patch_21_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_22
raw_get_current_context_x64_systemv_avx512fpu_patch_22:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_22_end
raw_get_current_context_x64_systemv_avx512fpu_patch_22_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_23
raw_get_current_context_x64_systemv_avx512fpu_patch_23:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_23_end
raw_get_current_context_x64_systemv_avx512fpu_patch_23_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_24
raw_get_current_context_x64_systemv_avx512fpu_patch_24:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_24_end
raw_get_current_context_x64_systemv_avx512fpu_patch_24_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_25
raw_get_current_context_x64_systemv_avx512fpu_patch_25:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_25_end
raw_get_current_context_x64_systemv_avx512fpu_patch_25_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_26
raw_get_current_context_x64_systemv_avx512fpu_patch_26:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_26_end
raw_get_current_context_x64_systemv_avx512fpu_patch_26_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_27
raw_get_current_context_x64_systemv_avx512fpu_patch_27:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_27_end
raw_get_current_context_x64_systemv_avx512fpu_patch_27_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_28
raw_get_current_context_x64_systemv_avx512fpu_patch_28:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_28_end
raw_get_current_context_x64_systemv_avx512fpu_patch_28_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_29
raw_get_current_context_x64_systemv_avx512fpu_patch_29:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_29_end
raw_get_current_context_x64_systemv_avx512fpu_patch_29_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_30
raw_get_current_context_x64_systemv_avx512fpu_patch_30:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_30_end
raw_get_current_context_x64_systemv_avx512fpu_patch_30_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_31
raw_get_current_context_x64_systemv_avx512fpu_patch_31:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_31_end
raw_get_current_context_x64_systemv_avx512fpu_patch_31_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_32
raw_get_current_context_x64_systemv_avx512fpu_patch_32:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_32_end
raw_get_current_context_x64_systemv_avx512fpu_patch_32_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_33
raw_get_current_context_x64_systemv_avx512fpu_patch_33:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_33_end
raw_get_current_context_x64_systemv_avx512fpu_patch_33_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_34
raw_get_current_context_x64_systemv_avx512fpu_patch_34:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm0
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_34_end
raw_get_current_context_x64_systemv_avx512fpu_patch_34_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_35
raw_get_current_context_x64_systemv_avx512fpu_patch_35:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm1
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_35_end
raw_get_current_context_x64_systemv_avx512fpu_patch_35_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_36
raw_get_current_context_x64_systemv_avx512fpu_patch_36:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm2
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_36_end
raw_get_current_context_x64_systemv_avx512fpu_patch_36_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_37
raw_get_current_context_x64_systemv_avx512fpu_patch_37:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm3
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_37_end
raw_get_current_context_x64_systemv_avx512fpu_patch_37_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_38
raw_get_current_context_x64_systemv_avx512fpu_patch_38:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm4
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_38_end
raw_get_current_context_x64_systemv_avx512fpu_patch_38_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_39
raw_get_current_context_x64_systemv_avx512fpu_patch_39:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm5
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_39_end
raw_get_current_context_x64_systemv_avx512fpu_patch_39_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_40
raw_get_current_context_x64_systemv_avx512fpu_patch_40:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm6
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_40_end
raw_get_current_context_x64_systemv_avx512fpu_patch_40_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_41
raw_get_current_context_x64_systemv_avx512fpu_patch_41:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm7
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_41_end
raw_get_current_context_x64_systemv_avx512fpu_patch_41_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_42
raw_get_current_context_x64_systemv_avx512fpu_patch_42:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm8
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_42_end
raw_get_current_context_x64_systemv_avx512fpu_patch_42_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_43
raw_get_current_context_x64_systemv_avx512fpu_patch_43:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm9
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_43_end
raw_get_current_context_x64_systemv_avx512fpu_patch_43_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_44
raw_get_current_context_x64_systemv_avx512fpu_patch_44:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_44_end
raw_get_current_context_x64_systemv_avx512fpu_patch_44_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_45
raw_get_current_context_x64_systemv_avx512fpu_patch_45:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm11
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_45_end
raw_get_current_context_x64_systemv_avx512fpu_patch_45_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_46
raw_get_current_context_x64_systemv_avx512fpu_patch_46:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm12
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_46_end
raw_get_current_context_x64_systemv_avx512fpu_patch_46_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_47
raw_get_current_context_x64_systemv_avx512fpu_patch_47:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm13
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_47_end
raw_get_current_context_x64_systemv_avx512fpu_patch_47_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_48
raw_get_current_context_x64_systemv_avx512fpu_patch_48:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm14
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_48_end
raw_get_current_context_x64_systemv_avx512fpu_patch_48_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_49
raw_get_current_context_x64_systemv_avx512fpu_patch_49:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm15
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_49_end
raw_get_current_context_x64_systemv_avx512fpu_patch_49_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_50
raw_get_current_context_x64_systemv_avx512fpu_patch_50:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm0
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_50_end
raw_get_current_context_x64_systemv_avx512fpu_patch_50_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_51
raw_get_current_context_x64_systemv_avx512fpu_patch_51:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm1
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_51_end
raw_get_current_context_x64_systemv_avx512fpu_patch_51_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_52
raw_get_current_context_x64_systemv_avx512fpu_patch_52:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm2
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_52_end
raw_get_current_context_x64_systemv_avx512fpu_patch_52_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_53
raw_get_current_context_x64_systemv_avx512fpu_patch_53:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm3
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_53_end
raw_get_current_context_x64_systemv_avx512fpu_patch_53_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_54
raw_get_current_context_x64_systemv_avx512fpu_patch_54:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm4
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_54_end
raw_get_current_context_x64_systemv_avx512fpu_patch_54_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_55
raw_get_current_context_x64_systemv_avx512fpu_patch_55:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm5
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_55_end
raw_get_current_context_x64_systemv_avx512fpu_patch_55_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_56
raw_get_current_context_x64_systemv_avx512fpu_patch_56:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm6
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_56_end
raw_get_current_context_x64_systemv_avx512fpu_patch_56_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_57
raw_get_current_context_x64_systemv_avx512fpu_patch_57:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm7
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_57_end
raw_get_current_context_x64_systemv_avx512fpu_patch_57_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_58
raw_get_current_context_x64_systemv_avx512fpu_patch_58:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm8
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_58_end
raw_get_current_context_x64_systemv_avx512fpu_patch_58_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_59
raw_get_current_context_x64_systemv_avx512fpu_patch_59:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm9
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_59_end
raw_get_current_context_x64_systemv_avx512fpu_patch_59_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_60
raw_get_current_context_x64_systemv_avx512fpu_patch_60:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm10
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_60_end
raw_get_current_context_x64_systemv_avx512fpu_patch_60_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_61
raw_get_current_context_x64_systemv_avx512fpu_patch_61:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm11
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_61_end
raw_get_current_context_x64_systemv_avx512fpu_patch_61_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_62
raw_get_current_context_x64_systemv_avx512fpu_patch_62:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm12
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_62_end
raw_get_current_context_x64_systemv_avx512fpu_patch_62_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_63
raw_get_current_context_x64_systemv_avx512fpu_patch_63:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm13
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_63_end
raw_get_current_context_x64_systemv_avx512fpu_patch_63_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_64
raw_get_current_context_x64_systemv_avx512fpu_patch_64:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm14
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_64_end
raw_get_current_context_x64_systemv_avx512fpu_patch_64_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_65
raw_get_current_context_x64_systemv_avx512fpu_patch_65:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm15
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_65_end
raw_get_current_context_x64_systemv_avx512fpu_patch_65_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_66
raw_get_current_context_x64_systemv_avx512fpu_patch_66:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm16
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_66_end
raw_get_current_context_x64_systemv_avx512fpu_patch_66_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_67
raw_get_current_context_x64_systemv_avx512fpu_patch_67:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm17
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_67_end
raw_get_current_context_x64_systemv_avx512fpu_patch_67_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_68
raw_get_current_context_x64_systemv_avx512fpu_patch_68:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm18
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_68_end
raw_get_current_context_x64_systemv_avx512fpu_patch_68_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_69
raw_get_current_context_x64_systemv_avx512fpu_patch_69:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm19
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_69_end
raw_get_current_context_x64_systemv_avx512fpu_patch_69_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_70
raw_get_current_context_x64_systemv_avx512fpu_patch_70:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm20
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_70_end
raw_get_current_context_x64_systemv_avx512fpu_patch_70_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_71
raw_get_current_context_x64_systemv_avx512fpu_patch_71:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm21
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_71_end
raw_get_current_context_x64_systemv_avx512fpu_patch_71_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_72
raw_get_current_context_x64_systemv_avx512fpu_patch_72:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm22
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_72_end
raw_get_current_context_x64_systemv_avx512fpu_patch_72_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_73
raw_get_current_context_x64_systemv_avx512fpu_patch_73:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm23
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_73_end
raw_get_current_context_x64_systemv_avx512fpu_patch_73_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_74
raw_get_current_context_x64_systemv_avx512fpu_patch_74:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm24
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_74_end
raw_get_current_context_x64_systemv_avx512fpu_patch_74_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_75
raw_get_current_context_x64_systemv_avx512fpu_patch_75:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm25
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_75_end
raw_get_current_context_x64_systemv_avx512fpu_patch_75_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_76
raw_get_current_context_x64_systemv_avx512fpu_patch_76:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm26
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_76_end
raw_get_current_context_x64_systemv_avx512fpu_patch_76_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_77
raw_get_current_context_x64_systemv_avx512fpu_patch_77:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm27
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_77_end
raw_get_current_context_x64_systemv_avx512fpu_patch_77_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_78
raw_get_current_context_x64_systemv_avx512fpu_patch_78:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm28
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_78_end
raw_get_current_context_x64_systemv_avx512fpu_patch_78_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_79
raw_get_current_context_x64_systemv_avx512fpu_patch_79:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm29
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_79_end
raw_get_current_context_x64_systemv_avx512fpu_patch_79_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_80
raw_get_current_context_x64_systemv_avx512fpu_patch_80:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm30
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_80_end
raw_get_current_context_x64_systemv_avx512fpu_patch_80_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_81
raw_get_current_context_x64_systemv_avx512fpu_patch_81:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm31
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_81_end
raw_get_current_context_x64_systemv_avx512fpu_patch_81_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_82
raw_get_current_context_x64_systemv_avx512fpu_patch_82:
	fsave [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_82_end
raw_get_current_context_x64_systemv_avx512fpu_patch_82_end:
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_83
raw_get_current_context_x64_systemv_avx512fpu_patch_83:
	frstor [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_avx512fpu_patch_83_end
raw_get_current_context_x64_systemv_avx512fpu_patch_83_end:
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
	popfq
	ret

# GetCurrentContext: x64 systemv AVX512
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_systemv_avx512
raw_get_current_context_x64_systemv_avx512:
	pushfq
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
	mov r11, qword ptr [rsp + 0x40]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_systemv_avx512_patch_0
raw_get_current_context_x64_systemv_avx512_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_0_end
raw_get_current_context_x64_systemv_avx512_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_systemv_avx512_patch_1
raw_get_current_context_x64_systemv_avx512_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_1_end
raw_get_current_context_x64_systemv_avx512_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_systemv_avx512_patch_2
raw_get_current_context_x64_systemv_avx512_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_2_end
raw_get_current_context_x64_systemv_avx512_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_systemv_avx512_patch_3
raw_get_current_context_x64_systemv_avx512_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_3_end
raw_get_current_context_x64_systemv_avx512_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_systemv_avx512_patch_4
raw_get_current_context_x64_systemv_avx512_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_4_end
raw_get_current_context_x64_systemv_avx512_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_systemv_avx512_patch_5
raw_get_current_context_x64_systemv_avx512_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_5_end
raw_get_current_context_x64_systemv_avx512_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_systemv_avx512_patch_6
raw_get_current_context_x64_systemv_avx512_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_6_end
raw_get_current_context_x64_systemv_avx512_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_systemv_avx512_patch_7
raw_get_current_context_x64_systemv_avx512_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_7_end
raw_get_current_context_x64_systemv_avx512_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_systemv_avx512_patch_8
raw_get_current_context_x64_systemv_avx512_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_8_end
raw_get_current_context_x64_systemv_avx512_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_systemv_avx512_patch_9
raw_get_current_context_x64_systemv_avx512_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_9_end
raw_get_current_context_x64_systemv_avx512_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_systemv_avx512_patch_10
raw_get_current_context_x64_systemv_avx512_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_10_end
raw_get_current_context_x64_systemv_avx512_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_systemv_avx512_patch_11
raw_get_current_context_x64_systemv_avx512_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_11_end
raw_get_current_context_x64_systemv_avx512_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_systemv_avx512_patch_12
raw_get_current_context_x64_systemv_avx512_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_12_end
raw_get_current_context_x64_systemv_avx512_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_systemv_avx512_patch_13
raw_get_current_context_x64_systemv_avx512_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_13_end
raw_get_current_context_x64_systemv_avx512_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_systemv_avx512_patch_14
raw_get_current_context_x64_systemv_avx512_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_14_end
raw_get_current_context_x64_systemv_avx512_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_systemv_avx512_patch_15
raw_get_current_context_x64_systemv_avx512_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_15_end
raw_get_current_context_x64_systemv_avx512_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_systemv_avx512_patch_16
raw_get_current_context_x64_systemv_avx512_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx512_patch_16_end
raw_get_current_context_x64_systemv_avx512_patch_16_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_17
raw_get_current_context_x64_systemv_avx512_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_avx512_patch_17_end
raw_get_current_context_x64_systemv_avx512_patch_17_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_18
raw_get_current_context_x64_systemv_avx512_patch_18:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_systemv_avx512_patch_18_end
raw_get_current_context_x64_systemv_avx512_patch_18_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_19
raw_get_current_context_x64_systemv_avx512_patch_19:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_systemv_avx512_patch_19_end
raw_get_current_context_x64_systemv_avx512_patch_19_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_20
raw_get_current_context_x64_systemv_avx512_patch_20:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_systemv_avx512_patch_20_end
raw_get_current_context_x64_systemv_avx512_patch_20_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_21
raw_get_current_context_x64_systemv_avx512_patch_21:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_systemv_avx512_patch_21_end
raw_get_current_context_x64_systemv_avx512_patch_21_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_22
raw_get_current_context_x64_systemv_avx512_patch_22:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_systemv_avx512_patch_22_end
raw_get_current_context_x64_systemv_avx512_patch_22_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_23
raw_get_current_context_x64_systemv_avx512_patch_23:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_systemv_avx512_patch_23_end
raw_get_current_context_x64_systemv_avx512_patch_23_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_24
raw_get_current_context_x64_systemv_avx512_patch_24:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_systemv_avx512_patch_24_end
raw_get_current_context_x64_systemv_avx512_patch_24_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_25
raw_get_current_context_x64_systemv_avx512_patch_25:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_systemv_avx512_patch_25_end
raw_get_current_context_x64_systemv_avx512_patch_25_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_26
raw_get_current_context_x64_systemv_avx512_patch_26:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_systemv_avx512_patch_26_end
raw_get_current_context_x64_systemv_avx512_patch_26_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_27
raw_get_current_context_x64_systemv_avx512_patch_27:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_systemv_avx512_patch_27_end
raw_get_current_context_x64_systemv_avx512_patch_27_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_28
raw_get_current_context_x64_systemv_avx512_patch_28:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_systemv_avx512_patch_28_end
raw_get_current_context_x64_systemv_avx512_patch_28_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_29
raw_get_current_context_x64_systemv_avx512_patch_29:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_systemv_avx512_patch_29_end
raw_get_current_context_x64_systemv_avx512_patch_29_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_30
raw_get_current_context_x64_systemv_avx512_patch_30:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_systemv_avx512_patch_30_end
raw_get_current_context_x64_systemv_avx512_patch_30_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_31
raw_get_current_context_x64_systemv_avx512_patch_31:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_systemv_avx512_patch_31_end
raw_get_current_context_x64_systemv_avx512_patch_31_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_32
raw_get_current_context_x64_systemv_avx512_patch_32:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_systemv_avx512_patch_32_end
raw_get_current_context_x64_systemv_avx512_patch_32_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_33
raw_get_current_context_x64_systemv_avx512_patch_33:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_systemv_avx512_patch_33_end
raw_get_current_context_x64_systemv_avx512_patch_33_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_34
raw_get_current_context_x64_systemv_avx512_patch_34:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm0
.globl raw_get_current_context_x64_systemv_avx512_patch_34_end
raw_get_current_context_x64_systemv_avx512_patch_34_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_35
raw_get_current_context_x64_systemv_avx512_patch_35:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm1
.globl raw_get_current_context_x64_systemv_avx512_patch_35_end
raw_get_current_context_x64_systemv_avx512_patch_35_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_36
raw_get_current_context_x64_systemv_avx512_patch_36:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm2
.globl raw_get_current_context_x64_systemv_avx512_patch_36_end
raw_get_current_context_x64_systemv_avx512_patch_36_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_37
raw_get_current_context_x64_systemv_avx512_patch_37:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm3
.globl raw_get_current_context_x64_systemv_avx512_patch_37_end
raw_get_current_context_x64_systemv_avx512_patch_37_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_38
raw_get_current_context_x64_systemv_avx512_patch_38:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm4
.globl raw_get_current_context_x64_systemv_avx512_patch_38_end
raw_get_current_context_x64_systemv_avx512_patch_38_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_39
raw_get_current_context_x64_systemv_avx512_patch_39:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm5
.globl raw_get_current_context_x64_systemv_avx512_patch_39_end
raw_get_current_context_x64_systemv_avx512_patch_39_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_40
raw_get_current_context_x64_systemv_avx512_patch_40:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm6
.globl raw_get_current_context_x64_systemv_avx512_patch_40_end
raw_get_current_context_x64_systemv_avx512_patch_40_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_41
raw_get_current_context_x64_systemv_avx512_patch_41:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm7
.globl raw_get_current_context_x64_systemv_avx512_patch_41_end
raw_get_current_context_x64_systemv_avx512_patch_41_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_42
raw_get_current_context_x64_systemv_avx512_patch_42:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm8
.globl raw_get_current_context_x64_systemv_avx512_patch_42_end
raw_get_current_context_x64_systemv_avx512_patch_42_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_43
raw_get_current_context_x64_systemv_avx512_patch_43:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm9
.globl raw_get_current_context_x64_systemv_avx512_patch_43_end
raw_get_current_context_x64_systemv_avx512_patch_43_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_44
raw_get_current_context_x64_systemv_avx512_patch_44:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm10
.globl raw_get_current_context_x64_systemv_avx512_patch_44_end
raw_get_current_context_x64_systemv_avx512_patch_44_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_45
raw_get_current_context_x64_systemv_avx512_patch_45:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm11
.globl raw_get_current_context_x64_systemv_avx512_patch_45_end
raw_get_current_context_x64_systemv_avx512_patch_45_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_46
raw_get_current_context_x64_systemv_avx512_patch_46:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm12
.globl raw_get_current_context_x64_systemv_avx512_patch_46_end
raw_get_current_context_x64_systemv_avx512_patch_46_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_47
raw_get_current_context_x64_systemv_avx512_patch_47:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm13
.globl raw_get_current_context_x64_systemv_avx512_patch_47_end
raw_get_current_context_x64_systemv_avx512_patch_47_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_48
raw_get_current_context_x64_systemv_avx512_patch_48:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm14
.globl raw_get_current_context_x64_systemv_avx512_patch_48_end
raw_get_current_context_x64_systemv_avx512_patch_48_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_49
raw_get_current_context_x64_systemv_avx512_patch_49:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm15
.globl raw_get_current_context_x64_systemv_avx512_patch_49_end
raw_get_current_context_x64_systemv_avx512_patch_49_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_50
raw_get_current_context_x64_systemv_avx512_patch_50:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm0
.globl raw_get_current_context_x64_systemv_avx512_patch_50_end
raw_get_current_context_x64_systemv_avx512_patch_50_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_51
raw_get_current_context_x64_systemv_avx512_patch_51:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm1
.globl raw_get_current_context_x64_systemv_avx512_patch_51_end
raw_get_current_context_x64_systemv_avx512_patch_51_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_52
raw_get_current_context_x64_systemv_avx512_patch_52:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm2
.globl raw_get_current_context_x64_systemv_avx512_patch_52_end
raw_get_current_context_x64_systemv_avx512_patch_52_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_53
raw_get_current_context_x64_systemv_avx512_patch_53:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm3
.globl raw_get_current_context_x64_systemv_avx512_patch_53_end
raw_get_current_context_x64_systemv_avx512_patch_53_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_54
raw_get_current_context_x64_systemv_avx512_patch_54:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm4
.globl raw_get_current_context_x64_systemv_avx512_patch_54_end
raw_get_current_context_x64_systemv_avx512_patch_54_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_55
raw_get_current_context_x64_systemv_avx512_patch_55:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm5
.globl raw_get_current_context_x64_systemv_avx512_patch_55_end
raw_get_current_context_x64_systemv_avx512_patch_55_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_56
raw_get_current_context_x64_systemv_avx512_patch_56:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm6
.globl raw_get_current_context_x64_systemv_avx512_patch_56_end
raw_get_current_context_x64_systemv_avx512_patch_56_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_57
raw_get_current_context_x64_systemv_avx512_patch_57:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm7
.globl raw_get_current_context_x64_systemv_avx512_patch_57_end
raw_get_current_context_x64_systemv_avx512_patch_57_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_58
raw_get_current_context_x64_systemv_avx512_patch_58:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm8
.globl raw_get_current_context_x64_systemv_avx512_patch_58_end
raw_get_current_context_x64_systemv_avx512_patch_58_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_59
raw_get_current_context_x64_systemv_avx512_patch_59:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm9
.globl raw_get_current_context_x64_systemv_avx512_patch_59_end
raw_get_current_context_x64_systemv_avx512_patch_59_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_60
raw_get_current_context_x64_systemv_avx512_patch_60:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm10
.globl raw_get_current_context_x64_systemv_avx512_patch_60_end
raw_get_current_context_x64_systemv_avx512_patch_60_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_61
raw_get_current_context_x64_systemv_avx512_patch_61:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm11
.globl raw_get_current_context_x64_systemv_avx512_patch_61_end
raw_get_current_context_x64_systemv_avx512_patch_61_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_62
raw_get_current_context_x64_systemv_avx512_patch_62:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm12
.globl raw_get_current_context_x64_systemv_avx512_patch_62_end
raw_get_current_context_x64_systemv_avx512_patch_62_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_63
raw_get_current_context_x64_systemv_avx512_patch_63:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm13
.globl raw_get_current_context_x64_systemv_avx512_patch_63_end
raw_get_current_context_x64_systemv_avx512_patch_63_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_64
raw_get_current_context_x64_systemv_avx512_patch_64:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm14
.globl raw_get_current_context_x64_systemv_avx512_patch_64_end
raw_get_current_context_x64_systemv_avx512_patch_64_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_65
raw_get_current_context_x64_systemv_avx512_patch_65:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm15
.globl raw_get_current_context_x64_systemv_avx512_patch_65_end
raw_get_current_context_x64_systemv_avx512_patch_65_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_66
raw_get_current_context_x64_systemv_avx512_patch_66:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm16
.globl raw_get_current_context_x64_systemv_avx512_patch_66_end
raw_get_current_context_x64_systemv_avx512_patch_66_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_67
raw_get_current_context_x64_systemv_avx512_patch_67:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm17
.globl raw_get_current_context_x64_systemv_avx512_patch_67_end
raw_get_current_context_x64_systemv_avx512_patch_67_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_68
raw_get_current_context_x64_systemv_avx512_patch_68:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm18
.globl raw_get_current_context_x64_systemv_avx512_patch_68_end
raw_get_current_context_x64_systemv_avx512_patch_68_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_69
raw_get_current_context_x64_systemv_avx512_patch_69:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm19
.globl raw_get_current_context_x64_systemv_avx512_patch_69_end
raw_get_current_context_x64_systemv_avx512_patch_69_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_70
raw_get_current_context_x64_systemv_avx512_patch_70:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm20
.globl raw_get_current_context_x64_systemv_avx512_patch_70_end
raw_get_current_context_x64_systemv_avx512_patch_70_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_71
raw_get_current_context_x64_systemv_avx512_patch_71:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm21
.globl raw_get_current_context_x64_systemv_avx512_patch_71_end
raw_get_current_context_x64_systemv_avx512_patch_71_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_72
raw_get_current_context_x64_systemv_avx512_patch_72:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm22
.globl raw_get_current_context_x64_systemv_avx512_patch_72_end
raw_get_current_context_x64_systemv_avx512_patch_72_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_73
raw_get_current_context_x64_systemv_avx512_patch_73:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm23
.globl raw_get_current_context_x64_systemv_avx512_patch_73_end
raw_get_current_context_x64_systemv_avx512_patch_73_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_74
raw_get_current_context_x64_systemv_avx512_patch_74:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm24
.globl raw_get_current_context_x64_systemv_avx512_patch_74_end
raw_get_current_context_x64_systemv_avx512_patch_74_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_75
raw_get_current_context_x64_systemv_avx512_patch_75:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm25
.globl raw_get_current_context_x64_systemv_avx512_patch_75_end
raw_get_current_context_x64_systemv_avx512_patch_75_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_76
raw_get_current_context_x64_systemv_avx512_patch_76:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm26
.globl raw_get_current_context_x64_systemv_avx512_patch_76_end
raw_get_current_context_x64_systemv_avx512_patch_76_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_77
raw_get_current_context_x64_systemv_avx512_patch_77:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm27
.globl raw_get_current_context_x64_systemv_avx512_patch_77_end
raw_get_current_context_x64_systemv_avx512_patch_77_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_78
raw_get_current_context_x64_systemv_avx512_patch_78:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm28
.globl raw_get_current_context_x64_systemv_avx512_patch_78_end
raw_get_current_context_x64_systemv_avx512_patch_78_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_79
raw_get_current_context_x64_systemv_avx512_patch_79:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm29
.globl raw_get_current_context_x64_systemv_avx512_patch_79_end
raw_get_current_context_x64_systemv_avx512_patch_79_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_80
raw_get_current_context_x64_systemv_avx512_patch_80:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm30
.globl raw_get_current_context_x64_systemv_avx512_patch_80_end
raw_get_current_context_x64_systemv_avx512_patch_80_end:
.globl raw_get_current_context_x64_systemv_avx512_patch_81
raw_get_current_context_x64_systemv_avx512_patch_81:
	vmovups zmmword ptr [r11 + 0x7fffffff], zmm31
.globl raw_get_current_context_x64_systemv_avx512_patch_81_end
raw_get_current_context_x64_systemv_avx512_patch_81_end:
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
	popfq
	ret

# GetCurrentContext: x64 systemv AVXFPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_systemv_avxfpu
raw_get_current_context_x64_systemv_avxfpu:
	pushfq
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
	mov r11, qword ptr [rsp + 0x40]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_0
raw_get_current_context_x64_systemv_avxfpu_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_0_end
raw_get_current_context_x64_systemv_avxfpu_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_1
raw_get_current_context_x64_systemv_avxfpu_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_1_end
raw_get_current_context_x64_systemv_avxfpu_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_2
raw_get_current_context_x64_systemv_avxfpu_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_2_end
raw_get_current_context_x64_systemv_avxfpu_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_3
raw_get_current_context_x64_systemv_avxfpu_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_3_end
raw_get_current_context_x64_systemv_avxfpu_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_4
raw_get_current_context_x64_systemv_avxfpu_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_4_end
raw_get_current_context_x64_systemv_avxfpu_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_5
raw_get_current_context_x64_systemv_avxfpu_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_5_end
raw_get_current_context_x64_systemv_avxfpu_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_6
raw_get_current_context_x64_systemv_avxfpu_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_6_end
raw_get_current_context_x64_systemv_avxfpu_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_7
raw_get_current_context_x64_systemv_avxfpu_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_7_end
raw_get_current_context_x64_systemv_avxfpu_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_8
raw_get_current_context_x64_systemv_avxfpu_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_8_end
raw_get_current_context_x64_systemv_avxfpu_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_9
raw_get_current_context_x64_systemv_avxfpu_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_9_end
raw_get_current_context_x64_systemv_avxfpu_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_10
raw_get_current_context_x64_systemv_avxfpu_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_10_end
raw_get_current_context_x64_systemv_avxfpu_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_11
raw_get_current_context_x64_systemv_avxfpu_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_11_end
raw_get_current_context_x64_systemv_avxfpu_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_12
raw_get_current_context_x64_systemv_avxfpu_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_12_end
raw_get_current_context_x64_systemv_avxfpu_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_13
raw_get_current_context_x64_systemv_avxfpu_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_13_end
raw_get_current_context_x64_systemv_avxfpu_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_14
raw_get_current_context_x64_systemv_avxfpu_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_14_end
raw_get_current_context_x64_systemv_avxfpu_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_15
raw_get_current_context_x64_systemv_avxfpu_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_15_end
raw_get_current_context_x64_systemv_avxfpu_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_16
raw_get_current_context_x64_systemv_avxfpu_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_16_end
raw_get_current_context_x64_systemv_avxfpu_patch_16_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_17
raw_get_current_context_x64_systemv_avxfpu_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_17_end
raw_get_current_context_x64_systemv_avxfpu_patch_17_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_18
raw_get_current_context_x64_systemv_avxfpu_patch_18:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_systemv_avxfpu_patch_18_end
raw_get_current_context_x64_systemv_avxfpu_patch_18_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_19
raw_get_current_context_x64_systemv_avxfpu_patch_19:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_systemv_avxfpu_patch_19_end
raw_get_current_context_x64_systemv_avxfpu_patch_19_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_20
raw_get_current_context_x64_systemv_avxfpu_patch_20:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_systemv_avxfpu_patch_20_end
raw_get_current_context_x64_systemv_avxfpu_patch_20_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_21
raw_get_current_context_x64_systemv_avxfpu_patch_21:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_systemv_avxfpu_patch_21_end
raw_get_current_context_x64_systemv_avxfpu_patch_21_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_22
raw_get_current_context_x64_systemv_avxfpu_patch_22:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_systemv_avxfpu_patch_22_end
raw_get_current_context_x64_systemv_avxfpu_patch_22_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_23
raw_get_current_context_x64_systemv_avxfpu_patch_23:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_systemv_avxfpu_patch_23_end
raw_get_current_context_x64_systemv_avxfpu_patch_23_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_24
raw_get_current_context_x64_systemv_avxfpu_patch_24:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_systemv_avxfpu_patch_24_end
raw_get_current_context_x64_systemv_avxfpu_patch_24_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_25
raw_get_current_context_x64_systemv_avxfpu_patch_25:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_systemv_avxfpu_patch_25_end
raw_get_current_context_x64_systemv_avxfpu_patch_25_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_26
raw_get_current_context_x64_systemv_avxfpu_patch_26:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_systemv_avxfpu_patch_26_end
raw_get_current_context_x64_systemv_avxfpu_patch_26_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_27
raw_get_current_context_x64_systemv_avxfpu_patch_27:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_systemv_avxfpu_patch_27_end
raw_get_current_context_x64_systemv_avxfpu_patch_27_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_28
raw_get_current_context_x64_systemv_avxfpu_patch_28:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_28_end
raw_get_current_context_x64_systemv_avxfpu_patch_28_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_29
raw_get_current_context_x64_systemv_avxfpu_patch_29:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_systemv_avxfpu_patch_29_end
raw_get_current_context_x64_systemv_avxfpu_patch_29_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_30
raw_get_current_context_x64_systemv_avxfpu_patch_30:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_systemv_avxfpu_patch_30_end
raw_get_current_context_x64_systemv_avxfpu_patch_30_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_31
raw_get_current_context_x64_systemv_avxfpu_patch_31:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_systemv_avxfpu_patch_31_end
raw_get_current_context_x64_systemv_avxfpu_patch_31_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_32
raw_get_current_context_x64_systemv_avxfpu_patch_32:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_systemv_avxfpu_patch_32_end
raw_get_current_context_x64_systemv_avxfpu_patch_32_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_33
raw_get_current_context_x64_systemv_avxfpu_patch_33:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_systemv_avxfpu_patch_33_end
raw_get_current_context_x64_systemv_avxfpu_patch_33_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_34
raw_get_current_context_x64_systemv_avxfpu_patch_34:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm0
.globl raw_get_current_context_x64_systemv_avxfpu_patch_34_end
raw_get_current_context_x64_systemv_avxfpu_patch_34_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_35
raw_get_current_context_x64_systemv_avxfpu_patch_35:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm1
.globl raw_get_current_context_x64_systemv_avxfpu_patch_35_end
raw_get_current_context_x64_systemv_avxfpu_patch_35_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_36
raw_get_current_context_x64_systemv_avxfpu_patch_36:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm2
.globl raw_get_current_context_x64_systemv_avxfpu_patch_36_end
raw_get_current_context_x64_systemv_avxfpu_patch_36_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_37
raw_get_current_context_x64_systemv_avxfpu_patch_37:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm3
.globl raw_get_current_context_x64_systemv_avxfpu_patch_37_end
raw_get_current_context_x64_systemv_avxfpu_patch_37_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_38
raw_get_current_context_x64_systemv_avxfpu_patch_38:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm4
.globl raw_get_current_context_x64_systemv_avxfpu_patch_38_end
raw_get_current_context_x64_systemv_avxfpu_patch_38_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_39
raw_get_current_context_x64_systemv_avxfpu_patch_39:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm5
.globl raw_get_current_context_x64_systemv_avxfpu_patch_39_end
raw_get_current_context_x64_systemv_avxfpu_patch_39_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_40
raw_get_current_context_x64_systemv_avxfpu_patch_40:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm6
.globl raw_get_current_context_x64_systemv_avxfpu_patch_40_end
raw_get_current_context_x64_systemv_avxfpu_patch_40_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_41
raw_get_current_context_x64_systemv_avxfpu_patch_41:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm7
.globl raw_get_current_context_x64_systemv_avxfpu_patch_41_end
raw_get_current_context_x64_systemv_avxfpu_patch_41_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_42
raw_get_current_context_x64_systemv_avxfpu_patch_42:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm8
.globl raw_get_current_context_x64_systemv_avxfpu_patch_42_end
raw_get_current_context_x64_systemv_avxfpu_patch_42_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_43
raw_get_current_context_x64_systemv_avxfpu_patch_43:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm9
.globl raw_get_current_context_x64_systemv_avxfpu_patch_43_end
raw_get_current_context_x64_systemv_avxfpu_patch_43_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_44
raw_get_current_context_x64_systemv_avxfpu_patch_44:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm10
.globl raw_get_current_context_x64_systemv_avxfpu_patch_44_end
raw_get_current_context_x64_systemv_avxfpu_patch_44_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_45
raw_get_current_context_x64_systemv_avxfpu_patch_45:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm11
.globl raw_get_current_context_x64_systemv_avxfpu_patch_45_end
raw_get_current_context_x64_systemv_avxfpu_patch_45_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_46
raw_get_current_context_x64_systemv_avxfpu_patch_46:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm12
.globl raw_get_current_context_x64_systemv_avxfpu_patch_46_end
raw_get_current_context_x64_systemv_avxfpu_patch_46_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_47
raw_get_current_context_x64_systemv_avxfpu_patch_47:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm13
.globl raw_get_current_context_x64_systemv_avxfpu_patch_47_end
raw_get_current_context_x64_systemv_avxfpu_patch_47_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_48
raw_get_current_context_x64_systemv_avxfpu_patch_48:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm14
.globl raw_get_current_context_x64_systemv_avxfpu_patch_48_end
raw_get_current_context_x64_systemv_avxfpu_patch_48_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_49
raw_get_current_context_x64_systemv_avxfpu_patch_49:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm15
.globl raw_get_current_context_x64_systemv_avxfpu_patch_49_end
raw_get_current_context_x64_systemv_avxfpu_patch_49_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_50
raw_get_current_context_x64_systemv_avxfpu_patch_50:
	fsave [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_50_end
raw_get_current_context_x64_systemv_avxfpu_patch_50_end:
.globl raw_get_current_context_x64_systemv_avxfpu_patch_51
raw_get_current_context_x64_systemv_avxfpu_patch_51:
	frstor [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_avxfpu_patch_51_end
raw_get_current_context_x64_systemv_avxfpu_patch_51_end:
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
	popfq
	ret

# GetCurrentContext: x64 systemv AVX
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_systemv_avx
raw_get_current_context_x64_systemv_avx:
	pushfq
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
	mov r11, qword ptr [rsp + 0x40]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_systemv_avx_patch_0
raw_get_current_context_x64_systemv_avx_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_0_end
raw_get_current_context_x64_systemv_avx_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_systemv_avx_patch_1
raw_get_current_context_x64_systemv_avx_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_1_end
raw_get_current_context_x64_systemv_avx_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_systemv_avx_patch_2
raw_get_current_context_x64_systemv_avx_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_2_end
raw_get_current_context_x64_systemv_avx_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_systemv_avx_patch_3
raw_get_current_context_x64_systemv_avx_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_3_end
raw_get_current_context_x64_systemv_avx_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_systemv_avx_patch_4
raw_get_current_context_x64_systemv_avx_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_4_end
raw_get_current_context_x64_systemv_avx_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_systemv_avx_patch_5
raw_get_current_context_x64_systemv_avx_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_5_end
raw_get_current_context_x64_systemv_avx_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_systemv_avx_patch_6
raw_get_current_context_x64_systemv_avx_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_6_end
raw_get_current_context_x64_systemv_avx_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_systemv_avx_patch_7
raw_get_current_context_x64_systemv_avx_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_7_end
raw_get_current_context_x64_systemv_avx_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_systemv_avx_patch_8
raw_get_current_context_x64_systemv_avx_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_8_end
raw_get_current_context_x64_systemv_avx_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_systemv_avx_patch_9
raw_get_current_context_x64_systemv_avx_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_9_end
raw_get_current_context_x64_systemv_avx_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_systemv_avx_patch_10
raw_get_current_context_x64_systemv_avx_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_10_end
raw_get_current_context_x64_systemv_avx_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_systemv_avx_patch_11
raw_get_current_context_x64_systemv_avx_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_11_end
raw_get_current_context_x64_systemv_avx_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_systemv_avx_patch_12
raw_get_current_context_x64_systemv_avx_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_12_end
raw_get_current_context_x64_systemv_avx_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_systemv_avx_patch_13
raw_get_current_context_x64_systemv_avx_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_13_end
raw_get_current_context_x64_systemv_avx_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_systemv_avx_patch_14
raw_get_current_context_x64_systemv_avx_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_14_end
raw_get_current_context_x64_systemv_avx_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_systemv_avx_patch_15
raw_get_current_context_x64_systemv_avx_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_15_end
raw_get_current_context_x64_systemv_avx_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_systemv_avx_patch_16
raw_get_current_context_x64_systemv_avx_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_avx_patch_16_end
raw_get_current_context_x64_systemv_avx_patch_16_end:
.globl raw_get_current_context_x64_systemv_avx_patch_17
raw_get_current_context_x64_systemv_avx_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_avx_patch_17_end
raw_get_current_context_x64_systemv_avx_patch_17_end:
.globl raw_get_current_context_x64_systemv_avx_patch_18
raw_get_current_context_x64_systemv_avx_patch_18:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_systemv_avx_patch_18_end
raw_get_current_context_x64_systemv_avx_patch_18_end:
.globl raw_get_current_context_x64_systemv_avx_patch_19
raw_get_current_context_x64_systemv_avx_patch_19:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_systemv_avx_patch_19_end
raw_get_current_context_x64_systemv_avx_patch_19_end:
.globl raw_get_current_context_x64_systemv_avx_patch_20
raw_get_current_context_x64_systemv_avx_patch_20:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_systemv_avx_patch_20_end
raw_get_current_context_x64_systemv_avx_patch_20_end:
.globl raw_get_current_context_x64_systemv_avx_patch_21
raw_get_current_context_x64_systemv_avx_patch_21:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_systemv_avx_patch_21_end
raw_get_current_context_x64_systemv_avx_patch_21_end:
.globl raw_get_current_context_x64_systemv_avx_patch_22
raw_get_current_context_x64_systemv_avx_patch_22:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_systemv_avx_patch_22_end
raw_get_current_context_x64_systemv_avx_patch_22_end:
.globl raw_get_current_context_x64_systemv_avx_patch_23
raw_get_current_context_x64_systemv_avx_patch_23:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_systemv_avx_patch_23_end
raw_get_current_context_x64_systemv_avx_patch_23_end:
.globl raw_get_current_context_x64_systemv_avx_patch_24
raw_get_current_context_x64_systemv_avx_patch_24:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_systemv_avx_patch_24_end
raw_get_current_context_x64_systemv_avx_patch_24_end:
.globl raw_get_current_context_x64_systemv_avx_patch_25
raw_get_current_context_x64_systemv_avx_patch_25:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_systemv_avx_patch_25_end
raw_get_current_context_x64_systemv_avx_patch_25_end:
.globl raw_get_current_context_x64_systemv_avx_patch_26
raw_get_current_context_x64_systemv_avx_patch_26:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_systemv_avx_patch_26_end
raw_get_current_context_x64_systemv_avx_patch_26_end:
.globl raw_get_current_context_x64_systemv_avx_patch_27
raw_get_current_context_x64_systemv_avx_patch_27:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_systemv_avx_patch_27_end
raw_get_current_context_x64_systemv_avx_patch_27_end:
.globl raw_get_current_context_x64_systemv_avx_patch_28
raw_get_current_context_x64_systemv_avx_patch_28:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_systemv_avx_patch_28_end
raw_get_current_context_x64_systemv_avx_patch_28_end:
.globl raw_get_current_context_x64_systemv_avx_patch_29
raw_get_current_context_x64_systemv_avx_patch_29:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_systemv_avx_patch_29_end
raw_get_current_context_x64_systemv_avx_patch_29_end:
.globl raw_get_current_context_x64_systemv_avx_patch_30
raw_get_current_context_x64_systemv_avx_patch_30:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_systemv_avx_patch_30_end
raw_get_current_context_x64_systemv_avx_patch_30_end:
.globl raw_get_current_context_x64_systemv_avx_patch_31
raw_get_current_context_x64_systemv_avx_patch_31:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_systemv_avx_patch_31_end
raw_get_current_context_x64_systemv_avx_patch_31_end:
.globl raw_get_current_context_x64_systemv_avx_patch_32
raw_get_current_context_x64_systemv_avx_patch_32:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_systemv_avx_patch_32_end
raw_get_current_context_x64_systemv_avx_patch_32_end:
.globl raw_get_current_context_x64_systemv_avx_patch_33
raw_get_current_context_x64_systemv_avx_patch_33:
	vmovups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_systemv_avx_patch_33_end
raw_get_current_context_x64_systemv_avx_patch_33_end:
.globl raw_get_current_context_x64_systemv_avx_patch_34
raw_get_current_context_x64_systemv_avx_patch_34:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm0
.globl raw_get_current_context_x64_systemv_avx_patch_34_end
raw_get_current_context_x64_systemv_avx_patch_34_end:
.globl raw_get_current_context_x64_systemv_avx_patch_35
raw_get_current_context_x64_systemv_avx_patch_35:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm1
.globl raw_get_current_context_x64_systemv_avx_patch_35_end
raw_get_current_context_x64_systemv_avx_patch_35_end:
.globl raw_get_current_context_x64_systemv_avx_patch_36
raw_get_current_context_x64_systemv_avx_patch_36:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm2
.globl raw_get_current_context_x64_systemv_avx_patch_36_end
raw_get_current_context_x64_systemv_avx_patch_36_end:
.globl raw_get_current_context_x64_systemv_avx_patch_37
raw_get_current_context_x64_systemv_avx_patch_37:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm3
.globl raw_get_current_context_x64_systemv_avx_patch_37_end
raw_get_current_context_x64_systemv_avx_patch_37_end:
.globl raw_get_current_context_x64_systemv_avx_patch_38
raw_get_current_context_x64_systemv_avx_patch_38:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm4
.globl raw_get_current_context_x64_systemv_avx_patch_38_end
raw_get_current_context_x64_systemv_avx_patch_38_end:
.globl raw_get_current_context_x64_systemv_avx_patch_39
raw_get_current_context_x64_systemv_avx_patch_39:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm5
.globl raw_get_current_context_x64_systemv_avx_patch_39_end
raw_get_current_context_x64_systemv_avx_patch_39_end:
.globl raw_get_current_context_x64_systemv_avx_patch_40
raw_get_current_context_x64_systemv_avx_patch_40:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm6
.globl raw_get_current_context_x64_systemv_avx_patch_40_end
raw_get_current_context_x64_systemv_avx_patch_40_end:
.globl raw_get_current_context_x64_systemv_avx_patch_41
raw_get_current_context_x64_systemv_avx_patch_41:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm7
.globl raw_get_current_context_x64_systemv_avx_patch_41_end
raw_get_current_context_x64_systemv_avx_patch_41_end:
.globl raw_get_current_context_x64_systemv_avx_patch_42
raw_get_current_context_x64_systemv_avx_patch_42:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm8
.globl raw_get_current_context_x64_systemv_avx_patch_42_end
raw_get_current_context_x64_systemv_avx_patch_42_end:
.globl raw_get_current_context_x64_systemv_avx_patch_43
raw_get_current_context_x64_systemv_avx_patch_43:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm9
.globl raw_get_current_context_x64_systemv_avx_patch_43_end
raw_get_current_context_x64_systemv_avx_patch_43_end:
.globl raw_get_current_context_x64_systemv_avx_patch_44
raw_get_current_context_x64_systemv_avx_patch_44:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm10
.globl raw_get_current_context_x64_systemv_avx_patch_44_end
raw_get_current_context_x64_systemv_avx_patch_44_end:
.globl raw_get_current_context_x64_systemv_avx_patch_45
raw_get_current_context_x64_systemv_avx_patch_45:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm11
.globl raw_get_current_context_x64_systemv_avx_patch_45_end
raw_get_current_context_x64_systemv_avx_patch_45_end:
.globl raw_get_current_context_x64_systemv_avx_patch_46
raw_get_current_context_x64_systemv_avx_patch_46:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm12
.globl raw_get_current_context_x64_systemv_avx_patch_46_end
raw_get_current_context_x64_systemv_avx_patch_46_end:
.globl raw_get_current_context_x64_systemv_avx_patch_47
raw_get_current_context_x64_systemv_avx_patch_47:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm13
.globl raw_get_current_context_x64_systemv_avx_patch_47_end
raw_get_current_context_x64_systemv_avx_patch_47_end:
.globl raw_get_current_context_x64_systemv_avx_patch_48
raw_get_current_context_x64_systemv_avx_patch_48:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm14
.globl raw_get_current_context_x64_systemv_avx_patch_48_end
raw_get_current_context_x64_systemv_avx_patch_48_end:
.globl raw_get_current_context_x64_systemv_avx_patch_49
raw_get_current_context_x64_systemv_avx_patch_49:
	vmovups ymmword ptr [r11 + 0x7fffffff], ymm15
.globl raw_get_current_context_x64_systemv_avx_patch_49_end
raw_get_current_context_x64_systemv_avx_patch_49_end:
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
	popfq
	ret

# GetCurrentContext: x64 systemv SSEFPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_systemv_ssefpu
raw_get_current_context_x64_systemv_ssefpu:
	pushfq
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
	mov r11, qword ptr [rsp + 0x40]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_0
raw_get_current_context_x64_systemv_ssefpu_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_0_end
raw_get_current_context_x64_systemv_ssefpu_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_1
raw_get_current_context_x64_systemv_ssefpu_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_1_end
raw_get_current_context_x64_systemv_ssefpu_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_2
raw_get_current_context_x64_systemv_ssefpu_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_2_end
raw_get_current_context_x64_systemv_ssefpu_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_3
raw_get_current_context_x64_systemv_ssefpu_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_3_end
raw_get_current_context_x64_systemv_ssefpu_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_4
raw_get_current_context_x64_systemv_ssefpu_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_4_end
raw_get_current_context_x64_systemv_ssefpu_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_5
raw_get_current_context_x64_systemv_ssefpu_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_5_end
raw_get_current_context_x64_systemv_ssefpu_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_6
raw_get_current_context_x64_systemv_ssefpu_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_6_end
raw_get_current_context_x64_systemv_ssefpu_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_7
raw_get_current_context_x64_systemv_ssefpu_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_7_end
raw_get_current_context_x64_systemv_ssefpu_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_8
raw_get_current_context_x64_systemv_ssefpu_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_8_end
raw_get_current_context_x64_systemv_ssefpu_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_9
raw_get_current_context_x64_systemv_ssefpu_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_9_end
raw_get_current_context_x64_systemv_ssefpu_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_10
raw_get_current_context_x64_systemv_ssefpu_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_10_end
raw_get_current_context_x64_systemv_ssefpu_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_11
raw_get_current_context_x64_systemv_ssefpu_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_11_end
raw_get_current_context_x64_systemv_ssefpu_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_12
raw_get_current_context_x64_systemv_ssefpu_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_12_end
raw_get_current_context_x64_systemv_ssefpu_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_13
raw_get_current_context_x64_systemv_ssefpu_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_13_end
raw_get_current_context_x64_systemv_ssefpu_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_14
raw_get_current_context_x64_systemv_ssefpu_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_14_end
raw_get_current_context_x64_systemv_ssefpu_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_15
raw_get_current_context_x64_systemv_ssefpu_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_15_end
raw_get_current_context_x64_systemv_ssefpu_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_16
raw_get_current_context_x64_systemv_ssefpu_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_16_end
raw_get_current_context_x64_systemv_ssefpu_patch_16_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_17
raw_get_current_context_x64_systemv_ssefpu_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_17_end
raw_get_current_context_x64_systemv_ssefpu_patch_17_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_18
raw_get_current_context_x64_systemv_ssefpu_patch_18:
	movups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_systemv_ssefpu_patch_18_end
raw_get_current_context_x64_systemv_ssefpu_patch_18_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_19
raw_get_current_context_x64_systemv_ssefpu_patch_19:
	movups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_systemv_ssefpu_patch_19_end
raw_get_current_context_x64_systemv_ssefpu_patch_19_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_20
raw_get_current_context_x64_systemv_ssefpu_patch_20:
	movups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_systemv_ssefpu_patch_20_end
raw_get_current_context_x64_systemv_ssefpu_patch_20_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_21
raw_get_current_context_x64_systemv_ssefpu_patch_21:
	movups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_systemv_ssefpu_patch_21_end
raw_get_current_context_x64_systemv_ssefpu_patch_21_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_22
raw_get_current_context_x64_systemv_ssefpu_patch_22:
	movups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_systemv_ssefpu_patch_22_end
raw_get_current_context_x64_systemv_ssefpu_patch_22_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_23
raw_get_current_context_x64_systemv_ssefpu_patch_23:
	movups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_systemv_ssefpu_patch_23_end
raw_get_current_context_x64_systemv_ssefpu_patch_23_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_24
raw_get_current_context_x64_systemv_ssefpu_patch_24:
	movups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_systemv_ssefpu_patch_24_end
raw_get_current_context_x64_systemv_ssefpu_patch_24_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_25
raw_get_current_context_x64_systemv_ssefpu_patch_25:
	movups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_systemv_ssefpu_patch_25_end
raw_get_current_context_x64_systemv_ssefpu_patch_25_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_26
raw_get_current_context_x64_systemv_ssefpu_patch_26:
	movups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_systemv_ssefpu_patch_26_end
raw_get_current_context_x64_systemv_ssefpu_patch_26_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_27
raw_get_current_context_x64_systemv_ssefpu_patch_27:
	movups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_systemv_ssefpu_patch_27_end
raw_get_current_context_x64_systemv_ssefpu_patch_27_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_28
raw_get_current_context_x64_systemv_ssefpu_patch_28:
	movups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_systemv_ssefpu_patch_28_end
raw_get_current_context_x64_systemv_ssefpu_patch_28_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_29
raw_get_current_context_x64_systemv_ssefpu_patch_29:
	movups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_systemv_ssefpu_patch_29_end
raw_get_current_context_x64_systemv_ssefpu_patch_29_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_30
raw_get_current_context_x64_systemv_ssefpu_patch_30:
	movups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_systemv_ssefpu_patch_30_end
raw_get_current_context_x64_systemv_ssefpu_patch_30_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_31
raw_get_current_context_x64_systemv_ssefpu_patch_31:
	movups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_systemv_ssefpu_patch_31_end
raw_get_current_context_x64_systemv_ssefpu_patch_31_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_32
raw_get_current_context_x64_systemv_ssefpu_patch_32:
	movups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_systemv_ssefpu_patch_32_end
raw_get_current_context_x64_systemv_ssefpu_patch_32_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_33
raw_get_current_context_x64_systemv_ssefpu_patch_33:
	movups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_systemv_ssefpu_patch_33_end
raw_get_current_context_x64_systemv_ssefpu_patch_33_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_34
raw_get_current_context_x64_systemv_ssefpu_patch_34:
	fsave [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_34_end
raw_get_current_context_x64_systemv_ssefpu_patch_34_end:
.globl raw_get_current_context_x64_systemv_ssefpu_patch_35
raw_get_current_context_x64_systemv_ssefpu_patch_35:
	frstor [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_ssefpu_patch_35_end
raw_get_current_context_x64_systemv_ssefpu_patch_35_end:
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
	popfq
	ret

# GetCurrentContext: x64 systemv SSE
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_systemv_sse
raw_get_current_context_x64_systemv_sse:
	pushfq
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
	mov r11, qword ptr [rsp + 0x40]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_systemv_sse_patch_0
raw_get_current_context_x64_systemv_sse_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_0_end
raw_get_current_context_x64_systemv_sse_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_systemv_sse_patch_1
raw_get_current_context_x64_systemv_sse_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_1_end
raw_get_current_context_x64_systemv_sse_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_systemv_sse_patch_2
raw_get_current_context_x64_systemv_sse_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_2_end
raw_get_current_context_x64_systemv_sse_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_systemv_sse_patch_3
raw_get_current_context_x64_systemv_sse_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_3_end
raw_get_current_context_x64_systemv_sse_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_systemv_sse_patch_4
raw_get_current_context_x64_systemv_sse_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_4_end
raw_get_current_context_x64_systemv_sse_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_systemv_sse_patch_5
raw_get_current_context_x64_systemv_sse_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_5_end
raw_get_current_context_x64_systemv_sse_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_systemv_sse_patch_6
raw_get_current_context_x64_systemv_sse_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_6_end
raw_get_current_context_x64_systemv_sse_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_systemv_sse_patch_7
raw_get_current_context_x64_systemv_sse_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_7_end
raw_get_current_context_x64_systemv_sse_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_systemv_sse_patch_8
raw_get_current_context_x64_systemv_sse_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_8_end
raw_get_current_context_x64_systemv_sse_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_systemv_sse_patch_9
raw_get_current_context_x64_systemv_sse_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_9_end
raw_get_current_context_x64_systemv_sse_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_systemv_sse_patch_10
raw_get_current_context_x64_systemv_sse_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_10_end
raw_get_current_context_x64_systemv_sse_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_systemv_sse_patch_11
raw_get_current_context_x64_systemv_sse_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_11_end
raw_get_current_context_x64_systemv_sse_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_systemv_sse_patch_12
raw_get_current_context_x64_systemv_sse_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_12_end
raw_get_current_context_x64_systemv_sse_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_systemv_sse_patch_13
raw_get_current_context_x64_systemv_sse_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_13_end
raw_get_current_context_x64_systemv_sse_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_systemv_sse_patch_14
raw_get_current_context_x64_systemv_sse_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_14_end
raw_get_current_context_x64_systemv_sse_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_systemv_sse_patch_15
raw_get_current_context_x64_systemv_sse_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_15_end
raw_get_current_context_x64_systemv_sse_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_systemv_sse_patch_16
raw_get_current_context_x64_systemv_sse_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_sse_patch_16_end
raw_get_current_context_x64_systemv_sse_patch_16_end:
.globl raw_get_current_context_x64_systemv_sse_patch_17
raw_get_current_context_x64_systemv_sse_patch_17:
	stmxcsr dword ptr [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_sse_patch_17_end
raw_get_current_context_x64_systemv_sse_patch_17_end:
.globl raw_get_current_context_x64_systemv_sse_patch_18
raw_get_current_context_x64_systemv_sse_patch_18:
	movups xmmword ptr [r11 + 0x7fffffff], xmm0
.globl raw_get_current_context_x64_systemv_sse_patch_18_end
raw_get_current_context_x64_systemv_sse_patch_18_end:
.globl raw_get_current_context_x64_systemv_sse_patch_19
raw_get_current_context_x64_systemv_sse_patch_19:
	movups xmmword ptr [r11 + 0x7fffffff], xmm1
.globl raw_get_current_context_x64_systemv_sse_patch_19_end
raw_get_current_context_x64_systemv_sse_patch_19_end:
.globl raw_get_current_context_x64_systemv_sse_patch_20
raw_get_current_context_x64_systemv_sse_patch_20:
	movups xmmword ptr [r11 + 0x7fffffff], xmm2
.globl raw_get_current_context_x64_systemv_sse_patch_20_end
raw_get_current_context_x64_systemv_sse_patch_20_end:
.globl raw_get_current_context_x64_systemv_sse_patch_21
raw_get_current_context_x64_systemv_sse_patch_21:
	movups xmmword ptr [r11 + 0x7fffffff], xmm3
.globl raw_get_current_context_x64_systemv_sse_patch_21_end
raw_get_current_context_x64_systemv_sse_patch_21_end:
.globl raw_get_current_context_x64_systemv_sse_patch_22
raw_get_current_context_x64_systemv_sse_patch_22:
	movups xmmword ptr [r11 + 0x7fffffff], xmm4
.globl raw_get_current_context_x64_systemv_sse_patch_22_end
raw_get_current_context_x64_systemv_sse_patch_22_end:
.globl raw_get_current_context_x64_systemv_sse_patch_23
raw_get_current_context_x64_systemv_sse_patch_23:
	movups xmmword ptr [r11 + 0x7fffffff], xmm5
.globl raw_get_current_context_x64_systemv_sse_patch_23_end
raw_get_current_context_x64_systemv_sse_patch_23_end:
.globl raw_get_current_context_x64_systemv_sse_patch_24
raw_get_current_context_x64_systemv_sse_patch_24:
	movups xmmword ptr [r11 + 0x7fffffff], xmm6
.globl raw_get_current_context_x64_systemv_sse_patch_24_end
raw_get_current_context_x64_systemv_sse_patch_24_end:
.globl raw_get_current_context_x64_systemv_sse_patch_25
raw_get_current_context_x64_systemv_sse_patch_25:
	movups xmmword ptr [r11 + 0x7fffffff], xmm7
.globl raw_get_current_context_x64_systemv_sse_patch_25_end
raw_get_current_context_x64_systemv_sse_patch_25_end:
.globl raw_get_current_context_x64_systemv_sse_patch_26
raw_get_current_context_x64_systemv_sse_patch_26:
	movups xmmword ptr [r11 + 0x7fffffff], xmm8
.globl raw_get_current_context_x64_systemv_sse_patch_26_end
raw_get_current_context_x64_systemv_sse_patch_26_end:
.globl raw_get_current_context_x64_systemv_sse_patch_27
raw_get_current_context_x64_systemv_sse_patch_27:
	movups xmmword ptr [r11 + 0x7fffffff], xmm9
.globl raw_get_current_context_x64_systemv_sse_patch_27_end
raw_get_current_context_x64_systemv_sse_patch_27_end:
.globl raw_get_current_context_x64_systemv_sse_patch_28
raw_get_current_context_x64_systemv_sse_patch_28:
	movups xmmword ptr [r11 + 0x7fffffff], xmm10
.globl raw_get_current_context_x64_systemv_sse_patch_28_end
raw_get_current_context_x64_systemv_sse_patch_28_end:
.globl raw_get_current_context_x64_systemv_sse_patch_29
raw_get_current_context_x64_systemv_sse_patch_29:
	movups xmmword ptr [r11 + 0x7fffffff], xmm11
.globl raw_get_current_context_x64_systemv_sse_patch_29_end
raw_get_current_context_x64_systemv_sse_patch_29_end:
.globl raw_get_current_context_x64_systemv_sse_patch_30
raw_get_current_context_x64_systemv_sse_patch_30:
	movups xmmword ptr [r11 + 0x7fffffff], xmm12
.globl raw_get_current_context_x64_systemv_sse_patch_30_end
raw_get_current_context_x64_systemv_sse_patch_30_end:
.globl raw_get_current_context_x64_systemv_sse_patch_31
raw_get_current_context_x64_systemv_sse_patch_31:
	movups xmmword ptr [r11 + 0x7fffffff], xmm13
.globl raw_get_current_context_x64_systemv_sse_patch_31_end
raw_get_current_context_x64_systemv_sse_patch_31_end:
.globl raw_get_current_context_x64_systemv_sse_patch_32
raw_get_current_context_x64_systemv_sse_patch_32:
	movups xmmword ptr [r11 + 0x7fffffff], xmm14
.globl raw_get_current_context_x64_systemv_sse_patch_32_end
raw_get_current_context_x64_systemv_sse_patch_32_end:
.globl raw_get_current_context_x64_systemv_sse_patch_33
raw_get_current_context_x64_systemv_sse_patch_33:
	movups xmmword ptr [r11 + 0x7fffffff], xmm15
.globl raw_get_current_context_x64_systemv_sse_patch_33_end
raw_get_current_context_x64_systemv_sse_patch_33_end:
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
	popfq
	ret

# GetCurrentContext: x64 systemv FPU
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_systemv_fpu
raw_get_current_context_x64_systemv_fpu:
	pushfq
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
	mov r11, qword ptr [rsp + 0x40]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_systemv_fpu_patch_0
raw_get_current_context_x64_systemv_fpu_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_0_end
raw_get_current_context_x64_systemv_fpu_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_systemv_fpu_patch_1
raw_get_current_context_x64_systemv_fpu_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_1_end
raw_get_current_context_x64_systemv_fpu_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_systemv_fpu_patch_2
raw_get_current_context_x64_systemv_fpu_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_2_end
raw_get_current_context_x64_systemv_fpu_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_systemv_fpu_patch_3
raw_get_current_context_x64_systemv_fpu_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_3_end
raw_get_current_context_x64_systemv_fpu_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_systemv_fpu_patch_4
raw_get_current_context_x64_systemv_fpu_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_4_end
raw_get_current_context_x64_systemv_fpu_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_systemv_fpu_patch_5
raw_get_current_context_x64_systemv_fpu_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_5_end
raw_get_current_context_x64_systemv_fpu_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_systemv_fpu_patch_6
raw_get_current_context_x64_systemv_fpu_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_6_end
raw_get_current_context_x64_systemv_fpu_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_systemv_fpu_patch_7
raw_get_current_context_x64_systemv_fpu_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_7_end
raw_get_current_context_x64_systemv_fpu_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_systemv_fpu_patch_8
raw_get_current_context_x64_systemv_fpu_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_8_end
raw_get_current_context_x64_systemv_fpu_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_systemv_fpu_patch_9
raw_get_current_context_x64_systemv_fpu_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_9_end
raw_get_current_context_x64_systemv_fpu_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_systemv_fpu_patch_10
raw_get_current_context_x64_systemv_fpu_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_10_end
raw_get_current_context_x64_systemv_fpu_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_systemv_fpu_patch_11
raw_get_current_context_x64_systemv_fpu_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_11_end
raw_get_current_context_x64_systemv_fpu_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_systemv_fpu_patch_12
raw_get_current_context_x64_systemv_fpu_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_12_end
raw_get_current_context_x64_systemv_fpu_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_systemv_fpu_patch_13
raw_get_current_context_x64_systemv_fpu_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_13_end
raw_get_current_context_x64_systemv_fpu_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_systemv_fpu_patch_14
raw_get_current_context_x64_systemv_fpu_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_14_end
raw_get_current_context_x64_systemv_fpu_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_systemv_fpu_patch_15
raw_get_current_context_x64_systemv_fpu_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_15_end
raw_get_current_context_x64_systemv_fpu_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_systemv_fpu_patch_16
raw_get_current_context_x64_systemv_fpu_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_fpu_patch_16_end
raw_get_current_context_x64_systemv_fpu_patch_16_end:
.globl raw_get_current_context_x64_systemv_fpu_patch_17
raw_get_current_context_x64_systemv_fpu_patch_17:
	fsave [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_fpu_patch_17_end
raw_get_current_context_x64_systemv_fpu_patch_17_end:
.globl raw_get_current_context_x64_systemv_fpu_patch_18
raw_get_current_context_x64_systemv_fpu_patch_18:
	frstor [r11 + 0x7fffffff]
.globl raw_get_current_context_x64_systemv_fpu_patch_18_end
raw_get_current_context_x64_systemv_fpu_patch_18_end:
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
	popfq
	ret

# GetCurrentContext: x64 systemv Native
.intel_syntax noprefix
.text
.globl raw_get_current_context_x64_systemv_native
raw_get_current_context_x64_systemv_native:
	pushfq
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
	mov r11, qword ptr [rsp + 0x40]
	mov r10, qword ptr [rsp + 0x78]
.globl raw_get_current_context_x64_systemv_native_patch_0
raw_get_current_context_x64_systemv_native_patch_0:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_0_end
raw_get_current_context_x64_systemv_native_patch_0_end:
	mov r10, qword ptr [rsp + 0x70]
.globl raw_get_current_context_x64_systemv_native_patch_1
raw_get_current_context_x64_systemv_native_patch_1:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_1_end
raw_get_current_context_x64_systemv_native_patch_1_end:
	mov r10, qword ptr [rsp + 0x68]
.globl raw_get_current_context_x64_systemv_native_patch_2
raw_get_current_context_x64_systemv_native_patch_2:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_2_end
raw_get_current_context_x64_systemv_native_patch_2_end:
	mov r10, qword ptr [rsp + 0x60]
.globl raw_get_current_context_x64_systemv_native_patch_3
raw_get_current_context_x64_systemv_native_patch_3:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_3_end
raw_get_current_context_x64_systemv_native_patch_3_end:
	mov r10, qword ptr [rsp + 0x58]
.globl raw_get_current_context_x64_systemv_native_patch_4
raw_get_current_context_x64_systemv_native_patch_4:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_4_end
raw_get_current_context_x64_systemv_native_patch_4_end:
	lea r10, [rsp + 0x80]
.globl raw_get_current_context_x64_systemv_native_patch_5
raw_get_current_context_x64_systemv_native_patch_5:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_5_end
raw_get_current_context_x64_systemv_native_patch_5_end:
	mov r10, qword ptr [rsp + 0x50]
.globl raw_get_current_context_x64_systemv_native_patch_6
raw_get_current_context_x64_systemv_native_patch_6:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_6_end
raw_get_current_context_x64_systemv_native_patch_6_end:
	mov r10, qword ptr [rsp + 0x48]
.globl raw_get_current_context_x64_systemv_native_patch_7
raw_get_current_context_x64_systemv_native_patch_7:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_7_end
raw_get_current_context_x64_systemv_native_patch_7_end:
	mov r10, qword ptr [rsp + 0x40]
.globl raw_get_current_context_x64_systemv_native_patch_8
raw_get_current_context_x64_systemv_native_patch_8:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_8_end
raw_get_current_context_x64_systemv_native_patch_8_end:
	mov r10, qword ptr [rsp + 0x38]
.globl raw_get_current_context_x64_systemv_native_patch_9
raw_get_current_context_x64_systemv_native_patch_9:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_9_end
raw_get_current_context_x64_systemv_native_patch_9_end:
	mov r10, qword ptr [rsp + 0x30]
.globl raw_get_current_context_x64_systemv_native_patch_10
raw_get_current_context_x64_systemv_native_patch_10:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_10_end
raw_get_current_context_x64_systemv_native_patch_10_end:
	mov r10, qword ptr [rsp + 0x28]
.globl raw_get_current_context_x64_systemv_native_patch_11
raw_get_current_context_x64_systemv_native_patch_11:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_11_end
raw_get_current_context_x64_systemv_native_patch_11_end:
	mov r10, qword ptr [rsp + 0x20]
.globl raw_get_current_context_x64_systemv_native_patch_12
raw_get_current_context_x64_systemv_native_patch_12:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_12_end
raw_get_current_context_x64_systemv_native_patch_12_end:
	mov r10, qword ptr [rsp + 0x18]
.globl raw_get_current_context_x64_systemv_native_patch_13
raw_get_current_context_x64_systemv_native_patch_13:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_13_end
raw_get_current_context_x64_systemv_native_patch_13_end:
	mov r10, qword ptr [rsp + 0x10]
.globl raw_get_current_context_x64_systemv_native_patch_14
raw_get_current_context_x64_systemv_native_patch_14:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_14_end
raw_get_current_context_x64_systemv_native_patch_14_end:
	mov r10, qword ptr [rsp + 0x8]
.globl raw_get_current_context_x64_systemv_native_patch_15
raw_get_current_context_x64_systemv_native_patch_15:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_15_end
raw_get_current_context_x64_systemv_native_patch_15_end:
	mov r10, qword ptr [rsp + 0x0]
.globl raw_get_current_context_x64_systemv_native_patch_16
raw_get_current_context_x64_systemv_native_patch_16:
	mov qword ptr [r11 + 0x7fffffff], r10
.globl raw_get_current_context_x64_systemv_native_patch_16_end
raw_get_current_context_x64_systemv_native_patch_16_end:
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
	popfq
	ret
