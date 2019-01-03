	.file	"test_half.c"
	.text
	.globl	test
	.type	test, @function
test:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	cmpl	$255, -4(%rbp)
	jbe	.L2
	movl	$9, %eax
	jmp	.L3
.L2:
	cmpl	$128, -4(%rbp)
	jbe	.L4
	movl	$8, %eax
	jmp	.L3
.L4:
	cmpl	$64, -4(%rbp)
	jbe	.L5
	movl	$7, %eax
	jmp	.L3
.L5:
	cmpl	$32, -4(%rbp)
	jbe	.L6
	movl	$6, %eax
	jmp	.L3
.L6:
	cmpl	$16, -4(%rbp)
	jbe	.L7
	movl	$5, %eax
	jmp	.L3
.L7:
	cmpl	$8, -4(%rbp)
	jbe	.L8
	movl	$4, %eax
	jmp	.L3
.L8:
	cmpl	$4, -4(%rbp)
	jbe	.L9
	movl	$3, %eax
	jmp	.L3
.L9:
	cmpl	$2, -4(%rbp)
	jbe	.L10
	movl	$2, %eax
	jmp	.L3
.L10:
	cmpl	$1, -4(%rbp)
	jbe	.L11
	movl	$1, %eax
	jmp	.L3
.L11:
	movl	$0, %eax
.L3:
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	test, .-test
	.globl	main
	.type	main, @function
main:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movl	%edi, -20(%rbp)
	movq	%rsi, -32(%rbp)
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	leaq	-13(%rbp), %rax
	movl	$1, %edx
	movq	%rax, %rsi
	movl	$0, %edi
	call	read@PLT
	movzbl	-13(%rbp), %eax
	movzbl	%al, %eax
	movl	%eax, %edi
	call	test
	movl	%eax, -12(%rbp)
	movl	-12(%rbp), %eax
	movq	-8(%rbp), %rcx
	xorq	%fs:40, %rcx
	je	.L14
	call	__stack_chk_fail@PLT
.L14:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0"
	.section	.note.GNU-stack,"",@progbits
