	.file	"test_bise.c"
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
	ja	.L2
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	cmpl	$128, -4(%rbp)
	ja	.L3
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	cmpl	$64, -4(%rbp)
	ja	.L4
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	cmpl	$32, -4(%rbp)
	ja	.L5
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	cmpl	$16, -4(%rbp)
	ja	.L6
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	cmpl	$8, -4(%rbp)
	ja	.L7
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	cmpl	$4, -4(%rbp)
	ja	.L8
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	cmpl	$2, -4(%rbp)
	ja	.L9
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	cmpl	$1, -4(%rbp)
	ja	.L10
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$1, %eax
	jmp	.L11
.L10:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$2, %eax
	jmp	.L11
.L9:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$3, %eax
	jmp	.L11
.L8:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$4, %eax
	jmp	.L11
.L7:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$5, %eax
	jmp	.L11
.L6:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$6, %eax
	jmp	.L11
.L5:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$7, %eax
	jmp	.L11
.L4:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$8, %eax
	jmp	.L11
.L3:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$9, %eax
	jmp	.L11
.L2:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	movl	$0, %eax
.L11:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
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
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	call	__stack_chk_fail@PLT
.L14:
	sub $128,%rsp
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r11
	call	__trace_jump
	pop  %r11
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add $128,%rsp
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0"
	.section	.note.GNU-stack,"",@progbits
