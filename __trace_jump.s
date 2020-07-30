.global __trace_jump
.global __trace_jump_set

__trace_jump_set:
    mov    _state@GOTPCREL(%rip), %rax  # rax = &state
	movl   $0, (%rax)                   # *rax = 0
	retq
       
__trace_jump:
	push   %rbp
	mov    %rsp,%rbp

	movq	_state@GOTPCREL(%rip), %rax # rax = &state
	cmpl	$1, (%rax)                  # *rax == 0, assume rax == 0 before trace_jump_set
	je	LBB2_2                          # skip tracing
        
	mov     0x8(%rbp),%edi              # get the address in caller to return to
	sub     $0x13,%edi
	mov     $0, %eax
	call    save_to_errbuf@PLT

	movq	_state@GOTPCREL(%rip), %rax # clear @state
	movl	$1, (%rax)                  # *rax = 1

LBB2_2:
	pop    %rbp
	ret

	.comm	_state,4,2              ## @state
