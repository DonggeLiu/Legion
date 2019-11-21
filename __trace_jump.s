.global __trace_jump
.global __trace_jump_set

__trace_jump_set:
    mov    _state@GOTPCREL(%rip), %rax   # rax = &state
	movl   $0, (%rax)                    # *rax = 0
	retq
       
__trace_jump:
	push   %rbp
	mov    %rsp,%rbp

	movq	_state@GOTPCREL(%rip), %rax # rax = &state
	cmpl	$1, (%rax)                  # *rax == 0, assume rax == 0 before trace_jump_set
	je	LBB2_2                          # skip tracing
        
	mov    0x8(%rbp),%rax               # get the address in caller to return to
	sub    $0x13,%rax                   # rewind back over call
#	mov    %rax,-0x8(%rbp)              # store on stack

	mov	    $8, %esi                    # size of each item to write by fwrite
	mov 	$1, %edx                    # number of items to write by fwrite
	movq	stderr(%rip), %rcx          # where to write
    push    %rax                        # store on the stack
    # now rsp points to the mem holding the value in rax
    mov     %rsp, %rdi                  # the thing to write by fwrite
	call	fwrite@PLT
	pop     %rax                        #undo pushing rax

#	mov    $0x1,%rax                    # system call number 1 = write
#	mov    $0x2,%rdi                    # file handle        2 = stderr
#	mov    %rbp,%rsi                    #
#	sub    $0x8,%rsi
#	mov    $0x8,%rdx
#	syscall

	movq	_state@GOTPCREL(%rip), %rax # clear @state
	movl	$1, (%rax)                  # *rax = 1

LBB2_2:
	pop    %rbp
	ret

	.comm	_state,4,2              ## @state
