.global __trace_jump

__trace_jump:
	push   %rbp
	mov    %rsp,%rbp
	mov    0x8(%rbp),%rax   # get return address
	sub    $0x13,%rax        # rewind back over call
	mov    %rax,-0x8(%rbp)  # store on stack
	
	mov    $0x1,%rax        # system call number 1 = write
	mov    $0x2,%rdi        # file handle        2 = stderr
	mov    %rbp,%rsi        # 
	sub    $0x8,%rsi
	mov    $0x8,%rdx
	syscall
	
	pop    %rbp
	ret
