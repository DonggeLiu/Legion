
../Instrumented/empty_main.instr:     file format elf64-x86-64


Disassembly of section .init:

0000000000400390 <_init>:
  400390:	48 83 ec 08          	sub    $0x8,%rsp
  400394:	48 8b 05 5d 0c 20 00 	mov    0x200c5d(%rip),%rax        # 600ff8 <__gmon_start__>
  40039b:	48 85 c0             	test   %rax,%rax
  40039e:	74 02                	je     4003a2 <_init+0x12>
  4003a0:	ff d0                	callq  *%rax
  4003a2:	48 83 c4 08          	add    $0x8,%rsp
  4003a6:	c3                   	retq   

Disassembly of section .text:

00000000004003b0 <_start>:
  4003b0:	31 ed                	xor    %ebp,%ebp
  4003b2:	49 89 d1             	mov    %rdx,%r9
  4003b5:	5e                   	pop    %rsi
  4003b6:	48 89 e2             	mov    %rsp,%rdx
  4003b9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4003bd:	50                   	push   %rax
  4003be:	54                   	push   %rsp
  4003bf:	49 c7 c0 70 05 40 00 	mov    $0x400570,%r8
  4003c6:	48 c7 c1 00 05 40 00 	mov    $0x400500,%rcx
  4003cd:	48 c7 c7 97 04 40 00 	mov    $0x400497,%rdi
  4003d4:	ff 15 16 0c 20 00    	callq  *0x200c16(%rip)        # 600ff0 <__libc_start_main@GLIBC_2.2.5>
  4003da:	f4                   	hlt    
  4003db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000004003e0 <_dl_relocate_static_pie>:
  4003e0:	f3 c3                	repz retq 
  4003e2:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4003e9:	00 00 00 
  4003ec:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004003f0 <deregister_tm_clones>:
  4003f0:	55                   	push   %rbp
  4003f1:	b8 28 10 60 00       	mov    $0x601028,%eax
  4003f6:	48 3d 28 10 60 00    	cmp    $0x601028,%rax
  4003fc:	48 89 e5             	mov    %rsp,%rbp
  4003ff:	74 17                	je     400418 <deregister_tm_clones+0x28>
  400401:	b8 00 00 00 00       	mov    $0x0,%eax
  400406:	48 85 c0             	test   %rax,%rax
  400409:	74 0d                	je     400418 <deregister_tm_clones+0x28>
  40040b:	5d                   	pop    %rbp
  40040c:	bf 28 10 60 00       	mov    $0x601028,%edi
  400411:	ff e0                	jmpq   *%rax
  400413:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400418:	5d                   	pop    %rbp
  400419:	c3                   	retq   
  40041a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400420 <register_tm_clones>:
  400420:	be 28 10 60 00       	mov    $0x601028,%esi
  400425:	55                   	push   %rbp
  400426:	48 81 ee 28 10 60 00 	sub    $0x601028,%rsi
  40042d:	48 89 e5             	mov    %rsp,%rbp
  400430:	48 c1 fe 03          	sar    $0x3,%rsi
  400434:	48 89 f0             	mov    %rsi,%rax
  400437:	48 c1 e8 3f          	shr    $0x3f,%rax
  40043b:	48 01 c6             	add    %rax,%rsi
  40043e:	48 d1 fe             	sar    %rsi
  400441:	74 15                	je     400458 <register_tm_clones+0x38>
  400443:	b8 00 00 00 00       	mov    $0x0,%eax
  400448:	48 85 c0             	test   %rax,%rax
  40044b:	74 0b                	je     400458 <register_tm_clones+0x38>
  40044d:	5d                   	pop    %rbp
  40044e:	bf 28 10 60 00       	mov    $0x601028,%edi
  400453:	ff e0                	jmpq   *%rax
  400455:	0f 1f 00             	nopl   (%rax)
  400458:	5d                   	pop    %rbp
  400459:	c3                   	retq   
  40045a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400460 <__do_global_dtors_aux>:
  400460:	80 3d c1 0b 20 00 00 	cmpb   $0x0,0x200bc1(%rip)        # 601028 <__TMC_END__>
  400467:	75 17                	jne    400480 <__do_global_dtors_aux+0x20>
  400469:	55                   	push   %rbp
  40046a:	48 89 e5             	mov    %rsp,%rbp
  40046d:	e8 7e ff ff ff       	callq  4003f0 <deregister_tm_clones>
  400472:	c6 05 af 0b 20 00 01 	movb   $0x1,0x200baf(%rip)        # 601028 <__TMC_END__>
  400479:	5d                   	pop    %rbp
  40047a:	c3                   	retq   
  40047b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400480:	f3 c3                	repz retq 
  400482:	0f 1f 40 00          	nopl   0x0(%rax)
  400486:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40048d:	00 00 00 

0000000000400490 <frame_dummy>:
  400490:	55                   	push   %rbp
  400491:	48 89 e5             	mov    %rsp,%rbp
  400494:	5d                   	pop    %rbp
  400495:	eb 89                	jmp    400420 <register_tm_clones>

0000000000400497 <main>:
  400497:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40049e:	50                   	push   %rax
  40049f:	57                   	push   %rdi
  4004a0:	56                   	push   %rsi
  4004a1:	52                   	push   %rdx
  4004a2:	51                   	push   %rcx
  4004a3:	41 53                	push   %r11
  4004a5:	e8 20 00 00 00       	callq  4004ca <__trace_jump>
  4004aa:	41 5b                	pop    %r11
  4004ac:	59                   	pop    %rcx
  4004ad:	5a                   	pop    %rdx
  4004ae:	5e                   	pop    %rsi
  4004af:	5f                   	pop    %rdi
  4004b0:	58                   	pop    %rax
  4004b1:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4004b8:	55                   	push   %rbp
  4004b9:	48 89 e5             	mov    %rsp,%rbp
  4004bc:	89 7d fc             	mov    %edi,-0x4(%rbp)
  4004bf:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  4004c3:	b8 00 00 00 00       	mov    $0x0,%eax
  4004c8:	5d                   	pop    %rbp
  4004c9:	c3                   	retq   

00000000004004ca <__trace_jump>:
  4004ca:	55                   	push   %rbp
  4004cb:	48 89 e5             	mov    %rsp,%rbp
  4004ce:	48 8b 45 08          	mov    0x8(%rbp),%rax
  4004d2:	48 83 e8 13          	sub    $0x13,%rax
  4004d6:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4004da:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  4004e1:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  4004e8:	48 89 ee             	mov    %rbp,%rsi
  4004eb:	48 83 ee 08          	sub    $0x8,%rsi
  4004ef:	48 c7 c2 08 00 00 00 	mov    $0x8,%rdx
  4004f6:	0f 05                	syscall 
  4004f8:	5d                   	pop    %rbp
  4004f9:	c3                   	retq   
  4004fa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400500 <__libc_csu_init>:
  400500:	41 57                	push   %r15
  400502:	41 56                	push   %r14
  400504:	49 89 d7             	mov    %rdx,%r15
  400507:	41 55                	push   %r13
  400509:	41 54                	push   %r12
  40050b:	4c 8d 25 3e 09 20 00 	lea    0x20093e(%rip),%r12        # 600e50 <__frame_dummy_init_array_entry>
  400512:	55                   	push   %rbp
  400513:	48 8d 2d 3e 09 20 00 	lea    0x20093e(%rip),%rbp        # 600e58 <__init_array_end>
  40051a:	53                   	push   %rbx
  40051b:	41 89 fd             	mov    %edi,%r13d
  40051e:	49 89 f6             	mov    %rsi,%r14
  400521:	4c 29 e5             	sub    %r12,%rbp
  400524:	48 83 ec 08          	sub    $0x8,%rsp
  400528:	48 c1 fd 03          	sar    $0x3,%rbp
  40052c:	e8 5f fe ff ff       	callq  400390 <_init>
  400531:	48 85 ed             	test   %rbp,%rbp
  400534:	74 20                	je     400556 <__libc_csu_init+0x56>
  400536:	31 db                	xor    %ebx,%ebx
  400538:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40053f:	00 
  400540:	4c 89 fa             	mov    %r15,%rdx
  400543:	4c 89 f6             	mov    %r14,%rsi
  400546:	44 89 ef             	mov    %r13d,%edi
  400549:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  40054d:	48 83 c3 01          	add    $0x1,%rbx
  400551:	48 39 dd             	cmp    %rbx,%rbp
  400554:	75 ea                	jne    400540 <__libc_csu_init+0x40>
  400556:	48 83 c4 08          	add    $0x8,%rsp
  40055a:	5b                   	pop    %rbx
  40055b:	5d                   	pop    %rbp
  40055c:	41 5c                	pop    %r12
  40055e:	41 5d                	pop    %r13
  400560:	41 5e                	pop    %r14
  400562:	41 5f                	pop    %r15
  400564:	c3                   	retq   
  400565:	90                   	nop
  400566:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40056d:	00 00 00 

0000000000400570 <__libc_csu_fini>:
  400570:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400574 <_fini>:
  400574:	48 83 ec 08          	sub    $0x8,%rsp
  400578:	48 83 c4 08          	add    $0x8,%rsp
  40057c:	c3                   	retq   
