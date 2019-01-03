
../Instrumented/test_while.instr:     file format elf64-x86-64


Disassembly of section .init:

0000000000400428 <_init>:
  400428:	48 83 ec 08          	sub    $0x8,%rsp
  40042c:	48 8b 05 c5 0b 20 00 	mov    0x200bc5(%rip),%rax        # 600ff8 <__gmon_start__>
  400433:	48 85 c0             	test   %rax,%rax
  400436:	74 02                	je     40043a <_init+0x12>
  400438:	ff d0                	callq  *%rax
  40043a:	48 83 c4 08          	add    $0x8,%rsp
  40043e:	c3                   	retq   

Disassembly of section .plt:

0000000000400440 <.plt>:
  400440:	ff 35 c2 0b 20 00    	pushq  0x200bc2(%rip)        # 601008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400446:	ff 25 c4 0b 20 00    	jmpq   *0x200bc4(%rip)        # 601010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40044c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400450 <__stack_chk_fail@plt>:
  400450:	ff 25 c2 0b 20 00    	jmpq   *0x200bc2(%rip)        # 601018 <__stack_chk_fail@GLIBC_2.4>
  400456:	68 00 00 00 00       	pushq  $0x0
  40045b:	e9 e0 ff ff ff       	jmpq   400440 <.plt>

0000000000400460 <read@plt>:
  400460:	ff 25 ba 0b 20 00    	jmpq   *0x200bba(%rip)        # 601020 <read@GLIBC_2.2.5>
  400466:	68 01 00 00 00       	pushq  $0x1
  40046b:	e9 d0 ff ff ff       	jmpq   400440 <.plt>

Disassembly of section .text:

0000000000400470 <_start>:
  400470:	31 ed                	xor    %ebp,%ebp
  400472:	49 89 d1             	mov    %rdx,%r9
  400475:	5e                   	pop    %rsi
  400476:	48 89 e2             	mov    %rsp,%rdx
  400479:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  40047d:	50                   	push   %rax
  40047e:	54                   	push   %rsp
  40047f:	49 c7 c0 f0 07 40 00 	mov    $0x4007f0,%r8
  400486:	48 c7 c1 80 07 40 00 	mov    $0x400780,%rcx
  40048d:	48 c7 c7 8a 06 40 00 	mov    $0x40068a,%rdi
  400494:	ff 15 56 0b 20 00    	callq  *0x200b56(%rip)        # 600ff0 <__libc_start_main@GLIBC_2.2.5>
  40049a:	f4                   	hlt    
  40049b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000004004a0 <_dl_relocate_static_pie>:
  4004a0:	f3 c3                	repz retq 
  4004a2:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4004a9:	00 00 00 
  4004ac:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004004b0 <deregister_tm_clones>:
  4004b0:	55                   	push   %rbp
  4004b1:	b8 38 10 60 00       	mov    $0x601038,%eax
  4004b6:	48 3d 38 10 60 00    	cmp    $0x601038,%rax
  4004bc:	48 89 e5             	mov    %rsp,%rbp
  4004bf:	74 17                	je     4004d8 <deregister_tm_clones+0x28>
  4004c1:	b8 00 00 00 00       	mov    $0x0,%eax
  4004c6:	48 85 c0             	test   %rax,%rax
  4004c9:	74 0d                	je     4004d8 <deregister_tm_clones+0x28>
  4004cb:	5d                   	pop    %rbp
  4004cc:	bf 38 10 60 00       	mov    $0x601038,%edi
  4004d1:	ff e0                	jmpq   *%rax
  4004d3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4004d8:	5d                   	pop    %rbp
  4004d9:	c3                   	retq   
  4004da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000004004e0 <register_tm_clones>:
  4004e0:	be 38 10 60 00       	mov    $0x601038,%esi
  4004e5:	55                   	push   %rbp
  4004e6:	48 81 ee 38 10 60 00 	sub    $0x601038,%rsi
  4004ed:	48 89 e5             	mov    %rsp,%rbp
  4004f0:	48 c1 fe 03          	sar    $0x3,%rsi
  4004f4:	48 89 f0             	mov    %rsi,%rax
  4004f7:	48 c1 e8 3f          	shr    $0x3f,%rax
  4004fb:	48 01 c6             	add    %rax,%rsi
  4004fe:	48 d1 fe             	sar    %rsi
  400501:	74 15                	je     400518 <register_tm_clones+0x38>
  400503:	b8 00 00 00 00       	mov    $0x0,%eax
  400508:	48 85 c0             	test   %rax,%rax
  40050b:	74 0b                	je     400518 <register_tm_clones+0x38>
  40050d:	5d                   	pop    %rbp
  40050e:	bf 38 10 60 00       	mov    $0x601038,%edi
  400513:	ff e0                	jmpq   *%rax
  400515:	0f 1f 00             	nopl   (%rax)
  400518:	5d                   	pop    %rbp
  400519:	c3                   	retq   
  40051a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400520 <__do_global_dtors_aux>:
  400520:	80 3d 11 0b 20 00 00 	cmpb   $0x0,0x200b11(%rip)        # 601038 <__TMC_END__>
  400527:	75 17                	jne    400540 <__do_global_dtors_aux+0x20>
  400529:	55                   	push   %rbp
  40052a:	48 89 e5             	mov    %rsp,%rbp
  40052d:	e8 7e ff ff ff       	callq  4004b0 <deregister_tm_clones>
  400532:	c6 05 ff 0a 20 00 01 	movb   $0x1,0x200aff(%rip)        # 601038 <__TMC_END__>
  400539:	5d                   	pop    %rbp
  40053a:	c3                   	retq   
  40053b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400540:	f3 c3                	repz retq 
  400542:	0f 1f 40 00          	nopl   0x0(%rax)
  400546:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40054d:	00 00 00 

0000000000400550 <frame_dummy>:
  400550:	55                   	push   %rbp
  400551:	48 89 e5             	mov    %rsp,%rbp
  400554:	5d                   	pop    %rbp
  400555:	eb 89                	jmp    4004e0 <register_tm_clones>

0000000000400557 <test>:
  400557:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40055e:	50                   	push   %rax
  40055f:	57                   	push   %rdi
  400560:	56                   	push   %rsi
  400561:	52                   	push   %rdx
  400562:	51                   	push   %rcx
  400563:	41 53                	push   %r11
  400565:	e8 e1 01 00 00       	callq  40074b <__trace_jump>
  40056a:	41 5b                	pop    %r11
  40056c:	59                   	pop    %rcx
  40056d:	5a                   	pop    %rdx
  40056e:	5e                   	pop    %rsi
  40056f:	5f                   	pop    %rdi
  400570:	58                   	pop    %rax
  400571:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400578:	55                   	push   %rbp
  400579:	48 89 e5             	mov    %rsp,%rbp
  40057c:	89 7d ec             	mov    %edi,-0x14(%rbp)
  40057f:	c7 45 fc 00 01 00 00 	movl   $0x100,-0x4(%rbp)
  400586:	e9 8b 00 00 00       	jmpq   400616 <test+0xbf>
  40058b:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400592:	50                   	push   %rax
  400593:	57                   	push   %rdi
  400594:	56                   	push   %rsi
  400595:	52                   	push   %rdx
  400596:	51                   	push   %rcx
  400597:	41 53                	push   %r11
  400599:	e8 ad 01 00 00       	callq  40074b <__trace_jump>
  40059e:	41 5b                	pop    %r11
  4005a0:	59                   	pop    %rcx
  4005a1:	5a                   	pop    %rdx
  4005a2:	5e                   	pop    %rsi
  4005a3:	5f                   	pop    %rdi
  4005a4:	58                   	pop    %rax
  4005a5:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005ac:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4005af:	89 c2                	mov    %eax,%edx
  4005b1:	c1 ea 1f             	shr    $0x1f,%edx
  4005b4:	01 d0                	add    %edx,%eax
  4005b6:	d1 f8                	sar    %eax
  4005b8:	39 45 ec             	cmp    %eax,-0x14(%rbp)
  4005bb:	76 29                	jbe    4005e6 <test+0x8f>
  4005bd:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005c4:	50                   	push   %rax
  4005c5:	57                   	push   %rdi
  4005c6:	56                   	push   %rsi
  4005c7:	52                   	push   %rdx
  4005c8:	51                   	push   %rcx
  4005c9:	41 53                	push   %r11
  4005cb:	e8 7b 01 00 00       	callq  40074b <__trace_jump>
  4005d0:	41 5b                	pop    %r11
  4005d2:	59                   	pop    %rcx
  4005d3:	5a                   	pop    %rdx
  4005d4:	5e                   	pop    %rsi
  4005d5:	5f                   	pop    %rdi
  4005d6:	58                   	pop    %rax
  4005d7:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005de:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4005e1:	e9 81 00 00 00       	jmpq   400667 <test+0x110>
  4005e6:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005ed:	50                   	push   %rax
  4005ee:	57                   	push   %rdi
  4005ef:	56                   	push   %rsi
  4005f0:	52                   	push   %rdx
  4005f1:	51                   	push   %rcx
  4005f2:	41 53                	push   %r11
  4005f4:	e8 52 01 00 00       	callq  40074b <__trace_jump>
  4005f9:	41 5b                	pop    %r11
  4005fb:	59                   	pop    %rcx
  4005fc:	5a                   	pop    %rdx
  4005fd:	5e                   	pop    %rsi
  4005fe:	5f                   	pop    %rdi
  4005ff:	58                   	pop    %rax
  400600:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400607:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40060a:	89 c2                	mov    %eax,%edx
  40060c:	c1 ea 1f             	shr    $0x1f,%edx
  40060f:	01 d0                	add    %edx,%eax
  400611:	d1 f8                	sar    %eax
  400613:	89 45 fc             	mov    %eax,-0x4(%rbp)
  400616:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40061d:	50                   	push   %rax
  40061e:	57                   	push   %rdi
  40061f:	56                   	push   %rsi
  400620:	52                   	push   %rdx
  400621:	51                   	push   %rcx
  400622:	41 53                	push   %r11
  400624:	e8 22 01 00 00       	callq  40074b <__trace_jump>
  400629:	41 5b                	pop    %r11
  40062b:	59                   	pop    %rcx
  40062c:	5a                   	pop    %rdx
  40062d:	5e                   	pop    %rsi
  40062e:	5f                   	pop    %rdi
  40062f:	58                   	pop    %rax
  400630:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400637:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40063a:	39 45 ec             	cmp    %eax,-0x14(%rbp)
  40063d:	0f 82 48 ff ff ff    	jb     40058b <test+0x34>
  400643:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40064a:	50                   	push   %rax
  40064b:	57                   	push   %rdi
  40064c:	56                   	push   %rsi
  40064d:	52                   	push   %rdx
  40064e:	51                   	push   %rcx
  40064f:	41 53                	push   %r11
  400651:	e8 f5 00 00 00       	callq  40074b <__trace_jump>
  400656:	41 5b                	pop    %r11
  400658:	59                   	pop    %rcx
  400659:	5a                   	pop    %rdx
  40065a:	5e                   	pop    %rsi
  40065b:	5f                   	pop    %rdi
  40065c:	58                   	pop    %rax
  40065d:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400664:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400667:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40066e:	50                   	push   %rax
  40066f:	57                   	push   %rdi
  400670:	56                   	push   %rsi
  400671:	52                   	push   %rdx
  400672:	51                   	push   %rcx
  400673:	41 53                	push   %r11
  400675:	e8 d1 00 00 00       	callq  40074b <__trace_jump>
  40067a:	41 5b                	pop    %r11
  40067c:	59                   	pop    %rcx
  40067d:	5a                   	pop    %rdx
  40067e:	5e                   	pop    %rsi
  40067f:	5f                   	pop    %rdi
  400680:	58                   	pop    %rax
  400681:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400688:	5d                   	pop    %rbp
  400689:	c3                   	retq   

000000000040068a <main>:
  40068a:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400691:	50                   	push   %rax
  400692:	57                   	push   %rdi
  400693:	56                   	push   %rsi
  400694:	52                   	push   %rdx
  400695:	51                   	push   %rcx
  400696:	41 53                	push   %r11
  400698:	e8 ae 00 00 00       	callq  40074b <__trace_jump>
  40069d:	41 5b                	pop    %r11
  40069f:	59                   	pop    %rcx
  4006a0:	5a                   	pop    %rdx
  4006a1:	5e                   	pop    %rsi
  4006a2:	5f                   	pop    %rdi
  4006a3:	58                   	pop    %rax
  4006a4:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006ab:	55                   	push   %rbp
  4006ac:	48 89 e5             	mov    %rsp,%rbp
  4006af:	48 83 ec 20          	sub    $0x20,%rsp
  4006b3:	89 7d ec             	mov    %edi,-0x14(%rbp)
  4006b6:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  4006ba:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  4006c1:	00 00 
  4006c3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4006c7:	31 c0                	xor    %eax,%eax
  4006c9:	48 8d 45 f3          	lea    -0xd(%rbp),%rax
  4006cd:	ba 01 00 00 00       	mov    $0x1,%edx
  4006d2:	48 89 c6             	mov    %rax,%rsi
  4006d5:	bf 00 00 00 00       	mov    $0x0,%edi
  4006da:	e8 81 fd ff ff       	callq  400460 <read@plt>
  4006df:	0f b6 45 f3          	movzbl -0xd(%rbp),%eax
  4006e3:	0f b6 c0             	movzbl %al,%eax
  4006e6:	89 c7                	mov    %eax,%edi
  4006e8:	e8 6a fe ff ff       	callq  400557 <test>
  4006ed:	89 45 f4             	mov    %eax,-0xc(%rbp)
  4006f0:	8b 45 f4             	mov    -0xc(%rbp),%eax
  4006f3:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  4006f7:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  4006fe:	00 00 
  400700:	74 26                	je     400728 <main+0x9e>
  400702:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400709:	50                   	push   %rax
  40070a:	57                   	push   %rdi
  40070b:	56                   	push   %rsi
  40070c:	52                   	push   %rdx
  40070d:	51                   	push   %rcx
  40070e:	41 53                	push   %r11
  400710:	e8 36 00 00 00       	callq  40074b <__trace_jump>
  400715:	41 5b                	pop    %r11
  400717:	59                   	pop    %rcx
  400718:	5a                   	pop    %rdx
  400719:	5e                   	pop    %rsi
  40071a:	5f                   	pop    %rdi
  40071b:	58                   	pop    %rax
  40071c:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400723:	e8 28 fd ff ff       	callq  400450 <__stack_chk_fail@plt>
  400728:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40072f:	50                   	push   %rax
  400730:	57                   	push   %rdi
  400731:	56                   	push   %rsi
  400732:	52                   	push   %rdx
  400733:	51                   	push   %rcx
  400734:	41 53                	push   %r11
  400736:	e8 10 00 00 00       	callq  40074b <__trace_jump>
  40073b:	41 5b                	pop    %r11
  40073d:	59                   	pop    %rcx
  40073e:	5a                   	pop    %rdx
  40073f:	5e                   	pop    %rsi
  400740:	5f                   	pop    %rdi
  400741:	58                   	pop    %rax
  400742:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400749:	c9                   	leaveq 
  40074a:	c3                   	retq   

000000000040074b <__trace_jump>:
  40074b:	55                   	push   %rbp
  40074c:	48 89 e5             	mov    %rsp,%rbp
  40074f:	48 8b 45 08          	mov    0x8(%rbp),%rax
  400753:	48 83 e8 13          	sub    $0x13,%rax
  400757:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  40075b:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  400762:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  400769:	48 89 ee             	mov    %rbp,%rsi
  40076c:	48 83 ee 08          	sub    $0x8,%rsi
  400770:	48 c7 c2 08 00 00 00 	mov    $0x8,%rdx
  400777:	0f 05                	syscall 
  400779:	5d                   	pop    %rbp
  40077a:	c3                   	retq   
  40077b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000400780 <__libc_csu_init>:
  400780:	41 57                	push   %r15
  400782:	41 56                	push   %r14
  400784:	49 89 d7             	mov    %rdx,%r15
  400787:	41 55                	push   %r13
  400789:	41 54                	push   %r12
  40078b:	4c 8d 25 7e 06 20 00 	lea    0x20067e(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  400792:	55                   	push   %rbp
  400793:	48 8d 2d 7e 06 20 00 	lea    0x20067e(%rip),%rbp        # 600e18 <__init_array_end>
  40079a:	53                   	push   %rbx
  40079b:	41 89 fd             	mov    %edi,%r13d
  40079e:	49 89 f6             	mov    %rsi,%r14
  4007a1:	4c 29 e5             	sub    %r12,%rbp
  4007a4:	48 83 ec 08          	sub    $0x8,%rsp
  4007a8:	48 c1 fd 03          	sar    $0x3,%rbp
  4007ac:	e8 77 fc ff ff       	callq  400428 <_init>
  4007b1:	48 85 ed             	test   %rbp,%rbp
  4007b4:	74 20                	je     4007d6 <__libc_csu_init+0x56>
  4007b6:	31 db                	xor    %ebx,%ebx
  4007b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4007bf:	00 
  4007c0:	4c 89 fa             	mov    %r15,%rdx
  4007c3:	4c 89 f6             	mov    %r14,%rsi
  4007c6:	44 89 ef             	mov    %r13d,%edi
  4007c9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4007cd:	48 83 c3 01          	add    $0x1,%rbx
  4007d1:	48 39 dd             	cmp    %rbx,%rbp
  4007d4:	75 ea                	jne    4007c0 <__libc_csu_init+0x40>
  4007d6:	48 83 c4 08          	add    $0x8,%rsp
  4007da:	5b                   	pop    %rbx
  4007db:	5d                   	pop    %rbp
  4007dc:	41 5c                	pop    %r12
  4007de:	41 5d                	pop    %r13
  4007e0:	41 5e                	pop    %r14
  4007e2:	41 5f                	pop    %r15
  4007e4:	c3                   	retq   
  4007e5:	90                   	nop
  4007e6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4007ed:	00 00 00 

00000000004007f0 <__libc_csu_fini>:
  4007f0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000004007f4 <_fini>:
  4007f4:	48 83 ec 08          	sub    $0x8,%rsp
  4007f8:	48 83 c4 08          	add    $0x8,%rsp
  4007fc:	c3                   	retq   
