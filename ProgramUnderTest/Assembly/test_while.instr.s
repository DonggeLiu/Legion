
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
  40047f:	49 c7 c0 40 08 40 00 	mov    $0x400840,%r8
  400486:	48 c7 c1 d0 07 40 00 	mov    $0x4007d0,%rcx
  40048d:	48 c7 c7 79 06 40 00 	mov    $0x400679,%rdi
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
  400565:	e8 2f 02 00 00       	callq  400799 <__trace_jump>
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
  400586:	eb 7d                	jmp    400605 <test+0xae>
  400588:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40058f:	50                   	push   %rax
  400590:	57                   	push   %rdi
  400591:	56                   	push   %rsi
  400592:	52                   	push   %rdx
  400593:	51                   	push   %rcx
  400594:	41 53                	push   %r11
  400596:	e8 fe 01 00 00       	callq  400799 <__trace_jump>
  40059b:	41 5b                	pop    %r11
  40059d:	59                   	pop    %rcx
  40059e:	5a                   	pop    %rdx
  40059f:	5e                   	pop    %rsi
  4005a0:	5f                   	pop    %rdi
  4005a1:	58                   	pop    %rax
  4005a2:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005a9:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4005ac:	89 c2                	mov    %eax,%edx
  4005ae:	c1 ea 1f             	shr    $0x1f,%edx
  4005b1:	01 d0                	add    %edx,%eax
  4005b3:	d1 f8                	sar    %eax
  4005b5:	39 45 ec             	cmp    %eax,-0x14(%rbp)
  4005b8:	76 26                	jbe    4005e0 <test+0x89>
  4005ba:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005c1:	50                   	push   %rax
  4005c2:	57                   	push   %rdi
  4005c3:	56                   	push   %rsi
  4005c4:	52                   	push   %rdx
  4005c5:	51                   	push   %rcx
  4005c6:	41 53                	push   %r11
  4005c8:	e8 cc 01 00 00       	callq  400799 <__trace_jump>
  4005cd:	41 5b                	pop    %r11
  4005cf:	59                   	pop    %rcx
  4005d0:	5a                   	pop    %rdx
  4005d1:	5e                   	pop    %rsi
  4005d2:	5f                   	pop    %rdi
  4005d3:	58                   	pop    %rax
  4005d4:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005db:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4005de:	eb 76                	jmp    400656 <test+0xff>
  4005e0:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005e7:	50                   	push   %rax
  4005e8:	57                   	push   %rdi
  4005e9:	56                   	push   %rsi
  4005ea:	52                   	push   %rdx
  4005eb:	51                   	push   %rcx
  4005ec:	41 53                	push   %r11
  4005ee:	e8 a6 01 00 00       	callq  400799 <__trace_jump>
  4005f3:	41 5b                	pop    %r11
  4005f5:	59                   	pop    %rcx
  4005f6:	5a                   	pop    %rdx
  4005f7:	5e                   	pop    %rsi
  4005f8:	5f                   	pop    %rdi
  4005f9:	58                   	pop    %rax
  4005fa:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400601:	83 6d fc 08          	subl   $0x8,-0x4(%rbp)
  400605:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40060c:	50                   	push   %rax
  40060d:	57                   	push   %rdi
  40060e:	56                   	push   %rsi
  40060f:	52                   	push   %rdx
  400610:	51                   	push   %rcx
  400611:	41 53                	push   %r11
  400613:	e8 81 01 00 00       	callq  400799 <__trace_jump>
  400618:	41 5b                	pop    %r11
  40061a:	59                   	pop    %rcx
  40061b:	5a                   	pop    %rdx
  40061c:	5e                   	pop    %rsi
  40061d:	5f                   	pop    %rdi
  40061e:	58                   	pop    %rax
  40061f:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400626:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400629:	39 45 ec             	cmp    %eax,-0x14(%rbp)
  40062c:	0f 82 56 ff ff ff    	jb     400588 <test+0x31>
  400632:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400639:	50                   	push   %rax
  40063a:	57                   	push   %rdi
  40063b:	56                   	push   %rsi
  40063c:	52                   	push   %rdx
  40063d:	51                   	push   %rcx
  40063e:	41 53                	push   %r11
  400640:	e8 54 01 00 00       	callq  400799 <__trace_jump>
  400645:	41 5b                	pop    %r11
  400647:	59                   	pop    %rcx
  400648:	5a                   	pop    %rdx
  400649:	5e                   	pop    %rsi
  40064a:	5f                   	pop    %rdi
  40064b:	58                   	pop    %rax
  40064c:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400653:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400656:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40065d:	50                   	push   %rax
  40065e:	57                   	push   %rdi
  40065f:	56                   	push   %rsi
  400660:	52                   	push   %rdx
  400661:	51                   	push   %rcx
  400662:	41 53                	push   %r11
  400664:	e8 30 01 00 00       	callq  400799 <__trace_jump>
  400669:	41 5b                	pop    %r11
  40066b:	59                   	pop    %rcx
  40066c:	5a                   	pop    %rdx
  40066d:	5e                   	pop    %rsi
  40066e:	5f                   	pop    %rdi
  40066f:	58                   	pop    %rax
  400670:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400677:	5d                   	pop    %rbp
  400678:	c3                   	retq   

0000000000400679 <main>:
  400679:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400680:	50                   	push   %rax
  400681:	57                   	push   %rdi
  400682:	56                   	push   %rsi
  400683:	52                   	push   %rdx
  400684:	51                   	push   %rcx
  400685:	41 53                	push   %r11
  400687:	e8 0d 01 00 00       	callq  400799 <__trace_jump>
  40068c:	41 5b                	pop    %r11
  40068e:	59                   	pop    %rcx
  40068f:	5a                   	pop    %rdx
  400690:	5e                   	pop    %rsi
  400691:	5f                   	pop    %rdi
  400692:	58                   	pop    %rax
  400693:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40069a:	55                   	push   %rbp
  40069b:	48 89 e5             	mov    %rsp,%rbp
  40069e:	48 83 ec 20          	sub    $0x20,%rsp
  4006a2:	89 7d ec             	mov    %edi,-0x14(%rbp)
  4006a5:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  4006a9:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  4006b0:	00 00 
  4006b2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4006b6:	31 c0                	xor    %eax,%eax
  4006b8:	48 8d 45 f6          	lea    -0xa(%rbp),%rax
  4006bc:	ba 01 00 00 00       	mov    $0x1,%edx
  4006c1:	48 89 c6             	mov    %rax,%rsi
  4006c4:	bf 00 00 00 00       	mov    $0x0,%edi
  4006c9:	e8 92 fd ff ff       	callq  400460 <read@plt>
  4006ce:	48 8d 45 f7          	lea    -0x9(%rbp),%rax
  4006d2:	ba 01 00 00 00       	mov    $0x1,%edx
  4006d7:	48 89 c6             	mov    %rax,%rsi
  4006da:	bf 00 00 00 00       	mov    $0x0,%edi
  4006df:	e8 7c fd ff ff       	callq  400460 <read@plt>
  4006e4:	0f b6 45 f7          	movzbl -0x9(%rbp),%eax
  4006e8:	3c f0                	cmp    $0xf0,%al
  4006ea:	76 2f                	jbe    40071b <main+0xa2>
  4006ec:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006f3:	50                   	push   %rax
  4006f4:	57                   	push   %rdi
  4006f5:	56                   	push   %rsi
  4006f6:	52                   	push   %rdx
  4006f7:	51                   	push   %rcx
  4006f8:	41 53                	push   %r11
  4006fa:	e8 9a 00 00 00       	callq  400799 <__trace_jump>
  4006ff:	41 5b                	pop    %r11
  400701:	59                   	pop    %rcx
  400702:	5a                   	pop    %rdx
  400703:	5e                   	pop    %rsi
  400704:	5f                   	pop    %rdi
  400705:	58                   	pop    %rax
  400706:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40070d:	0f b6 45 f6          	movzbl -0xa(%rbp),%eax
  400711:	0f b6 c0             	movzbl %al,%eax
  400714:	89 c7                	mov    %eax,%edi
  400716:	e8 3c fe ff ff       	callq  400557 <test>
  40071b:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400722:	50                   	push   %rax
  400723:	57                   	push   %rdi
  400724:	56                   	push   %rsi
  400725:	52                   	push   %rdx
  400726:	51                   	push   %rcx
  400727:	41 53                	push   %r11
  400729:	e8 6b 00 00 00       	callq  400799 <__trace_jump>
  40072e:	41 5b                	pop    %r11
  400730:	59                   	pop    %rcx
  400731:	5a                   	pop    %rdx
  400732:	5e                   	pop    %rsi
  400733:	5f                   	pop    %rdi
  400734:	58                   	pop    %rax
  400735:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40073c:	b8 00 00 00 00       	mov    $0x0,%eax
  400741:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  400745:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  40074c:	00 00 
  40074e:	74 26                	je     400776 <main+0xfd>
  400750:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400757:	50                   	push   %rax
  400758:	57                   	push   %rdi
  400759:	56                   	push   %rsi
  40075a:	52                   	push   %rdx
  40075b:	51                   	push   %rcx
  40075c:	41 53                	push   %r11
  40075e:	e8 36 00 00 00       	callq  400799 <__trace_jump>
  400763:	41 5b                	pop    %r11
  400765:	59                   	pop    %rcx
  400766:	5a                   	pop    %rdx
  400767:	5e                   	pop    %rsi
  400768:	5f                   	pop    %rdi
  400769:	58                   	pop    %rax
  40076a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400771:	e8 da fc ff ff       	callq  400450 <__stack_chk_fail@plt>
  400776:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40077d:	50                   	push   %rax
  40077e:	57                   	push   %rdi
  40077f:	56                   	push   %rsi
  400780:	52                   	push   %rdx
  400781:	51                   	push   %rcx
  400782:	41 53                	push   %r11
  400784:	e8 10 00 00 00       	callq  400799 <__trace_jump>
  400789:	41 5b                	pop    %r11
  40078b:	59                   	pop    %rcx
  40078c:	5a                   	pop    %rdx
  40078d:	5e                   	pop    %rsi
  40078e:	5f                   	pop    %rdi
  40078f:	58                   	pop    %rax
  400790:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400797:	c9                   	leaveq 
  400798:	c3                   	retq   

0000000000400799 <__trace_jump>:
  400799:	55                   	push   %rbp
  40079a:	48 89 e5             	mov    %rsp,%rbp
  40079d:	48 8b 45 08          	mov    0x8(%rbp),%rax
  4007a1:	48 83 e8 13          	sub    $0x13,%rax
  4007a5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4007a9:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  4007b0:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  4007b7:	48 89 ee             	mov    %rbp,%rsi
  4007ba:	48 83 ee 08          	sub    $0x8,%rsi
  4007be:	48 c7 c2 08 00 00 00 	mov    $0x8,%rdx
  4007c5:	0f 05                	syscall 
  4007c7:	5d                   	pop    %rbp
  4007c8:	c3                   	retq   
  4007c9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000004007d0 <__libc_csu_init>:
  4007d0:	41 57                	push   %r15
  4007d2:	41 56                	push   %r14
  4007d4:	49 89 d7             	mov    %rdx,%r15
  4007d7:	41 55                	push   %r13
  4007d9:	41 54                	push   %r12
  4007db:	4c 8d 25 2e 06 20 00 	lea    0x20062e(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  4007e2:	55                   	push   %rbp
  4007e3:	48 8d 2d 2e 06 20 00 	lea    0x20062e(%rip),%rbp        # 600e18 <__init_array_end>
  4007ea:	53                   	push   %rbx
  4007eb:	41 89 fd             	mov    %edi,%r13d
  4007ee:	49 89 f6             	mov    %rsi,%r14
  4007f1:	4c 29 e5             	sub    %r12,%rbp
  4007f4:	48 83 ec 08          	sub    $0x8,%rsp
  4007f8:	48 c1 fd 03          	sar    $0x3,%rbp
  4007fc:	e8 27 fc ff ff       	callq  400428 <_init>
  400801:	48 85 ed             	test   %rbp,%rbp
  400804:	74 20                	je     400826 <__libc_csu_init+0x56>
  400806:	31 db                	xor    %ebx,%ebx
  400808:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40080f:	00 
  400810:	4c 89 fa             	mov    %r15,%rdx
  400813:	4c 89 f6             	mov    %r14,%rsi
  400816:	44 89 ef             	mov    %r13d,%edi
  400819:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  40081d:	48 83 c3 01          	add    $0x1,%rbx
  400821:	48 39 dd             	cmp    %rbx,%rbp
  400824:	75 ea                	jne    400810 <__libc_csu_init+0x40>
  400826:	48 83 c4 08          	add    $0x8,%rsp
  40082a:	5b                   	pop    %rbx
  40082b:	5d                   	pop    %rbp
  40082c:	41 5c                	pop    %r12
  40082e:	41 5d                	pop    %r13
  400830:	41 5e                	pop    %r14
  400832:	41 5f                	pop    %r15
  400834:	c3                   	retq   
  400835:	90                   	nop
  400836:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40083d:	00 00 00 

0000000000400840 <__libc_csu_fini>:
  400840:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400844 <_fini>:
  400844:	48 83 ec 08          	sub    $0x8,%rsp
  400848:	48 83 c4 08          	add    $0x8,%rsp
  40084c:	c3                   	retq   
