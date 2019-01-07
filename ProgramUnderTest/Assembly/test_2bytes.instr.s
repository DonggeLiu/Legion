
../Instrumented/test_2bytes.instr:     file format elf64-x86-64


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
  40047f:	49 c7 c0 40 0a 40 00 	mov    $0x400a40,%r8
  400486:	48 c7 c1 d0 09 40 00 	mov    $0x4009d0,%rcx
  40048d:	48 c7 c7 d1 08 40 00 	mov    $0x4008d1,%rdi
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
  400565:	e8 29 04 00 00       	callq  400993 <__trace_jump>
  40056a:	41 5b                	pop    %r11
  40056c:	59                   	pop    %rcx
  40056d:	5a                   	pop    %rdx
  40056e:	5e                   	pop    %rsi
  40056f:	5f                   	pop    %rdi
  400570:	58                   	pop    %rax
  400571:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400578:	55                   	push   %rbp
  400579:	48 89 e5             	mov    %rsp,%rbp
  40057c:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  400580:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  400584:	0f b6 00             	movzbl (%rax),%eax
  400587:	3c 64                	cmp    $0x64,%al
  400589:	76 2b                	jbe    4005b6 <test+0x5f>
  40058b:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400592:	50                   	push   %rax
  400593:	57                   	push   %rdi
  400594:	56                   	push   %rsi
  400595:	52                   	push   %rdx
  400596:	51                   	push   %rcx
  400597:	41 53                	push   %r11
  400599:	e8 f5 03 00 00       	callq  400993 <__trace_jump>
  40059e:	41 5b                	pop    %r11
  4005a0:	59                   	pop    %rcx
  4005a1:	5a                   	pop    %rdx
  4005a2:	5e                   	pop    %rsi
  4005a3:	5f                   	pop    %rdi
  4005a4:	58                   	pop    %rax
  4005a5:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005ac:	b8 09 00 00 00       	mov    $0x9,%eax
  4005b1:	e9 f8 02 00 00       	jmpq   4008ae <test+0x357>
  4005b6:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005bd:	50                   	push   %rax
  4005be:	57                   	push   %rdi
  4005bf:	56                   	push   %rsi
  4005c0:	52                   	push   %rdx
  4005c1:	51                   	push   %rcx
  4005c2:	41 53                	push   %r11
  4005c4:	e8 ca 03 00 00       	callq  400993 <__trace_jump>
  4005c9:	41 5b                	pop    %r11
  4005cb:	59                   	pop    %rcx
  4005cc:	5a                   	pop    %rdx
  4005cd:	5e                   	pop    %rsi
  4005ce:	5f                   	pop    %rdi
  4005cf:	58                   	pop    %rax
  4005d0:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005d7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4005db:	48 83 c0 01          	add    $0x1,%rax
  4005df:	0f b6 00             	movzbl (%rax),%eax
  4005e2:	3c 80                	cmp    $0x80,%al
  4005e4:	76 2b                	jbe    400611 <test+0xba>
  4005e6:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005ed:	50                   	push   %rax
  4005ee:	57                   	push   %rdi
  4005ef:	56                   	push   %rsi
  4005f0:	52                   	push   %rdx
  4005f1:	51                   	push   %rcx
  4005f2:	41 53                	push   %r11
  4005f4:	e8 9a 03 00 00       	callq  400993 <__trace_jump>
  4005f9:	41 5b                	pop    %r11
  4005fb:	59                   	pop    %rcx
  4005fc:	5a                   	pop    %rdx
  4005fd:	5e                   	pop    %rsi
  4005fe:	5f                   	pop    %rdi
  4005ff:	58                   	pop    %rax
  400600:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400607:	b8 08 00 00 00       	mov    $0x8,%eax
  40060c:	e9 9d 02 00 00       	jmpq   4008ae <test+0x357>
  400611:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400618:	50                   	push   %rax
  400619:	57                   	push   %rdi
  40061a:	56                   	push   %rsi
  40061b:	52                   	push   %rdx
  40061c:	51                   	push   %rcx
  40061d:	41 53                	push   %r11
  40061f:	e8 6f 03 00 00       	callq  400993 <__trace_jump>
  400624:	41 5b                	pop    %r11
  400626:	59                   	pop    %rcx
  400627:	5a                   	pop    %rdx
  400628:	5e                   	pop    %rsi
  400629:	5f                   	pop    %rdi
  40062a:	58                   	pop    %rax
  40062b:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400632:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  400636:	48 83 c0 01          	add    $0x1,%rax
  40063a:	0f b6 00             	movzbl (%rax),%eax
  40063d:	3c 40                	cmp    $0x40,%al
  40063f:	76 2b                	jbe    40066c <test+0x115>
  400641:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400648:	50                   	push   %rax
  400649:	57                   	push   %rdi
  40064a:	56                   	push   %rsi
  40064b:	52                   	push   %rdx
  40064c:	51                   	push   %rcx
  40064d:	41 53                	push   %r11
  40064f:	e8 3f 03 00 00       	callq  400993 <__trace_jump>
  400654:	41 5b                	pop    %r11
  400656:	59                   	pop    %rcx
  400657:	5a                   	pop    %rdx
  400658:	5e                   	pop    %rsi
  400659:	5f                   	pop    %rdi
  40065a:	58                   	pop    %rax
  40065b:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400662:	b8 07 00 00 00       	mov    $0x7,%eax
  400667:	e9 42 02 00 00       	jmpq   4008ae <test+0x357>
  40066c:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400673:	50                   	push   %rax
  400674:	57                   	push   %rdi
  400675:	56                   	push   %rsi
  400676:	52                   	push   %rdx
  400677:	51                   	push   %rcx
  400678:	41 53                	push   %r11
  40067a:	e8 14 03 00 00       	callq  400993 <__trace_jump>
  40067f:	41 5b                	pop    %r11
  400681:	59                   	pop    %rcx
  400682:	5a                   	pop    %rdx
  400683:	5e                   	pop    %rsi
  400684:	5f                   	pop    %rdi
  400685:	58                   	pop    %rax
  400686:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40068d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  400691:	48 83 c0 01          	add    $0x1,%rax
  400695:	0f b6 00             	movzbl (%rax),%eax
  400698:	3c 20                	cmp    $0x20,%al
  40069a:	76 2b                	jbe    4006c7 <test+0x170>
  40069c:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006a3:	50                   	push   %rax
  4006a4:	57                   	push   %rdi
  4006a5:	56                   	push   %rsi
  4006a6:	52                   	push   %rdx
  4006a7:	51                   	push   %rcx
  4006a8:	41 53                	push   %r11
  4006aa:	e8 e4 02 00 00       	callq  400993 <__trace_jump>
  4006af:	41 5b                	pop    %r11
  4006b1:	59                   	pop    %rcx
  4006b2:	5a                   	pop    %rdx
  4006b3:	5e                   	pop    %rsi
  4006b4:	5f                   	pop    %rdi
  4006b5:	58                   	pop    %rax
  4006b6:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006bd:	b8 06 00 00 00       	mov    $0x6,%eax
  4006c2:	e9 e7 01 00 00       	jmpq   4008ae <test+0x357>
  4006c7:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006ce:	50                   	push   %rax
  4006cf:	57                   	push   %rdi
  4006d0:	56                   	push   %rsi
  4006d1:	52                   	push   %rdx
  4006d2:	51                   	push   %rcx
  4006d3:	41 53                	push   %r11
  4006d5:	e8 b9 02 00 00       	callq  400993 <__trace_jump>
  4006da:	41 5b                	pop    %r11
  4006dc:	59                   	pop    %rcx
  4006dd:	5a                   	pop    %rdx
  4006de:	5e                   	pop    %rsi
  4006df:	5f                   	pop    %rdi
  4006e0:	58                   	pop    %rax
  4006e1:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006e8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4006ec:	48 83 c0 01          	add    $0x1,%rax
  4006f0:	0f b6 00             	movzbl (%rax),%eax
  4006f3:	3c 10                	cmp    $0x10,%al
  4006f5:	76 2b                	jbe    400722 <test+0x1cb>
  4006f7:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006fe:	50                   	push   %rax
  4006ff:	57                   	push   %rdi
  400700:	56                   	push   %rsi
  400701:	52                   	push   %rdx
  400702:	51                   	push   %rcx
  400703:	41 53                	push   %r11
  400705:	e8 89 02 00 00       	callq  400993 <__trace_jump>
  40070a:	41 5b                	pop    %r11
  40070c:	59                   	pop    %rcx
  40070d:	5a                   	pop    %rdx
  40070e:	5e                   	pop    %rsi
  40070f:	5f                   	pop    %rdi
  400710:	58                   	pop    %rax
  400711:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400718:	b8 05 00 00 00       	mov    $0x5,%eax
  40071d:	e9 8c 01 00 00       	jmpq   4008ae <test+0x357>
  400722:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400729:	50                   	push   %rax
  40072a:	57                   	push   %rdi
  40072b:	56                   	push   %rsi
  40072c:	52                   	push   %rdx
  40072d:	51                   	push   %rcx
  40072e:	41 53                	push   %r11
  400730:	e8 5e 02 00 00       	callq  400993 <__trace_jump>
  400735:	41 5b                	pop    %r11
  400737:	59                   	pop    %rcx
  400738:	5a                   	pop    %rdx
  400739:	5e                   	pop    %rsi
  40073a:	5f                   	pop    %rdi
  40073b:	58                   	pop    %rax
  40073c:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400743:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  400747:	48 83 c0 01          	add    $0x1,%rax
  40074b:	0f b6 00             	movzbl (%rax),%eax
  40074e:	3c 08                	cmp    $0x8,%al
  400750:	76 2b                	jbe    40077d <test+0x226>
  400752:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400759:	50                   	push   %rax
  40075a:	57                   	push   %rdi
  40075b:	56                   	push   %rsi
  40075c:	52                   	push   %rdx
  40075d:	51                   	push   %rcx
  40075e:	41 53                	push   %r11
  400760:	e8 2e 02 00 00       	callq  400993 <__trace_jump>
  400765:	41 5b                	pop    %r11
  400767:	59                   	pop    %rcx
  400768:	5a                   	pop    %rdx
  400769:	5e                   	pop    %rsi
  40076a:	5f                   	pop    %rdi
  40076b:	58                   	pop    %rax
  40076c:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400773:	b8 04 00 00 00       	mov    $0x4,%eax
  400778:	e9 31 01 00 00       	jmpq   4008ae <test+0x357>
  40077d:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400784:	50                   	push   %rax
  400785:	57                   	push   %rdi
  400786:	56                   	push   %rsi
  400787:	52                   	push   %rdx
  400788:	51                   	push   %rcx
  400789:	41 53                	push   %r11
  40078b:	e8 03 02 00 00       	callq  400993 <__trace_jump>
  400790:	41 5b                	pop    %r11
  400792:	59                   	pop    %rcx
  400793:	5a                   	pop    %rdx
  400794:	5e                   	pop    %rsi
  400795:	5f                   	pop    %rdi
  400796:	58                   	pop    %rax
  400797:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40079e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4007a2:	48 83 c0 01          	add    $0x1,%rax
  4007a6:	0f b6 00             	movzbl (%rax),%eax
  4007a9:	3c 04                	cmp    $0x4,%al
  4007ab:	76 2b                	jbe    4007d8 <test+0x281>
  4007ad:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007b4:	50                   	push   %rax
  4007b5:	57                   	push   %rdi
  4007b6:	56                   	push   %rsi
  4007b7:	52                   	push   %rdx
  4007b8:	51                   	push   %rcx
  4007b9:	41 53                	push   %r11
  4007bb:	e8 d3 01 00 00       	callq  400993 <__trace_jump>
  4007c0:	41 5b                	pop    %r11
  4007c2:	59                   	pop    %rcx
  4007c3:	5a                   	pop    %rdx
  4007c4:	5e                   	pop    %rsi
  4007c5:	5f                   	pop    %rdi
  4007c6:	58                   	pop    %rax
  4007c7:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4007ce:	b8 03 00 00 00       	mov    $0x3,%eax
  4007d3:	e9 d6 00 00 00       	jmpq   4008ae <test+0x357>
  4007d8:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007df:	50                   	push   %rax
  4007e0:	57                   	push   %rdi
  4007e1:	56                   	push   %rsi
  4007e2:	52                   	push   %rdx
  4007e3:	51                   	push   %rcx
  4007e4:	41 53                	push   %r11
  4007e6:	e8 a8 01 00 00       	callq  400993 <__trace_jump>
  4007eb:	41 5b                	pop    %r11
  4007ed:	59                   	pop    %rcx
  4007ee:	5a                   	pop    %rdx
  4007ef:	5e                   	pop    %rsi
  4007f0:	5f                   	pop    %rdi
  4007f1:	58                   	pop    %rax
  4007f2:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4007f9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4007fd:	48 83 c0 01          	add    $0x1,%rax
  400801:	0f b6 00             	movzbl (%rax),%eax
  400804:	3c 02                	cmp    $0x2,%al
  400806:	76 28                	jbe    400830 <test+0x2d9>
  400808:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40080f:	50                   	push   %rax
  400810:	57                   	push   %rdi
  400811:	56                   	push   %rsi
  400812:	52                   	push   %rdx
  400813:	51                   	push   %rcx
  400814:	41 53                	push   %r11
  400816:	e8 78 01 00 00       	callq  400993 <__trace_jump>
  40081b:	41 5b                	pop    %r11
  40081d:	59                   	pop    %rcx
  40081e:	5a                   	pop    %rdx
  40081f:	5e                   	pop    %rsi
  400820:	5f                   	pop    %rdi
  400821:	58                   	pop    %rax
  400822:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400829:	b8 02 00 00 00       	mov    $0x2,%eax
  40082e:	eb 7e                	jmp    4008ae <test+0x357>
  400830:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400837:	50                   	push   %rax
  400838:	57                   	push   %rdi
  400839:	56                   	push   %rsi
  40083a:	52                   	push   %rdx
  40083b:	51                   	push   %rcx
  40083c:	41 53                	push   %r11
  40083e:	e8 50 01 00 00       	callq  400993 <__trace_jump>
  400843:	41 5b                	pop    %r11
  400845:	59                   	pop    %rcx
  400846:	5a                   	pop    %rdx
  400847:	5e                   	pop    %rsi
  400848:	5f                   	pop    %rdi
  400849:	58                   	pop    %rax
  40084a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400851:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  400855:	48 83 c0 01          	add    $0x1,%rax
  400859:	0f b6 00             	movzbl (%rax),%eax
  40085c:	3c 01                	cmp    $0x1,%al
  40085e:	76 28                	jbe    400888 <test+0x331>
  400860:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400867:	50                   	push   %rax
  400868:	57                   	push   %rdi
  400869:	56                   	push   %rsi
  40086a:	52                   	push   %rdx
  40086b:	51                   	push   %rcx
  40086c:	41 53                	push   %r11
  40086e:	e8 20 01 00 00       	callq  400993 <__trace_jump>
  400873:	41 5b                	pop    %r11
  400875:	59                   	pop    %rcx
  400876:	5a                   	pop    %rdx
  400877:	5e                   	pop    %rsi
  400878:	5f                   	pop    %rdi
  400879:	58                   	pop    %rax
  40087a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400881:	b8 01 00 00 00       	mov    $0x1,%eax
  400886:	eb 26                	jmp    4008ae <test+0x357>
  400888:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40088f:	50                   	push   %rax
  400890:	57                   	push   %rdi
  400891:	56                   	push   %rsi
  400892:	52                   	push   %rdx
  400893:	51                   	push   %rcx
  400894:	41 53                	push   %r11
  400896:	e8 f8 00 00 00       	callq  400993 <__trace_jump>
  40089b:	41 5b                	pop    %r11
  40089d:	59                   	pop    %rcx
  40089e:	5a                   	pop    %rdx
  40089f:	5e                   	pop    %rsi
  4008a0:	5f                   	pop    %rdi
  4008a1:	58                   	pop    %rax
  4008a2:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4008a9:	b8 00 00 00 00       	mov    $0x0,%eax
  4008ae:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4008b5:	50                   	push   %rax
  4008b6:	57                   	push   %rdi
  4008b7:	56                   	push   %rsi
  4008b8:	52                   	push   %rdx
  4008b9:	51                   	push   %rcx
  4008ba:	41 53                	push   %r11
  4008bc:	e8 d2 00 00 00       	callq  400993 <__trace_jump>
  4008c1:	41 5b                	pop    %r11
  4008c3:	59                   	pop    %rcx
  4008c4:	5a                   	pop    %rdx
  4008c5:	5e                   	pop    %rsi
  4008c6:	5f                   	pop    %rdi
  4008c7:	58                   	pop    %rax
  4008c8:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4008cf:	5d                   	pop    %rbp
  4008d0:	c3                   	retq   

00000000004008d1 <main>:
  4008d1:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4008d8:	50                   	push   %rax
  4008d9:	57                   	push   %rdi
  4008da:	56                   	push   %rsi
  4008db:	52                   	push   %rdx
  4008dc:	51                   	push   %rcx
  4008dd:	41 53                	push   %r11
  4008df:	e8 af 00 00 00       	callq  400993 <__trace_jump>
  4008e4:	41 5b                	pop    %r11
  4008e6:	59                   	pop    %rcx
  4008e7:	5a                   	pop    %rdx
  4008e8:	5e                   	pop    %rsi
  4008e9:	5f                   	pop    %rdi
  4008ea:	58                   	pop    %rax
  4008eb:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4008f2:	55                   	push   %rbp
  4008f3:	48 89 e5             	mov    %rsp,%rbp
  4008f6:	48 83 ec 30          	sub    $0x30,%rsp
  4008fa:	89 7d dc             	mov    %edi,-0x24(%rbp)
  4008fd:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
  400901:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  400908:	00 00 
  40090a:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  40090e:	31 c0                	xor    %eax,%eax
  400910:	48 8d 45 f6          	lea    -0xa(%rbp),%rax
  400914:	ba 02 00 00 00       	mov    $0x2,%edx
  400919:	48 89 c6             	mov    %rax,%rsi
  40091c:	bf 00 00 00 00       	mov    $0x0,%edi
  400921:	e8 3a fb ff ff       	callq  400460 <read@plt>
  400926:	89 45 ec             	mov    %eax,-0x14(%rbp)
  400929:	48 8d 45 f6          	lea    -0xa(%rbp),%rax
  40092d:	48 89 c7             	mov    %rax,%rdi
  400930:	e8 22 fc ff ff       	callq  400557 <test>
  400935:	89 45 f0             	mov    %eax,-0x10(%rbp)
  400938:	8b 45 f0             	mov    -0x10(%rbp),%eax
  40093b:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  40093f:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  400946:	00 00 
  400948:	74 26                	je     400970 <main+0x9f>
  40094a:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400951:	50                   	push   %rax
  400952:	57                   	push   %rdi
  400953:	56                   	push   %rsi
  400954:	52                   	push   %rdx
  400955:	51                   	push   %rcx
  400956:	41 53                	push   %r11
  400958:	e8 36 00 00 00       	callq  400993 <__trace_jump>
  40095d:	41 5b                	pop    %r11
  40095f:	59                   	pop    %rcx
  400960:	5a                   	pop    %rdx
  400961:	5e                   	pop    %rsi
  400962:	5f                   	pop    %rdi
  400963:	58                   	pop    %rax
  400964:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40096b:	e8 e0 fa ff ff       	callq  400450 <__stack_chk_fail@plt>
  400970:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400977:	50                   	push   %rax
  400978:	57                   	push   %rdi
  400979:	56                   	push   %rsi
  40097a:	52                   	push   %rdx
  40097b:	51                   	push   %rcx
  40097c:	41 53                	push   %r11
  40097e:	e8 10 00 00 00       	callq  400993 <__trace_jump>
  400983:	41 5b                	pop    %r11
  400985:	59                   	pop    %rcx
  400986:	5a                   	pop    %rdx
  400987:	5e                   	pop    %rsi
  400988:	5f                   	pop    %rdi
  400989:	58                   	pop    %rax
  40098a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400991:	c9                   	leaveq 
  400992:	c3                   	retq   

0000000000400993 <__trace_jump>:
  400993:	55                   	push   %rbp
  400994:	48 89 e5             	mov    %rsp,%rbp
  400997:	48 8b 45 08          	mov    0x8(%rbp),%rax
  40099b:	48 83 e8 13          	sub    $0x13,%rax
  40099f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4009a3:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  4009aa:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  4009b1:	48 89 ee             	mov    %rbp,%rsi
  4009b4:	48 83 ee 08          	sub    $0x8,%rsi
  4009b8:	48 c7 c2 08 00 00 00 	mov    $0x8,%rdx
  4009bf:	0f 05                	syscall 
  4009c1:	5d                   	pop    %rbp
  4009c2:	c3                   	retq   
  4009c3:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4009ca:	00 00 00 
  4009cd:	0f 1f 00             	nopl   (%rax)

00000000004009d0 <__libc_csu_init>:
  4009d0:	41 57                	push   %r15
  4009d2:	41 56                	push   %r14
  4009d4:	49 89 d7             	mov    %rdx,%r15
  4009d7:	41 55                	push   %r13
  4009d9:	41 54                	push   %r12
  4009db:	4c 8d 25 2e 04 20 00 	lea    0x20042e(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  4009e2:	55                   	push   %rbp
  4009e3:	48 8d 2d 2e 04 20 00 	lea    0x20042e(%rip),%rbp        # 600e18 <__init_array_end>
  4009ea:	53                   	push   %rbx
  4009eb:	41 89 fd             	mov    %edi,%r13d
  4009ee:	49 89 f6             	mov    %rsi,%r14
  4009f1:	4c 29 e5             	sub    %r12,%rbp
  4009f4:	48 83 ec 08          	sub    $0x8,%rsp
  4009f8:	48 c1 fd 03          	sar    $0x3,%rbp
  4009fc:	e8 27 fa ff ff       	callq  400428 <_init>
  400a01:	48 85 ed             	test   %rbp,%rbp
  400a04:	74 20                	je     400a26 <__libc_csu_init+0x56>
  400a06:	31 db                	xor    %ebx,%ebx
  400a08:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  400a0f:	00 
  400a10:	4c 89 fa             	mov    %r15,%rdx
  400a13:	4c 89 f6             	mov    %r14,%rsi
  400a16:	44 89 ef             	mov    %r13d,%edi
  400a19:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  400a1d:	48 83 c3 01          	add    $0x1,%rbx
  400a21:	48 39 dd             	cmp    %rbx,%rbp
  400a24:	75 ea                	jne    400a10 <__libc_csu_init+0x40>
  400a26:	48 83 c4 08          	add    $0x8,%rsp
  400a2a:	5b                   	pop    %rbx
  400a2b:	5d                   	pop    %rbp
  400a2c:	41 5c                	pop    %r12
  400a2e:	41 5d                	pop    %r13
  400a30:	41 5e                	pop    %r14
  400a32:	41 5f                	pop    %r15
  400a34:	c3                   	retq   
  400a35:	90                   	nop
  400a36:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  400a3d:	00 00 00 

0000000000400a40 <__libc_csu_fini>:
  400a40:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400a44 <_fini>:
  400a44:	48 83 ec 08          	sub    $0x8,%rsp
  400a48:	48 83 c4 08          	add    $0x8,%rsp
  400a4c:	c3                   	retq   
