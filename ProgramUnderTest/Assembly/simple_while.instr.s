
../Instrumented/simple_while.instr:     file format elf64-x86-64


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
  40047f:	49 c7 c0 10 09 40 00 	mov    $0x400910,%r8
  400486:	48 c7 c1 a0 08 40 00 	mov    $0x4008a0,%rcx
  40048d:	48 c7 c7 1f 07 40 00 	mov    $0x40071f,%rdi
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

0000000000400557 <region1>:
  400557:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40055e:	50                   	push   %rax
  40055f:	57                   	push   %rdi
  400560:	56                   	push   %rsi
  400561:	52                   	push   %rdx
  400562:	51                   	push   %rcx
  400563:	41 53                	push   %r11
  400565:	e8 06 03 00 00       	callq  400870 <__trace_jump>
  40056a:	41 5b                	pop    %r11
  40056c:	59                   	pop    %rcx
  40056d:	5a                   	pop    %rdx
  40056e:	5e                   	pop    %rsi
  40056f:	5f                   	pop    %rdi
  400570:	58                   	pop    %rax
  400571:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400578:	55                   	push   %rbp
  400579:	48 89 e5             	mov    %rsp,%rbp
  40057c:	89 7d fc             	mov    %edi,-0x4(%rbp)
  40057f:	eb 25                	jmp    4005a6 <region1+0x4f>
  400581:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400588:	50                   	push   %rax
  400589:	57                   	push   %rdi
  40058a:	56                   	push   %rsi
  40058b:	52                   	push   %rdx
  40058c:	51                   	push   %rcx
  40058d:	41 53                	push   %r11
  40058f:	e8 dc 02 00 00       	callq  400870 <__trace_jump>
  400594:	41 5b                	pop    %r11
  400596:	59                   	pop    %rcx
  400597:	5a                   	pop    %rdx
  400598:	5e                   	pop    %rsi
  400599:	5f                   	pop    %rdi
  40059a:	58                   	pop    %rax
  40059b:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005a2:	83 6d fc 01          	subl   $0x1,-0x4(%rbp)
  4005a6:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005ad:	50                   	push   %rax
  4005ae:	57                   	push   %rdi
  4005af:	56                   	push   %rsi
  4005b0:	52                   	push   %rdx
  4005b1:	51                   	push   %rcx
  4005b2:	41 53                	push   %r11
  4005b4:	e8 b7 02 00 00       	callq  400870 <__trace_jump>
  4005b9:	41 5b                	pop    %r11
  4005bb:	59                   	pop    %rcx
  4005bc:	5a                   	pop    %rdx
  4005bd:	5e                   	pop    %rsi
  4005be:	5f                   	pop    %rdi
  4005bf:	58                   	pop    %rax
  4005c0:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005c7:	83 7d fc 20          	cmpl   $0x20,-0x4(%rbp)
  4005cb:	76 48                	jbe    400615 <region1+0xbe>
  4005cd:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005d4:	50                   	push   %rax
  4005d5:	57                   	push   %rdi
  4005d6:	56                   	push   %rsi
  4005d7:	52                   	push   %rdx
  4005d8:	51                   	push   %rcx
  4005d9:	41 53                	push   %r11
  4005db:	e8 90 02 00 00       	callq  400870 <__trace_jump>
  4005e0:	41 5b                	pop    %r11
  4005e2:	59                   	pop    %rcx
  4005e3:	5a                   	pop    %rdx
  4005e4:	5e                   	pop    %rsi
  4005e5:	5f                   	pop    %rdi
  4005e6:	58                   	pop    %rax
  4005e7:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005ee:	83 7d fc 27          	cmpl   $0x27,-0x4(%rbp)
  4005f2:	76 8d                	jbe    400581 <region1+0x2a>
  4005f4:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005fb:	50                   	push   %rax
  4005fc:	57                   	push   %rdi
  4005fd:	56                   	push   %rsi
  4005fe:	52                   	push   %rdx
  4005ff:	51                   	push   %rcx
  400600:	41 53                	push   %r11
  400602:	e8 69 02 00 00       	callq  400870 <__trace_jump>
  400607:	41 5b                	pop    %r11
  400609:	59                   	pop    %rcx
  40060a:	5a                   	pop    %rdx
  40060b:	5e                   	pop    %rsi
  40060c:	5f                   	pop    %rdi
  40060d:	58                   	pop    %rax
  40060e:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400615:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40061c:	50                   	push   %rax
  40061d:	57                   	push   %rdi
  40061e:	56                   	push   %rsi
  40061f:	52                   	push   %rdx
  400620:	51                   	push   %rcx
  400621:	41 53                	push   %r11
  400623:	e8 48 02 00 00       	callq  400870 <__trace_jump>
  400628:	41 5b                	pop    %r11
  40062a:	59                   	pop    %rcx
  40062b:	5a                   	pop    %rdx
  40062c:	5e                   	pop    %rsi
  40062d:	5f                   	pop    %rdi
  40062e:	58                   	pop    %rax
  40062f:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400636:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400639:	5d                   	pop    %rbp
  40063a:	c3                   	retq   

000000000040063b <region2>:
  40063b:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400642:	50                   	push   %rax
  400643:	57                   	push   %rdi
  400644:	56                   	push   %rsi
  400645:	52                   	push   %rdx
  400646:	51                   	push   %rcx
  400647:	41 53                	push   %r11
  400649:	e8 22 02 00 00       	callq  400870 <__trace_jump>
  40064e:	41 5b                	pop    %r11
  400650:	59                   	pop    %rcx
  400651:	5a                   	pop    %rdx
  400652:	5e                   	pop    %rsi
  400653:	5f                   	pop    %rdi
  400654:	58                   	pop    %rax
  400655:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40065c:	55                   	push   %rbp
  40065d:	48 89 e5             	mov    %rsp,%rbp
  400660:	89 7d fc             	mov    %edi,-0x4(%rbp)
  400663:	eb 25                	jmp    40068a <region2+0x4f>
  400665:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40066c:	50                   	push   %rax
  40066d:	57                   	push   %rdi
  40066e:	56                   	push   %rsi
  40066f:	52                   	push   %rdx
  400670:	51                   	push   %rcx
  400671:	41 53                	push   %r11
  400673:	e8 f8 01 00 00       	callq  400870 <__trace_jump>
  400678:	41 5b                	pop    %r11
  40067a:	59                   	pop    %rcx
  40067b:	5a                   	pop    %rdx
  40067c:	5e                   	pop    %rsi
  40067d:	5f                   	pop    %rdi
  40067e:	58                   	pop    %rax
  40067f:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400686:	83 6d fc 01          	subl   $0x1,-0x4(%rbp)
  40068a:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400691:	50                   	push   %rax
  400692:	57                   	push   %rdi
  400693:	56                   	push   %rsi
  400694:	52                   	push   %rdx
  400695:	51                   	push   %rcx
  400696:	41 53                	push   %r11
  400698:	e8 d3 01 00 00       	callq  400870 <__trace_jump>
  40069d:	41 5b                	pop    %r11
  40069f:	59                   	pop    %rcx
  4006a0:	5a                   	pop    %rdx
  4006a1:	5e                   	pop    %rsi
  4006a2:	5f                   	pop    %rdi
  4006a3:	58                   	pop    %rax
  4006a4:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006ab:	83 7d fc 64          	cmpl   $0x64,-0x4(%rbp)
  4006af:	76 48                	jbe    4006f9 <region2+0xbe>
  4006b1:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006b8:	50                   	push   %rax
  4006b9:	57                   	push   %rdi
  4006ba:	56                   	push   %rsi
  4006bb:	52                   	push   %rdx
  4006bc:	51                   	push   %rcx
  4006bd:	41 53                	push   %r11
  4006bf:	e8 ac 01 00 00       	callq  400870 <__trace_jump>
  4006c4:	41 5b                	pop    %r11
  4006c6:	59                   	pop    %rcx
  4006c7:	5a                   	pop    %rdx
  4006c8:	5e                   	pop    %rsi
  4006c9:	5f                   	pop    %rdi
  4006ca:	58                   	pop    %rax
  4006cb:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006d2:	83 7d fc 6b          	cmpl   $0x6b,-0x4(%rbp)
  4006d6:	76 8d                	jbe    400665 <region2+0x2a>
  4006d8:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006df:	50                   	push   %rax
  4006e0:	57                   	push   %rdi
  4006e1:	56                   	push   %rsi
  4006e2:	52                   	push   %rdx
  4006e3:	51                   	push   %rcx
  4006e4:	41 53                	push   %r11
  4006e6:	e8 85 01 00 00       	callq  400870 <__trace_jump>
  4006eb:	41 5b                	pop    %r11
  4006ed:	59                   	pop    %rcx
  4006ee:	5a                   	pop    %rdx
  4006ef:	5e                   	pop    %rsi
  4006f0:	5f                   	pop    %rdi
  4006f1:	58                   	pop    %rax
  4006f2:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006f9:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400700:	50                   	push   %rax
  400701:	57                   	push   %rdi
  400702:	56                   	push   %rsi
  400703:	52                   	push   %rdx
  400704:	51                   	push   %rcx
  400705:	41 53                	push   %r11
  400707:	e8 64 01 00 00       	callq  400870 <__trace_jump>
  40070c:	41 5b                	pop    %r11
  40070e:	59                   	pop    %rcx
  40070f:	5a                   	pop    %rdx
  400710:	5e                   	pop    %rsi
  400711:	5f                   	pop    %rdi
  400712:	58                   	pop    %rax
  400713:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40071a:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40071d:	5d                   	pop    %rbp
  40071e:	c3                   	retq   

000000000040071f <main>:
  40071f:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400726:	50                   	push   %rax
  400727:	57                   	push   %rdi
  400728:	56                   	push   %rsi
  400729:	52                   	push   %rdx
  40072a:	51                   	push   %rcx
  40072b:	41 53                	push   %r11
  40072d:	e8 3e 01 00 00       	callq  400870 <__trace_jump>
  400732:	41 5b                	pop    %r11
  400734:	59                   	pop    %rcx
  400735:	5a                   	pop    %rdx
  400736:	5e                   	pop    %rsi
  400737:	5f                   	pop    %rdi
  400738:	58                   	pop    %rax
  400739:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400740:	55                   	push   %rbp
  400741:	48 89 e5             	mov    %rsp,%rbp
  400744:	48 83 ec 20          	sub    $0x20,%rsp
  400748:	89 7d ec             	mov    %edi,-0x14(%rbp)
  40074b:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  40074f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  400756:	00 00 
  400758:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  40075c:	31 c0                	xor    %eax,%eax
  40075e:	48 8d 45 f6          	lea    -0xa(%rbp),%rax
  400762:	ba 02 00 00 00       	mov    $0x2,%edx
  400767:	48 89 c6             	mov    %rax,%rsi
  40076a:	bf 00 00 00 00       	mov    $0x0,%edi
  40076f:	e8 ec fc ff ff       	callq  400460 <read@plt>
  400774:	89 45 f0             	mov    %eax,-0x10(%rbp)
  400777:	0f b6 45 f6          	movzbl -0xa(%rbp),%eax
  40077b:	3c 19                	cmp    $0x19,%al
  40077d:	75 65                	jne    4007e4 <main+0xc5>
  40077f:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400786:	50                   	push   %rax
  400787:	57                   	push   %rdi
  400788:	56                   	push   %rsi
  400789:	52                   	push   %rdx
  40078a:	51                   	push   %rcx
  40078b:	41 53                	push   %r11
  40078d:	e8 de 00 00 00       	callq  400870 <__trace_jump>
  400792:	41 5b                	pop    %r11
  400794:	59                   	pop    %rcx
  400795:	5a                   	pop    %rdx
  400796:	5e                   	pop    %rsi
  400797:	5f                   	pop    %rdi
  400798:	58                   	pop    %rax
  400799:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4007a0:	0f b6 45 f6          	movzbl -0xa(%rbp),%eax
  4007a4:	0f b6 d0             	movzbl %al,%edx
  4007a7:	0f b6 45 f7          	movzbl -0x9(%rbp),%eax
  4007ab:	0f b6 c0             	movzbl %al,%eax
  4007ae:	01 d0                	add    %edx,%eax
  4007b0:	83 f8 40             	cmp    $0x40,%eax
  4007b3:	7f 2f                	jg     4007e4 <main+0xc5>
  4007b5:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007bc:	50                   	push   %rax
  4007bd:	57                   	push   %rdi
  4007be:	56                   	push   %rsi
  4007bf:	52                   	push   %rdx
  4007c0:	51                   	push   %rcx
  4007c1:	41 53                	push   %r11
  4007c3:	e8 a8 00 00 00       	callq  400870 <__trace_jump>
  4007c8:	41 5b                	pop    %r11
  4007ca:	59                   	pop    %rcx
  4007cb:	5a                   	pop    %rdx
  4007cc:	5e                   	pop    %rsi
  4007cd:	5f                   	pop    %rdi
  4007ce:	58                   	pop    %rax
  4007cf:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4007d6:	0f b6 45 f7          	movzbl -0x9(%rbp),%eax
  4007da:	0f b6 c0             	movzbl %al,%eax
  4007dd:	89 c7                	mov    %eax,%edi
  4007df:	e8 73 fd ff ff       	callq  400557 <region1>
  4007e4:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007eb:	50                   	push   %rax
  4007ec:	57                   	push   %rdi
  4007ed:	56                   	push   %rsi
  4007ee:	52                   	push   %rdx
  4007ef:	51                   	push   %rcx
  4007f0:	41 53                	push   %r11
  4007f2:	e8 79 00 00 00       	callq  400870 <__trace_jump>
  4007f7:	41 5b                	pop    %r11
  4007f9:	59                   	pop    %rcx
  4007fa:	5a                   	pop    %rdx
  4007fb:	5e                   	pop    %rsi
  4007fc:	5f                   	pop    %rdi
  4007fd:	58                   	pop    %rax
  4007fe:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400805:	0f b6 45 f6          	movzbl -0xa(%rbp),%eax
  400809:	0f b6 c0             	movzbl %al,%eax
  40080c:	89 c7                	mov    %eax,%edi
  40080e:	e8 28 fe ff ff       	callq  40063b <region2>
  400813:	b8 00 00 00 00       	mov    $0x0,%eax
  400818:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  40081c:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  400823:	00 00 
  400825:	74 26                	je     40084d <main+0x12e>
  400827:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40082e:	50                   	push   %rax
  40082f:	57                   	push   %rdi
  400830:	56                   	push   %rsi
  400831:	52                   	push   %rdx
  400832:	51                   	push   %rcx
  400833:	41 53                	push   %r11
  400835:	e8 36 00 00 00       	callq  400870 <__trace_jump>
  40083a:	41 5b                	pop    %r11
  40083c:	59                   	pop    %rcx
  40083d:	5a                   	pop    %rdx
  40083e:	5e                   	pop    %rsi
  40083f:	5f                   	pop    %rdi
  400840:	58                   	pop    %rax
  400841:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400848:	e8 03 fc ff ff       	callq  400450 <__stack_chk_fail@plt>
  40084d:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400854:	50                   	push   %rax
  400855:	57                   	push   %rdi
  400856:	56                   	push   %rsi
  400857:	52                   	push   %rdx
  400858:	51                   	push   %rcx
  400859:	41 53                	push   %r11
  40085b:	e8 10 00 00 00       	callq  400870 <__trace_jump>
  400860:	41 5b                	pop    %r11
  400862:	59                   	pop    %rcx
  400863:	5a                   	pop    %rdx
  400864:	5e                   	pop    %rsi
  400865:	5f                   	pop    %rdi
  400866:	58                   	pop    %rax
  400867:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40086e:	c9                   	leaveq 
  40086f:	c3                   	retq   

0000000000400870 <__trace_jump>:
  400870:	55                   	push   %rbp
  400871:	48 89 e5             	mov    %rsp,%rbp
  400874:	48 8b 45 08          	mov    0x8(%rbp),%rax
  400878:	48 83 e8 13          	sub    $0x13,%rax
  40087c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  400880:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  400887:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  40088e:	48 89 ee             	mov    %rbp,%rsi
  400891:	48 83 ee 08          	sub    $0x8,%rsi
  400895:	48 c7 c2 08 00 00 00 	mov    $0x8,%rdx
  40089c:	0f 05                	syscall 
  40089e:	5d                   	pop    %rbp
  40089f:	c3                   	retq   

00000000004008a0 <__libc_csu_init>:
  4008a0:	41 57                	push   %r15
  4008a2:	41 56                	push   %r14
  4008a4:	49 89 d7             	mov    %rdx,%r15
  4008a7:	41 55                	push   %r13
  4008a9:	41 54                	push   %r12
  4008ab:	4c 8d 25 5e 05 20 00 	lea    0x20055e(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  4008b2:	55                   	push   %rbp
  4008b3:	48 8d 2d 5e 05 20 00 	lea    0x20055e(%rip),%rbp        # 600e18 <__init_array_end>
  4008ba:	53                   	push   %rbx
  4008bb:	41 89 fd             	mov    %edi,%r13d
  4008be:	49 89 f6             	mov    %rsi,%r14
  4008c1:	4c 29 e5             	sub    %r12,%rbp
  4008c4:	48 83 ec 08          	sub    $0x8,%rsp
  4008c8:	48 c1 fd 03          	sar    $0x3,%rbp
  4008cc:	e8 57 fb ff ff       	callq  400428 <_init>
  4008d1:	48 85 ed             	test   %rbp,%rbp
  4008d4:	74 20                	je     4008f6 <__libc_csu_init+0x56>
  4008d6:	31 db                	xor    %ebx,%ebx
  4008d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4008df:	00 
  4008e0:	4c 89 fa             	mov    %r15,%rdx
  4008e3:	4c 89 f6             	mov    %r14,%rsi
  4008e6:	44 89 ef             	mov    %r13d,%edi
  4008e9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4008ed:	48 83 c3 01          	add    $0x1,%rbx
  4008f1:	48 39 dd             	cmp    %rbx,%rbp
  4008f4:	75 ea                	jne    4008e0 <__libc_csu_init+0x40>
  4008f6:	48 83 c4 08          	add    $0x8,%rsp
  4008fa:	5b                   	pop    %rbx
  4008fb:	5d                   	pop    %rbp
  4008fc:	41 5c                	pop    %r12
  4008fe:	41 5d                	pop    %r13
  400900:	41 5e                	pop    %r14
  400902:	41 5f                	pop    %r15
  400904:	c3                   	retq   
  400905:	90                   	nop
  400906:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40090d:	00 00 00 

0000000000400910 <__libc_csu_fini>:
  400910:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400914 <_fini>:
  400914:	48 83 ec 08          	sub    $0x8,%rsp
  400918:	48 83 c4 08          	add    $0x8,%rsp
  40091c:	c3                   	retq   
