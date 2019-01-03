
../Instrumented/test_half.instr:     file format elf64-x86-64


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
  40047f:	49 c7 c0 f0 09 40 00 	mov    $0x4009f0,%r8
  400486:	48 c7 c1 80 09 40 00 	mov    $0x400980,%rcx
  40048d:	48 c7 c7 89 08 40 00 	mov    $0x400889,%rdi
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
  400565:	e8 e0 03 00 00       	callq  40094a <__trace_jump>
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
  40057f:	81 7d fc ff 00 00 00 	cmpl   $0xff,-0x4(%rbp)
  400586:	76 2b                	jbe    4005b3 <test+0x5c>
  400588:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40058f:	50                   	push   %rax
  400590:	57                   	push   %rdi
  400591:	56                   	push   %rsi
  400592:	52                   	push   %rdx
  400593:	51                   	push   %rcx
  400594:	41 53                	push   %r11
  400596:	e8 af 03 00 00       	callq  40094a <__trace_jump>
  40059b:	41 5b                	pop    %r11
  40059d:	59                   	pop    %rcx
  40059e:	5a                   	pop    %rdx
  40059f:	5e                   	pop    %rsi
  4005a0:	5f                   	pop    %rdi
  4005a1:	58                   	pop    %rax
  4005a2:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005a9:	b8 09 00 00 00       	mov    $0x9,%eax
  4005ae:	e9 b3 02 00 00       	jmpq   400866 <test+0x30f>
  4005b3:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005ba:	50                   	push   %rax
  4005bb:	57                   	push   %rdi
  4005bc:	56                   	push   %rsi
  4005bd:	52                   	push   %rdx
  4005be:	51                   	push   %rcx
  4005bf:	41 53                	push   %r11
  4005c1:	e8 84 03 00 00       	callq  40094a <__trace_jump>
  4005c6:	41 5b                	pop    %r11
  4005c8:	59                   	pop    %rcx
  4005c9:	5a                   	pop    %rdx
  4005ca:	5e                   	pop    %rsi
  4005cb:	5f                   	pop    %rdi
  4005cc:	58                   	pop    %rax
  4005cd:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005d4:	81 7d fc 80 00 00 00 	cmpl   $0x80,-0x4(%rbp)
  4005db:	76 2b                	jbe    400608 <test+0xb1>
  4005dd:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005e4:	50                   	push   %rax
  4005e5:	57                   	push   %rdi
  4005e6:	56                   	push   %rsi
  4005e7:	52                   	push   %rdx
  4005e8:	51                   	push   %rcx
  4005e9:	41 53                	push   %r11
  4005eb:	e8 5a 03 00 00       	callq  40094a <__trace_jump>
  4005f0:	41 5b                	pop    %r11
  4005f2:	59                   	pop    %rcx
  4005f3:	5a                   	pop    %rdx
  4005f4:	5e                   	pop    %rsi
  4005f5:	5f                   	pop    %rdi
  4005f6:	58                   	pop    %rax
  4005f7:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005fe:	b8 08 00 00 00       	mov    $0x8,%eax
  400603:	e9 5e 02 00 00       	jmpq   400866 <test+0x30f>
  400608:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40060f:	50                   	push   %rax
  400610:	57                   	push   %rdi
  400611:	56                   	push   %rsi
  400612:	52                   	push   %rdx
  400613:	51                   	push   %rcx
  400614:	41 53                	push   %r11
  400616:	e8 2f 03 00 00       	callq  40094a <__trace_jump>
  40061b:	41 5b                	pop    %r11
  40061d:	59                   	pop    %rcx
  40061e:	5a                   	pop    %rdx
  40061f:	5e                   	pop    %rsi
  400620:	5f                   	pop    %rdi
  400621:	58                   	pop    %rax
  400622:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400629:	83 7d fc 40          	cmpl   $0x40,-0x4(%rbp)
  40062d:	76 2b                	jbe    40065a <test+0x103>
  40062f:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400636:	50                   	push   %rax
  400637:	57                   	push   %rdi
  400638:	56                   	push   %rsi
  400639:	52                   	push   %rdx
  40063a:	51                   	push   %rcx
  40063b:	41 53                	push   %r11
  40063d:	e8 08 03 00 00       	callq  40094a <__trace_jump>
  400642:	41 5b                	pop    %r11
  400644:	59                   	pop    %rcx
  400645:	5a                   	pop    %rdx
  400646:	5e                   	pop    %rsi
  400647:	5f                   	pop    %rdi
  400648:	58                   	pop    %rax
  400649:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400650:	b8 07 00 00 00       	mov    $0x7,%eax
  400655:	e9 0c 02 00 00       	jmpq   400866 <test+0x30f>
  40065a:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400661:	50                   	push   %rax
  400662:	57                   	push   %rdi
  400663:	56                   	push   %rsi
  400664:	52                   	push   %rdx
  400665:	51                   	push   %rcx
  400666:	41 53                	push   %r11
  400668:	e8 dd 02 00 00       	callq  40094a <__trace_jump>
  40066d:	41 5b                	pop    %r11
  40066f:	59                   	pop    %rcx
  400670:	5a                   	pop    %rdx
  400671:	5e                   	pop    %rsi
  400672:	5f                   	pop    %rdi
  400673:	58                   	pop    %rax
  400674:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40067b:	83 7d fc 20          	cmpl   $0x20,-0x4(%rbp)
  40067f:	76 2b                	jbe    4006ac <test+0x155>
  400681:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400688:	50                   	push   %rax
  400689:	57                   	push   %rdi
  40068a:	56                   	push   %rsi
  40068b:	52                   	push   %rdx
  40068c:	51                   	push   %rcx
  40068d:	41 53                	push   %r11
  40068f:	e8 b6 02 00 00       	callq  40094a <__trace_jump>
  400694:	41 5b                	pop    %r11
  400696:	59                   	pop    %rcx
  400697:	5a                   	pop    %rdx
  400698:	5e                   	pop    %rsi
  400699:	5f                   	pop    %rdi
  40069a:	58                   	pop    %rax
  40069b:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006a2:	b8 06 00 00 00       	mov    $0x6,%eax
  4006a7:	e9 ba 01 00 00       	jmpq   400866 <test+0x30f>
  4006ac:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006b3:	50                   	push   %rax
  4006b4:	57                   	push   %rdi
  4006b5:	56                   	push   %rsi
  4006b6:	52                   	push   %rdx
  4006b7:	51                   	push   %rcx
  4006b8:	41 53                	push   %r11
  4006ba:	e8 8b 02 00 00       	callq  40094a <__trace_jump>
  4006bf:	41 5b                	pop    %r11
  4006c1:	59                   	pop    %rcx
  4006c2:	5a                   	pop    %rdx
  4006c3:	5e                   	pop    %rsi
  4006c4:	5f                   	pop    %rdi
  4006c5:	58                   	pop    %rax
  4006c6:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006cd:	83 7d fc 10          	cmpl   $0x10,-0x4(%rbp)
  4006d1:	76 2b                	jbe    4006fe <test+0x1a7>
  4006d3:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006da:	50                   	push   %rax
  4006db:	57                   	push   %rdi
  4006dc:	56                   	push   %rsi
  4006dd:	52                   	push   %rdx
  4006de:	51                   	push   %rcx
  4006df:	41 53                	push   %r11
  4006e1:	e8 64 02 00 00       	callq  40094a <__trace_jump>
  4006e6:	41 5b                	pop    %r11
  4006e8:	59                   	pop    %rcx
  4006e9:	5a                   	pop    %rdx
  4006ea:	5e                   	pop    %rsi
  4006eb:	5f                   	pop    %rdi
  4006ec:	58                   	pop    %rax
  4006ed:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006f4:	b8 05 00 00 00       	mov    $0x5,%eax
  4006f9:	e9 68 01 00 00       	jmpq   400866 <test+0x30f>
  4006fe:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400705:	50                   	push   %rax
  400706:	57                   	push   %rdi
  400707:	56                   	push   %rsi
  400708:	52                   	push   %rdx
  400709:	51                   	push   %rcx
  40070a:	41 53                	push   %r11
  40070c:	e8 39 02 00 00       	callq  40094a <__trace_jump>
  400711:	41 5b                	pop    %r11
  400713:	59                   	pop    %rcx
  400714:	5a                   	pop    %rdx
  400715:	5e                   	pop    %rsi
  400716:	5f                   	pop    %rdi
  400717:	58                   	pop    %rax
  400718:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40071f:	83 7d fc 08          	cmpl   $0x8,-0x4(%rbp)
  400723:	76 2b                	jbe    400750 <test+0x1f9>
  400725:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40072c:	50                   	push   %rax
  40072d:	57                   	push   %rdi
  40072e:	56                   	push   %rsi
  40072f:	52                   	push   %rdx
  400730:	51                   	push   %rcx
  400731:	41 53                	push   %r11
  400733:	e8 12 02 00 00       	callq  40094a <__trace_jump>
  400738:	41 5b                	pop    %r11
  40073a:	59                   	pop    %rcx
  40073b:	5a                   	pop    %rdx
  40073c:	5e                   	pop    %rsi
  40073d:	5f                   	pop    %rdi
  40073e:	58                   	pop    %rax
  40073f:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400746:	b8 04 00 00 00       	mov    $0x4,%eax
  40074b:	e9 16 01 00 00       	jmpq   400866 <test+0x30f>
  400750:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400757:	50                   	push   %rax
  400758:	57                   	push   %rdi
  400759:	56                   	push   %rsi
  40075a:	52                   	push   %rdx
  40075b:	51                   	push   %rcx
  40075c:	41 53                	push   %r11
  40075e:	e8 e7 01 00 00       	callq  40094a <__trace_jump>
  400763:	41 5b                	pop    %r11
  400765:	59                   	pop    %rcx
  400766:	5a                   	pop    %rdx
  400767:	5e                   	pop    %rsi
  400768:	5f                   	pop    %rdi
  400769:	58                   	pop    %rax
  40076a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400771:	83 7d fc 04          	cmpl   $0x4,-0x4(%rbp)
  400775:	76 2b                	jbe    4007a2 <test+0x24b>
  400777:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40077e:	50                   	push   %rax
  40077f:	57                   	push   %rdi
  400780:	56                   	push   %rsi
  400781:	52                   	push   %rdx
  400782:	51                   	push   %rcx
  400783:	41 53                	push   %r11
  400785:	e8 c0 01 00 00       	callq  40094a <__trace_jump>
  40078a:	41 5b                	pop    %r11
  40078c:	59                   	pop    %rcx
  40078d:	5a                   	pop    %rdx
  40078e:	5e                   	pop    %rsi
  40078f:	5f                   	pop    %rdi
  400790:	58                   	pop    %rax
  400791:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400798:	b8 03 00 00 00       	mov    $0x3,%eax
  40079d:	e9 c4 00 00 00       	jmpq   400866 <test+0x30f>
  4007a2:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007a9:	50                   	push   %rax
  4007aa:	57                   	push   %rdi
  4007ab:	56                   	push   %rsi
  4007ac:	52                   	push   %rdx
  4007ad:	51                   	push   %rcx
  4007ae:	41 53                	push   %r11
  4007b0:	e8 95 01 00 00       	callq  40094a <__trace_jump>
  4007b5:	41 5b                	pop    %r11
  4007b7:	59                   	pop    %rcx
  4007b8:	5a                   	pop    %rdx
  4007b9:	5e                   	pop    %rsi
  4007ba:	5f                   	pop    %rdi
  4007bb:	58                   	pop    %rax
  4007bc:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4007c3:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
  4007c7:	76 28                	jbe    4007f1 <test+0x29a>
  4007c9:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007d0:	50                   	push   %rax
  4007d1:	57                   	push   %rdi
  4007d2:	56                   	push   %rsi
  4007d3:	52                   	push   %rdx
  4007d4:	51                   	push   %rcx
  4007d5:	41 53                	push   %r11
  4007d7:	e8 6e 01 00 00       	callq  40094a <__trace_jump>
  4007dc:	41 5b                	pop    %r11
  4007de:	59                   	pop    %rcx
  4007df:	5a                   	pop    %rdx
  4007e0:	5e                   	pop    %rsi
  4007e1:	5f                   	pop    %rdi
  4007e2:	58                   	pop    %rax
  4007e3:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4007ea:	b8 02 00 00 00       	mov    $0x2,%eax
  4007ef:	eb 75                	jmp    400866 <test+0x30f>
  4007f1:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007f8:	50                   	push   %rax
  4007f9:	57                   	push   %rdi
  4007fa:	56                   	push   %rsi
  4007fb:	52                   	push   %rdx
  4007fc:	51                   	push   %rcx
  4007fd:	41 53                	push   %r11
  4007ff:	e8 46 01 00 00       	callq  40094a <__trace_jump>
  400804:	41 5b                	pop    %r11
  400806:	59                   	pop    %rcx
  400807:	5a                   	pop    %rdx
  400808:	5e                   	pop    %rsi
  400809:	5f                   	pop    %rdi
  40080a:	58                   	pop    %rax
  40080b:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400812:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
  400816:	76 28                	jbe    400840 <test+0x2e9>
  400818:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40081f:	50                   	push   %rax
  400820:	57                   	push   %rdi
  400821:	56                   	push   %rsi
  400822:	52                   	push   %rdx
  400823:	51                   	push   %rcx
  400824:	41 53                	push   %r11
  400826:	e8 1f 01 00 00       	callq  40094a <__trace_jump>
  40082b:	41 5b                	pop    %r11
  40082d:	59                   	pop    %rcx
  40082e:	5a                   	pop    %rdx
  40082f:	5e                   	pop    %rsi
  400830:	5f                   	pop    %rdi
  400831:	58                   	pop    %rax
  400832:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400839:	b8 01 00 00 00       	mov    $0x1,%eax
  40083e:	eb 26                	jmp    400866 <test+0x30f>
  400840:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400847:	50                   	push   %rax
  400848:	57                   	push   %rdi
  400849:	56                   	push   %rsi
  40084a:	52                   	push   %rdx
  40084b:	51                   	push   %rcx
  40084c:	41 53                	push   %r11
  40084e:	e8 f7 00 00 00       	callq  40094a <__trace_jump>
  400853:	41 5b                	pop    %r11
  400855:	59                   	pop    %rcx
  400856:	5a                   	pop    %rdx
  400857:	5e                   	pop    %rsi
  400858:	5f                   	pop    %rdi
  400859:	58                   	pop    %rax
  40085a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400861:	b8 00 00 00 00       	mov    $0x0,%eax
  400866:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40086d:	50                   	push   %rax
  40086e:	57                   	push   %rdi
  40086f:	56                   	push   %rsi
  400870:	52                   	push   %rdx
  400871:	51                   	push   %rcx
  400872:	41 53                	push   %r11
  400874:	e8 d1 00 00 00       	callq  40094a <__trace_jump>
  400879:	41 5b                	pop    %r11
  40087b:	59                   	pop    %rcx
  40087c:	5a                   	pop    %rdx
  40087d:	5e                   	pop    %rsi
  40087e:	5f                   	pop    %rdi
  40087f:	58                   	pop    %rax
  400880:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400887:	5d                   	pop    %rbp
  400888:	c3                   	retq   

0000000000400889 <main>:
  400889:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400890:	50                   	push   %rax
  400891:	57                   	push   %rdi
  400892:	56                   	push   %rsi
  400893:	52                   	push   %rdx
  400894:	51                   	push   %rcx
  400895:	41 53                	push   %r11
  400897:	e8 ae 00 00 00       	callq  40094a <__trace_jump>
  40089c:	41 5b                	pop    %r11
  40089e:	59                   	pop    %rcx
  40089f:	5a                   	pop    %rdx
  4008a0:	5e                   	pop    %rsi
  4008a1:	5f                   	pop    %rdi
  4008a2:	58                   	pop    %rax
  4008a3:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4008aa:	55                   	push   %rbp
  4008ab:	48 89 e5             	mov    %rsp,%rbp
  4008ae:	48 83 ec 20          	sub    $0x20,%rsp
  4008b2:	89 7d ec             	mov    %edi,-0x14(%rbp)
  4008b5:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  4008b9:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  4008c0:	00 00 
  4008c2:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4008c6:	31 c0                	xor    %eax,%eax
  4008c8:	48 8d 45 f3          	lea    -0xd(%rbp),%rax
  4008cc:	ba 01 00 00 00       	mov    $0x1,%edx
  4008d1:	48 89 c6             	mov    %rax,%rsi
  4008d4:	bf 00 00 00 00       	mov    $0x0,%edi
  4008d9:	e8 82 fb ff ff       	callq  400460 <read@plt>
  4008de:	0f b6 45 f3          	movzbl -0xd(%rbp),%eax
  4008e2:	0f b6 c0             	movzbl %al,%eax
  4008e5:	89 c7                	mov    %eax,%edi
  4008e7:	e8 6b fc ff ff       	callq  400557 <test>
  4008ec:	89 45 f4             	mov    %eax,-0xc(%rbp)
  4008ef:	8b 45 f4             	mov    -0xc(%rbp),%eax
  4008f2:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  4008f6:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  4008fd:	00 00 
  4008ff:	74 26                	je     400927 <main+0x9e>
  400901:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400908:	50                   	push   %rax
  400909:	57                   	push   %rdi
  40090a:	56                   	push   %rsi
  40090b:	52                   	push   %rdx
  40090c:	51                   	push   %rcx
  40090d:	41 53                	push   %r11
  40090f:	e8 36 00 00 00       	callq  40094a <__trace_jump>
  400914:	41 5b                	pop    %r11
  400916:	59                   	pop    %rcx
  400917:	5a                   	pop    %rdx
  400918:	5e                   	pop    %rsi
  400919:	5f                   	pop    %rdi
  40091a:	58                   	pop    %rax
  40091b:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400922:	e8 29 fb ff ff       	callq  400450 <__stack_chk_fail@plt>
  400927:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40092e:	50                   	push   %rax
  40092f:	57                   	push   %rdi
  400930:	56                   	push   %rsi
  400931:	52                   	push   %rdx
  400932:	51                   	push   %rcx
  400933:	41 53                	push   %r11
  400935:	e8 10 00 00 00       	callq  40094a <__trace_jump>
  40093a:	41 5b                	pop    %r11
  40093c:	59                   	pop    %rcx
  40093d:	5a                   	pop    %rdx
  40093e:	5e                   	pop    %rsi
  40093f:	5f                   	pop    %rdi
  400940:	58                   	pop    %rax
  400941:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400948:	c9                   	leaveq 
  400949:	c3                   	retq   

000000000040094a <__trace_jump>:
  40094a:	55                   	push   %rbp
  40094b:	48 89 e5             	mov    %rsp,%rbp
  40094e:	48 8b 45 08          	mov    0x8(%rbp),%rax
  400952:	48 83 e8 13          	sub    $0x13,%rax
  400956:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  40095a:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  400961:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  400968:	48 89 ee             	mov    %rbp,%rsi
  40096b:	48 83 ee 08          	sub    $0x8,%rsi
  40096f:	48 c7 c2 08 00 00 00 	mov    $0x8,%rdx
  400976:	0f 05                	syscall 
  400978:	5d                   	pop    %rbp
  400979:	c3                   	retq   
  40097a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400980 <__libc_csu_init>:
  400980:	41 57                	push   %r15
  400982:	41 56                	push   %r14
  400984:	49 89 d7             	mov    %rdx,%r15
  400987:	41 55                	push   %r13
  400989:	41 54                	push   %r12
  40098b:	4c 8d 25 7e 04 20 00 	lea    0x20047e(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  400992:	55                   	push   %rbp
  400993:	48 8d 2d 7e 04 20 00 	lea    0x20047e(%rip),%rbp        # 600e18 <__init_array_end>
  40099a:	53                   	push   %rbx
  40099b:	41 89 fd             	mov    %edi,%r13d
  40099e:	49 89 f6             	mov    %rsi,%r14
  4009a1:	4c 29 e5             	sub    %r12,%rbp
  4009a4:	48 83 ec 08          	sub    $0x8,%rsp
  4009a8:	48 c1 fd 03          	sar    $0x3,%rbp
  4009ac:	e8 77 fa ff ff       	callq  400428 <_init>
  4009b1:	48 85 ed             	test   %rbp,%rbp
  4009b4:	74 20                	je     4009d6 <__libc_csu_init+0x56>
  4009b6:	31 db                	xor    %ebx,%ebx
  4009b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4009bf:	00 
  4009c0:	4c 89 fa             	mov    %r15,%rdx
  4009c3:	4c 89 f6             	mov    %r14,%rsi
  4009c6:	44 89 ef             	mov    %r13d,%edi
  4009c9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4009cd:	48 83 c3 01          	add    $0x1,%rbx
  4009d1:	48 39 dd             	cmp    %rbx,%rbp
  4009d4:	75 ea                	jne    4009c0 <__libc_csu_init+0x40>
  4009d6:	48 83 c4 08          	add    $0x8,%rsp
  4009da:	5b                   	pop    %rbx
  4009db:	5d                   	pop    %rbp
  4009dc:	41 5c                	pop    %r12
  4009de:	41 5d                	pop    %r13
  4009e0:	41 5e                	pop    %r14
  4009e2:	41 5f                	pop    %r15
  4009e4:	c3                   	retq   
  4009e5:	90                   	nop
  4009e6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4009ed:	00 00 00 

00000000004009f0 <__libc_csu_fini>:
  4009f0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000004009f4 <_fini>:
  4009f4:	48 83 ec 08          	sub    $0x8,%rsp
  4009f8:	48 83 c4 08          	add    $0x8,%rsp
  4009fc:	c3                   	retq   
