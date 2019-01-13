
../Instrumented/test_bise.instr:     file format elf64-x86-64


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
  40047f:	49 c7 c0 d0 09 40 00 	mov    $0x4009d0,%r8
  400486:	48 c7 c1 60 09 40 00 	mov    $0x400960,%rcx
  40048d:	48 c7 c7 81 08 40 00 	mov    $0x400881,%rdi
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
  400557:	55                   	push   %rbp
  400558:	48 89 e5             	mov    %rsp,%rbp
  40055b:	89 7d fc             	mov    %edi,-0x4(%rbp)
  40055e:	81 7d fc ff 00 00 00 	cmpl   $0xff,-0x4(%rbp)
  400565:	0f 87 cd 02 00 00    	ja     400838 <test+0x2e1>
  40056b:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400572:	50                   	push   %rax
  400573:	57                   	push   %rdi
  400574:	56                   	push   %rsi
  400575:	52                   	push   %rdx
  400576:	51                   	push   %rcx
  400577:	41 53                	push   %r11
  400579:	e8 a3 03 00 00       	callq  400921 <__trace_jump>
  40057e:	41 5b                	pop    %r11
  400580:	59                   	pop    %rcx
  400581:	5a                   	pop    %rdx
  400582:	5e                   	pop    %rsi
  400583:	5f                   	pop    %rdi
  400584:	58                   	pop    %rax
  400585:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40058c:	81 7d fc 80 00 00 00 	cmpl   $0x80,-0x4(%rbp)
  400593:	0f 87 77 02 00 00    	ja     400810 <test+0x2b9>
  400599:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005a0:	50                   	push   %rax
  4005a1:	57                   	push   %rdi
  4005a2:	56                   	push   %rsi
  4005a3:	52                   	push   %rdx
  4005a4:	51                   	push   %rcx
  4005a5:	41 53                	push   %r11
  4005a7:	e8 75 03 00 00       	callq  400921 <__trace_jump>
  4005ac:	41 5b                	pop    %r11
  4005ae:	59                   	pop    %rcx
  4005af:	5a                   	pop    %rdx
  4005b0:	5e                   	pop    %rsi
  4005b1:	5f                   	pop    %rdi
  4005b2:	58                   	pop    %rax
  4005b3:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005ba:	83 7d fc 40          	cmpl   $0x40,-0x4(%rbp)
  4005be:	0f 87 24 02 00 00    	ja     4007e8 <test+0x291>
  4005c4:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005cb:	50                   	push   %rax
  4005cc:	57                   	push   %rdi
  4005cd:	56                   	push   %rsi
  4005ce:	52                   	push   %rdx
  4005cf:	51                   	push   %rcx
  4005d0:	41 53                	push   %r11
  4005d2:	e8 4a 03 00 00       	callq  400921 <__trace_jump>
  4005d7:	41 5b                	pop    %r11
  4005d9:	59                   	pop    %rcx
  4005da:	5a                   	pop    %rdx
  4005db:	5e                   	pop    %rsi
  4005dc:	5f                   	pop    %rdi
  4005dd:	58                   	pop    %rax
  4005de:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4005e5:	83 7d fc 20          	cmpl   $0x20,-0x4(%rbp)
  4005e9:	0f 87 d1 01 00 00    	ja     4007c0 <test+0x269>
  4005ef:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4005f6:	50                   	push   %rax
  4005f7:	57                   	push   %rdi
  4005f8:	56                   	push   %rsi
  4005f9:	52                   	push   %rdx
  4005fa:	51                   	push   %rcx
  4005fb:	41 53                	push   %r11
  4005fd:	e8 1f 03 00 00       	callq  400921 <__trace_jump>
  400602:	41 5b                	pop    %r11
  400604:	59                   	pop    %rcx
  400605:	5a                   	pop    %rdx
  400606:	5e                   	pop    %rsi
  400607:	5f                   	pop    %rdi
  400608:	58                   	pop    %rax
  400609:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400610:	83 7d fc 10          	cmpl   $0x10,-0x4(%rbp)
  400614:	0f 87 7b 01 00 00    	ja     400795 <test+0x23e>
  40061a:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400621:	50                   	push   %rax
  400622:	57                   	push   %rdi
  400623:	56                   	push   %rsi
  400624:	52                   	push   %rdx
  400625:	51                   	push   %rcx
  400626:	41 53                	push   %r11
  400628:	e8 f4 02 00 00       	callq  400921 <__trace_jump>
  40062d:	41 5b                	pop    %r11
  40062f:	59                   	pop    %rcx
  400630:	5a                   	pop    %rdx
  400631:	5e                   	pop    %rsi
  400632:	5f                   	pop    %rdi
  400633:	58                   	pop    %rax
  400634:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40063b:	83 7d fc 08          	cmpl   $0x8,-0x4(%rbp)
  40063f:	0f 87 25 01 00 00    	ja     40076a <test+0x213>
  400645:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40064c:	50                   	push   %rax
  40064d:	57                   	push   %rdi
  40064e:	56                   	push   %rsi
  40064f:	52                   	push   %rdx
  400650:	51                   	push   %rcx
  400651:	41 53                	push   %r11
  400653:	e8 c9 02 00 00       	callq  400921 <__trace_jump>
  400658:	41 5b                	pop    %r11
  40065a:	59                   	pop    %rcx
  40065b:	5a                   	pop    %rdx
  40065c:	5e                   	pop    %rsi
  40065d:	5f                   	pop    %rdi
  40065e:	58                   	pop    %rax
  40065f:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400666:	83 7d fc 04          	cmpl   $0x4,-0x4(%rbp)
  40066a:	0f 87 cf 00 00 00    	ja     40073f <test+0x1e8>
  400670:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400677:	50                   	push   %rax
  400678:	57                   	push   %rdi
  400679:	56                   	push   %rsi
  40067a:	52                   	push   %rdx
  40067b:	51                   	push   %rcx
  40067c:	41 53                	push   %r11
  40067e:	e8 9e 02 00 00       	callq  400921 <__trace_jump>
  400683:	41 5b                	pop    %r11
  400685:	59                   	pop    %rcx
  400686:	5a                   	pop    %rdx
  400687:	5e                   	pop    %rsi
  400688:	5f                   	pop    %rdi
  400689:	58                   	pop    %rax
  40068a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400691:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
  400695:	77 7d                	ja     400714 <test+0x1bd>
  400697:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40069e:	50                   	push   %rax
  40069f:	57                   	push   %rdi
  4006a0:	56                   	push   %rsi
  4006a1:	52                   	push   %rdx
  4006a2:	51                   	push   %rcx
  4006a3:	41 53                	push   %r11
  4006a5:	e8 77 02 00 00       	callq  400921 <__trace_jump>
  4006aa:	41 5b                	pop    %r11
  4006ac:	59                   	pop    %rcx
  4006ad:	5a                   	pop    %rdx
  4006ae:	5e                   	pop    %rsi
  4006af:	5f                   	pop    %rdi
  4006b0:	58                   	pop    %rax
  4006b1:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006b8:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
  4006bc:	77 2b                	ja     4006e9 <test+0x192>
  4006be:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006c5:	50                   	push   %rax
  4006c6:	57                   	push   %rdi
  4006c7:	56                   	push   %rsi
  4006c8:	52                   	push   %rdx
  4006c9:	51                   	push   %rcx
  4006ca:	41 53                	push   %r11
  4006cc:	e8 50 02 00 00       	callq  400921 <__trace_jump>
  4006d1:	41 5b                	pop    %r11
  4006d3:	59                   	pop    %rcx
  4006d4:	5a                   	pop    %rdx
  4006d5:	5e                   	pop    %rsi
  4006d6:	5f                   	pop    %rdi
  4006d7:	58                   	pop    %rax
  4006d8:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4006df:	b8 01 00 00 00       	mov    $0x1,%eax
  4006e4:	e9 75 01 00 00       	jmpq   40085e <test+0x307>
  4006e9:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4006f0:	50                   	push   %rax
  4006f1:	57                   	push   %rdi
  4006f2:	56                   	push   %rsi
  4006f3:	52                   	push   %rdx
  4006f4:	51                   	push   %rcx
  4006f5:	41 53                	push   %r11
  4006f7:	e8 25 02 00 00       	callq  400921 <__trace_jump>
  4006fc:	41 5b                	pop    %r11
  4006fe:	59                   	pop    %rcx
  4006ff:	5a                   	pop    %rdx
  400700:	5e                   	pop    %rsi
  400701:	5f                   	pop    %rdi
  400702:	58                   	pop    %rax
  400703:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40070a:	b8 02 00 00 00       	mov    $0x2,%eax
  40070f:	e9 4a 01 00 00       	jmpq   40085e <test+0x307>
  400714:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40071b:	50                   	push   %rax
  40071c:	57                   	push   %rdi
  40071d:	56                   	push   %rsi
  40071e:	52                   	push   %rdx
  40071f:	51                   	push   %rcx
  400720:	41 53                	push   %r11
  400722:	e8 fa 01 00 00       	callq  400921 <__trace_jump>
  400727:	41 5b                	pop    %r11
  400729:	59                   	pop    %rcx
  40072a:	5a                   	pop    %rdx
  40072b:	5e                   	pop    %rsi
  40072c:	5f                   	pop    %rdi
  40072d:	58                   	pop    %rax
  40072e:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400735:	b8 03 00 00 00       	mov    $0x3,%eax
  40073a:	e9 1f 01 00 00       	jmpq   40085e <test+0x307>
  40073f:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400746:	50                   	push   %rax
  400747:	57                   	push   %rdi
  400748:	56                   	push   %rsi
  400749:	52                   	push   %rdx
  40074a:	51                   	push   %rcx
  40074b:	41 53                	push   %r11
  40074d:	e8 cf 01 00 00       	callq  400921 <__trace_jump>
  400752:	41 5b                	pop    %r11
  400754:	59                   	pop    %rcx
  400755:	5a                   	pop    %rdx
  400756:	5e                   	pop    %rsi
  400757:	5f                   	pop    %rdi
  400758:	58                   	pop    %rax
  400759:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400760:	b8 04 00 00 00       	mov    $0x4,%eax
  400765:	e9 f4 00 00 00       	jmpq   40085e <test+0x307>
  40076a:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400771:	50                   	push   %rax
  400772:	57                   	push   %rdi
  400773:	56                   	push   %rsi
  400774:	52                   	push   %rdx
  400775:	51                   	push   %rcx
  400776:	41 53                	push   %r11
  400778:	e8 a4 01 00 00       	callq  400921 <__trace_jump>
  40077d:	41 5b                	pop    %r11
  40077f:	59                   	pop    %rcx
  400780:	5a                   	pop    %rdx
  400781:	5e                   	pop    %rsi
  400782:	5f                   	pop    %rdi
  400783:	58                   	pop    %rax
  400784:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40078b:	b8 05 00 00 00       	mov    $0x5,%eax
  400790:	e9 c9 00 00 00       	jmpq   40085e <test+0x307>
  400795:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40079c:	50                   	push   %rax
  40079d:	57                   	push   %rdi
  40079e:	56                   	push   %rsi
  40079f:	52                   	push   %rdx
  4007a0:	51                   	push   %rcx
  4007a1:	41 53                	push   %r11
  4007a3:	e8 79 01 00 00       	callq  400921 <__trace_jump>
  4007a8:	41 5b                	pop    %r11
  4007aa:	59                   	pop    %rcx
  4007ab:	5a                   	pop    %rdx
  4007ac:	5e                   	pop    %rsi
  4007ad:	5f                   	pop    %rdi
  4007ae:	58                   	pop    %rax
  4007af:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4007b6:	b8 06 00 00 00       	mov    $0x6,%eax
  4007bb:	e9 9e 00 00 00       	jmpq   40085e <test+0x307>
  4007c0:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007c7:	50                   	push   %rax
  4007c8:	57                   	push   %rdi
  4007c9:	56                   	push   %rsi
  4007ca:	52                   	push   %rdx
  4007cb:	51                   	push   %rcx
  4007cc:	41 53                	push   %r11
  4007ce:	e8 4e 01 00 00       	callq  400921 <__trace_jump>
  4007d3:	41 5b                	pop    %r11
  4007d5:	59                   	pop    %rcx
  4007d6:	5a                   	pop    %rdx
  4007d7:	5e                   	pop    %rsi
  4007d8:	5f                   	pop    %rdi
  4007d9:	58                   	pop    %rax
  4007da:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4007e1:	b8 07 00 00 00       	mov    $0x7,%eax
  4007e6:	eb 76                	jmp    40085e <test+0x307>
  4007e8:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4007ef:	50                   	push   %rax
  4007f0:	57                   	push   %rdi
  4007f1:	56                   	push   %rsi
  4007f2:	52                   	push   %rdx
  4007f3:	51                   	push   %rcx
  4007f4:	41 53                	push   %r11
  4007f6:	e8 26 01 00 00       	callq  400921 <__trace_jump>
  4007fb:	41 5b                	pop    %r11
  4007fd:	59                   	pop    %rcx
  4007fe:	5a                   	pop    %rdx
  4007ff:	5e                   	pop    %rsi
  400800:	5f                   	pop    %rdi
  400801:	58                   	pop    %rax
  400802:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400809:	b8 08 00 00 00       	mov    $0x8,%eax
  40080e:	eb 4e                	jmp    40085e <test+0x307>
  400810:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400817:	50                   	push   %rax
  400818:	57                   	push   %rdi
  400819:	56                   	push   %rsi
  40081a:	52                   	push   %rdx
  40081b:	51                   	push   %rcx
  40081c:	41 53                	push   %r11
  40081e:	e8 fe 00 00 00       	callq  400921 <__trace_jump>
  400823:	41 5b                	pop    %r11
  400825:	59                   	pop    %rcx
  400826:	5a                   	pop    %rdx
  400827:	5e                   	pop    %rsi
  400828:	5f                   	pop    %rdi
  400829:	58                   	pop    %rax
  40082a:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400831:	b8 09 00 00 00       	mov    $0x9,%eax
  400836:	eb 26                	jmp    40085e <test+0x307>
  400838:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  40083f:	50                   	push   %rax
  400840:	57                   	push   %rdi
  400841:	56                   	push   %rsi
  400842:	52                   	push   %rdx
  400843:	51                   	push   %rcx
  400844:	41 53                	push   %r11
  400846:	e8 d6 00 00 00       	callq  400921 <__trace_jump>
  40084b:	41 5b                	pop    %r11
  40084d:	59                   	pop    %rcx
  40084e:	5a                   	pop    %rdx
  40084f:	5e                   	pop    %rsi
  400850:	5f                   	pop    %rdi
  400851:	58                   	pop    %rax
  400852:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  400859:	b8 00 00 00 00       	mov    $0x0,%eax
  40085e:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400865:	50                   	push   %rax
  400866:	57                   	push   %rdi
  400867:	56                   	push   %rsi
  400868:	52                   	push   %rdx
  400869:	51                   	push   %rcx
  40086a:	41 53                	push   %r11
  40086c:	e8 b0 00 00 00       	callq  400921 <__trace_jump>
  400871:	41 5b                	pop    %r11
  400873:	59                   	pop    %rcx
  400874:	5a                   	pop    %rdx
  400875:	5e                   	pop    %rsi
  400876:	5f                   	pop    %rdi
  400877:	58                   	pop    %rax
  400878:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40087f:	5d                   	pop    %rbp
  400880:	c3                   	retq   

0000000000400881 <main>:
  400881:	55                   	push   %rbp
  400882:	48 89 e5             	mov    %rsp,%rbp
  400885:	48 83 ec 20          	sub    $0x20,%rsp
  400889:	89 7d ec             	mov    %edi,-0x14(%rbp)
  40088c:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  400890:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  400897:	00 00 
  400899:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  40089d:	31 c0                	xor    %eax,%eax
  40089f:	48 8d 45 f3          	lea    -0xd(%rbp),%rax
  4008a3:	ba 01 00 00 00       	mov    $0x1,%edx
  4008a8:	48 89 c6             	mov    %rax,%rsi
  4008ab:	bf 00 00 00 00       	mov    $0x0,%edi
  4008b0:	e8 ab fb ff ff       	callq  400460 <read@plt>
  4008b5:	0f b6 45 f3          	movzbl -0xd(%rbp),%eax
  4008b9:	0f b6 c0             	movzbl %al,%eax
  4008bc:	89 c7                	mov    %eax,%edi
  4008be:	e8 94 fc ff ff       	callq  400557 <test>
  4008c3:	89 45 f4             	mov    %eax,-0xc(%rbp)
  4008c6:	8b 45 f4             	mov    -0xc(%rbp),%eax
  4008c9:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  4008cd:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
  4008d4:	00 00 
  4008d6:	74 26                	je     4008fe <main+0x7d>
  4008d8:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  4008df:	50                   	push   %rax
  4008e0:	57                   	push   %rdi
  4008e1:	56                   	push   %rsi
  4008e2:	52                   	push   %rdx
  4008e3:	51                   	push   %rcx
  4008e4:	41 53                	push   %r11
  4008e6:	e8 36 00 00 00       	callq  400921 <__trace_jump>
  4008eb:	41 5b                	pop    %r11
  4008ed:	59                   	pop    %rcx
  4008ee:	5a                   	pop    %rdx
  4008ef:	5e                   	pop    %rsi
  4008f0:	5f                   	pop    %rdi
  4008f1:	58                   	pop    %rax
  4008f2:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  4008f9:	e8 52 fb ff ff       	callq  400450 <__stack_chk_fail@plt>
  4008fe:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
  400905:	50                   	push   %rax
  400906:	57                   	push   %rdi
  400907:	56                   	push   %rsi
  400908:	52                   	push   %rdx
  400909:	51                   	push   %rcx
  40090a:	41 53                	push   %r11
  40090c:	e8 10 00 00 00       	callq  400921 <__trace_jump>
  400911:	41 5b                	pop    %r11
  400913:	59                   	pop    %rcx
  400914:	5a                   	pop    %rdx
  400915:	5e                   	pop    %rsi
  400916:	5f                   	pop    %rdi
  400917:	58                   	pop    %rax
  400918:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
  40091f:	c9                   	leaveq 
  400920:	c3                   	retq   

0000000000400921 <__trace_jump>:
  400921:	55                   	push   %rbp
  400922:	48 89 e5             	mov    %rsp,%rbp
  400925:	48 8b 45 08          	mov    0x8(%rbp),%rax
  400929:	48 83 e8 13          	sub    $0x13,%rax
  40092d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  400931:	48 c7 c0 01 00 00 00 	mov    $0x1,%rax
  400938:	48 c7 c7 02 00 00 00 	mov    $0x2,%rdi
  40093f:	48 89 ee             	mov    %rbp,%rsi
  400942:	48 83 ee 08          	sub    $0x8,%rsi
  400946:	48 c7 c2 08 00 00 00 	mov    $0x8,%rdx
  40094d:	0f 05                	syscall 
  40094f:	5d                   	pop    %rbp
  400950:	c3                   	retq   
  400951:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  400958:	00 00 00 
  40095b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000400960 <__libc_csu_init>:
  400960:	41 57                	push   %r15
  400962:	41 56                	push   %r14
  400964:	49 89 d7             	mov    %rdx,%r15
  400967:	41 55                	push   %r13
  400969:	41 54                	push   %r12
  40096b:	4c 8d 25 9e 04 20 00 	lea    0x20049e(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
  400972:	55                   	push   %rbp
  400973:	48 8d 2d 9e 04 20 00 	lea    0x20049e(%rip),%rbp        # 600e18 <__init_array_end>
  40097a:	53                   	push   %rbx
  40097b:	41 89 fd             	mov    %edi,%r13d
  40097e:	49 89 f6             	mov    %rsi,%r14
  400981:	4c 29 e5             	sub    %r12,%rbp
  400984:	48 83 ec 08          	sub    $0x8,%rsp
  400988:	48 c1 fd 03          	sar    $0x3,%rbp
  40098c:	e8 97 fa ff ff       	callq  400428 <_init>
  400991:	48 85 ed             	test   %rbp,%rbp
  400994:	74 20                	je     4009b6 <__libc_csu_init+0x56>
  400996:	31 db                	xor    %ebx,%ebx
  400998:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40099f:	00 
  4009a0:	4c 89 fa             	mov    %r15,%rdx
  4009a3:	4c 89 f6             	mov    %r14,%rsi
  4009a6:	44 89 ef             	mov    %r13d,%edi
  4009a9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4009ad:	48 83 c3 01          	add    $0x1,%rbx
  4009b1:	48 39 dd             	cmp    %rbx,%rbp
  4009b4:	75 ea                	jne    4009a0 <__libc_csu_init+0x40>
  4009b6:	48 83 c4 08          	add    $0x8,%rsp
  4009ba:	5b                   	pop    %rbx
  4009bb:	5d                   	pop    %rbp
  4009bc:	41 5c                	pop    %r12
  4009be:	41 5d                	pop    %r13
  4009c0:	41 5e                	pop    %r14
  4009c2:	41 5f                	pop    %r15
  4009c4:	c3                   	retq   
  4009c5:	90                   	nop
  4009c6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4009cd:	00 00 00 

00000000004009d0 <__libc_csu_fini>:
  4009d0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000004009d4 <_fini>:
  4009d4:	48 83 ec 08          	sub    $0x8,%rsp
  4009d8:	48 83 c4 08          	add    $0x8,%rsp
  4009dc:	c3                   	retq   
