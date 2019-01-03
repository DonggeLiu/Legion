
../Orignal/test_half:     file format elf64-x86-64


Disassembly of section .init:

0000000000000548 <_init>:
 548:	48 83 ec 08          	sub    $0x8,%rsp
 54c:	48 8b 05 95 0a 20 00 	mov    0x200a95(%rip),%rax        # 200fe8 <__gmon_start__>
 553:	48 85 c0             	test   %rax,%rax
 556:	74 02                	je     55a <_init+0x12>
 558:	ff d0                	callq  *%rax
 55a:	48 83 c4 08          	add    $0x8,%rsp
 55e:	c3                   	retq   

Disassembly of section .plt:

0000000000000560 <.plt>:
 560:	ff 35 52 0a 20 00    	pushq  0x200a52(%rip)        # 200fb8 <_GLOBAL_OFFSET_TABLE_+0x8>
 566:	ff 25 54 0a 20 00    	jmpq   *0x200a54(%rip)        # 200fc0 <_GLOBAL_OFFSET_TABLE_+0x10>
 56c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000000570 <__stack_chk_fail@plt>:
 570:	ff 25 52 0a 20 00    	jmpq   *0x200a52(%rip)        # 200fc8 <__stack_chk_fail@GLIBC_2.4>
 576:	68 00 00 00 00       	pushq  $0x0
 57b:	e9 e0 ff ff ff       	jmpq   560 <.plt>

0000000000000580 <read@plt>:
 580:	ff 25 4a 0a 20 00    	jmpq   *0x200a4a(%rip)        # 200fd0 <read@GLIBC_2.2.5>
 586:	68 01 00 00 00       	pushq  $0x1
 58b:	e9 d0 ff ff ff       	jmpq   560 <.plt>

Disassembly of section .plt.got:

0000000000000590 <__cxa_finalize@plt>:
 590:	ff 25 62 0a 20 00    	jmpq   *0x200a62(%rip)        # 200ff8 <__cxa_finalize@GLIBC_2.2.5>
 596:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

00000000000005a0 <_start>:
 5a0:	31 ed                	xor    %ebp,%ebp
 5a2:	49 89 d1             	mov    %rdx,%r9
 5a5:	5e                   	pop    %rsi
 5a6:	48 89 e2             	mov    %rsp,%rdx
 5a9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
 5ad:	50                   	push   %rax
 5ae:	54                   	push   %rsp
 5af:	4c 8d 05 5a 02 00 00 	lea    0x25a(%rip),%r8        # 810 <__libc_csu_fini>
 5b6:	48 8d 0d e3 01 00 00 	lea    0x1e3(%rip),%rcx        # 7a0 <__libc_csu_init>
 5bd:	48 8d 3d 6f 01 00 00 	lea    0x16f(%rip),%rdi        # 733 <main>
 5c4:	ff 15 16 0a 20 00    	callq  *0x200a16(%rip)        # 200fe0 <__libc_start_main@GLIBC_2.2.5>
 5ca:	f4                   	hlt    
 5cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000005d0 <deregister_tm_clones>:
 5d0:	48 8d 3d 39 0a 20 00 	lea    0x200a39(%rip),%rdi        # 201010 <__TMC_END__>
 5d7:	55                   	push   %rbp
 5d8:	48 8d 05 31 0a 20 00 	lea    0x200a31(%rip),%rax        # 201010 <__TMC_END__>
 5df:	48 39 f8             	cmp    %rdi,%rax
 5e2:	48 89 e5             	mov    %rsp,%rbp
 5e5:	74 19                	je     600 <deregister_tm_clones+0x30>
 5e7:	48 8b 05 ea 09 20 00 	mov    0x2009ea(%rip),%rax        # 200fd8 <_ITM_deregisterTMCloneTable>
 5ee:	48 85 c0             	test   %rax,%rax
 5f1:	74 0d                	je     600 <deregister_tm_clones+0x30>
 5f3:	5d                   	pop    %rbp
 5f4:	ff e0                	jmpq   *%rax
 5f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 5fd:	00 00 00 
 600:	5d                   	pop    %rbp
 601:	c3                   	retq   
 602:	0f 1f 40 00          	nopl   0x0(%rax)
 606:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 60d:	00 00 00 

0000000000000610 <register_tm_clones>:
 610:	48 8d 3d f9 09 20 00 	lea    0x2009f9(%rip),%rdi        # 201010 <__TMC_END__>
 617:	48 8d 35 f2 09 20 00 	lea    0x2009f2(%rip),%rsi        # 201010 <__TMC_END__>
 61e:	55                   	push   %rbp
 61f:	48 29 fe             	sub    %rdi,%rsi
 622:	48 89 e5             	mov    %rsp,%rbp
 625:	48 c1 fe 03          	sar    $0x3,%rsi
 629:	48 89 f0             	mov    %rsi,%rax
 62c:	48 c1 e8 3f          	shr    $0x3f,%rax
 630:	48 01 c6             	add    %rax,%rsi
 633:	48 d1 fe             	sar    %rsi
 636:	74 18                	je     650 <register_tm_clones+0x40>
 638:	48 8b 05 b1 09 20 00 	mov    0x2009b1(%rip),%rax        # 200ff0 <_ITM_registerTMCloneTable>
 63f:	48 85 c0             	test   %rax,%rax
 642:	74 0c                	je     650 <register_tm_clones+0x40>
 644:	5d                   	pop    %rbp
 645:	ff e0                	jmpq   *%rax
 647:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
 64e:	00 00 
 650:	5d                   	pop    %rbp
 651:	c3                   	retq   
 652:	0f 1f 40 00          	nopl   0x0(%rax)
 656:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 65d:	00 00 00 

0000000000000660 <__do_global_dtors_aux>:
 660:	80 3d a9 09 20 00 00 	cmpb   $0x0,0x2009a9(%rip)        # 201010 <__TMC_END__>
 667:	75 2f                	jne    698 <__do_global_dtors_aux+0x38>
 669:	48 83 3d 87 09 20 00 	cmpq   $0x0,0x200987(%rip)        # 200ff8 <__cxa_finalize@GLIBC_2.2.5>
 670:	00 
 671:	55                   	push   %rbp
 672:	48 89 e5             	mov    %rsp,%rbp
 675:	74 0c                	je     683 <__do_global_dtors_aux+0x23>
 677:	48 8b 3d 8a 09 20 00 	mov    0x20098a(%rip),%rdi        # 201008 <__dso_handle>
 67e:	e8 0d ff ff ff       	callq  590 <__cxa_finalize@plt>
 683:	e8 48 ff ff ff       	callq  5d0 <deregister_tm_clones>
 688:	c6 05 81 09 20 00 01 	movb   $0x1,0x200981(%rip)        # 201010 <__TMC_END__>
 68f:	5d                   	pop    %rbp
 690:	c3                   	retq   
 691:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
 698:	f3 c3                	repz retq 
 69a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000006a0 <frame_dummy>:
 6a0:	55                   	push   %rbp
 6a1:	48 89 e5             	mov    %rsp,%rbp
 6a4:	5d                   	pop    %rbp
 6a5:	e9 66 ff ff ff       	jmpq   610 <register_tm_clones>

00000000000006aa <test>:
 6aa:	55                   	push   %rbp
 6ab:	48 89 e5             	mov    %rsp,%rbp
 6ae:	89 7d fc             	mov    %edi,-0x4(%rbp)
 6b1:	81 7d fc ff 00 00 00 	cmpl   $0xff,-0x4(%rbp)
 6b8:	76 07                	jbe    6c1 <test+0x17>
 6ba:	b8 09 00 00 00       	mov    $0x9,%eax
 6bf:	eb 70                	jmp    731 <test+0x87>
 6c1:	81 7d fc 80 00 00 00 	cmpl   $0x80,-0x4(%rbp)
 6c8:	76 07                	jbe    6d1 <test+0x27>
 6ca:	b8 08 00 00 00       	mov    $0x8,%eax
 6cf:	eb 60                	jmp    731 <test+0x87>
 6d1:	83 7d fc 40          	cmpl   $0x40,-0x4(%rbp)
 6d5:	76 07                	jbe    6de <test+0x34>
 6d7:	b8 07 00 00 00       	mov    $0x7,%eax
 6dc:	eb 53                	jmp    731 <test+0x87>
 6de:	83 7d fc 20          	cmpl   $0x20,-0x4(%rbp)
 6e2:	76 07                	jbe    6eb <test+0x41>
 6e4:	b8 06 00 00 00       	mov    $0x6,%eax
 6e9:	eb 46                	jmp    731 <test+0x87>
 6eb:	83 7d fc 10          	cmpl   $0x10,-0x4(%rbp)
 6ef:	76 07                	jbe    6f8 <test+0x4e>
 6f1:	b8 05 00 00 00       	mov    $0x5,%eax
 6f6:	eb 39                	jmp    731 <test+0x87>
 6f8:	83 7d fc 08          	cmpl   $0x8,-0x4(%rbp)
 6fc:	76 07                	jbe    705 <test+0x5b>
 6fe:	b8 04 00 00 00       	mov    $0x4,%eax
 703:	eb 2c                	jmp    731 <test+0x87>
 705:	83 7d fc 04          	cmpl   $0x4,-0x4(%rbp)
 709:	76 07                	jbe    712 <test+0x68>
 70b:	b8 03 00 00 00       	mov    $0x3,%eax
 710:	eb 1f                	jmp    731 <test+0x87>
 712:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
 716:	76 07                	jbe    71f <test+0x75>
 718:	b8 02 00 00 00       	mov    $0x2,%eax
 71d:	eb 12                	jmp    731 <test+0x87>
 71f:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
 723:	76 07                	jbe    72c <test+0x82>
 725:	b8 01 00 00 00       	mov    $0x1,%eax
 72a:	eb 05                	jmp    731 <test+0x87>
 72c:	b8 00 00 00 00       	mov    $0x0,%eax
 731:	5d                   	pop    %rbp
 732:	c3                   	retq   

0000000000000733 <main>:
 733:	55                   	push   %rbp
 734:	48 89 e5             	mov    %rsp,%rbp
 737:	48 83 ec 20          	sub    $0x20,%rsp
 73b:	89 7d ec             	mov    %edi,-0x14(%rbp)
 73e:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
 742:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
 749:	00 00 
 74b:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
 74f:	31 c0                	xor    %eax,%eax
 751:	48 8d 45 f3          	lea    -0xd(%rbp),%rax
 755:	ba 01 00 00 00       	mov    $0x1,%edx
 75a:	48 89 c6             	mov    %rax,%rsi
 75d:	bf 00 00 00 00       	mov    $0x0,%edi
 762:	e8 19 fe ff ff       	callq  580 <read@plt>
 767:	0f b6 45 f3          	movzbl -0xd(%rbp),%eax
 76b:	0f b6 c0             	movzbl %al,%eax
 76e:	89 c7                	mov    %eax,%edi
 770:	e8 35 ff ff ff       	callq  6aa <test>
 775:	89 45 f4             	mov    %eax,-0xc(%rbp)
 778:	8b 45 f4             	mov    -0xc(%rbp),%eax
 77b:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
 77f:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
 786:	00 00 
 788:	74 05                	je     78f <main+0x5c>
 78a:	e8 e1 fd ff ff       	callq  570 <__stack_chk_fail@plt>
 78f:	c9                   	leaveq 
 790:	c3                   	retq   
 791:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 798:	00 00 00 
 79b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000007a0 <__libc_csu_init>:
 7a0:	41 57                	push   %r15
 7a2:	41 56                	push   %r14
 7a4:	49 89 d7             	mov    %rdx,%r15
 7a7:	41 55                	push   %r13
 7a9:	41 54                	push   %r12
 7ab:	4c 8d 25 fe 05 20 00 	lea    0x2005fe(%rip),%r12        # 200db0 <__frame_dummy_init_array_entry>
 7b2:	55                   	push   %rbp
 7b3:	48 8d 2d fe 05 20 00 	lea    0x2005fe(%rip),%rbp        # 200db8 <__init_array_end>
 7ba:	53                   	push   %rbx
 7bb:	41 89 fd             	mov    %edi,%r13d
 7be:	49 89 f6             	mov    %rsi,%r14
 7c1:	4c 29 e5             	sub    %r12,%rbp
 7c4:	48 83 ec 08          	sub    $0x8,%rsp
 7c8:	48 c1 fd 03          	sar    $0x3,%rbp
 7cc:	e8 77 fd ff ff       	callq  548 <_init>
 7d1:	48 85 ed             	test   %rbp,%rbp
 7d4:	74 20                	je     7f6 <__libc_csu_init+0x56>
 7d6:	31 db                	xor    %ebx,%ebx
 7d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
 7df:	00 
 7e0:	4c 89 fa             	mov    %r15,%rdx
 7e3:	4c 89 f6             	mov    %r14,%rsi
 7e6:	44 89 ef             	mov    %r13d,%edi
 7e9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
 7ed:	48 83 c3 01          	add    $0x1,%rbx
 7f1:	48 39 dd             	cmp    %rbx,%rbp
 7f4:	75 ea                	jne    7e0 <__libc_csu_init+0x40>
 7f6:	48 83 c4 08          	add    $0x8,%rsp
 7fa:	5b                   	pop    %rbx
 7fb:	5d                   	pop    %rbp
 7fc:	41 5c                	pop    %r12
 7fe:	41 5d                	pop    %r13
 800:	41 5e                	pop    %r14
 802:	41 5f                	pop    %r15
 804:	c3                   	retq   
 805:	90                   	nop
 806:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 80d:	00 00 00 

0000000000000810 <__libc_csu_fini>:
 810:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000000814 <_fini>:
 814:	48 83 ec 08          	sub    $0x8,%rsp
 818:	48 83 c4 08          	add    $0x8,%rsp
 81c:	c3                   	retq   
