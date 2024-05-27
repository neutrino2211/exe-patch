	.file	"stage-two.c"
	.text
	.globl	__stage_one__
	.section .rdata,"dr"
.LC0:
	.ascii "hello\0"
	.section	.ssv,"w"
	.align 8
__stage_one__:
	.quad	.LC0
	.text
	.globl	__stage_two
	.def	__stage_two;	.scl	2;	.type	32;	.endef
	.seh_proc	__stage_two
__stage_two:
	pushq	%rbp
	.seh_pushreg	%rbp
	movq	%rsp, %rbp
	.seh_setframe	%rbp, 0
	subq	$48, %rsp
	.seh_stackalloc	48
	.seh_endprologue
	movl	$64, %r9d
	movl	$4096, %r8d
	movl	$8, %edx
	movl	$0, %ecx
	movq	__imp_VirtualAlloc(%rip), %rax
	call	*%rax
	movq	%rax, -8(%rbp)
	movq	__stage_one__(%rip), %rax
	movq	(%rax), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	call	*%rax
	nop
	addq	$48, %rsp
	popq	%rbp
	ret
	.seh_endproc
	.ident	"GCC: (GNU) 13.1.0"
