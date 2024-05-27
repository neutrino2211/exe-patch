	.file	"payload-test.c"
	.text
	.globl	kernel32_str
	.data
	.align 16
kernel32_str:
	.ascii "k\0e\0r\0n\0e\0l\0"
	.ascii "3\0"
	.ascii "2\0.\0d\0l\0l\0\0\0"
	.globl	load_lib_str
	.align 8
load_lib_str:
	.ascii "LoadLibraryA\0"
	.def	__main;	.scl	2;	.type	32;	.endef
	.text
	.globl	main
	.def	main;	.scl	2;	.type	32;	.endef
	.seh_proc	main
main:
	pushq	%rbp
	.seh_pushreg	%rbp
	movq	%rsp, %rbp
	.seh_setframe	%rbp, 0
	subq	$224, %rsp
	.seh_stackalloc	224
	.seh_endprologue
	call	__main
	movw	$107, -96(%rbp)
	movw	$101, -94(%rbp)
	movw	$114, -92(%rbp)
	movw	$110, -90(%rbp)
	movw	$101, -88(%rbp)
	movw	$108, -86(%rbp)
	movw	$51, -84(%rbp)
	movw	$50, -82(%rbp)
	movw	$46, -80(%rbp)
	movw	$100, -78(%rbp)
	movw	$108, -76(%rbp)
	movw	$108, -74(%rbp)
	movw	$0, -72(%rbp)
	movabsq	$8242266044863967052, %rax
	movq	%rax, -109(%rbp)
	movabsq	$18429405654311529, %rax
	movq	%rax, -104(%rbp)
	movabsq	$4711732171926431047, %rax
	movq	%rax, -124(%rbp)
	movabsq	$32496501869798465, %rax
	movq	%rax, -117(%rbp)
	movabsq	$7218762449265455989, %rax
	movq	%rax, -135(%rbp)
	movl	$7105636, -128(%rbp)
	movabsq	$4784343847397451085, %rax
	movq	%rax, -147(%rbp)
	movl	$5732463, -139(%rbp)
	movw	$72, -176(%rbp)
	movw	$101, -174(%rbp)
	movw	$108, -172(%rbp)
	movw	$108, -170(%rbp)
	movw	$111, -168(%rbp)
	movw	$32, -166(%rbp)
	movw	$87, -164(%rbp)
	movw	$111, -162(%rbp)
	movw	$114, -160(%rbp)
	movw	$108, -158(%rbp)
	movw	$100, -156(%rbp)
	movw	$33, -154(%rbp)
	movw	$0, -152(%rbp)
	movw	$68, -188(%rbp)
	movw	$101, -186(%rbp)
	movw	$109, -184(%rbp)
	movw	$111, -182(%rbp)
	movw	$33, -180(%rbp)
	movw	$0, -178(%rbp)
	leaq	-96(%rbp), %rax
	movq	%rax, %rcx
	call	get_module_by_name
	movq	%rax, -8(%rbp)
	cmpq	$0, -8(%rbp)
	jne	.L2
	movl	$1, %eax
	jmp	.L7
.L2:
	leaq	-109(%rbp), %rdx
	movq	-8(%rbp), %rax
	movq	%rax, %rcx
	call	get_func_by_name
	movq	%rax, -16(%rbp)
	cmpq	$0, -16(%rbp)
	jne	.L4
	movl	$2, %eax
	jmp	.L7
.L4:
	leaq	-124(%rbp), %rdx
	movq	-8(%rbp), %rax
	movq	%rax, %rcx
	call	get_func_by_name
	movq	%rax, -24(%rbp)
	cmpq	$0, -24(%rbp)
	jne	.L5
	movl	$3, %eax
	jmp	.L7
.L5:
	movq	-16(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-24(%rbp), %rax
	movq	%rax, -40(%rbp)
	leaq	-135(%rbp), %rax
	movq	-32(%rbp), %rdx
	movq	%rax, %rcx
	call	*%rdx
	movq	%rax, -48(%rbp)
	leaq	-147(%rbp), %rdx
	movq	-48(%rbp), %rax
	movq	-40(%rbp), %r8
	movq	%rax, %rcx
	call	*%r8
	movq	%rax, -56(%rbp)
	cmpq	$0, -56(%rbp)
	jne	.L6
	movl	$4, %eax
	jmp	.L7
.L6:
	leaq	-188(%rbp), %rdx
	leaq	-176(%rbp), %rax
	movq	-56(%rbp), %r10
	movl	$0, %r9d
	movq	%rdx, %r8
	movq	%rax, %rdx
	movl	$0, %ecx
	call	*%r10
	movl	$0, %eax
.L7:
	addq	$224, %rsp
	popq	%rbp
	ret
	.seh_endproc
	.ident	"GCC: (GNU) 13.1.0"
	.def	get_module_by_name;	.scl	2;	.type	32;	.endef
	.def	get_func_by_name;	.scl	2;	.type	32;	.endef
