#include "_internal_s2n_bignum.h"

        S2N_BN_SYM_VISIBILITY_DIRECTIVE(keccak1600)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(keccak1600)

.globl	mlkem_keccak_f1600
.type	mlkem_keccak_f1600,@function
.align	
mlkem_keccak_f1600:
S2N_BN_SYMBOL(mlkem_keccak_f1600):
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	leaq	100(%rdi),%rdi
	subq	$200,%rsp
	notq	-92(%rdi)
	notq	-84(%rdi)
	notq	-36(%rdi)
	notq	-4(%rdi)
	notq	36(%rdi)
	notq	60(%rdi)
	leaq	iotas_x86_64(%rip),%r15
	leaq	100(%rsp),%rsi

	// 	Core KeccakF1600 Function
	movq	60(%rdi),%rax                      // mov	$A[4][0](%rdi),@C[0]
	movq	68(%rdi),%rbx	                   // mov	$A[4][1](%rdi),@C[1]
	movq	76(%rdi),%rcx	                   // mov	$A[4][2](%rdi),@C[2]
	movq	84(%rdi),%rdx	                   // mov	$A[4][3](%rdi),@C[3]
	movq	92(%rdi),%rbp	                   // mov	$A[4][4](%rdi),@C[4]
.Loop:
	movq	-100(%rdi),%r8                     // mov	$A[0][0](%rdi),@D[0]
	movq	-52(%rdi), %r9 	                   // mov	$A[1][1](%rdi),@D[1]
	movq	-4(%rdi), %r10 	                   // mov	$A[2][2](%rdi),@D[2]
	movq	44(%rdi), %r11 	                   // mov	$A[3][3](%rdi),@D[3]
    xorq	-84(%rdi),%rcx                     // xor	$A[0][2](%rdi),@C[2]
    xorq	-76(%rdi),%rdx	                   // xor	$A[0][3](%rdi),@C[3]
	xorq	%r8,%rax	                       // xor	@D[0],         @C[0]
	xorq	-92(%rdi),%rbx	                   // xor	$A[0][1](%rdi),@C[1]
	xorq	-44(%rdi),%rcx	                   // xor	$A[1][2](%rdi),@C[2]
	xorq	-60(%rdi),%rax	                   // xor	$A[1][0](%rdi),@C[0]
	movq	%rbp,%r12                          // mov	@C[4],@D[4]
	xorq	-68(%rdi),%rbp                     // xor	$A[0][4](%rdi),@C[4]
	xorq	%r10,%rcx    	                   // xor	@D[2],         @C[2]
	xorq	-20(%rdi),%rax                     // xor	$A[2][0](%rdi),@C[0]
	xorq	-36(%rdi),%rdx                     // xor	$A[1][3](%rdi),@C[3]
	xorq	%r9,%rbx    	                   // xor	@D[1],         @C[1]
	xorq	-28(%rdi),%rbp                     // xor	$A[1][4](%rdi),@C[4]
	xorq	36(%rdi),%rcx                      // xor	$A[3][2](%rdi),@C[2]
	xorq	20(%rdi),%rax                      // xor	$A[3][0](%rdi),@C[0]
	xorq	4(%rdi),%rdx                       // xor	$A[2][3](%rdi),@C[3]
	xorq	-12(%rdi),%rbx                     // xor	$A[2][1](%rdi),@C[1]
	xorq	12(%rdi),%rbp                      // xor	$A[2][4](%rdi),@C[4]
	movq	%rcx,%r13                          // mov	@C[2],@T[0]
	rolq	$1,%rcx                            // rol	\$1,@C[2]
	xorq	%rax,%rcx    	                   // xor	@C[0],@C[2]
	xorq	%r11,%rdx    	                   // xor	@D[3],@C[3]
	rolq	$1,%rax                            // rol	\$1,@C[0]
	xorq	%rdx,%rax    	                   // xor	@C[3],@C[0]
	xorq	28(%rdi),%rbx                      // xor	$A[3][1](%rdi),@C[1]
	rolq	$1,%rdx                            // rol	\$1,@C[3]
	xorq	%rbx,%rdx    	                   // xor	@C[1],@C[3]		
	xorq	52(%rdi),%rbp                      // xor	$A[3][4](%rdi),@C[4]
	rolq	$1,%rbx                            // rol	\$1,@C[1]
	xorq	%rbp,%rbx    	                   // xor	@C[4],@C[1]		
	rolq	$1,%rbp                            // rol	\$1,@C[4]
	xorq	%r13,%rbp    	                   // xor	@T[0],@C[4]		
	xorq	%rcx,%r9                           // xor	@D[1],@C[1]    
	xorq	%rdx,%r10                          // xor	@D[2],@C[2]   
	rolq	$44,%r9                            // rol	\$$rhotates[1][1],@C[1]
	xorq	%rbp,%r11                          // xor	@D[3],@C[3]    
	xorq	%rax,%r12                          // xor	@D[4],@C[4]   
	rolq	$43,%r10                           // rol	\$$rhotates[2][2],@C[2]
	xorq	%rbx,%r8                           // xor	@D[0],@C[0]  
	movq	%r9,%r13                           // mov	@C[1],@T[0]    
	rolq	$21,%r11                           // rol	\$$rhotates[3][3],@C[3]   
	orq	%r10,%r9                               // or	@C[2],@C[1]             
	xorq	%r8,%r9                            // xor	@C[0],@C[1]		
	rolq	$14,%r12                           // rol	\$$rhotates[4][4],@C[4]           
	xorq	(%r15),%r9                         // xor	($iotas_x86_64),@C[1]           
	leaq	8(%r15),%r15                       // lea	8($iotas_x86_64),$iotas_x86_64
	movq	%r12,%r14                          // mov	@C[4],@T[1]            
	andq	%r11,%r12                          // and	@C[3],@C[4]           
	movq	%r9,-100(%rsi)                     // mov	@C[1],$A[0][0](%rsi)	
    xorq	%r10,%r12                          // xor	@C[2],@C[4]		
    notq	%r10                               // not	@C[2]
    movq	%r12,-84(%rsi)                     // mov	@C[4],$A[0][2](%rsi)	
    orq	%r11,%r10                              // or	@C[3],@C[2]
    movq	76(%rdi),%r12                      // mov	$A[4][2](%rdi),@C[4]
    xorq	%r13,%r10                          // xor	@T[0],@C[2]		
    movq	%r10,-92(%rsi)                     // mov	@C[2],$A[0][1](%rsi)	
    andq	%r8,%r13                           // and	@C[0],@T[0]
    movq	-28(%rdi),%r9                      // mov	$A[1][4](%rdi),@C[1]
    xorq	%r14,%r13                          // xor	@T[1],@T[0]	
    movq	-20(%rdi),%r10                     // mov	$A[2][0](%rdi),@C[2]
    movq	%r13,-68(%rsi)                     // mov	@T[0],$A[0][4](%rsi)	
    orq	%r8,%r14                               // or	@C[0],@T[1]
    movq	-76(%rdi),%r8                      // mov	$A[0][3](%rdi),@C[0]
    xorq	%r11,%r14                          // xor	@C[3],@T[1]		
    movq	28(%rdi),%r11                      // mov	$A[3][1](%rdi),@C[3]
    movq	%r14,-76(%rsi)                     // mov	@T[1],$A[0][3](%rsi)	
    xorq	%rbp,%r8                           // xor	@D[3],@C[0]
    xorq	%rdx,%r12                          // xor	@D[2],@C[4]
    rolq	$28,%r8                            // rol	\$$rhotates[0][3],@C[0]
    xorq	%rcx,%r11                          // xor	@D[1],@C[3] 
    xorq	%rax,%r9     	                   // xor	@D[4],@C[1]
    rolq	$61,%r12     	                   // rol	\$$rhotates[4][2],@C[4]
    rolq	$45,%r11     	                   // rol	\$$rhotates[3][1],@C[3]
    xorq	%rbx,%r10     	                   // xor	@D[0],@C[2]
    rolq	$20,%r9     	                   // rol	\$$rhotates[1][4],@C[1]
    movq	%r8,%r13     	                   // mov	@C[0],@T[0]
    orq	%r12,%r8     	                       // or	@C[4],@C[0]
    rolq	$3,%r10     	                   // rol	\$$rhotates[2][0],@C[2]
    xorq	%r11,%r8     	                   // xor	@C[3],@C[0]		
    movq	%r8,-36(%rsi)                      // mov	@C[0],$A[1][3](%rsi)
    movq	%r9,%r14                 	       // mov	@C[1],@T[1]
    andq	%r13,%r9       				       // and	@T[0],@C[1]
    movq	-92(%rdi),%r8                      // mov	$A[0][1](%rdi),@C[0]
    xorq	%r12,%r9          	               // xor	@C[4],@C[1]	
    notq	%r12          	                   // not	@C[4]
    movq	%r9,-28(%rsi)          	           // mov	@C[1],$A[1][4](%rsi)	
    orq	%r11,%r12          	                   // or	@C[3],@C[4]
    movq	-44(%rdi),%r9                      // mov	$A[1][2](%rdi),@C[1]
    xorq	%r10,%r12                          // xor	@C[2],@C[4]		
    movq	%r12,-44(%rsi)                     // mov	@C[4],$A[1][2](%rsi)	
    andq	%r10,%r11                          // and	@C[2],@C[3]
    movq	60(%rdi),%r12                      // mov	$A[4][0](%rdi),@C[4]
    xorq	%r14,%r11                          // xor	@T[1],@C[3]	
    movq	%r11,-52(%rsi)                     // mov	@C[3],$A[1][1](%rsi)
    orq	%r10,%r14              	               // or	@C[2],@T[1]
    movq	4(%rdi),%r10              	       // mov	$A[2][3](%rdi),@C[2]
    xorq	%r13,%r14              	           // xor	@T[0],@T[1]		
    movq	52(%rdi),%r11                      // mov	$A[3][4](%rdi),@C[3]
    movq	%r14,-60(%rsi)             	       // mov	@T[1],$A[1][0](%rsi)	
    xorq	%rbp,%r10             	           // xor	@D[3],@C[2]
    xorq	%rax,%r11             	           // xor	@D[4],@C[3]
    rolq	$25,%r10             	           // rol	\$$rhotates[2][3],@C[2]
    xorq	%rdx,%r9             	           // xor	@D[2],@C[1]
    rolq	$8,%r11             	           // rol	\$$rhotates[3][4],@C[3]
    xorq	%rbx,%r12             	           // xor	@D[0],@C[4]
    rolq	$6,%r9             	               // rol	\$$rhotates[1][2],@C[1]
    xorq	%rcx,%r8             	           // xor	@D[1],@C[0]
    rolq	$18,%r12                           // rol	\$$rhotates[4][0],@C[4]
    movq	%r10,%r13                 	       // mov	@C[2],@T[0]
    andq	%r11,%r10                 	       // and	@C[3],@C[2]
    rolq	$1,%r8                 	           // rol	\$$rhotates[0][1],@C[0]
    notq	%r11                 	           // not	@C[3]
    xorq	%r9,%r10                 	       // xor	@C[1],@C[2]		
    movq	%r10,-12(%rsi)                     // mov	@C[2],$A[2][1](%rsi)	
    movq	%r12,%r14                 	       // mov	@C[4],@T[1]
    andq	%r11,%r12                 	       // and	@C[3],@C[4]
    movq	-12(%rdi),%r10                     // mov	$A[2][1](%rdi),@C[2]
    xorq	%r13,%r12                 	       // xor	@T[0],@C[4]		
    movq	%r12,-4(%rsi)                      // mov	@C[4],$A[2][2](%rsi)	
    orq	%r9,%r13                 	           // or	@C[1],@T[0]
    movq	84(%rdi),%r12                      // mov	$A[4][3](%rdi),@C[4]
    xorq	%r8,%r13                 	       // xor	@C[0],@T[0]	
    movq	%r13,-20(%rsi)                     // mov	@T[0],$A[2][0](%rsi)	
    andq	%r8,%r9                 	       // and	@C[0],@C[1]
    xorq	%r14,%r9                 	       // xor	@T[1],@C[1]		
    movq	%r9,12(%rsi)                       // mov	@C[1],$A[2][4](%rsi)	
    orq	%r8,%r14                 	           // or	@C[0],@T[1]
    movq	-60(%rdi),%r9                      // mov	$A[1][0](%rdi),@C[1]
    xorq	%r11,%r14           	           // xor	@C[3],@T[1]		
    movq	36(%rdi),%r11           	       // mov	$A[3][2](%rdi),@C[3]
    movq	%r14,4(%rsi)           	           // mov	@T[1],$A[2][3](%rsi)	
    movq	-68(%rdi),%r8           	       // mov	$A[0][4](%rdi),@C[0]
    xorq	%rcx,%r10           	           // xor	@D[1],@C[2]
    xorq	%rdx,%r11           	           // xor	@D[2],@C[3]
    rolq	$10,%r10           	               // rol	\$$rhotates[2][1],@C[2]
    xorq	%rbx,%r9           	               // xor	@D[0],@C[1]
    rolq	$15,%r11           	               // rol	\$$rhotates[3][2],@C[3]
    xorq	%rbp,%r12                          // xor	@D[3],@C[4]
    rolq	$36,%r9            	               // rol	\$$rhotates[1][0],@C[1]
    xorq	%rax,%r8            	           // xor	@D[4],@C[0]
    rolq	$56,%r12            	           // rol	\$$rhotates[4][3],@C[4]
    movq	%r10,%r13            	           // mov	@C[2],@T[0]
    orq	%r11,%r10            	               // or	@C[3],@C[2]
    rolq	$27,%r8            	               // rol	\$$rhotates[0][4],@C[0]
    notq	%r11            	               // not	@C[3]
    xorq	%r9,%r10            	           // xor	@C[1],@C[2]		
    movq	%r10,28(%rsi)            	       // mov	@C[2],$A[3][1](%rsi)	
    movq	%r12,%r14                          // mov	@C[4],@T[1]
    orq	%r11,%r12                  	           // or	@C[3],@C[4]
    xorq	%r13,%r12                  	       // xor	@T[0],@C[4]		
    movq	%r12,36(%rsi)                      // mov	@C[4],$A[3][2](%rsi)	
    andq	%r9,%r13                  	       // and	@C[1],@T[0]
    xorq	%r8,%r13                  	       // xor	@C[0],@T[0]		
    movq	%r13,20(%rsi)                      // mov	@T[0],$A[3][0](%rsi)	
    orq	%r8,%r9                  	           // or	@C[0],@C[1]
    xorq	%r14,%r9                  	       // xor	@T[1],@C[1]		
    movq	%r9,52(%rsi)                       // mov	@C[1],$A[3][4](%rsi)	
    andq	%r14,%r8                  	       // and	@T[1],@C[0]
    xorq	%r11,%r8                  	       // xor	@C[3],@C[0]		
    movq	%r8,44(%rsi)                       // mov	@C[0],$A[3][3](%rsi)	
    xorq	-84(%rdi),%rdx                     // xor	$A[0][2](%rdi),@D[2]
    xorq	-36(%rdi),%rbp                     // xor	$A[1][3](%rdi),@D[3]
    rolq	$62,%rdx                  	       // rol	\$$rhotates[0][2],@D[2]
    xorq	68(%rdi),%rcx                      // xor	$A[4][1](%rdi),@D[1]
    rolq	$55,%rbp                  	       // rol	\$$rhotates[1][3],@D[3]
    xorq	12(%rdi),%rax                      // xor	$A[2][4](%rdi),@D[4]
    rolq	$2,%rcx                  	       // rol	\$$rhotates[4][1],@D[1]
    xorq	20(%rdi),%rbx                      // xor	$A[3][0](%rdi),@D[0]
    xchgq	%rsi,%rdi     	                   // xchg	%rsi,%rdi
    rolq	$39,%rax     	                   // rol	\$$rhotates[2][4],@D[4]
    rolq	$41,%rbx     	                   // rol	\$$rhotates[3][0],@D[0]
    movq	%rdx,%r13                          // mov	@C[0],@T[0]
    andq	%rbp,%rdx                 	       // and	@C[1],@C[0]
    notq	%rbp                 	           // not	@C[1]
    xorq	%rcx,%rdx                 	       // xor	@C[4],@C[0]	
    movq	%rdx,92(%rdi)                      // mov	@C[0],$A[4][4](%rdi)	
    movq	%rax,%r14                 	       // mov	@C[2],@T[1]
    andq	%rbp,%rax                 	       // and	@C[1],@C[2]
    xorq	%r13,%rax                 	       // xor	@T[0],@C[2]		
    movq	%rax,60(%rdi)                      // mov	@C[2],$A[4][0](%rdi)	
    orq	%rcx,%r13                 	           // or	@C[4],@T[0]
    xorq	%rbx,%r13                 	       // xor	@C[3],@T[0]		
    movq	%r13,84(%rdi)                      // mov	@T[0],$A[4][3](%rdi)
    andq	%rbx,%rcx                 	       // and	@C[3],@C[4]
    xorq	%r14,%rcx                 	       // xor	@T[1],@C[4]		
    movq	%rcx,76(%rdi)                      // mov	@C[4],$A[4][2](%rdi)	
    orq	%r14,%rbx                 	           // or	@T[1],@C[3]
    xorq	%rbp,%rbx                 	       // xor	@C[1],@C[3]		
    movq	%rbx,68(%rdi)                      // mov	@C[3],$A[4][1](%rdi)	
    movq	%rdx,%rbp                 	       // mov	@C[0],@C[1]		
    movq	%r13,%rdx                 	       // mov	@T[0],@C[0]
    testq	$255,%r15                          // test	\$255,$iotas_x86_64
    jnz	.Loop
    leaq	-192(%r15),%r15  

    notq	-92(%rdi)
    notq	-84(%rdi)
    notq	-36(%rdi)
    notq	-4(%rdi)
    notq	36(%rdi)
    notq	60(%rdi)
    addq	$200,%rsp
    leaq	-100(%rdi),%rdi
    popq	%r15
    popq	%r14
    popq	%r13
    popq	%r12
    popq	%rbp
    popq	%rbx
    .byte	0xf3,0xc3
.size	mlkem_keccak_f1600,.-mlkem_keccak_f1600

.section	.rodata
.align	256
.quad	0,0,0,0,0,0,0,0
.type	iotas_x86_64,@object
iotas_x86_64:
.quad	0x0000000000000001
.quad	0x0000000000008082
.quad	0x800000000000808a
.quad	0x8000000080008000
.quad	0x000000000000808b
.quad	0x0000000080000001
.quad	0x8000000080008081
.quad	0x8000000000008009
.quad	0x000000000000008a
.quad	0x0000000000000088
.quad	0x0000000080008009
.quad	0x000000008000000a
.quad	0x000000008000808b
.quad	0x800000000000008b
.quad	0x8000000000008089
.quad	0x8000000000008003
.quad	0x8000000000008002
.quad	0x8000000000000080
.quad	0x000000000000800a
.quad	0x800000008000000a
.quad	0x8000000080008081
.quad	0x8000000000008080
.quad	0x0000000080000001
.quad	0x8000000080008008
.size	iotas_x86_64,.-iotas_x86_64

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif