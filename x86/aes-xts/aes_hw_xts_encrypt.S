// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Description
// Inputs; output
//
// extern void aes_hw_xts_encrypt(const uint8_t *inp, uint8_t *out,
//   size_t len, const AES_KEY *key1, const AES_KEY *key2,
//   const uint8_t iv[16]);
//
// Standard x86-64 ABI: rdi = inp, rsi = out, rdx = len,
//                      rcx = key1, r8 = key2, r9 = iv
// Microsoft x64 ABI:   ???
// ----------------------------------------------------------------------------

#include "_internal_s2n_bignum.h"

        // .intel_syntax noprefix
        S2N_BN_SYM_VISIBILITY_DIRECTIVE(aes_hw_xts_encrypt)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(aes_hw_xts_encrypt)
        .text

.type  aes_hw_xts_encrypt,@function
.align  16
aes_hw_xts_encrypt:
.cfi_startproc
_CET_ENDBR
  leaq  (%rsp),%r11
// .cfi_def_cfa_register  %r11
  pushq  %rbp
// .cfi_offset  %rbp,-16
  subq  $112,%rsp
  andq  $-16,%rsp
  movups  (%r9),%xmm2
  movl  240(%r8),%eax
  movl  240(%rcx),%r10d
  movups  (%r8),%xmm0
  movups  16(%r8),%xmm1
  leaq  32(%r8),%r8
  xorps  %xmm0,%xmm2
.Loop_enc1_6:
.byte  102,15,56,220,209
  decl  %eax
  movups  (%r8),%xmm1
  leaq  16(%r8),%r8
  jnz  .Loop_enc1_6
.byte  102,15,56,221,209
  movups  (%rcx),%xmm0
  movq  %rcx,%rbp
  movl  %r10d,%eax
  shll  $4,%r10d
  movq  %rdx,%r9
  andq  $-16,%rdx

  movups  16(%rcx,%r10,1),%xmm1

  movdqa  .Lxts_magic(%rip),%xmm8
  movdqa  %xmm2,%xmm15
  pshufd  $0x5f,%xmm2,%xmm9
  pxor  %xmm0,%xmm1
  movdqa  %xmm9,%xmm14
  paddd  %xmm9,%xmm9
  movdqa  %xmm15,%xmm10
  psrad  $31,%xmm14
  paddq  %xmm15,%xmm15
  pand  %xmm8,%xmm14
  pxor  %xmm0,%xmm10
  pxor  %xmm14,%xmm15
  movdqa  %xmm9,%xmm14
  paddd  %xmm9,%xmm9
  movdqa  %xmm15,%xmm11
  psrad  $31,%xmm14
  paddq  %xmm15,%xmm15
  pand  %xmm8,%xmm14
  pxor  %xmm0,%xmm11
  pxor  %xmm14,%xmm15
  movdqa  %xmm9,%xmm14
  paddd  %xmm9,%xmm9
  movdqa  %xmm15,%xmm12
  psrad  $31,%xmm14
  paddq  %xmm15,%xmm15
  pand  %xmm8,%xmm14
  pxor  %xmm0,%xmm12
  pxor  %xmm14,%xmm15
  movdqa  %xmm9,%xmm14
  paddd  %xmm9,%xmm9
  movdqa  %xmm15,%xmm13
  psrad  $31,%xmm14
  paddq  %xmm15,%xmm15
  pand  %xmm8,%xmm14
  pxor  %xmm0,%xmm13
  pxor  %xmm14,%xmm15
  movdqa  %xmm15,%xmm14
  psrad  $31,%xmm9
  paddq  %xmm15,%xmm15
  pand  %xmm8,%xmm9
  pxor  %xmm0,%xmm14
  pxor  %xmm9,%xmm15
  movaps  %xmm1,96(%rsp)

  subq  $96,%rdx
  jc  .Lxts_enc_short

  movl  $16+96,%eax
  leaq  32(%rbp,%r10,1),%rcx
  subq  %r10,%rax
  movups  16(%rbp),%xmm1
  movq  %rax,%r10
  leaq  .Lxts_magic(%rip),%r8
  jmp  .Lxts_enc_grandloop

.align  32
.Lxts_enc_grandloop:
  movdqu  0(%rdi),%xmm2
  movdqa  %xmm0,%xmm8
  movdqu  16(%rdi),%xmm3
  pxor  %xmm10,%xmm2
  movdqu  32(%rdi),%xmm4
  pxor  %xmm11,%xmm3
.byte  102,15,56,220,209
  movdqu  48(%rdi),%xmm5
  pxor  %xmm12,%xmm4
.byte  102,15,56,220,217
  movdqu  64(%rdi),%xmm6
  pxor  %xmm13,%xmm5
.byte  102,15,56,220,225
  movdqu  80(%rdi),%xmm7
  pxor  %xmm15,%xmm8
  movdqa  96(%rsp),%xmm9
  pxor  %xmm14,%xmm6
.byte  102,15,56,220,233
  movups  32(%rbp),%xmm0
  leaq  96(%rdi),%rdi
  pxor  %xmm8,%xmm7

  pxor  %xmm9,%xmm10
.byte  102,15,56,220,241
  pxor  %xmm9,%xmm11
  movdqa  %xmm10,0(%rsp)
.byte  102,15,56,220,249
  movups  48(%rbp),%xmm1
  pxor  %xmm9,%xmm12

.byte  102,15,56,220,208
  pxor  %xmm9,%xmm13
  movdqa  %xmm11,16(%rsp)
.byte  102,15,56,220,216
  pxor  %xmm9,%xmm14
  movdqa  %xmm12,32(%rsp)
.byte  102,15,56,220,224
.byte  102,15,56,220,232
  pxor  %xmm9,%xmm8
  movdqa  %xmm14,64(%rsp)
.byte  102,15,56,220,240
.byte  102,15,56,220,248
  movups  64(%rbp),%xmm0
  movdqa  %xmm8,80(%rsp)
  pshufd  $0x5f,%xmm15,%xmm9
  jmp  .Lxts_enc_loop6
.align  32
.Lxts_enc_loop6:
.byte  102,15,56,220,209
.byte  102,15,56,220,217
.byte  102,15,56,220,225
.byte  102,15,56,220,233
.byte  102,15,56,220,241
.byte  102,15,56,220,249
  movups  -64(%rcx,%rax,1),%xmm1
  addq  $32,%rax

.byte  102,15,56,220,208
.byte  102,15,56,220,216
.byte  102,15,56,220,224
.byte  102,15,56,220,232
.byte  102,15,56,220,240
.byte  102,15,56,220,248
  movups  -80(%rcx,%rax,1),%xmm0
  jnz  .Lxts_enc_loop6

  movdqa  (%r8),%xmm8
  movdqa  %xmm9,%xmm14
  paddd  %xmm9,%xmm9
.byte  102,15,56,220,209
  paddq  %xmm15,%xmm15
  psrad  $31,%xmm14
.byte  102,15,56,220,217
  pand  %xmm8,%xmm14
  movups  (%rbp),%xmm10
.byte  102,15,56,220,225
.byte  102,15,56,220,233
.byte  102,15,56,220,241
  pxor  %xmm14,%xmm15
  movaps  %xmm10,%xmm11
.byte  102,15,56,220,249
  movups  -64(%rcx),%xmm1

  movdqa  %xmm9,%xmm14
.byte  102,15,56,220,208
  paddd  %xmm9,%xmm9
  pxor  %xmm15,%xmm10
.byte  102,15,56,220,216
  psrad  $31,%xmm14
  paddq  %xmm15,%xmm15
.byte  102,15,56,220,224
.byte  102,15,56,220,232
  pand  %xmm8,%xmm14
  movaps  %xmm11,%xmm12
.byte  102,15,56,220,240
  pxor  %xmm14,%xmm15
  movdqa  %xmm9,%xmm14
.byte  102,15,56,220,248
  movups  -48(%rcx),%xmm0

  paddd  %xmm9,%xmm9
.byte  102,15,56,220,209
  pxor  %xmm15,%xmm11
  psrad  $31,%xmm14
.byte  102,15,56,220,217
  paddq  %xmm15,%xmm15
  pand  %xmm8,%xmm14
.byte  102,15,56,220,225
.byte  102,15,56,220,233
  movdqa  %xmm13,48(%rsp)
  pxor  %xmm14,%xmm15
.byte  102,15,56,220,241
  movaps  %xmm12,%xmm13
  movdqa  %xmm9,%xmm14
.byte  102,15,56,220,249
  movups  -32(%rcx),%xmm1

  paddd  %xmm9,%xmm9
.byte  102,15,56,220,208
  pxor  %xmm15,%xmm12
  psrad  $31,%xmm14
.byte  102,15,56,220,216
  paddq  %xmm15,%xmm15
  pand  %xmm8,%xmm14
.byte  102,15,56,220,224
.byte  102,15,56,220,232
.byte  102,15,56,220,240
  pxor  %xmm14,%xmm15
  movaps  %xmm13,%xmm14
.byte  102,15,56,220,248

  movdqa  %xmm9,%xmm0
  paddd  %xmm9,%xmm9
.byte  102,15,56,220,209
  pxor  %xmm15,%xmm13
  psrad  $31,%xmm0
.byte  102,15,56,220,217
  paddq  %xmm15,%xmm15
  pand  %xmm8,%xmm0
.byte  102,15,56,220,225
.byte  102,15,56,220,233
  pxor  %xmm0,%xmm15
  movups  (%rbp),%xmm0
.byte  102,15,56,220,241
.byte  102,15,56,220,249
  movups  16(%rbp),%xmm1

  pxor  %xmm15,%xmm14
.byte  102,15,56,221,84,36,0
  psrad  $31,%xmm9
  paddq  %xmm15,%xmm15
.byte  102,15,56,221,92,36,16
.byte  102,15,56,221,100,36,32
  pand  %xmm8,%xmm9
  movq  %r10,%rax
.byte  102,15,56,221,108,36,48
.byte  102,15,56,221,116,36,64
.byte  102,15,56,221,124,36,80
  pxor  %xmm9,%xmm15

  leaq  96(%rsi),%rsi
  movups  %xmm2,-96(%rsi)
  movups  %xmm3,-80(%rsi)
  movups  %xmm4,-64(%rsi)
  movups  %xmm5,-48(%rsi)
  movups  %xmm6,-32(%rsi)
  movups  %xmm7,-16(%rsi)
  subq  $96,%rdx
  jnc  .Lxts_enc_grandloop

  movl  $16+96,%eax
  subl  %r10d,%eax
  movq  %rbp,%rcx
  shrl  $4,%eax

.Lxts_enc_short:

  movl  %eax,%r10d
  pxor  %xmm0,%xmm10
  addq  $96,%rdx
  jz  .Lxts_enc_done

  pxor  %xmm0,%xmm11
  cmpq  $0x20,%rdx
  jb  .Lxts_enc_one
  pxor  %xmm0,%xmm12
  je  .Lxts_enc_two

  pxor  %xmm0,%xmm13
  cmpq  $0x40,%rdx
  jb  .Lxts_enc_three
  pxor  %xmm0,%xmm14
  je  .Lxts_enc_four

  movdqu  (%rdi),%xmm2
  movdqu  16(%rdi),%xmm3
  movdqu  32(%rdi),%xmm4
  pxor  %xmm10,%xmm2
  movdqu  48(%rdi),%xmm5
  pxor  %xmm11,%xmm3
  movdqu  64(%rdi),%xmm6
  leaq  80(%rdi),%rdi
  pxor  %xmm12,%xmm4
  pxor  %xmm13,%xmm5
  pxor  %xmm14,%xmm6
  pxor  %xmm7,%xmm7

  call  _aesni_encrypt6

  xorps  %xmm10,%xmm2
  movdqa  %xmm15,%xmm10
  xorps  %xmm11,%xmm3
  xorps  %xmm12,%xmm4
  movdqu  %xmm2,(%rsi)
  xorps  %xmm13,%xmm5
  movdqu  %xmm3,16(%rsi)
  xorps  %xmm14,%xmm6
  movdqu  %xmm4,32(%rsi)
  movdqu  %xmm5,48(%rsi)
  movdqu  %xmm6,64(%rsi)
  leaq  80(%rsi),%rsi
  jmp  .Lxts_enc_done

.align  16
.Lxts_enc_one:
  movups  (%rdi),%xmm2
  leaq  16(%rdi),%rdi
  xorps  %xmm10,%xmm2
  movups  (%rcx),%xmm0
  movups  16(%rcx),%xmm1
  leaq  32(%rcx),%rcx
  xorps  %xmm0,%xmm2
.Loop_enc1_7:
.byte  102,15,56,220,209
  decl  %eax
  movups  (%rcx),%xmm1
  leaq  16(%rcx),%rcx
  jnz  .Loop_enc1_7
.byte  102,15,56,221,209
  xorps  %xmm10,%xmm2
  movdqa  %xmm11,%xmm10
  movups  %xmm2,(%rsi)
  leaq  16(%rsi),%rsi
  jmp  .Lxts_enc_done

.align  16
.Lxts_enc_two:
  movups  (%rdi),%xmm2
  movups  16(%rdi),%xmm3
  leaq  32(%rdi),%rdi
  xorps  %xmm10,%xmm2
  xorps  %xmm11,%xmm3

  call  _aesni_encrypt2

  xorps  %xmm10,%xmm2
  movdqa  %xmm12,%xmm10
  xorps  %xmm11,%xmm3
  movups  %xmm2,(%rsi)
  movups  %xmm3,16(%rsi)
  leaq  32(%rsi),%rsi
  jmp  .Lxts_enc_done

.align  16
.Lxts_enc_three:
  movups  (%rdi),%xmm2
  movups  16(%rdi),%xmm3
  movups  32(%rdi),%xmm4
  leaq  48(%rdi),%rdi
  xorps  %xmm10,%xmm2
  xorps  %xmm11,%xmm3
  xorps  %xmm12,%xmm4

  call  _aesni_encrypt3

  xorps  %xmm10,%xmm2
  movdqa  %xmm13,%xmm10
  xorps  %xmm11,%xmm3
  xorps  %xmm12,%xmm4
  movups  %xmm2,(%rsi)
  movups  %xmm3,16(%rsi)
  movups  %xmm4,32(%rsi)
  leaq  48(%rsi),%rsi
  jmp  .Lxts_enc_done

.align  16
.Lxts_enc_four:
  movups  (%rdi),%xmm2
  movups  16(%rdi),%xmm3
  movups  32(%rdi),%xmm4
  xorps  %xmm10,%xmm2
  movups  48(%rdi),%xmm5
  leaq  64(%rdi),%rdi
  xorps  %xmm11,%xmm3
  xorps  %xmm12,%xmm4
  xorps  %xmm13,%xmm5

  call  _aesni_encrypt4

  pxor  %xmm10,%xmm2
  movdqa  %xmm14,%xmm10
  pxor  %xmm11,%xmm3
  pxor  %xmm12,%xmm4
  movdqu  %xmm2,(%rsi)
  pxor  %xmm13,%xmm5
  movdqu  %xmm3,16(%rsi)
  movdqu  %xmm4,32(%rsi)
  movdqu  %xmm5,48(%rsi)
  leaq  64(%rsi),%rsi
  jmp  .Lxts_enc_done

.align  16
.Lxts_enc_done:
  andq  $15,%r9
  jz  .Lxts_enc_ret
  movq  %r9,%rdx

.Lxts_enc_steal:
  movzbl  (%rdi),%eax
  movzbl  -16(%rsi),%ecx
  leaq  1(%rdi),%rdi
  movb  %al,-16(%rsi)
  movb  %cl,0(%rsi)
  leaq  1(%rsi),%rsi
  subq  $1,%rdx
  jnz  .Lxts_enc_steal

  subq  %r9,%rsi
  movq  %rbp,%rcx
  movl  %r10d,%eax

  movups  -16(%rsi),%xmm2
  xorps  %xmm10,%xmm2
  movups  (%rcx),%xmm0
  movups  16(%rcx),%xmm1
  leaq  32(%rcx),%rcx
  xorps  %xmm0,%xmm2
.Loop_enc1_8:
.byte  102,15,56,220,209
  decl  %eax
  movups  (%rcx),%xmm1
  leaq  16(%rcx),%rcx
  jnz  .Loop_enc1_8
.byte  102,15,56,221,209
  xorps  %xmm10,%xmm2
  movups  %xmm2,-16(%rsi)

.Lxts_enc_ret:
  xorps  %xmm0,%xmm0
  pxor  %xmm1,%xmm1
  pxor  %xmm2,%xmm2
  pxor  %xmm3,%xmm3
  pxor  %xmm4,%xmm4
  pxor  %xmm5,%xmm5
  pxor  %xmm6,%xmm6
  pxor  %xmm7,%xmm7
  movaps  %xmm0,0(%rsp)
  pxor  %xmm8,%xmm8
  movaps  %xmm0,16(%rsp)
  pxor  %xmm9,%xmm9
  movaps  %xmm0,32(%rsp)
  pxor  %xmm10,%xmm10
  movaps  %xmm0,48(%rsp)
  pxor  %xmm11,%xmm11
  movaps  %xmm0,64(%rsp)
  pxor  %xmm12,%xmm12
  movaps  %xmm0,80(%rsp)
  pxor  %xmm13,%xmm13
  movaps  %xmm0,96(%rsp)
  pxor  %xmm14,%xmm14
  pxor  %xmm15,%xmm15
  movq  -8(%r11),%rbp
// .cfi_restore  %rbp
  leaq  (%r11),%rsp
// .cfi_def_cfa_register  %rsp
.Lxts_enc_epilogue:
  ret
.cfi_endproc
.size  aes_hw_xts_encrypt,.-aes_hw_xts_encrypt

.type  _aesni_encrypt2,@function
.align  16
_aesni_encrypt2:
.cfi_startproc
  movups  (%rcx),%xmm0
  shll  $4,%eax
  movups  16(%rcx),%xmm1
  xorps  %xmm0,%xmm2
  xorps  %xmm0,%xmm3
  movups  32(%rcx),%xmm0
  leaq  32(%rcx,%rax,1),%rcx
  negq  %rax
  addq  $16,%rax

.Lenc_loop2:
.byte  102,15,56,220,209 // aesenc xmm2,xmm1
.byte  102,15,56,220,217  // aesenc xmm3,xmm1
  movups  (%rcx,%rax,1),%xmm1
  addq  $32,%rax
.byte  102,15,56,220,208
.byte  102,15,56,220,216
  movups  -16(%rcx,%rax,1),%xmm0
  jnz  .Lenc_loop2

.byte  102,15,56,220,209
.byte  102,15,56,220,217
.byte  102,15,56,221,208
.byte  102,15,56,221,216
  ret
.cfi_endproc
.size  _aesni_encrypt2,.-_aesni_encrypt2
.type  _aesni_encrypt3,@function
.align  16
_aesni_encrypt3:
.cfi_startproc
  movups  (%rcx),%xmm0
  shll  $4,%eax
  movups  16(%rcx),%xmm1
  xorps  %xmm0,%xmm2
  xorps  %xmm0,%xmm3
  xorps  %xmm0,%xmm4
  movups  32(%rcx),%xmm0
  leaq  32(%rcx,%rax,1),%rcx
  negq  %rax
  addq  $16,%rax

.Lenc_loop3:
.byte  102,15,56,220,209
.byte  102,15,56,220,217
.byte  102,15,56,220,225
  movups  (%rcx,%rax,1),%xmm1
  addq  $32,%rax
.byte  102,15,56,220,208
.byte  102,15,56,220,216
.byte  102,15,56,220,224
  movups  -16(%rcx,%rax,1),%xmm0
  jnz  .Lenc_loop3

.byte  102,15,56,220,209
.byte  102,15,56,220,217
.byte  102,15,56,220,225
.byte  102,15,56,221,208
.byte  102,15,56,221,216
.byte  102,15,56,221,224
  ret
.cfi_endproc
.size  _aesni_encrypt3,.-_aesni_encrypt3
.type  _aesni_encrypt4,@function
.align  16
_aesni_encrypt4:
.cfi_startproc
  movups  (%rcx),%xmm0
  shll  $4,%eax
  movups  16(%rcx),%xmm1
  xorps  %xmm0,%xmm2
  xorps  %xmm0,%xmm3
  xorps  %xmm0,%xmm4
  xorps  %xmm0,%xmm5
  movups  32(%rcx),%xmm0
  leaq  32(%rcx,%rax,1),%rcx
  negq  %rax
  .byte  0x0f,0x1f,0x00
  addq  $16,%rax

.Lenc_loop4:
.byte  102,15,56,220,209
.byte  102,15,56,220,217
.byte  102,15,56,220,225
.byte  102,15,56,220,233
  movups  (%rcx,%rax,1),%xmm1
  addq  $32,%rax
.byte  102,15,56,220,208
.byte  102,15,56,220,216
.byte  102,15,56,220,224
.byte  102,15,56,220,232
  movups  -16(%rcx,%rax,1),%xmm0
  jnz  .Lenc_loop4

.byte  102,15,56,220,209
.byte  102,15,56,220,217
.byte  102,15,56,220,225
.byte  102,15,56,220,233
.byte  102,15,56,221,208
.byte  102,15,56,221,216
.byte  102,15,56,221,224
.byte  102,15,56,221,232
  ret
.cfi_endproc
.size  _aesni_encrypt4,.-_aesni_encrypt4
.type  _aesni_encrypt6,@function
.align  16
_aesni_encrypt6:
.cfi_startproc
  movups  (%rcx),%xmm0
  shll  $4,%eax
  movups  16(%rcx),%xmm1
  xorps  %xmm0,%xmm2
  pxor  %xmm0,%xmm3
  pxor  %xmm0,%xmm4
.byte  102,15,56,220,209
  leaq  32(%rcx,%rax,1),%rcx
  negq  %rax
.byte  102,15,56,220,217
  pxor  %xmm0,%xmm5
  pxor  %xmm0,%xmm6
.byte  102,15,56,220,225
  pxor  %xmm0,%xmm7
  movups  (%rcx,%rax,1),%xmm0
  addq  $16,%rax
  jmp  .Lenc_loop6_enter
.align  16
.Lenc_loop6:
.byte  102,15,56,220,209
.byte  102,15,56,220,217
.byte  102,15,56,220,225
.Lenc_loop6_enter:
.byte  102,15,56,220,233
.byte  102,15,56,220,241
.byte  102,15,56,220,249
  movups  (%rcx,%rax,1),%xmm1
  addq  $32,%rax
.byte  102,15,56,220,208
.byte  102,15,56,220,216
.byte  102,15,56,220,224
.byte  102,15,56,220,232
.byte  102,15,56,220,240
.byte  102,15,56,220,248
  movups  -16(%rcx,%rax,1),%xmm0
  jnz  .Lenc_loop6

.byte  102,15,56,220,209
.byte  102,15,56,220,217
.byte  102,15,56,220,225
.byte  102,15,56,220,233
.byte  102,15,56,220,241
.byte  102,15,56,220,249
.byte  102,15,56,221,208
.byte  102,15,56,221,216
.byte  102,15,56,221,224
.byte  102,15,56,221,232
.byte  102,15,56,221,240
.byte  102,15,56,221,248
  ret
.cfi_endproc
.size  _aesni_encrypt6,.-_aesni_encrypt6

// TODO:
.align 16
.Lxts_magic:
    .long  0x87,0,1,0

.text
