// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Description:
// Inputs; output
//
// extern void aes_hw_xts_encrypt_clean(const uint8_t *inp, uint8_t *out,
//   size_t len, const AES_KEY *key1, const AES_KEY *key2,
//   const uint8_t iv[16]);
//
// Standard x86-64 ABI: rdi = inp, rsi = out, rdx = len,
//                      rcx = key1, r8 = key2, r9 = iv
// Microsoft x64 ABI:   ???
// ----------------------------------------------------------------------------

#include "_internal_s2n_bignum.h"

        // .intel_syntax noprefix
        S2N_BN_SYM_VISIBILITY_DIRECTIVE(aes_hw_xts_encrypt_clean)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(aes_hw_xts_encrypt_clean)
        .text

#define AESENCLOOP(name, pt, rk, ind, k_ptr)   \
        name:                                  ;\
         aesenc rk, pt                         ;\
         decl ind                              ;\
         movups (k_ptr), rk                    ;\
         leaq 16(k_ptr), k_ptr                 ;\
         jnz name

// name: Loop name; pt: plaintext; k_ptr: key pointer
// k0: roundkey[0]; k1: roundkey[1...]; ind: round index
#define AESENC(name, pt, k_ptr, k0, k1, ind)   \
        movups  (k_ptr), k0                    ;\
        movups  16(k_ptr), k1                  ;\
        leaq  32(k_ptr), k_ptr                 ;\
        xorps  k0, pt                          ;\
        AESENCLOOP(name, pt, k1, ind, k_ptr)   ;\
        aesenclast k1, pt

#define TWEAK(twres,twtmp,mask,magic)                       \
        movdqa  twtmp,mask                                 ;\
        psrad  $31,mask                                    ;\
        pand  magic,mask                                   ;\
        paddq  twres,twres                                 ;\
        pxor  mask,twres                                   ;\
        paddd  twtmp,twtmp

// Do not need to double ciphertext tweak shuffled for next round
#define TWEAK_LAST(twres,mask,magic)      \
        psrad  $31,mask                                 ;\
        pand  magic,mask                                ;\
        paddq  twres,twres                              ;\
        pxor  mask,twres

.type  aes_hw_xts_encrypt_clean,@function
.align  16
S2N_BN_SYMBOL(aes_hw_xts_encrypt_clean):
.cfi_startproc
_CET_ENDBR
  leaq  (%rsp),%r11  // save frame ptr from caller
// .cfi_def_cfa_register  %r11
  pushq  %rbp  // rbp should not change
// .cfi_offset  %rbp,-16
  subq  $112,%rsp  // allocate a frame
  andq  $-16,%rsp // align to 16-bytes
  movups  (%r9),%xmm2 // load cleartext tweak
  movl  240(%r8),%eax // key2->rounds
  movl  240(%rcx),%r10d // key1->rounds
  AESENC(.Loop_enc1_6,%xmm2,%r8,%xmm0,%xmm1,%eax)
  movups  (%rcx),%xmm0 // key1[0]
  movq  %rcx,%rbp
  movl  %r10d,%eax
  shll  $4,%r10d // key1->rounds * 16
  movq  %rdx,%r9
  andq  $-16,%rdx // round down len to multiple of 16

  movups  16(%rcx,%r10,1),%xmm1 // loadt last round of key1
  pxor  %xmm0,%xmm1 // key[0] ^ key[last], last = 14

  movdqa  .Lxts_magic(%rip),%xmm8
  movdqa  %xmm2,%xmm15 // xmm2 is the result of AESENC(plaintext tweak, key2)
  pshufd  $0x5f,%xmm2,%xmm9

  movdqa %xmm15,%xmm10
  pxor %xmm0,%xmm10

  TWEAK(%xmm15,%xmm9,%xmm14,%xmm8)
  movdqa %xmm15,%xmm11  // tweak[1]
  pxor %xmm0,%xmm11  // tweak[1] ^ key1[0]

  TWEAK(%xmm15,%xmm9,%xmm14,%xmm8)
  movdqa %xmm15,%xmm12
  pxor %xmm0,%xmm12

  TWEAK(%xmm15,%xmm9,%xmm14,%xmm8)
  movdqa %xmm15,%xmm13
  pxor %xmm0,%xmm13

  TWEAK(%xmm15,%xmm9,%xmm14,%xmm8)
  movdqa %xmm15,%xmm14
  pxor %xmm0,%xmm14

  TWEAK_LAST(%xmm15,%xmm9,%xmm8)
  // xmm10 - xmm14 now stores tweak[i] ^ key1[0]
  // xmm15 only stores tweak[5]

  // store key1[0] ^ key1[last] on stack
  // key1[0] later cancels out when xoring with tweak[i] ^ key1[0]
  movaps  %xmm1,96(%rsp)

  subq  $96,%rdx // subtract 6 blocks
  jc  .Lxts_enc_short

  movl  $16+96,%eax  // eax = 7 * 16
  leaq  32(%rbp,%r10,1),%rcx // rcx points to end of keyschedule
  subq  %r10,%rax // rax = 7*16 - 13*16 = -6*16
  movq  %rax,%r10 // back up twisted(negative) rounds
  movups  16(%rbp),%xmm1 // key1[1]
  leaq  .Lxts_magic(%rip),%r8
  jmp  .Lxts_enc_grandloop

.align  32
.Lxts_enc_grandloop:
  movdqu  0(%rdi),%xmm2
  movdqu  16(%rdi),%xmm3
  movdqu  32(%rdi),%xmm4
  movdqu  48(%rdi),%xmm5
  movdqu  64(%rdi),%xmm6
  movdqu  80(%rdi),%xmm7

  movdqa  %xmm0,%xmm8 // key1[0]
  pxor  %xmm15,%xmm8 // key1[0] ^ tweak[5]

  pxor  %xmm10,%xmm2
  pxor  %xmm11,%xmm3
  pxor  %xmm12,%xmm4
  pxor  %xmm13,%xmm5
  pxor  %xmm14,%xmm6
  pxor  %xmm8,%xmm7

  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenc %xmm1,%xmm5
  aesenc %xmm1,%xmm6
  aesenc %xmm1,%xmm7
  movups  32(%rbp),%xmm0 // key1[2]

  aesenc %xmm0,%xmm2
  aesenc %xmm0,%xmm3
  aesenc %xmm0,%xmm4
  aesenc %xmm0,%xmm5
  aesenc %xmm0,%xmm6
  aesenc %xmm0,%xmm7

  movdqa  96(%rsp),%xmm9 // key1[0] ^ key1[last]
  pxor  %xmm9,%xmm10 // key1[0] cancels out -> tweak[0] ^ key1[last]
  movdqa  %xmm10,0(%rsp)
  pxor  %xmm9,%xmm11 // tweak[1] ^ key1[last]
  movdqa  %xmm11,16(%rsp)
  pxor  %xmm9,%xmm12  // tweak[2] ^ key1[last]
  movdqa  %xmm12,32(%rsp)
  pxor  %xmm9,%xmm13 // tweak[3] ^ key1[last]
  movdqa  %xmm13,48(%rsp)
  pxor  %xmm9,%xmm14 // tweak[4] ^ key1[last]
  movdqa  %xmm14,64(%rsp)
  pxor  %xmm9,%xmm8 // tweak[5] ^ key1[last]
  movdqa  %xmm8,80(%rsp)

  movups  48(%rbp),%xmm1 // key1[3]
  movups  64(%rbp),%xmm0 // key1[4]

  leaq  96(%rdi),%rdi // rdi += 6*16
  jmp  .Lxts_enc_loop6
.align  32
.Lxts_enc_loop6:
  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenc %xmm1,%xmm5
  aesenc %xmm1,%xmm6
  aesenc %xmm1,%xmm7
  // rax = -6*16
  // addr = 15*16 - 6*16 - 4*16 = 5*16
  movups  -64(%rcx,%rax,1),%xmm1 // key1[5], key1[7], key1[9]
  addq  $32,%rax

  aesenc %xmm0,%xmm2
  aesenc %xmm0,%xmm3
  aesenc %xmm0,%xmm4
  aesenc %xmm0,%xmm5
  aesenc %xmm0,%xmm6
  aesenc %xmm0,%xmm7
  // rax = -4*16
  // addr = 15*16 - 4*16 - 5*16 = 6*16
  movups  -80(%rcx,%rax,1),%xmm0 // key1[6], key1[8], key1[10]
  jnz  .Lxts_enc_loop6
  // Now all 6 blocks are encrypted for 9 round keys

  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenc %xmm1,%xmm5
  aesenc %xmm1,%xmm6
  aesenc %xmm1,%xmm7
  movups  -64(%rcx),%xmm1 // key1[11]

  aesenc %xmm0,%xmm2
  aesenc %xmm0,%xmm3
  aesenc %xmm0,%xmm4
  aesenc %xmm0,%xmm5
  aesenc %xmm0,%xmm6
  aesenc %xmm0,%xmm7
  movups  -48(%rcx),%xmm0 // key1[12]

  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenc %xmm1,%xmm5
  aesenc %xmm1,%xmm6
  aesenc %xmm1,%xmm7
  movups  -32(%rcx),%xmm1 // key1[13]

  aesenc %xmm0,%xmm2
  aesenc %xmm0,%xmm3
  aesenc %xmm0,%xmm4
  aesenc %xmm0,%xmm5
  aesenc %xmm0,%xmm6
  aesenc %xmm0,%xmm7

  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenc %xmm1,%xmm5
  aesenc %xmm1,%xmm6
  aesenc %xmm1,%xmm7

  aesenclast 0(%rsp),%xmm2
  aesenclast 16(%rsp),%xmm3
  aesenclast 32(%rsp),%xmm4
  aesenclast 48(%rsp),%xmm5
  aesenclast 64(%rsp),%xmm6
  aesenclast 80(%rsp),%xmm7

  // Next 6 tweaks
  movdqa  (%r8),%xmm8  // magic
  movups  (%rbp),%xmm10 // key1[0]
  pshufd  $0x5f,%xmm15,%xmm9

  TWEAK(%xmm15,%xmm9,%xmm14,%xmm8) // tweak[0]
  movaps %xmm10,%xmm11
  pxor %xmm15,%xmm10

  TWEAK(%xmm15,%xmm9,%xmm14,%xmm8) // tweak[1]
  movaps %xmm11,%xmm12
  pxor %xmm15,%xmm11

  TWEAK(%xmm15,%xmm9,%xmm14,%xmm8) // tweak[2]
  movaps %xmm12,%xmm13
  pxor %xmm15,%xmm12

  TWEAK(%xmm15,%xmm9,%xmm14,%xmm8) // tweak[3]
  movaps %xmm13,%xmm14
  pxor %xmm15,%xmm13

  TWEAK(%xmm15,%xmm9,%xmm0,%xmm8) // tweak[4]
  pxor  %xmm15,%xmm14

  TWEAK_LAST(%xmm15,%xmm9,%xmm8)  // tweak[5]

  movq  %r10,%rax  // -6 * 16
  movups  (%rbp),%xmm0  // key1[0]
  movups  16(%rbp),%xmm1  // key1[1]

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
  subl  %r10d,%eax // 7 * 16 - (-6)*16 = 13 * 16
  movq  %rbp,%rcx  // restore key
  shrl  $4,%eax  // restore original value: 13

// Less than 6 blocks left
.Lxts_enc_short:

  movl  %eax,%r10d // back up rounds 13
  pxor  %xmm0,%xmm10 // cancel out the key1[0] from key1[0]^tweak[0]
  addq  $96,%rdx  // restore remaining len
  jz  .Lxts_enc_done  // less than one block

  pxor  %xmm0,%xmm11
  cmpq  $0x20,%rdx
  jb  .Lxts_enc_one  // [1, 2) blocks
  pxor  %xmm0,%xmm12
  je  .Lxts_enc_two  // [2, 3) blocks

  pxor  %xmm0,%xmm13
  cmpq  $0x40,%rdx
  jb  .Lxts_enc_three // [3, 4) blocks
  pxor  %xmm0,%xmm14
  je  .Lxts_enc_four // [4, 5) blocks

  // [5, 6) blocks
  movdqu  (%rdi),%xmm2
  movdqu  16(%rdi),%xmm3
  movdqu  32(%rdi),%xmm4
  movdqu  48(%rdi),%xmm5
  movdqu  64(%rdi),%xmm6
  leaq  80(%rdi),%rdi

  pxor  %xmm10,%xmm2
  pxor  %xmm11,%xmm3
  pxor  %xmm12,%xmm4
  pxor  %xmm13,%xmm5
  pxor  %xmm14,%xmm6
  pxor  %xmm7,%xmm7 // Seems to be cleanup %xmm7 -- using encrypt6 for encrypt5

  call  _aesni_encrypt6

  xorps  %xmm10,%xmm2
  xorps  %xmm11,%xmm3
  xorps  %xmm12,%xmm4
  xorps  %xmm13,%xmm5
  xorps  %xmm14,%xmm6
  movdqa  %xmm15,%xmm10 // tweak[5] moved to %xmm10 for cipher stealing

  movdqu  %xmm2,(%rsi)
  movdqu  %xmm3,16(%rsi)
  movdqu  %xmm4,32(%rsi)
  movdqu  %xmm5,48(%rsi)
  movdqu  %xmm6,64(%rsi)
  leaq  80(%rsi),%rsi
  jmp  .Lxts_enc_done

.align  16
.Lxts_enc_one:
  movups  (%rdi),%xmm2
  leaq  16(%rdi),%rdi

  xorps  %xmm10,%xmm2 // tweak[0] ^ block[0]
  AESENC(.Loop_enc1_7, %xmm2, %rcx, %xmm0, %xmm1, %eax)
  xorps  %xmm10,%xmm2 // add tweak after AESENC
  movdqa  %xmm11,%xmm10 // move tweak[1] to %xmm10 for cipher stealing

  movups  %xmm2,(%rsi)
  leaq  16(%rsi),%rsi
  jmp  .Lxts_enc_done

.align  16
.Lxts_enc_two:
  movups  (%rdi),%xmm2
  movups  16(%rdi),%xmm3
  leaq  32(%rdi),%rdi
  xorps  %xmm10,%xmm2 // tweak[0] ^ block[0]
  xorps  %xmm11,%xmm3 // tweak[1] ^ block[1]

  call  _aesni_encrypt2

  xorps  %xmm10,%xmm2 // add tweak after AESENC
  xorps  %xmm11,%xmm3
  movdqa  %xmm12,%xmm10 // move tweak[2] to %xmm10 for cipher stealing
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
  xorps  %xmm11,%xmm3
  xorps  %xmm12,%xmm4

  movdqa  %xmm13,%xmm10
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
  movups  48(%rdi),%xmm5
  leaq  64(%rdi),%rdi
  xorps  %xmm10,%xmm2
  xorps  %xmm11,%xmm3
  xorps  %xmm12,%xmm4
  xorps  %xmm13,%xmm5

  call  _aesni_encrypt4

  pxor  %xmm10,%xmm2
  pxor  %xmm11,%xmm3
  pxor  %xmm12,%xmm4
  pxor  %xmm13,%xmm5

  movdqa  %xmm14,%xmm10
  movdqu  %xmm2,(%rsi)
  movdqu  %xmm3,16(%rsi)
  movdqu  %xmm4,32(%rsi)
  movdqu  %xmm5,48(%rsi)
  leaq  64(%rsi),%rsi
  jmp  .Lxts_enc_done

.align  16
.Lxts_enc_done:
  andq  $15,%r9 // get bytes less than a block
  jz  .Lxts_enc_ret // if none return
  movq  %r9,%rdx

// After this loop,
// -16(%rsi) stores the plaintext to be encrypted
// The residual encrypted bytes are moved to (%rsi)
.Lxts_enc_steal:
  movzbl  (%rdi),%eax // byte to exchange in input
  movzbl  -16(%rsi),%ecx // byte to exchange in output
  leaq  1(%rdi),%rdi
  movb  %al,-16(%rsi)
  movb  %cl,0(%rsi)
  leaq  1(%rsi),%rsi
  subq  $1,%rdx
  jnz  .Lxts_enc_steal

  subq  %r9,%rsi // rewind %rsi
  movq  %rbp,%rcx // restore key1
  movl  %r10d,%eax // restore rounds

  movups  -16(%rsi),%xmm2
  xorps  %xmm10,%xmm2 // Adding tweak
  AESENC(.Loop_enc1_8,%xmm2,%rcx,%xmm0,%xmm1,%eax)
  xorps  %xmm10,%xmm2 // Adding tweak
  movups  %xmm2,-16(%rsi)

.Lxts_enc_ret:
  xorps  %xmm0,%xmm0  // clear register bank
  pxor  %xmm1,%xmm1
  pxor  %xmm2,%xmm2
  pxor  %xmm3,%xmm3
  pxor  %xmm4,%xmm4
  pxor  %xmm5,%xmm5
  pxor  %xmm6,%xmm6
  pxor  %xmm7,%xmm7
  pxor  %xmm8,%xmm8
  pxor  %xmm9,%xmm9
  pxor  %xmm10,%xmm10
  pxor  %xmm11,%xmm11
  pxor  %xmm12,%xmm12
  pxor  %xmm13,%xmm13
  pxor  %xmm14,%xmm14
  pxor  %xmm15,%xmm15
  movaps  %xmm0,0(%rsp)  // clear stack
  movaps  %xmm0,16(%rsp)
  movaps  %xmm0,32(%rsp)
  movaps  %xmm0,48(%rsp)
  movaps  %xmm0,64(%rsp)
  movaps  %xmm0,80(%rsp)
  movaps  %xmm0,96(%rsp)
  movq  -8(%r11),%rbp
//.cfi_restore  %rbp
  leaq  (%r11),%rsp
//.cfi_def_cfa_register  %rsp
.Lxts_enc_epilogue:
  ret
.cfi_endproc
.size  aes_hw_xts_encrypt_clean,.-aes_hw_xts_encrypt_clean

// Copied from AWS-LC:
// _aesni_[en|de]cryptN are private interfaces, N denotes interleave
// factor. Why 3x subroutine were originally used in loops? Even though
// aes[enc|dec] latency was originally 6, it could be scheduled only
// every *2nd* cycle. Thus 3x interleave was the one providing optimal
// utilization, i.e. when subroutine's throughput is virtually same as
// of non-interleaved subroutine [for number of input blocks up to 3].
// This is why it originally made no sense to implement 2x subroutine.
// But times change and it became appropriate to spend extra 192 bytes
// on 2x subroutine on Atom Silvermont account. For processors that
// can schedule aes[enc|dec] every cycle optimal interleave factor
// equals to corresponding instructions latency. 8x is optimal for
// * Bridge and "super-optimal" for other Intel CPUs...
.type  _aesni_encrypt2,@function
.align  16
_aesni_encrypt2:
.cfi_startproc
  shll  $4,%eax // rounds * 16
  movups  (%rcx),%xmm0 // key1[0]
  movups  16(%rcx),%xmm1 // key1[1]
  xorps  %xmm0,%xmm2
  xorps  %xmm0,%xmm3
  movups  32(%rcx),%xmm0 // key1[2]
  leaq  32(%rcx,%rax,1),%rcx // rcx = end of key schedule
  negq  %rax // -13*16
  addq  $16,%rax // -12*16

.Lenc_loop2:
  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  movups  (%rcx,%rax,1),%xmm1 // key1[3]
  addq  $32,%rax
  aesenc %xmm0,%xmm2
  aesenc %xmm0,%xmm3
  movups  -16(%rcx,%rax,1),%xmm0 // key1[4]
  jnz  .Lenc_loop2

  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenclast %xmm0, %xmm2
  aesenclast %xmm0, %xmm3
  ret
.cfi_endproc
.size  _aesni_encrypt2,.-_aesni_encrypt2

.type  _aesni_encrypt3,@function
.align  16
_aesni_encrypt3:
.cfi_startproc
  shll  $4,%eax
  movups  (%rcx),%xmm0
  movups  16(%rcx),%xmm1
  xorps  %xmm0,%xmm2
  xorps  %xmm0,%xmm3
  xorps  %xmm0,%xmm4
  movups  32(%rcx),%xmm0  // key1[2]
  leaq  32(%rcx,%rax,1),%rcx
  negq  %rax
  addq  $16,%rax

.Lenc_loop3:
  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  movups  (%rcx,%rax,1),%xmm1
  addq  $32,%rax
  aesenc %xmm0,%xmm2
  aesenc %xmm0,%xmm3
  aesenc %xmm0,%xmm4
  movups  -16(%rcx,%rax,1),%xmm0
  jnz  .Lenc_loop3

  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenclast %xmm0,%xmm2
  aesenclast %xmm0,%xmm3
  aesenclast %xmm0,%xmm4
  ret
.cfi_endproc
.size  _aesni_encrypt3,.-_aesni_encrypt3

// Taken from AWS-LC:
// 4x interleave is implemented to improve small block performance,
// most notably [and naturally] 4 block by ~30%. One can argue that one
// should have implemented 5x as well, but improvement would be <20%,
// so it's not worth it...
.type  _aesni_encrypt4,@function
.align  16
_aesni_encrypt4:
.cfi_startproc
  shll  $4,%eax
  movups  (%rcx),%xmm0
  movups  16(%rcx),%xmm1
  xorps  %xmm0,%xmm2
  xorps  %xmm0,%xmm3
  xorps  %xmm0,%xmm4
  xorps  %xmm0,%xmm5
  movups  32(%rcx),%xmm0
  leaq  32(%rcx,%rax,1),%rcx
  negq  %rax
  .byte  0x0f,0x1f,0x00 // probably for aligning .Lenc_loop4
  addq  $16,%rax

.Lenc_loop4:
  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenc %xmm1,%xmm5
  movups  (%rcx,%rax,1),%xmm1
  addq  $32,%rax
  aesenc %xmm0,%xmm2
  aesenc %xmm0,%xmm3
  aesenc %xmm0,%xmm4
  aesenc %xmm0,%xmm5
  movups  -16(%rcx,%rax,1),%xmm0
  jnz  .Lenc_loop4

  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenc %xmm1,%xmm5
  aesenclast %xmm0,%xmm2
  aesenclast %xmm0,%xmm3
  aesenclast %xmm0,%xmm4
  aesenclast %xmm0,%xmm5
  ret
.cfi_endproc
.size  _aesni_encrypt4,.-_aesni_encrypt4

.type  _aesni_encrypt6,@function
.align  16
_aesni_encrypt6:
.cfi_startproc
  shll  $4,%eax  // rounds * 16
  movups  (%rcx),%xmm0  // key1[0]
  movups  16(%rcx),%xmm1  // key1[1]
  leaq  32(%rcx,%rax,1),%rcx // rcx = rcx + rax + 32 -> end of keyschedule
  negq  %rax // -13 * 16

  xorps  %xmm0,%xmm2
  pxor  %xmm0,%xmm3
  pxor  %xmm0,%xmm4
  pxor  %xmm0,%xmm5
  pxor  %xmm0,%xmm6
  pxor  %xmm0,%xmm7

  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4

  movups  (%rcx,%rax,1),%xmm0 // key1[2]
  addq  $16,%rax // -12*16

  jmp  .Lenc_loop6_enter
.align  16
.Lenc_loop6:
  aesenc %xmm1,%xmm2
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
.Lenc_loop6_enter:
  aesenc %xmm1,%xmm5
  aesenc %xmm1,%xmm6
  aesenc %xmm1,%xmm7
  movups  (%rcx,%rax,1),%xmm1 // key1[3], key1[5], key1[7], key1[9], key1[11], key1[13]
  addq  $32,%rax  // -10 * 16
  aesenc %xmm0,%xmm2
  aesenc %xmm0,%xmm3
  aesenc %xmm0,%xmm4
  aesenc %xmm0,%xmm5
  aesenc %xmm0,%xmm6
  aesenc %xmm0,%xmm7
  movups  -16(%rcx,%rax,1),%xmm0 // key1[4]...key1[12]
  jnz  .Lenc_loop6

  aesenc %xmm1,%xmm2 // key1[13]
  aesenc %xmm1,%xmm3
  aesenc %xmm1,%xmm4
  aesenc %xmm1,%xmm5
  aesenc %xmm1,%xmm6
  aesenc %xmm1,%xmm7
  aesenclast %xmm0,%xmm2 // key1[14]
  aesenclast %xmm0,%xmm3
  aesenclast %xmm0,%xmm4
  aesenclast %xmm0,%xmm5
  aesenclast %xmm0,%xmm6
  aesenclast %xmm0,%xmm7
  ret
.cfi_endproc
.size  _aesni_encrypt6,.-_aesni_encrypt6

// TODO:
.align 16
.Lxts_magic:
    .long  0x87,0,1,0

.text
