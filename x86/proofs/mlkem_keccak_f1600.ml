(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

 needs "x86/proofs/base.ml";;

(******************************************************************************
  Proving a mlkem_keccak_f1600 property about program 'mlkem_keccak_f1600.S'
******************************************************************************)

(* The following program
 
mlkem/mlkem_keccak_f1600.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <mlkem_keccak_f1600>:
   0:   53                      push   rbx
   1:   55                      push   rbp
   2:   41 54                   push   r12
   4:   41 55                   push   r13
   6:   41 56                   push   r14
   8:   41 57                   push   r15

   a:   48 8d 7f 64             lea    rdi,[rdi+0x64]
   e:   48 81 ec c8 00 00 00    sub    rsp,0xc8
  15:   48 f7 57 a4             not    QWORD PTR [rdi-0x5c]
  19:   48 f7 57 ac             not    QWORD PTR [rdi-0x54]
  1d:   48 f7 57 dc             not    QWORD PTR [rdi-0x24]
  21:   48 f7 57 fc             not    QWORD PTR [rdi-0x4]
  25:   48 f7 57 24             not    QWORD PTR [rdi+0x24]
  29:   48 f7 57 3c             not    QWORD PTR [rdi+0x3c]
  2d:   4c 8d 3d 00 00 00 00    lea    r15,[rip+0x0]        # 34 <mlkem_keccak_f1600+0x34>
  34:   48 8d 74 24 64          lea    rsi,[rsp+0x64]
  39:   48 8b 47 3c             mov    rax,QWORD PTR [rdi+0x3c]
  3d:   48 8b 5f 44             mov    rbx,QWORD PTR [rdi+0x44]
  41:   48 8b 4f 4c             mov    rcx,QWORD PTR [rdi+0x4c]
  45:   48 8b 57 54             mov    rdx,QWORD PTR [rdi+0x54]
  49:   48 8b 6f 5c             mov    rbp,QWORD PTR [rdi+0x5c]
  4d:   4c 8b 47 9c             mov    r8,QWORD PTR [rdi-0x64]
  51:   4c 8b 4f cc             mov    r9,QWORD PTR [rdi-0x34]
  55:   4c 8b 57 fc             mov    r10,QWORD PTR [rdi-0x4]
  59:   4c 8b 5f 2c             mov    r11,QWORD PTR [rdi+0x2c]
  5d:   48 33 4f ac             xor    rcx,QWORD PTR [rdi-0x54]
  61:   48 33 57 b4             xor    rdx,QWORD PTR [rdi-0x4c]
  65:   4c 31 c0                xor    rax,r8
  68:   48 33 5f a4             xor    rbx,QWORD PTR [rdi-0x5c]
  6c:   49 89 ec                mov    r12,rbp
  6f:   48 33 6f bc             xor    rbp,QWORD PTR [rdi-0x44]
  73:   4c 31 d1                xor    rcx,r10
  76:   48 33 47 ec             xor    rax,QWORD PTR [rdi-0x14]
  7a:   48 33 57 dc             xor    rdx,QWORD PTR [rdi-0x24]
  7e:   4c 31 cb                xor    rbx,r9
  81:   48 33 6f e4             xor    rbp,QWORD PTR [rdi-0x1c]
  85:   48 33 4f 24             xor    rcx,QWORD PTR [rdi+0x24]
  89:   48 33 47 14             xor    rax,QWORD PTR [rdi+0x14]
  8d:   48 33 57 04             xor    rdx,QWORD PTR [rdi+0x4]
  91:   48 33 5f f4             xor    rbx,QWORD PTR [rdi-0xc]
  95:   48 33 6f 0c             xor    rbp,QWORD PTR [rdi+0xc]
  99:   49 89 cd                mov    r13,rcx
  9c:   48 d1 c1                rol    rcx,1
  9f:   48 31 c1                xor    rcx,rax
  a2:   4c 31 da                xor    rdx,r11
  a5:   48 d1 c0                rol    rax,1
  a8:   48 31 d0                xor    rax,rdx
  ab:   48 33 5f 1c             xor    rbx,QWORD PTR [rdi+0x1c]
  af:   48 d1 c2                rol    rdx,1
  b2:   48 31 da                xor    rdx,rbx
  b5:   48 33 6f 34             xor    rbp,QWORD PTR [rdi+0x34]
  b9:   48 d1 c3                rol    rbx,1
  bc:   48 31 eb                xor    rbx,rbp
  bf:   48 d1 c5                rol    rbp,1
  c2:   4c 31 ed                xor    rbp,r13
  c5:   49 31 c9                xor    r9,rcx
  c8:   49 31 d2                xor    r10,rdx
  cb:   49 c1 c1 2c             rol    r9,0x2c
  cf:   49 31 eb                xor    r11,rbp
  d2:   49 31 c4                xor    r12,rax
  d5:   49 c1 c2 2b             rol    r10,0x2b
  d9:   49 31 d8                xor    r8,rbx
  dc:   4d 89 cd                mov    r13,r9
  df:   49 c1 c3 15             rol    r11,0x15
  e3:   4d 09 d1                or     r9,r10
  e6:   4d 31 c1                xor    r9,r8
  e9:   49 c1 c4 0e             rol    r12,0xe
  ed:   4d 33 0f                xor    r9,QWORD PTR [r15]
  f0:   4d 8d 7f 08             lea    r15,[r15+0x8]
  f4:   4d 89 e6                mov    r14,r12
  f7:   4d 21 dc                and    r12,r11
  fa:   4c 89 4e 9c             mov    QWORD PTR [rsi-0x64],r9
  fe:   4d 31 d4                xor    r12,r10
 101:   49 f7 d2                not    r10
 104:   4c 89 66 ac             mov    QWORD PTR [rsi-0x54],r12
 108:   4d 09 da                or     r10,r11
 10b:   4c 8b 67 4c             mov    r12,QWORD PTR [rdi+0x4c]
 10f:   4d 31 ea                xor    r10,r13
 112:   4c 89 56 a4             mov    QWORD PTR [rsi-0x5c],r10
 116:   4d 21 c5                and    r13,r8
 119:   4c 8b 4f e4             mov    r9,QWORD PTR [rdi-0x1c]
 11d:   4d 31 f5                xor    r13,r14
 120:   4c 8b 57 ec             mov    r10,QWORD PTR [rdi-0x14]
 124:   4c 89 6e bc             mov    QWORD PTR [rsi-0x44],r13
 128:   4d 09 c6                or     r14,r8
 12b:   4c 8b 47 b4             mov    r8,QWORD PTR [rdi-0x4c]
 12f:   4d 31 de                xor    r14,r11
 132:   4c 8b 5f 1c             mov    r11,QWORD PTR [rdi+0x1c]
 136:   4c 89 76 b4             mov    QWORD PTR [rsi-0x4c],r14
 13a:   49 31 e8                xor    r8,rbp
 13d:   49 31 d4                xor    r12,rdx
 140:   49 c1 c0 1c             rol    r8,0x1c
 144:   49 31 cb                xor    r11,rcx
 147:   49 31 c1                xor    r9,rax
 14a:   49 c1 c4 3d             rol    r12,0x3d
 14e:   49 c1 c3 2d             rol    r11,0x2d
 152:   49 31 da                xor    r10,rbx
 155:   49 c1 c1 14             rol    r9,0x14
 159:   4d 89 c5                mov    r13,r8
 15c:   4d 09 e0                or     r8,r12
 15f:   49 c1 c2 03             rol    r10,0x3
 163:   4d 31 d8                xor    r8,r11
 166:   4c 89 46 dc             mov    QWORD PTR [rsi-0x24],r8
 16a:   4d 89 ce                mov    r14,r9
 16d:   4d 21 e9                and    r9,r13
 170:   4c 8b 47 a4             mov    r8,QWORD PTR [rdi-0x5c]
 174:   4d 31 e1                xor    r9,r12
 177:   49 f7 d4                not    r12
 17a:   4c 89 4e e4             mov    QWORD PTR [rsi-0x1c],r9
 17e:   4d 09 dc                or     r12,r11
 181:   4c 8b 4f d4             mov    r9,QWORD PTR [rdi-0x2c]
 185:   4d 31 d4                xor    r12,r10
 188:   4c 89 66 d4             mov    QWORD PTR [rsi-0x2c],r12
 18c:   4d 21 d3                and    r11,r10
 18f:   4c 8b 67 3c             mov    r12,QWORD PTR [rdi+0x3c]
 193:   4d 31 f3                xor    r11,r14
 196:   4c 89 5e cc             mov    QWORD PTR [rsi-0x34],r11
 19a:   4d 09 d6                or     r14,r10
 19d:   4c 8b 57 04             mov    r10,QWORD PTR [rdi+0x4]
 1a1:   4d 31 ee                xor    r14,r13
 1a4:   4c 8b 5f 34             mov    r11,QWORD PTR [rdi+0x34]
 1a8:   4c 89 76 c4             mov    QWORD PTR [rsi-0x3c],r14
 1ac:   49 31 ea                xor    r10,rbp
 1af:   49 31 c3                xor    r11,rax
 1b2:   49 c1 c2 19             rol    r10,0x19
 1b6:   49 31 d1                xor    r9,rdx
 1b9:   49 c1 c3 08             rol    r11,0x8
 1bd:   49 31 dc                xor    r12,rbx
 1c0:   49 c1 c1 06             rol    r9,0x6
 1c4:   49 31 c8                xor    r8,rcx
 1c7:   49 c1 c4 12             rol    r12,0x12
 1cb:   4d 89 d5                mov    r13,r10
 1ce:   4d 21 da                and    r10,r11
 1d1:   49 d1 c0                rol    r8,1
 1d4:   49 f7 d3                not    r11
 1d7:   4d 31 ca                xor    r10,r9
 1da:   4c 89 56 f4             mov    QWORD PTR [rsi-0xc],r10
 1de:   4d 89 e6                mov    r14,r12
 1e1:   4d 21 dc                and    r12,r11
 1e4:   4c 8b 57 f4             mov    r10,QWORD PTR [rdi-0xc]
 1e8:   4d 31 ec                xor    r12,r13
 1eb:   4c 89 66 fc             mov    QWORD PTR [rsi-0x4],r12
 1ef:   4d 09 cd                or     r13,r9
 1f2:   4c 8b 67 54             mov    r12,QWORD PTR [rdi+0x54]
 1f6:   4d 31 c5                xor    r13,r8
 1f9:   4c 89 6e ec             mov    QWORD PTR [rsi-0x14],r13
 1fd:   4d 21 c1                and    r9,r8
 200:   4d 31 f1                xor    r9,r14
 203:   4c 89 4e 0c             mov    QWORD PTR [rsi+0xc],r9
 207:   4d 09 c6                or     r14,r8
 20a:   4c 8b 4f c4             mov    r9,QWORD PTR [rdi-0x3c]
 20e:   4d 31 de                xor    r14,r11
 211:   4c 8b 5f 24             mov    r11,QWORD PTR [rdi+0x24]
 215:   4c 89 76 04             mov    QWORD PTR [rsi+0x4],r14
 219:   4c 8b 47 bc             mov    r8,QWORD PTR [rdi-0x44]
 21d:   49 31 ca                xor    r10,rcx
 220:   49 31 d3                xor    r11,rdx
 223:   49 c1 c2 0a             rol    r10,0xa
 227:   49 31 d9                xor    r9,rbx
 22a:   49 c1 c3 0f             rol    r11,0xf
 22e:   49 31 ec                xor    r12,rbp
 231:   49 c1 c1 24             rol    r9,0x24
 235:   49 31 c0                xor    r8,rax
 238:   49 c1 c4 38             rol    r12,0x38
 23c:   4d 89 d5                mov    r13,r10
 23f:   4d 09 da                or     r10,r11
 242:   49 c1 c0 1b             rol    r8,0x1b
 246:   49 f7 d3                not    r11
 249:   4d 31 ca                xor    r10,r9
 24c:   4c 89 56 1c             mov    QWORD PTR [rsi+0x1c],r10
 250:   4d 89 e6                mov    r14,r12
 253:   4d 09 dc                or     r12,r11
 256:   4d 31 ec                xor    r12,r13
 259:   4c 89 66 24             mov    QWORD PTR [rsi+0x24],r12
 25d:   4d 21 cd                and    r13,r9
 260:   4d 31 c5                xor    r13,r8
 263:   4c 89 6e 14             mov    QWORD PTR [rsi+0x14],r13
 267:   4d 09 c1                or     r9,r8
 26a:   4d 31 f1                xor    r9,r14
 26d:   4c 89 4e 34             mov    QWORD PTR [rsi+0x34],r9
 271:   4d 21 f0                and    r8,r14
 274:   4d 31 d8                xor    r8,r11
 277:   4c 89 46 2c             mov    QWORD PTR [rsi+0x2c],r8
 27b:   48 33 57 ac             xor    rdx,QWORD PTR [rdi-0x54]
 27f:   48 33 6f dc             xor    rbp,QWORD PTR [rdi-0x24]
 283:   48 c1 c2 3e             rol    rdx,0x3e
 287:   48 33 4f 44             xor    rcx,QWORD PTR [rdi+0x44]
 28b:   48 c1 c5 37             rol    rbp,0x37
 28f:   48 33 47 0c             xor    rax,QWORD PTR [rdi+0xc]
 293:   48 c1 c1 02             rol    rcx,0x2
 297:   48 33 5f 14             xor    rbx,QWORD PTR [rdi+0x14]
 29b:   48 87 f7                xchg   rdi,rsi
 29e:   48 c1 c0 27             rol    rax,0x27
 2a2:   48 c1 c3 29             rol    rbx,0x29
 2a6:   49 89 d5                mov    r13,rdx
 2a9:   48 21 ea                and    rdx,rbp
 2ac:   48 f7 d5                not    rbp
 2af:   48 31 ca                xor    rdx,rcx
 2b2:   48 89 57 5c             mov    QWORD PTR [rdi+0x5c],rdx
 2b6:   49 89 c6                mov    r14,rax
 2b9:   48 21 e8                and    rax,rbp
 2bc:   4c 31 e8                xor    rax,r13
 2bf:   48 89 47 3c             mov    QWORD PTR [rdi+0x3c],rax
 2c3:   49 09 cd                or     r13,rcx
 2c6:   49 31 dd                xor    r13,rbx
 2c9:   4c 89 6f 54             mov    QWORD PTR [rdi+0x54],r13
 2cd:   48 21 d9                and    rcx,rbx
 2d0:   4c 31 f1                xor    rcx,r14
 2d3:   48 89 4f 4c             mov    QWORD PTR [rdi+0x4c],rcx
 2d7:   4c 09 f3                or     rbx,r14
 2da:   48 31 eb                xor    rbx,rbp
 2dd:   48 89 5f 44             mov    QWORD PTR [rdi+0x44],rbx
 2e1:   48 89 d5                mov    rbp,rdx
 2e4:   4c 89 ea                mov    rdx,r13
 2e7:   49 f7 c7 ff 00 00 00    test   r15,0xff
 2ee:   0f 85 59 fd ff ff       jne    4d <mlkem_keccak_f1600+0x4d>
 2f4:   4d 8d bf 40 ff ff ff    lea    r15,[r15-0xc0]
 2fb:   48 f7 57 a4             not    QWORD PTR [rdi-0x5c]
 2ff:   48 f7 57 ac             not    QWORD PTR [rdi-0x54]
 303:   48 f7 57 dc             not    QWORD PTR [rdi-0x24]
 307:   48 f7 57 fc             not    QWORD PTR [rdi-0x4]
 30b:   48 f7 57 24             not    QWORD PTR [rdi+0x24]
 30f:   48 f7 57 3c             not    QWORD PTR [rdi+0x3c]
 313:   48 81 c4 c8 00 00 00    add    rsp,0xc8
 31a:   48 8d 7f 9c             lea    rdi,[rdi-0x64]

 31e:   41 5f                   pop    r15
 320:   41 5e                   pop    r14
 322:   41 5d                   pop    r13
 324:   41 5c                   pop    r12
 326:   5d                      pop    rbp
 327:   5b                      pop    rbx
 328:   f3 c3                   repz ret

  ... performs KeccakF1600 cryptography algorithm along with saving 
  the callee-saved registers on the stack.
*)

(*
word 0x53; 
word 0x55; 
word 0x41; word 0x54; 
word 0x41; word 0x55; 
word 0x41; word 0x56; 
word 0x41; word 0x57; 
word 0x48; word 0x8d; word 0x7f; word 0x64; 
word 0x48; word 0x81; word 0xec; word 0xc8; word 0x00; word 0x00; word 0x00; 
word 0x48; word 0xf7; word 0x57; word 0xa4; 
word 0x48; word 0xf7; word 0x57; word 0xac; 
word 0x48; word 0xf7; word 0x57; word 0xdc; 
word 0x48; word 0xf7; word 0x57; word 0xfc; 
word 0x48; word 0xf7; word 0x57; word 0x24; 
word 0x48; word 0xf7; word 0x57; word 0x3c; 
word 0x4c; word 0x8d; word 0x3d; word 0x00; word 0x00; word 0x00; word 0x00; word 0x34; 
word 0x48; word 0x8d; word 0x74; word 0x24; word 0x64; 
word 0x48; word 0x8b; word 0x47; word 0x3c; 
word 0x48; word 0x8b; word 0x5f; word 0x44; 
word 0x48; word 0x8b; word 0x4f; word 0x4c; 
word 0x48; word 0x8b; word 0x57; word 0x54; 
word 0x48; word 0x8b; word 0x6f; word 0x5c; 
word 0x4c; word 0x8b; word 0x47; word 0x9c; 
word 0x4c; word 0x8b; word 0x4f; word 0xcc; 
word 0x4c; word 0x8b; word 0x57; word 0xfc; 
word 0x4c; word 0x8b; word 0x5f; word 0x2c; 
word 0x48; word 0x33; word 0x4f; word 0xac; 
word 0x48; word 0x33; word 0x57; word 0xb4; 
word 0x4c; word 0x31; word 0xc0; 
word 0x48; word 0x33; word 0x5f; word 0xa4; 
word 0x49; word 0x89; word 0xec; 
word 0x48; word 0x33; word 0x6f; word 0xbc; 
word 0x4c; word 0x31; word 0xd1; 
word 0x48; word 0x33; word 0x47; word 0xec; 
word 0x48; word 0x33; word 0x57; word 0xdc; 
word 0x4c; word 0x31; word 0xcb; 
word 0x48; word 0x33; word 0x6f; word 0xe4; 
word 0x48; word 0x33; word 0x4f; word 0x24; 
word 0x48; word 0x33; word 0x47; word 0x14; 
word 0x48; word 0x33; word 0x57; word 0x04; 
word 0x48; word 0x33; word 0x5f; word 0xf4; 
word 0x48; word 0x33; word 0x6f; word 0x0c; 
word 0x49; word 0x89; word 0xcd; 
word 0x48; word 0xd1; word 0xc1; 
word 0x48; word 0x31; word 0xc1; 
word 0x4c; word 0x31; word 0xda; 
word 0x48; word 0xd1; word 0xc0; 
word 0x48; word 0x31; word 0xd0; 
word 0x48; word 0x33; word 0x5f; word 0x1c; 
word 0x48; word 0xd1; word 0xc2; 
word 0x48; word 0x31; word 0xda; 
word 0x48; word 0x33; word 0x6f; word 0x34; 
word 0x48; word 0xd1; word 0xc3; 
word 0x48; word 0x31; word 0xeb; 
word 0x48; word 0xd1; word 0xc5; 
word 0x4c; word 0x31; word 0xed; 
word 0x49; word 0x31; word 0xc9; 
word 0x49; word 0x31; word 0xd2; 
word 0x49; word 0xc1; word 0xc1; word 0x2c; 
word 0x49; word 0x31; word 0xeb; 
word 0x49; word 0x31; word 0xc4; 
word 0x49; word 0xc1; word 0xc2; word 0x2b; 
word 0x49; word 0x31; word 0xd8; 
word 0x4d; word 0x89; word 0xcd; 
word 0x49; word 0xc1; word 0xc3; word 0x15; 
word 0x4d; word 0x09; word 0xd1; 
word 0x4d; word 0x31; word 0xc1; 
word 0x49; word 0xc1; word 0xc4; word 0x0e; 
word 0x4d; word 0x33; word 0x0f; 
word 0x4d; word 0x8d; word 0x7f; word 0x08; 
word 0x4d; word 0x89; word 0xe6; 
word 0x4d; word 0x21; word 0xdc; 
word 0x4c; word 0x89; word 0x4e; word 0x9c; 
word 0x4d; word 0x31; word 0xd4; 
word 0x49; word 0xf7; word 0xd2; 
word 0x4c; word 0x89; word 0x66; word 0xac; 
word 0x4d; word 0x09; word 0xda; 
word 0x4c; word 0x8b; word 0x67; word 0x4c; 
word 0x4d; word 0x31; word 0xea; 
word 0x4c; word 0x89; word 0x56; word 0xa4; 
word 0x4d; word 0x21; word 0xc5; 
word 0x4c; word 0x8b; word 0x4f; word 0xe4; 
word 0x4d; word 0x31; word 0xf5; 
word 0x4c; word 0x8b; word 0x57; word 0xec; 
word 0x4c; word 0x89; word 0x6e; word 0xbc; 
word 0x4d; word 0x09; word 0xc6; 
word 0x4c; word 0x8b; word 0x47; word 0xb4; 
word 0x4d; word 0x31; word 0xde; 
word 0x4c; word 0x8b; word 0x5f; word 0x1c; 
word 0x4c; word 0x89; word 0x76; word 0xb4; 
word 0x49; word 0x31; word 0xe8; 
word 0x49; word 0x31; word 0xd4; 
word 0x49; word 0xc1; word 0xc0; word 0x1c; 
word 0x49; word 0x31; word 0xcb; 
word 0x49; word 0x31; word 0xc1; 
word 0x49; word 0xc1; word 0xc4; word 0x3d; 
word 0x49; word 0xc1; word 0xc3; word 0x2d; 
word 0x49; word 0x31; word 0xda; 
word 0x49; word 0xc1; word 0xc1; word 0x14; 
word 0x4d; word 0x89; word 0xc5; 
word 0x4d; word 0x09; word 0xe0; 
word 0x49; word 0xc1; word 0xc2; word 0x03; 
word 0x4d; word 0x31; word 0xd8; 
word 0x4c; word 0x89; word 0x46; word 0xdc; 
word 0x4d; word 0x89; word 0xce; 
word 0x4d; word 0x21; word 0xe9; 
word 0x4c; word 0x8b; word 0x47; word 0xa4; 
word 0x4d; word 0x31; word 0xe1; 
word 0x49; word 0xf7; word 0xd4; 
word 0x4c; word 0x89; word 0x4e; word 0xe4; 
word 0x4d; word 0x09; word 0xdc; 
word 0x4c; word 0x8b; word 0x4f; word 0xd4; 
word 0x4d; word 0x31; word 0xd4; 
word 0x4c; word 0x89; word 0x66; word 0xd4; 
word 0x4d; word 0x21; word 0xd3; 
word 0x4c; word 0x8b; word 0x67; word 0x3c; 
word 0x4d; word 0x31; word 0xf3; 
word 0x4c; word 0x89; word 0x5e; word 0xcc; 
word 0x4d; word 0x09; word 0xd6; 
word 0x4c; word 0x8b; word 0x57; word 0x04; 
word 0x4d; word 0x31; word 0xee; 
word 0x4c; word 0x8b; word 0x5f; word 0x34; 
word 0x4c; word 0x89; word 0x76; word 0xc4; 
word 0x49; word 0x31; word 0xea; 
word 0x49; word 0x31; word 0xc3; 
word 0x49; word 0xc1; word 0xc2; word 0x19; 
word 0x49; word 0x31; word 0xd1; 
word 0x49; word 0xc1; word 0xc3; word 0x08; 
word 0x49; word 0x31; word 0xdc; 
word 0x49; word 0xc1; word 0xc1; word 0x06; 
word 0x49; word 0x31; word 0xc8; 
word 0x49; word 0xc1; word 0xc4; word 0x12; 
word 0x4d; word 0x89; word 0xd5; 
word 0x4d; word 0x21; word 0xda; 
word 0x49; word 0xd1; word 0xc0; 
word 0x49; word 0xf7; word 0xd3; 
word 0x4d; word 0x31; word 0xca; 
word 0x4c; word 0x89; word 0x56; word 0xf4; 
word 0x4d; word 0x89; word 0xe6; 
word 0x4d; word 0x21; word 0xdc; 
word 0x4c; word 0x8b; word 0x57; word 0xf4; 
word 0x4d; word 0x31; word 0xec; 
word 0x4c; word 0x89; word 0x66; word 0xfc; 
word 0x4d; word 0x09; word 0xcd; 
word 0x4c; word 0x8b; word 0x67; word 0x54; 
word 0x4d; word 0x31; word 0xc5; 
word 0x4c; word 0x89; word 0x6e; word 0xec; 
word 0x4d; word 0x21; word 0xc1; 
word 0x4d; word 0x31; word 0xf1; 
word 0x4c; word 0x89; word 0x4e; word 0x0c; 
word 0x4d; word 0x09; word 0xc6; 
word 0x4c; word 0x8b; word 0x4f; word 0xc4; 
word 0x4d; word 0x31; word 0xde; 
word 0x4c; word 0x8b; word 0x5f; word 0x24; 
word 0x4c; word 0x89; word 0x76; word 0x04; 
word 0x4c; word 0x8b; word 0x47; word 0xbc; 
word 0x49; word 0x31; word 0xca; 
word 0x49; word 0x31; word 0xd3; 
word 0x49; word 0xc1; word 0xc2; word 0x0a; 
word 0x49; word 0x31; word 0xd9; 
word 0x49; word 0xc1; word 0xc3; word 0x0f; 
word 0x49; word 0x31; word 0xec; 
word 0x49; word 0xc1; word 0xc1; word 0x24; 
word 0x49; word 0x31; word 0xc0; 
word 0x49; word 0xc1; word 0xc4; word 0x38; 
word 0x4d; word 0x89; word 0xd5; 
word 0x4d; word 0x09; word 0xda; 
word 0x49; word 0xc1; word 0xc0; word 0x1b; 
word 0x49; word 0xf7; word 0xd3; 
word 0x4d; word 0x31; word 0xca; 
word 0x4c; word 0x89; word 0x56; word 0x1c; 
word 0x4d; word 0x89; word 0xe6; 
word 0x4d; word 0x09; word 0xdc; 
word 0x4d; word 0x31; word 0xec; 
word 0x4c; word 0x89; word 0x66; word 0x24; 
word 0x4d; word 0x21; word 0xcd; 
word 0x4d; word 0x31; word 0xc5; 
word 0x4c; word 0x89; word 0x6e; word 0x14; 
word 0x4d; word 0x09; word 0xc1; 
word 0x4d; word 0x31; word 0xf1; 
word 0x4c; word 0x89; word 0x4e; word 0x34; 
word 0x4d; word 0x21; word 0xf0; 
word 0x4d; word 0x31; word 0xd8; 
word 0x4c; word 0x89; word 0x46; word 0x2c; 
word 0x48; word 0x33; word 0x57; word 0xac; 
word 0x48; word 0x33; word 0x6f; word 0xdc; 
word 0x48; word 0xc1; word 0xc2; word 0x3e; 
word 0x48; word 0x33; word 0x4f; word 0x44; 
word 0x48; word 0xc1; word 0xc5; word 0x37; 
word 0x48; word 0x33; word 0x47; word 0x0c; 
word 0x48; word 0xc1; word 0xc1; word 0x02; 
word 0x48; word 0x33; word 0x5f; word 0x14; 
word 0x48; word 0x87; word 0xf7; 
word 0x48; word 0xc1; word 0xc0; word 0x27; 
word 0x48; word 0xc1; word 0xc3; word 0x29; 
word 0x49; word 0x89; word 0xd5; 
word 0x48; word 0x21; word 0xea; 
word 0x48; word 0xf7; word 0xd5; 
word 0x48; word 0x31; word 0xca; 
word 0x48; word 0x89; word 0x57; word 0x5c; 
word 0x49; word 0x89; word 0xc6; 
word 0x48; word 0x21; word 0xe8; 
word 0x4c; word 0x31; word 0xe8; 
word 0x48; word 0x89; word 0x47; word 0x3c; 
word 0x49; word 0x09; word 0xcd; 
word 0x49; word 0x31; word 0xdd; 
word 0x4c; word 0x89; word 0x6f; word 0x54; 
word 0x48; word 0x21; word 0xd9; 
word 0x4c; word 0x31; word 0xf1; 
word 0x48; word 0x89; word 0x4f; word 0x4c; 
word 0x4c; word 0x09; word 0xf3; 
word 0x48; word 0x31; word 0xeb; 
word 0x48; word 0x89; word 0x5f; word 0x44; 
word 0x48; word 0x89; word 0xd5; 
word 0x4c; word 0x89; word 0xea; 
word 0x49; word 0xf7; word 0xc7; word 0xff; word 0x00; word 0x00; word 0x00; 
word 0x0f; word 0x85; word 0x59; word 0xfd; word 0xff; word 0xff;
word 0x4d; word 0x8d; word 0xbf; word 0x40; word 0xff; word 0xff; word 0xff; 
word 0x48; word 0xf7; word 0x57; word 0xa4; 
word 0x48; word 0xf7; word 0x57; word 0xac; 
word 0x48; word 0xf7; word 0x57; word 0xdc; 
word 0x48; word 0xf7; word 0x57; word 0xfc; 
word 0x48; word 0xf7; word 0x57; word 0x24; 
word 0x48; word 0xf7; word 0x57; word 0x3c; 
word 0x48; word 0x81; word 0xc4; word 0xc8; word 0x00; word 0x00; word 0x00;
word 0x48; word 0x8d; word 0x7f; word 0x9c; 
      ***
word 0x41; word 0x5f; 
word 0x41; word 0x5e; 
word 0x41; word 0x5d; 
word 0x41; word 0x5c; 
word 0x5d; 
word 0x5b; 
word 0xf3; word 0xc3; 
*) 

(* Later, the disassembly section will be checked against the actual object file "x86/mlkem/mlkem_keccak_f1600.o"
let mlkem_keccak_f1600_mc = define_assert_from_elf "mlkem_keccak_f1600_mc" "x86/mlkem/mlkem_keccak_f1600.o"
[
    ...
];;
*)

(* Can I undefine the new_definition (or to redefine it) *)
let mlkem_keccak_f1600_mc_longer = new_definition `mlkem_keccak_f1600_mc_longer = [
    word 0x53; 
    word 0x55; 
    word 0x41; word 0x54; 
    word 0x41; word 0x55; 
    word 0x41; word 0x56; 
    word 0x41; word 0x57; 
    word 0x41; word 0x5f; 
    word 0x41; word 0x5e; 
    word 0x41; word 0x5d; 
    word 0x41; word 0x5c; 
    word 0x5d; 
    word 0x5b
]:((8)word)list`;;

let EXEC = X86_MK_EXEC_RULE mlkem_keccak_f1600_mc_longer;;

(*  nonoverlapping_modulo (2 EXP 64) (pc, 0x2) (val (word_sub stackpointer (word 8):int64),8)
*** 
  nonoverlapping_modulo (2 EXP 64) (pc, 0x14) (val (word_sub stackpointer (word 8):int64),8) /\
  nonoverlapping_modulo (2 EXP 64) (pc, 0x14) (val (word_sub (word_sub stackpointer (word 8):int64) (word 8):int64),8) /\
  nonoverlapping_modulo (2 EXP 64) (pc,0x14)  (val (word_sub (word_sub (word_sub stackpointer (word 8):int64) (word 8):int64) (word 8):int64), 8) /\
  *)
let MLKEM_KECCAK_F1600_SPEC = prove(
  `forall pc:num stackpointer:int64. 
    P[stackpointer] /\
    nonoverlapping_modulo (2 EXP 64) (pc, 0x14) (val (word_sub stackpointer (word 48):int64),48)
    ==> ensures x86
    // Precondition
    (\s. bytes_loaded s (word pc) mlkem_keccak_f1600_mc_longer /\
         read RIP s = word pc/\
         read RSP s = stackpointer)
    // Postcondition
    (\s. read RIP s = word (pc+0x14))
    (MAYCHANGE [RIP;RSP;RBX;RBP;R12;R13;R14;R15] ,, MAYCHANGE SOME_FLAGS)`,
  
  (* REWRITE_TAC[fst EXEC] loads the porgram? 
  *)
  REWRITE_TAC[fst EXEC] THEN 
  (* MAP_EVERY X_GEN_TAC [`pc:num`] 
      o MAP_EVERY atac [a] - apply the following tactic to every element in the list 
            Map tactic-producing function over a list of arguments, apply in sequence
      o X_GEN_TAC - when the goal has a form like ∀pc:num. P(pc); this tactic would change the goal to just 
            P(pc) with pc as a new assumption in the context
      From ?- !x. p[x] to ?- p[y] with specified ‘y 
      *)
  MAP_EVERY X_GEN_TAC [`pc:num`] THEN
  (* WORD_FORALL_OFFSET_TAC - offsetting the base address when "stackpointer" is still universally quantified variable 
  *)
  WORD_FORALL_OFFSET_TAC 48 THEN
  (* CONV_TAC(ONCE_DEPTH_CONV NORMALIZE_RELATIVE_ADDRESS_CONV) - normaizes the addresses 
  *)
  CONV_TAC(ONCE_DEPTH_CONV NORMALIZE_RELATIVE_ADDRESS_CONV) THEN
  (*) MAP_EVERY X_GEN_TAC [`stackpointer:int64`] - From ?- !x. p[x] to ?- p[y] with specified ‘y  
  *) 
  MAP_EVERY X_GEN_TAC [`stackpointer:int64`] THEN
  (*) MAP_EVERY X_GEN_TAC [`stackpointer:int64`] - From ?- !x. p[x] to ?- p[y] with specified ‘y  
  *) 
  REWRITE_TAC[NONOVERLAPPING_CLAUSES] THEN 
  (* STRIP_TAC - simplifies and breaks down the goals
       o For goals of form P ∧ Q, it creates two subgoals: P and Q;
       o For goals of form P ⇒ Q, it adds P to the assumptions and makes Q the new goal;
       o For goals of form ∀x. P(x), it introduces a new variable and makes P(x) the goal;
    Break down goal, ?- p /\ q to ?- p and ?- q etc. etc. 
    *)
  STRIP_TAC THEN
  ENSURES_INIT_TAC "s0" THEN

  X86_STEPS_TAC EXEC (1--1) THEN
  X86_STEPS_TAC EXEC (2--2) THEN
  X86_STEPS_TAC EXEC (3--3) THEN
  X86_STEPS_TAC EXEC (4--12) THEN
  ENSURES_FINAL_STATE_TAC THEN

  ASM_REWRITE_TAC[]
  );;
