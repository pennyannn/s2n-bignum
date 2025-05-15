(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

needs "x86/proofs/equiv.ml";;

print_coda_from_elf 0x9b0 "x86/aes-xts/aes_hw_xts_encrypt.o";;
print_coda_from_elf 0x9d0 "x86/aes-xts/aes_hw_xts_encrypt_clean.o";;

let aes_hw_xts_encrypt_mc, xts_magic =
  define_coda_literal_from_elf
  "aes_hw_xts_encrypt_mc" "xts_magic"
  "x86/aes-xts/aes_hw_xts_encrypt.o"
  [
  0xf3; 0x0f; 0x1e; 0xfa;  (* ENDBR64 *)
  0x4c; 0x8d; 0x1c; 0x24;  (* LEA (% r11) (%% (rsp,0)) *)
  0x55;                    (* PUSH (% rbp) *)
  0x48; 0x83; 0xec; 0x70;  (* SUB (% rsp) (Imm8 (word 112)) *)
  0x48; 0x83; 0xe4; 0xf0;  (* AND (% rsp) (Imm8 (word 240)) *)
  0x41; 0x0f; 0x10; 0x11;  (* MOVUPS (%_% xmm2) (Memop Word128 (%% (r9,0))) *)
  0x41; 0x8b; 0x80; 0xf0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (r8,240))) *)
  0x44; 0x8b; 0x91; 0xf0; 0x00; 0x00; 0x00;
                           (* MOV (% r10d) (Memop Doubleword (%% (rcx,240))) *)
  0x41; 0x0f; 0x10; 0x00;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (r8,0))) *)
  0x41; 0x0f; 0x10; 0x48; 0x10;
                           (* MOVUPS (%_% xmm1) (Memop Word128 (%% (r8,16))) *)
  0x4d; 0x8d; 0x40; 0x20;  (* LEA (% r8) (%% (r8,32)) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0xff; 0xc8;              (* DEC (% eax) *)
  0x41; 0x0f; 0x10; 0x08;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (r8,0))) *)
  0x4d; 0x8d; 0x40; 0x10;  (* LEA (% r8) (%% (r8,16)) *)
  0x75; 0xef;              (* JNE (Imm8 (word 239)) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd1;
                           (* AESENCLAST (%_% xmm2) (%_% xmm1) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x48; 0x89; 0xcd;        (* MOV (% rbp) (% rcx) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0x41; 0xc1; 0xe2; 0x04;  (* SHL (% r10d) (Imm8 (word 4)) *)
  0x49; 0x89; 0xd1;        (* MOV (% r9) (% rdx) *)
  0x48; 0x83; 0xe2; 0xf0;  (* AND (% rdx) (Imm8 (word 240)) *)
  0x42; 0x0f; 0x10; 0x4c; 0x11; 0x10;
                           (* MOVUPS (%_% xmm1) (Memop Word128 (%%%% (rcx,0,r10,&16))) *)
  0x66; 0x44; 0x0f; 0x6f; 0x05; 0x44; 0x09; 0x00; 0x00;
                           (* MOVDQA (%_% xmm8) (Memop Word128 (Riprel (word 2372))) *)
  0x66; 0x44; 0x0f; 0x6f; 0xfa;
                           (* MOVDQA (%_% xmm15) (%_% xmm2) *)
  0x66; 0x44; 0x0f; 0x70; 0xca; 0x5f;
                           (* PSHUFD (%_% xmm9) (%_% xmm2) (Imm8 (word 95)) *)
  0x66; 0x0f; 0xef; 0xc8;  (* PXOR (%_% xmm1) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd7;
                           (* MOVDQA (%_% xmm10) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x44; 0x0f; 0xef; 0xd0;
                           (* PXOR (%_% xmm10) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0x6f; 0xdf;
                           (* MOVDQA (%_% xmm11) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x44; 0x0f; 0xef; 0xd8;
                           (* PXOR (%_% xmm11) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0x6f; 0xe7;
                           (* MOVDQA (%_% xmm12) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x44; 0x0f; 0xef; 0xe0;
                           (* PXOR (%_% xmm12) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0x6f; 0xef;
                           (* MOVDQA (%_% xmm13) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x44; 0x0f; 0xef; 0xe8;
                           (* PXOR (%_% xmm13) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf7;
                           (* MOVDQA (%_% xmm14) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe1; 0x1f;
                           (* PSRAD (%_% xmm9) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xdb; 0xc8;
                           (* PAND (%_% xmm9) (%_% xmm8) *)
  0x66; 0x44; 0x0f; 0xef; 0xf0;
                           (* PXOR (%_% xmm14) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xf9;
                           (* PXOR (%_% xmm15) (%_% xmm9) *)
  0x0f; 0x29; 0x4c; 0x24; 0x60;
                           (* MOVAPS (Memop Word128 (%% (rsp,96))) (%_% xmm1) *)
  0x48; 0x83; 0xea; 0x60;  (* SUB (% rdx) (Imm8 (word 96)) *)
  0x0f; 0x82; 0x53; 0x03; 0x00; 0x00;
                           (* JB (Imm32 (word 851)) *)
  0xb8; 0x70; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Imm32 (word 112)) *)
  0x4a; 0x8d; 0x4c; 0x15; 0x20;
                           (* LEA (% rcx) (%%%% (rbp,0,r10,&32)) *)
  0x4c; 0x29; 0xd0;        (* SUB (% rax) (% r10) *)
  0x0f; 0x10; 0x4d; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rbp,16))) *)
  0x49; 0x89; 0xc2;        (* MOV (% r10) (% rax) *)
  0x4c; 0x8d; 0x05; 0x48; 0x08; 0x00; 0x00;
                           (* LEA (% r8) (Riprel (word 2120)) *)
  0xeb; 0x16;              (* JMP (Imm8 (word 22)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0xf3; 0x0f; 0x6f; 0x17;  (* MOVDQU (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x66; 0x44; 0x0f; 0x6f; 0xc0;
                           (* MOVDQA (%_% xmm8) (%_% xmm0) *)
  0xf3; 0x0f; 0x6f; 0x5f; 0x10;
                           (* MOVDQU (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0x66; 0x41; 0x0f; 0xef; 0xd2;
                           (* PXOR (%_% xmm2) (%_% xmm10) *)
  0xf3; 0x0f; 0x6f; 0x67; 0x20;
                           (* MOVDQU (%_% xmm4) (Memop Word128 (%% (rdi,32))) *)
  0x66; 0x41; 0x0f; 0xef; 0xdb;
                           (* PXOR (%_% xmm3) (%_% xmm11) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0xf3; 0x0f; 0x6f; 0x6f; 0x30;
                           (* MOVDQU (%_% xmm5) (Memop Word128 (%% (rdi,48))) *)
  0x66; 0x41; 0x0f; 0xef; 0xe4;
                           (* PXOR (%_% xmm4) (%_% xmm12) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0xf3; 0x0f; 0x6f; 0x77; 0x40;
                           (* MOVDQU (%_% xmm6) (Memop Word128 (%% (rdi,64))) *)
  0x66; 0x41; 0x0f; 0xef; 0xed;
                           (* PXOR (%_% xmm5) (%_% xmm13) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0xf3; 0x0f; 0x6f; 0x7f; 0x50;
                           (* MOVDQU (%_% xmm7) (Memop Word128 (%% (rdi,80))) *)
  0x66; 0x45; 0x0f; 0xef; 0xc7;
                           (* PXOR (%_% xmm8) (%_% xmm15) *)
  0x66; 0x44; 0x0f; 0x6f; 0x4c; 0x24; 0x60;
                           (* MOVDQA (%_% xmm9) (Memop Word128 (%% (rsp,96))) *)
  0x66; 0x41; 0x0f; 0xef; 0xf6;
                           (* PXOR (%_% xmm6) (%_% xmm14) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x0f; 0x10; 0x45; 0x20;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rbp,32))) *)
  0x48; 0x8d; 0x7f; 0x60;  (* LEA (% rdi) (%% (rdi,96)) *)
  0x66; 0x41; 0x0f; 0xef; 0xf8;
                           (* PXOR (%_% xmm7) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xef; 0xd1;
                           (* PXOR (%_% xmm10) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x45; 0x0f; 0xef; 0xd9;
                           (* PXOR (%_% xmm11) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x14; 0x24;
                           (* MOVDQA (Memop Word128 (%% (rsp,0))) (%_% xmm10) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x4d; 0x30;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rbp,48))) *)
  0x66; 0x45; 0x0f; 0xef; 0xe1;
                           (* PXOR (%_% xmm12) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xe9;
                           (* PXOR (%_% xmm13) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x5c; 0x24; 0x10;
                           (* MOVDQA (Memop Word128 (%% (rsp,16))) (%_% xmm11) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xf1;
                           (* PXOR (%_% xmm14) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x64; 0x24; 0x20;
                           (* MOVDQA (Memop Word128 (%% (rsp,32))) (%_% xmm12) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xc1;
                           (* PXOR (%_% xmm8) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x74; 0x24; 0x40;
                           (* MOVDQA (Memop Word128 (%% (rsp,64))) (%_% xmm14) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x0f; 0x10; 0x45; 0x40;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rbp,64))) *)
  0x66; 0x44; 0x0f; 0x7f; 0x44; 0x24; 0x50;
                           (* MOVDQA (Memop Word128 (%% (rsp,80))) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0x70; 0xcf; 0x5f;
                           (* PSHUFD (%_% xmm9) (%_% xmm15) (Imm8 (word 95)) *)
  0xeb; 0x00;              (* JMP (Imm8 (word 0)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x4c; 0x01; 0xc0;
                           (* MOVUPS (%_% xmm1) (Memop Word128 (%%%% (rcx,0,rax,-- &64))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xb0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &80))) *)
  0x75; 0xb4;              (* JNE (Imm8 (word 180)) *)
  0x66; 0x45; 0x0f; 0x6f; 0x00;
                           (* MOVDQA (%_% xmm8) (Memop Word128 (%% (r8,0))) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x44; 0x0f; 0x10; 0x55; 0x00;
                           (* MOVUPS (%_% xmm10) (Memop Word128 (%% (rbp,0))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x45; 0x0f; 0x28; 0xda;  (* MOVAPS (%_% xmm11) (%_% xmm10) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x49; 0xc0;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,18446744073709551552))) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xef; 0xd7;
                           (* PXOR (%_% xmm10) (%_% xmm15) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x45; 0x0f; 0x28; 0xe3;  (* MOVAPS (%_% xmm12) (%_% xmm11) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x0f; 0x10; 0x41; 0xd0;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,18446744073709551568))) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x45; 0x0f; 0xef; 0xdf;
                           (* PXOR (%_% xmm11) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x44; 0x0f; 0x7f; 0x6c; 0x24; 0x30;
                           (* MOVDQA (Memop Word128 (%% (rsp,48))) (%_% xmm13) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x45; 0x0f; 0x28; 0xec;  (* MOVAPS (%_% xmm13) (%_% xmm12) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x49; 0xe0;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,18446744073709551584))) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xe7;
                           (* PXOR (%_% xmm12) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x45; 0x0f; 0x28; 0xf5;  (* MOVAPS (%_% xmm14) (%_% xmm13) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x66; 0x41; 0x0f; 0x6f; 0xc1;
                           (* MOVDQA (%_% xmm0) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x45; 0x0f; 0xef; 0xef;
                           (* PXOR (%_% xmm13) (%_% xmm15) *)
  0x66; 0x0f; 0x72; 0xe0; 0x1f;
                           (* PSRAD (%_% xmm0) (Imm8 (word 31)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0xdb; 0xc0;
                           (* PAND (%_% xmm0) (%_% xmm8) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x44; 0x0f; 0xef; 0xf8;
                           (* PXOR (%_% xmm15) (%_% xmm0) *)
  0x0f; 0x10; 0x45; 0x00;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rbp,0))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x4d; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rbp,16))) *)
  0x66; 0x45; 0x0f; 0xef; 0xf7;
                           (* PXOR (%_% xmm14) (%_% xmm15) *)
  0x66; 0x0f; 0x38; 0xdd; 0x54; 0x24; 0x00;
                           (* AESENCLAST (%_% xmm2) (Memop Word128 (%% (rsp,0))) *)
  0x66; 0x41; 0x0f; 0x72; 0xe1; 0x1f;
                           (* PSRAD (%_% xmm9) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x0f; 0x38; 0xdd; 0x5c; 0x24; 0x10;
                           (* AESENCLAST (%_% xmm3) (Memop Word128 (%% (rsp,16))) *)
  0x66; 0x0f; 0x38; 0xdd; 0x64; 0x24; 0x20;
                           (* AESENCLAST (%_% xmm4) (Memop Word128 (%% (rsp,32))) *)
  0x66; 0x45; 0x0f; 0xdb; 0xc8;
                           (* PAND (%_% xmm9) (%_% xmm8) *)
  0x4c; 0x89; 0xd0;        (* MOV (% rax) (% r10) *)
  0x66; 0x0f; 0x38; 0xdd; 0x6c; 0x24; 0x30;
                           (* AESENCLAST (%_% xmm5) (Memop Word128 (%% (rsp,48))) *)
  0x66; 0x0f; 0x38; 0xdd; 0x74; 0x24; 0x40;
                           (* AESENCLAST (%_% xmm6) (Memop Word128 (%% (rsp,64))) *)
  0x66; 0x0f; 0x38; 0xdd; 0x7c; 0x24; 0x50;
                           (* AESENCLAST (%_% xmm7) (Memop Word128 (%% (rsp,80))) *)
  0x66; 0x45; 0x0f; 0xef; 0xf9;
                           (* PXOR (%_% xmm15) (%_% xmm9) *)
  0x48; 0x8d; 0x76; 0x60;  (* LEA (% rsi) (%% (rsi,96)) *)
  0x0f; 0x11; 0x56; 0xa0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551520))) (%_% xmm2) *)
  0x0f; 0x11; 0x5e; 0xb0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551536))) (%_% xmm3) *)
  0x0f; 0x11; 0x66; 0xc0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551552))) (%_% xmm4) *)
  0x0f; 0x11; 0x6e; 0xd0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551568))) (%_% xmm5) *)
  0x0f; 0x11; 0x76; 0xe0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551584))) (%_% xmm6) *)
  0x0f; 0x11; 0x7e; 0xf0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551600))) (%_% xmm7) *)
  0x48; 0x83; 0xea; 0x60;  (* SUB (% rdx) (Imm8 (word 96)) *)
  0x0f; 0x83; 0xee; 0xfc; 0xff; 0xff;
                           (* JAE (Imm32 (word 4294966510)) *)
  0xb8; 0x70; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Imm32 (word 112)) *)
  0x44; 0x29; 0xd0;        (* SUB (% eax) (% r10d) *)
  0x48; 0x89; 0xe9;        (* MOV (% rcx) (% rbp) *)
  0xc1; 0xe8; 0x04;        (* SHR (% eax) (Imm8 (word 4)) *)
  0x41; 0x89; 0xc2;        (* MOV (% r10d) (% eax) *)
  0x66; 0x44; 0x0f; 0xef; 0xd0;
                           (* PXOR (%_% xmm10) (%_% xmm0) *)
  0x48; 0x83; 0xc2; 0x60;  (* ADD (% rdx) (Imm8 (word 96)) *)
  0x0f; 0x84; 0xee; 0x01; 0x00; 0x00;
                           (* JE (Imm32 (word 494)) *)
  0x66; 0x44; 0x0f; 0xef; 0xd8;
                           (* PXOR (%_% xmm11) (%_% xmm0) *)
  0x48; 0x83; 0xfa; 0x20;  (* CMP (% rdx) (Imm8 (word 32)) *)
  0x0f; 0x82; 0x9f; 0x00; 0x00; 0x00;
                           (* JB (Imm32 (word 159)) *)
  0x66; 0x44; 0x0f; 0xef; 0xe0;
                           (* PXOR (%_% xmm12) (%_% xmm0) *)
  0x0f; 0x84; 0xe4; 0x00; 0x00; 0x00;
                           (* JE (Imm32 (word 228)) *)
  0x66; 0x44; 0x0f; 0xef; 0xe8;
                           (* PXOR (%_% xmm13) (%_% xmm0) *)
  0x48; 0x83; 0xfa; 0x40;  (* CMP (% rdx) (Imm8 (word 64)) *)
  0x0f; 0x82; 0x15; 0x01; 0x00; 0x00;
                           (* JB (Imm32 (word 277)) *)
  0x66; 0x44; 0x0f; 0xef; 0xf0;
                           (* PXOR (%_% xmm14) (%_% xmm0) *)
  0x0f; 0x84; 0x5a; 0x01; 0x00; 0x00;
                           (* JE (Imm32 (word 346)) *)
  0xf3; 0x0f; 0x6f; 0x17;  (* MOVDQU (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0xf3; 0x0f; 0x6f; 0x5f; 0x10;
                           (* MOVDQU (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0xf3; 0x0f; 0x6f; 0x67; 0x20;
                           (* MOVDQU (%_% xmm4) (Memop Word128 (%% (rdi,32))) *)
  0x66; 0x41; 0x0f; 0xef; 0xd2;
                           (* PXOR (%_% xmm2) (%_% xmm10) *)
  0xf3; 0x0f; 0x6f; 0x6f; 0x30;
                           (* MOVDQU (%_% xmm5) (Memop Word128 (%% (rdi,48))) *)
  0x66; 0x41; 0x0f; 0xef; 0xdb;
                           (* PXOR (%_% xmm3) (%_% xmm11) *)
  0xf3; 0x0f; 0x6f; 0x77; 0x40;
                           (* MOVDQU (%_% xmm6) (Memop Word128 (%% (rdi,64))) *)
  0x48; 0x8d; 0x7f; 0x50;  (* LEA (% rdi) (%% (rdi,80)) *)
  0x66; 0x41; 0x0f; 0xef; 0xe4;
                           (* PXOR (%_% xmm4) (%_% xmm12) *)
  0x66; 0x41; 0x0f; 0xef; 0xed;
                           (* PXOR (%_% xmm5) (%_% xmm13) *)
  0x66; 0x41; 0x0f; 0xef; 0xf6;
                           (* PXOR (%_% xmm6) (%_% xmm14) *)
  0x66; 0x0f; 0xef; 0xff;  (* PXOR (%_% xmm7) (%_% xmm7) *)
  0xe8; 0xac; 0x03; 0x00; 0x00;
                           (* CALL (Imm32 (word 940)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd7;
                           (* MOVDQA (%_% xmm10) (%_% xmm15) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x41; 0x0f; 0x57; 0xe4;  (* XORPS (%_% xmm4) (%_% xmm12) *)
  0xf3; 0x0f; 0x7f; 0x16;  (* MOVDQU (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0x41; 0x0f; 0x57; 0xed;  (* XORPS (%_% xmm5) (%_% xmm13) *)
  0xf3; 0x0f; 0x7f; 0x5e; 0x10;
                           (* MOVDQU (Memop Word128 (%% (rsi,16))) (%_% xmm3) *)
  0x41; 0x0f; 0x57; 0xf6;  (* XORPS (%_% xmm6) (%_% xmm14) *)
  0xf3; 0x0f; 0x7f; 0x66; 0x20;
                           (* MOVDQU (Memop Word128 (%% (rsi,32))) (%_% xmm4) *)
  0xf3; 0x0f; 0x7f; 0x6e; 0x30;
                           (* MOVDQU (Memop Word128 (%% (rsi,48))) (%_% xmm5) *)
  0xf3; 0x0f; 0x7f; 0x76; 0x40;
                           (* MOVDQU (Memop Word128 (%% (rsi,64))) (%_% xmm6) *)
  0x48; 0x8d; 0x76; 0x50;  (* LEA (% rsi) (%% (rsi,80)) *)
  0xe9; 0x42; 0x01; 0x00; 0x00;
                           (* JMP (Imm32 (word 322)) *)
  0x66; 0x90;              (* NOP *)
  0x0f; 0x10; 0x17;        (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x48; 0x8d; 0x7f; 0x10;  (* LEA (% rdi) (%% (rdi,16)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x48; 0x8d; 0x49; 0x20;  (* LEA (% rcx) (%% (rcx,32)) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0xff; 0xc8;              (* DEC (% eax) *)
  0x0f; 0x10; 0x09;        (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,0))) *)
  0x48; 0x8d; 0x49; 0x10;  (* LEA (% rcx) (%% (rcx,16)) *)
  0x75; 0xf0;              (* JNE (Imm8 (word 240)) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd1;
                           (* AESENCLAST (%_% xmm2) (%_% xmm1) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd3;
                           (* MOVDQA (%_% xmm10) (%_% xmm11) *)
  0x0f; 0x11; 0x16;        (* MOVUPS (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0x48; 0x8d; 0x76; 0x10;  (* LEA (% rsi) (%% (rsi,16)) *)
  0xe9; 0xfd; 0x00; 0x00; 0x00;
                           (* JMP (Imm32 (word 253)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x66; 0x90;              (* NOP *)
  0x0f; 0x10; 0x17;        (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x0f; 0x10; 0x5f; 0x10;  (* MOVUPS (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0x48; 0x8d; 0x7f; 0x20;  (* LEA (% rdi) (%% (rdi,32)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0xe8; 0xa8; 0x01; 0x00; 0x00;
                           (* CALL (Imm32 (word 424)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd4;
                           (* MOVDQA (%_% xmm10) (%_% xmm12) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x0f; 0x11; 0x16;        (* MOVUPS (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0x0f; 0x11; 0x5e; 0x10;  (* MOVUPS (Memop Word128 (%% (rsi,16))) (%_% xmm3) *)
  0x48; 0x8d; 0x76; 0x20;  (* LEA (% rsi) (%% (rsi,32)) *)
  0xe9; 0xbb; 0x00; 0x00; 0x00;
                           (* JMP (Imm32 (word 187)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x0f; 0x10; 0x17;        (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x0f; 0x10; 0x5f; 0x10;  (* MOVUPS (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0x0f; 0x10; 0x67; 0x20;  (* MOVUPS (%_% xmm4) (Memop Word128 (%% (rdi,32))) *)
  0x48; 0x8d; 0x7f; 0x30;  (* LEA (% rdi) (%% (rdi,48)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x41; 0x0f; 0x57; 0xe4;  (* XORPS (%_% xmm4) (%_% xmm12) *)
  0xe8; 0xc0; 0x01; 0x00; 0x00;
                           (* CALL (Imm32 (word 448)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd5;
                           (* MOVDQA (%_% xmm10) (%_% xmm13) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x41; 0x0f; 0x57; 0xe4;  (* XORPS (%_% xmm4) (%_% xmm12) *)
  0x0f; 0x11; 0x16;        (* MOVUPS (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0x0f; 0x11; 0x5e; 0x10;  (* MOVUPS (Memop Word128 (%% (rsi,16))) (%_% xmm3) *)
  0x0f; 0x11; 0x66; 0x20;  (* MOVUPS (Memop Word128 (%% (rsi,32))) (%_% xmm4) *)
  0x48; 0x8d; 0x76; 0x30;  (* LEA (% rsi) (%% (rsi,48)) *)
  0xeb; 0x6e;              (* JMP (Imm8 (word 110)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x0f; 0x1f; 0x00;        (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0x0f; 0x10; 0x17;        (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x0f; 0x10; 0x5f; 0x10;  (* MOVUPS (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0x0f; 0x10; 0x67; 0x20;  (* MOVUPS (%_% xmm4) (Memop Word128 (%% (rdi,32))) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x0f; 0x10; 0x6f; 0x30;  (* MOVUPS (%_% xmm5) (Memop Word128 (%% (rdi,48))) *)
  0x48; 0x8d; 0x7f; 0x40;  (* LEA (% rdi) (%% (rdi,64)) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x41; 0x0f; 0x57; 0xe4;  (* XORPS (%_% xmm4) (%_% xmm12) *)
  0x41; 0x0f; 0x57; 0xed;  (* XORPS (%_% xmm5) (%_% xmm13) *)
  0xe8; 0xd8; 0x01; 0x00; 0x00;
                           (* CALL (Imm32 (word 472)) *)
  0x66; 0x41; 0x0f; 0xef; 0xd2;
                           (* PXOR (%_% xmm2) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd6;
                           (* MOVDQA (%_% xmm10) (%_% xmm14) *)
  0x66; 0x41; 0x0f; 0xef; 0xdb;
                           (* PXOR (%_% xmm3) (%_% xmm11) *)
  0x66; 0x41; 0x0f; 0xef; 0xe4;
                           (* PXOR (%_% xmm4) (%_% xmm12) *)
  0xf3; 0x0f; 0x7f; 0x16;  (* MOVDQU (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0x66; 0x41; 0x0f; 0xef; 0xed;
                           (* PXOR (%_% xmm5) (%_% xmm13) *)
  0xf3; 0x0f; 0x7f; 0x5e; 0x10;
                           (* MOVDQU (Memop Word128 (%% (rsi,16))) (%_% xmm3) *)
  0xf3; 0x0f; 0x7f; 0x66; 0x20;
                           (* MOVDQU (Memop Word128 (%% (rsi,32))) (%_% xmm4) *)
  0xf3; 0x0f; 0x7f; 0x6e; 0x30;
                           (* MOVDQU (Memop Word128 (%% (rsi,48))) (%_% xmm5) *)
  0x48; 0x8d; 0x76; 0x40;  (* LEA (% rsi) (%% (rsi,64)) *)
  0xeb; 0x06;              (* JMP (Imm8 (word 6)) *)
  0x66; 0x0f; 0x1f; 0x44; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x49; 0x83; 0xe1; 0x0f;  (* AND (% r9) (Imm8 (word 15)) *)
  0x74; 0x59;              (* JE (Imm8 (word 89)) *)
  0x4c; 0x89; 0xca;        (* MOV (% rdx) (% r9) *)
  0x0f; 0xb6; 0x07;        (* MOVZX (% eax) (Memop Byte (%% (rdi,0))) *)
  0x0f; 0xb6; 0x4e; 0xf0;  (* MOVZX (% ecx) (Memop Byte (%% (rsi,18446744073709551600))) *)
  0x48; 0x8d; 0x7f; 0x01;  (* LEA (% rdi) (%% (rdi,1)) *)
  0x88; 0x46; 0xf0;        (* MOV (Memop Byte (%% (rsi,18446744073709551600))) (% al) *)
  0x88; 0x0e;              (* MOV (Memop Byte (%% (rsi,0))) (% cl) *)
  0x48; 0x8d; 0x76; 0x01;  (* LEA (% rsi) (%% (rsi,1)) *)
  0x48; 0x83; 0xea; 0x01;  (* SUB (% rdx) (Imm8 (word 1)) *)
  0x75; 0xe6;              (* JNE (Imm8 (word 230)) *)
  0x4c; 0x29; 0xce;        (* SUB (% rsi) (% r9) *)
  0x48; 0x89; 0xe9;        (* MOV (% rcx) (% rbp) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0x0f; 0x10; 0x56; 0xf0;  (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rsi,18446744073709551600))) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x48; 0x8d; 0x49; 0x20;  (* LEA (% rcx) (%% (rcx,32)) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0xff; 0xc8;              (* DEC (% eax) *)
  0x0f; 0x10; 0x09;        (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,0))) *)
  0x48; 0x8d; 0x49; 0x10;  (* LEA (% rcx) (%% (rcx,16)) *)
  0x75; 0xf0;              (* JNE (Imm8 (word 240)) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd1;
                           (* AESENCLAST (%_% xmm2) (%_% xmm1) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x0f; 0x11; 0x56; 0xf0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551600))) (%_% xmm2) *)
  0x0f; 0x57; 0xc0;        (* XORPS (%_% xmm0) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xc9;  (* PXOR (%_% xmm1) (%_% xmm1) *)
  0x66; 0x0f; 0xef; 0xd2;  (* PXOR (%_% xmm2) (%_% xmm2) *)
  0x66; 0x0f; 0xef; 0xdb;  (* PXOR (%_% xmm3) (%_% xmm3) *)
  0x66; 0x0f; 0xef; 0xe4;  (* PXOR (%_% xmm4) (%_% xmm4) *)
  0x66; 0x0f; 0xef; 0xed;  (* PXOR (%_% xmm5) (%_% xmm5) *)
  0x66; 0x0f; 0xef; 0xf6;  (* PXOR (%_% xmm6) (%_% xmm6) *)
  0x66; 0x0f; 0xef; 0xff;  (* PXOR (%_% xmm7) (%_% xmm7) *)
  0x0f; 0x29; 0x04; 0x24;  (* MOVAPS (Memop Word128 (%% (rsp,0))) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xc0;
                           (* PXOR (%_% xmm8) (%_% xmm8) *)
  0x0f; 0x29; 0x44; 0x24; 0x10;
                           (* MOVAPS (Memop Word128 (%% (rsp,16))) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xc9;
                           (* PXOR (%_% xmm9) (%_% xmm9) *)
  0x0f; 0x29; 0x44; 0x24; 0x20;
                           (* MOVAPS (Memop Word128 (%% (rsp,32))) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xd2;
                           (* PXOR (%_% xmm10) (%_% xmm10) *)
  0x0f; 0x29; 0x44; 0x24; 0x30;
                           (* MOVAPS (Memop Word128 (%% (rsp,48))) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xdb;
                           (* PXOR (%_% xmm11) (%_% xmm11) *)
  0x0f; 0x29; 0x44; 0x24; 0x40;
                           (* MOVAPS (Memop Word128 (%% (rsp,64))) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xe4;
                           (* PXOR (%_% xmm12) (%_% xmm12) *)
  0x0f; 0x29; 0x44; 0x24; 0x50;
                           (* MOVAPS (Memop Word128 (%% (rsp,80))) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xed;
                           (* PXOR (%_% xmm13) (%_% xmm13) *)
  0x0f; 0x29; 0x44; 0x24; 0x60;
                           (* MOVAPS (Memop Word128 (%% (rsp,96))) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xf6;
                           (* PXOR (%_% xmm14) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xef; 0xff;
                           (* PXOR (%_% xmm15) (%_% xmm15) *)
  0x49; 0x8b; 0x6b; 0xf8;  (* MOV (% rbp) (Memop Quadword (%% (r11,18446744073709551608))) *)
  0x49; 0x8d; 0x23;        (* LEA (% rsp) (%% (r11,0)) *)
  0xc3;                    (* RET *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x0f; 0x57; 0xd8;        (* XORPS (%_% xmm3) (%_% xmm0) *)
  0x0f; 0x10; 0x41; 0x20;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,32))) *)
  0x48; 0x8d; 0x4c; 0x01; 0x20;
                           (* LEA (% rcx) (%%%% (rcx,0,rax,&32)) *)
  0x48; 0xf7; 0xd8;        (* NEG (% rax) *)
  0x48; 0x83; 0xc0; 0x10;  (* ADD (% rax) (Imm8 (word 16)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x0f; 0x10; 0x0c; 0x01;  (* MOVUPS (%_% xmm1) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xf0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &16))) *)
  0x75; 0xdd;              (* JNE (Imm8 (word 221)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd0;
                           (* AESENCLAST (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd8;
                           (* AESENCLAST (%_% xmm3) (%_% xmm0) *)
  0xc3;                    (* RET *)
  0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Doubleword (%%% (rax,0,rax))) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x0f; 0x57; 0xd8;        (* XORPS (%_% xmm3) (%_% xmm0) *)
  0x0f; 0x57; 0xe0;        (* XORPS (%_% xmm4) (%_% xmm0) *)
  0x0f; 0x10; 0x41; 0x20;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,32))) *)
  0x48; 0x8d; 0x4c; 0x01; 0x20;
                           (* LEA (% rcx) (%%%% (rcx,0,rax,&32)) *)
  0x48; 0xf7; 0xd8;        (* NEG (% rax) *)
  0x48; 0x83; 0xc0; 0x10;  (* ADD (% rax) (Imm8 (word 16)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x0f; 0x10; 0x0c; 0x01;  (* MOVUPS (%_% xmm1) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xf0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &16))) *)
  0x75; 0xd3;              (* JNE (Imm8 (word 211)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd0;
                           (* AESENCLAST (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd8;
                           (* AESENCLAST (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe0;
                           (* AESENCLAST (%_% xmm4) (%_% xmm0) *)
  0xc3;                    (* RET *)
  0x90;                    (* NOP *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x0f; 0x57; 0xd8;        (* XORPS (%_% xmm3) (%_% xmm0) *)
  0x0f; 0x57; 0xe0;        (* XORPS (%_% xmm4) (%_% xmm0) *)
  0x0f; 0x57; 0xe8;        (* XORPS (%_% xmm5) (%_% xmm0) *)
  0x0f; 0x10; 0x41; 0x20;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,32))) *)
  0x48; 0x8d; 0x4c; 0x01; 0x20;
                           (* LEA (% rcx) (%%%% (rcx,0,rax,&32)) *)
  0x48; 0xf7; 0xd8;        (* NEG (% rax) *)
  0x0f; 0x1f; 0x00;        (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0x48; 0x83; 0xc0; 0x10;  (* ADD (% rax) (Imm8 (word 16)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x0f; 0x10; 0x0c; 0x01;  (* MOVUPS (%_% xmm1) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xf0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &16))) *)
  0x75; 0xc9;              (* JNE (Imm8 (word 201)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd0;
                           (* AESENCLAST (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd8;
                           (* AESENCLAST (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe0;
                           (* AESENCLAST (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe8;
                           (* AESENCLAST (%_% xmm5) (%_% xmm0) *)
  0xc3;                    (* RET *)
  0x0f; 0x1f; 0x80; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xd8;  (* PXOR (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xe0;  (* PXOR (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x48; 0x8d; 0x4c; 0x01; 0x20;
                           (* LEA (% rcx) (%%%% (rcx,0,rax,&32)) *)
  0x48; 0xf7; 0xd8;        (* NEG (% rax) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0xef; 0xe8;  (* PXOR (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xf0;  (* PXOR (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0xef; 0xf8;  (* PXOR (%_% xmm7) (%_% xmm0) *)
  0x0f; 0x10; 0x04; 0x01;  (* MOVUPS (%_% xmm0) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x10;  (* ADD (% rax) (Imm8 (word 16)) *)
  0xeb; 0x1d;              (* JMP (Imm8 (word 29)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x0f; 0x1f; 0x00;        (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x0c; 0x01;  (* MOVUPS (%_% xmm1) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xf0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &16))) *)
  0x75; 0xb5;              (* JNE (Imm8 (word 181)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd0;
                           (* AESENCLAST (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd8;
                           (* AESENCLAST (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe0;
                           (* AESENCLAST (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe8;
                           (* AESENCLAST (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xf0;
                           (* AESENCLAST (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xf8;
                           (* AESENCLAST (%_% xmm7) (%_% xmm0) *)
  0xc3;                    (* RET *)
  0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00
                           (* NOP_N (Memop Doubleword (%%% (rax,0,rax))) *)
  ]
  [135; 0; 0; 0; 0; 0; 0; 0; 1; 0; 0; 0; 0; 0; 0; 0];;

let aes_hw_xts_encrypt_clean_mc, xts_magic_clean =
  define_coda_literal_from_elf
  "aes_hw_xts_encrypt_clean_mc" "xts_magic_clean"
  "x86/aes-xts/aes_hw_xts_encrypt_clean.o"
  [
  0xf3; 0x0f; 0x1e; 0xfa;  (* ENDBR64 *)
  0x4c; 0x8d; 0x1c; 0x24;  (* LEA (% r11) (%% (rsp,0)) *)
  0x55;                    (* PUSH (% rbp) *)
  0x48; 0x83; 0xec; 0x70;  (* SUB (% rsp) (Imm8 (word 112)) *)
  0x48; 0x83; 0xe4; 0xf0;  (* AND (% rsp) (Imm8 (word 240)) *)
  0x41; 0x0f; 0x10; 0x11;  (* MOVUPS (%_% xmm2) (Memop Word128 (%% (r9,0))) *)
  0x41; 0x8b; 0x80; 0xf0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (r8,240))) *)
  0x44; 0x8b; 0x91; 0xf0; 0x00; 0x00; 0x00;
                           (* MOV (% r10d) (Memop Doubleword (%% (rcx,240))) *)
  0x41; 0x0f; 0x10; 0x00;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (r8,0))) *)
  0x41; 0x0f; 0x10; 0x48; 0x10;
                           (* MOVUPS (%_% xmm1) (Memop Word128 (%% (r8,16))) *)
  0x4d; 0x8d; 0x40; 0x20;  (* LEA (% r8) (%% (r8,32)) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0xff; 0xc8;              (* DEC (% eax) *)
  0x41; 0x0f; 0x10; 0x08;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (r8,0))) *)
  0x4d; 0x8d; 0x40; 0x10;  (* LEA (% r8) (%% (r8,16)) *)
  0x75; 0xef;              (* JNE (Imm8 (word 239)) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd1;
                           (* AESENCLAST (%_% xmm2) (%_% xmm1) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x48; 0x89; 0xcd;        (* MOV (% rbp) (% rcx) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0x41; 0xc1; 0xe2; 0x04;  (* SHL (% r10d) (Imm8 (word 4)) *)
  0x49; 0x89; 0xd1;        (* MOV (% r9) (% rdx) *)
  0x48; 0x83; 0xe2; 0xf0;  (* AND (% rdx) (Imm8 (word 240)) *)
  0x42; 0x0f; 0x10; 0x4c; 0x11; 0x10;
                           (* MOVUPS (%_% xmm1) (Memop Word128 (%%%% (rcx,0,r10,&16))) *)
  0x66; 0x0f; 0xef; 0xc8;  (* PXOR (%_% xmm1) (%_% xmm0) *)
  0x66; 0x44; 0x0f; 0x6f; 0x05; 0x60; 0x09; 0x00; 0x00;
                           (* MOVDQA (%_% xmm8) (Memop Word128 (Riprel (word 2400))) *)
  0x66; 0x44; 0x0f; 0x6f; 0xfa;
                           (* MOVDQA (%_% xmm15) (%_% xmm2) *)
  0x66; 0x44; 0x0f; 0x70; 0xca; 0x5f;
                           (* PSHUFD (%_% xmm9) (%_% xmm2) (Imm8 (word 95)) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd7;
                           (* MOVDQA (%_% xmm10) (%_% xmm15) *)
  0x66; 0x44; 0x0f; 0xef; 0xd0;
                           (* PXOR (%_% xmm10) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0x6f; 0xdf;
                           (* MOVDQA (%_% xmm11) (%_% xmm15) *)
  0x66; 0x44; 0x0f; 0xef; 0xd8;
                           (* PXOR (%_% xmm11) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0x6f; 0xe7;
                           (* MOVDQA (%_% xmm12) (%_% xmm15) *)
  0x66; 0x44; 0x0f; 0xef; 0xe0;
                           (* PXOR (%_% xmm12) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0x6f; 0xef;
                           (* MOVDQA (%_% xmm13) (%_% xmm15) *)
  0x66; 0x44; 0x0f; 0xef; 0xe8;
                           (* PXOR (%_% xmm13) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf7;
                           (* MOVDQA (%_% xmm14) (%_% xmm15) *)
  0x66; 0x44; 0x0f; 0xef; 0xf0;
                           (* PXOR (%_% xmm14) (%_% xmm0) *)
  0x66; 0x41; 0x0f; 0x72; 0xe1; 0x1f;
                           (* PSRAD (%_% xmm9) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xc8;
                           (* PAND (%_% xmm9) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xf9;
                           (* PXOR (%_% xmm15) (%_% xmm9) *)
  0x0f; 0x29; 0x4c; 0x24; 0x60;
                           (* MOVAPS (Memop Word128 (%% (rsp,96))) (%_% xmm1) *)
  0x48; 0x83; 0xea; 0x60;  (* SUB (% rdx) (Imm8 (word 96)) *)
  0x0f; 0x82; 0x71; 0x03; 0x00; 0x00;
                           (* JB (Imm32 (word 881)) *)
  0xb8; 0x70; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Imm32 (word 112)) *)
  0x4a; 0x8d; 0x4c; 0x15; 0x20;
                           (* LEA (% rcx) (%%%% (rbp,0,r10,&32)) *)
  0x4c; 0x29; 0xd0;        (* SUB (% rax) (% r10) *)
  0x49; 0x89; 0xc2;        (* MOV (% r10) (% rax) *)
  0x0f; 0x10; 0x4d; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rbp,16))) *)
  0x4c; 0x8d; 0x05; 0x68; 0x08; 0x00; 0x00;
                           (* LEA (% r8) (Riprel (word 2152)) *)
  0xeb; 0x16;              (* JMP (Imm8 (word 22)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0xf3; 0x0f; 0x6f; 0x17;  (* MOVDQU (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0xf3; 0x0f; 0x6f; 0x5f; 0x10;
                           (* MOVDQU (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0xf3; 0x0f; 0x6f; 0x67; 0x20;
                           (* MOVDQU (%_% xmm4) (Memop Word128 (%% (rdi,32))) *)
  0xf3; 0x0f; 0x6f; 0x6f; 0x30;
                           (* MOVDQU (%_% xmm5) (Memop Word128 (%% (rdi,48))) *)
  0xf3; 0x0f; 0x6f; 0x77; 0x40;
                           (* MOVDQU (%_% xmm6) (Memop Word128 (%% (rdi,64))) *)
  0xf3; 0x0f; 0x6f; 0x7f; 0x50;
                           (* MOVDQU (%_% xmm7) (Memop Word128 (%% (rdi,80))) *)
  0x66; 0x44; 0x0f; 0x6f; 0xc0;
                           (* MOVDQA (%_% xmm8) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xef; 0xc7;
                           (* PXOR (%_% xmm8) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0xef; 0xd2;
                           (* PXOR (%_% xmm2) (%_% xmm10) *)
  0x66; 0x41; 0x0f; 0xef; 0xdb;
                           (* PXOR (%_% xmm3) (%_% xmm11) *)
  0x66; 0x41; 0x0f; 0xef; 0xe4;
                           (* PXOR (%_% xmm4) (%_% xmm12) *)
  0x66; 0x41; 0x0f; 0xef; 0xed;
                           (* PXOR (%_% xmm5) (%_% xmm13) *)
  0x66; 0x41; 0x0f; 0xef; 0xf6;
                           (* PXOR (%_% xmm6) (%_% xmm14) *)
  0x66; 0x41; 0x0f; 0xef; 0xf8;
                           (* PXOR (%_% xmm7) (%_% xmm8) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x45; 0x20;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rbp,32))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x66; 0x44; 0x0f; 0x6f; 0x4c; 0x24; 0x60;
                           (* MOVDQA (%_% xmm9) (Memop Word128 (%% (rsp,96))) *)
  0x66; 0x45; 0x0f; 0xef; 0xd1;
                           (* PXOR (%_% xmm10) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x14; 0x24;
                           (* MOVDQA (Memop Word128 (%% (rsp,0))) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0xef; 0xd9;
                           (* PXOR (%_% xmm11) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x5c; 0x24; 0x10;
                           (* MOVDQA (Memop Word128 (%% (rsp,16))) (%_% xmm11) *)
  0x66; 0x45; 0x0f; 0xef; 0xe1;
                           (* PXOR (%_% xmm12) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x64; 0x24; 0x20;
                           (* MOVDQA (Memop Word128 (%% (rsp,32))) (%_% xmm12) *)
  0x66; 0x45; 0x0f; 0xef; 0xe9;
                           (* PXOR (%_% xmm13) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x6c; 0x24; 0x30;
                           (* MOVDQA (Memop Word128 (%% (rsp,48))) (%_% xmm13) *)
  0x66; 0x45; 0x0f; 0xef; 0xf1;
                           (* PXOR (%_% xmm14) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x74; 0x24; 0x40;
                           (* MOVDQA (Memop Word128 (%% (rsp,64))) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xef; 0xc1;
                           (* PXOR (%_% xmm8) (%_% xmm9) *)
  0x66; 0x44; 0x0f; 0x7f; 0x44; 0x24; 0x50;
                           (* MOVDQA (Memop Word128 (%% (rsp,80))) (%_% xmm8) *)
  0x0f; 0x10; 0x4d; 0x30;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rbp,48))) *)
  0x0f; 0x10; 0x45; 0x40;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rbp,64))) *)
  0x48; 0x8d; 0x7f; 0x60;  (* LEA (% rdi) (%% (rdi,96)) *)
  0xeb; 0x1f;              (* JMP (Imm8 (word 31)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x66; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x4c; 0x01; 0xc0;
                           (* MOVUPS (%_% xmm1) (Memop Word128 (%%%% (rcx,0,rax,-- &64))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xb0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &80))) *)
  0x75; 0xb4;              (* JNE (Imm8 (word 180)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x49; 0xc0;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,18446744073709551552))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x0f; 0x10; 0x41; 0xd0;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,18446744073709551568))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x49; 0xe0;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,18446744073709551584))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0x14; 0x24;
                           (* AESENCLAST (%_% xmm2) (Memop Word128 (%% (rsp,0))) *)
  0x66; 0x0f; 0x38; 0xdd; 0x5c; 0x24; 0x10;
                           (* AESENCLAST (%_% xmm3) (Memop Word128 (%% (rsp,16))) *)
  0x66; 0x0f; 0x38; 0xdd; 0x64; 0x24; 0x20;
                           (* AESENCLAST (%_% xmm4) (Memop Word128 (%% (rsp,32))) *)
  0x66; 0x0f; 0x38; 0xdd; 0x6c; 0x24; 0x30;
                           (* AESENCLAST (%_% xmm5) (Memop Word128 (%% (rsp,48))) *)
  0x66; 0x0f; 0x38; 0xdd; 0x74; 0x24; 0x40;
                           (* AESENCLAST (%_% xmm6) (Memop Word128 (%% (rsp,64))) *)
  0x66; 0x0f; 0x38; 0xdd; 0x7c; 0x24; 0x50;
                           (* AESENCLAST (%_% xmm7) (Memop Word128 (%% (rsp,80))) *)
  0x66; 0x45; 0x0f; 0x6f; 0x00;
                           (* MOVDQA (%_% xmm8) (Memop Word128 (%% (r8,0))) *)
  0x44; 0x0f; 0x10; 0x55; 0x00;
                           (* MOVUPS (%_% xmm10) (Memop Word128 (%% (rbp,0))) *)
  0x66; 0x45; 0x0f; 0x70; 0xcf; 0x5f;
                           (* PSHUFD (%_% xmm9) (%_% xmm15) (Imm8 (word 95)) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x45; 0x0f; 0x28; 0xda;  (* MOVAPS (%_% xmm11) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0xef; 0xd7;
                           (* PXOR (%_% xmm10) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x45; 0x0f; 0x28; 0xe3;  (* MOVAPS (%_% xmm12) (%_% xmm11) *)
  0x66; 0x45; 0x0f; 0xef; 0xdf;
                           (* PXOR (%_% xmm11) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x45; 0x0f; 0x28; 0xec;  (* MOVAPS (%_% xmm13) (%_% xmm12) *)
  0x66; 0x45; 0x0f; 0xef; 0xe7;
                           (* PXOR (%_% xmm12) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0x6f; 0xf1;
                           (* MOVDQA (%_% xmm14) (%_% xmm9) *)
  0x66; 0x41; 0x0f; 0x72; 0xe6; 0x1f;
                           (* PSRAD (%_% xmm14) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xf0;
                           (* PAND (%_% xmm14) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xfe;
                           (* PXOR (%_% xmm15) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x45; 0x0f; 0x28; 0xf5;  (* MOVAPS (%_% xmm14) (%_% xmm13) *)
  0x66; 0x45; 0x0f; 0xef; 0xef;
                           (* PXOR (%_% xmm13) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x6f; 0xc1;
                           (* MOVDQA (%_% xmm0) (%_% xmm9) *)
  0x66; 0x0f; 0x72; 0xe0; 0x1f;
                           (* PSRAD (%_% xmm0) (Imm8 (word 31)) *)
  0x66; 0x41; 0x0f; 0xdb; 0xc0;
                           (* PAND (%_% xmm0) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x44; 0x0f; 0xef; 0xf8;
                           (* PXOR (%_% xmm15) (%_% xmm0) *)
  0x66; 0x45; 0x0f; 0xfe; 0xc9;
                           (* PADDD (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xef; 0xf7;
                           (* PXOR (%_% xmm14) (%_% xmm15) *)
  0x66; 0x41; 0x0f; 0x72; 0xe1; 0x1f;
                           (* PSRAD (%_% xmm9) (Imm8 (word 31)) *)
  0x66; 0x45; 0x0f; 0xdb; 0xc8;
                           (* PAND (%_% xmm9) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xd4; 0xff;
                           (* PADDQ (%_% xmm15) (%_% xmm15) *)
  0x66; 0x45; 0x0f; 0xef; 0xf9;
                           (* PXOR (%_% xmm15) (%_% xmm9) *)
  0x4c; 0x89; 0xd0;        (* MOV (% rax) (% r10) *)
  0x0f; 0x10; 0x45; 0x00;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rbp,0))) *)
  0x0f; 0x10; 0x4d; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rbp,16))) *)
  0x48; 0x8d; 0x76; 0x60;  (* LEA (% rsi) (%% (rsi,96)) *)
  0x0f; 0x11; 0x56; 0xa0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551520))) (%_% xmm2) *)
  0x0f; 0x11; 0x5e; 0xb0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551536))) (%_% xmm3) *)
  0x0f; 0x11; 0x66; 0xc0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551552))) (%_% xmm4) *)
  0x0f; 0x11; 0x6e; 0xd0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551568))) (%_% xmm5) *)
  0x0f; 0x11; 0x76; 0xe0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551584))) (%_% xmm6) *)
  0x0f; 0x11; 0x7e; 0xf0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551600))) (%_% xmm7) *)
  0x48; 0x83; 0xea; 0x60;  (* SUB (% rdx) (Imm8 (word 96)) *)
  0x0f; 0x83; 0xd0; 0xfc; 0xff; 0xff;
                           (* JAE (Imm32 (word 4294966480)) *)
  0xb8; 0x70; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Imm32 (word 112)) *)
  0x44; 0x29; 0xd0;        (* SUB (% eax) (% r10d) *)
  0x48; 0x89; 0xe9;        (* MOV (% rcx) (% rbp) *)
  0xc1; 0xe8; 0x04;        (* SHR (% eax) (Imm8 (word 4)) *)
  0x41; 0x89; 0xc2;        (* MOV (% r10d) (% eax) *)
  0x66; 0x44; 0x0f; 0xef; 0xd0;
                           (* PXOR (%_% xmm10) (%_% xmm0) *)
  0x48; 0x83; 0xc2; 0x60;  (* ADD (% rdx) (Imm8 (word 96)) *)
  0x0f; 0x84; 0xf0; 0x01; 0x00; 0x00;
                           (* JE (Imm32 (word 496)) *)
  0x66; 0x44; 0x0f; 0xef; 0xd8;
                           (* PXOR (%_% xmm11) (%_% xmm0) *)
  0x48; 0x83; 0xfa; 0x20;  (* CMP (% rdx) (Imm8 (word 32)) *)
  0x0f; 0x82; 0xa1; 0x00; 0x00; 0x00;
                           (* JB (Imm32 (word 161)) *)
  0x66; 0x44; 0x0f; 0xef; 0xe0;
                           (* PXOR (%_% xmm12) (%_% xmm0) *)
  0x0f; 0x84; 0xe6; 0x00; 0x00; 0x00;
                           (* JE (Imm32 (word 230)) *)
  0x66; 0x44; 0x0f; 0xef; 0xe8;
                           (* PXOR (%_% xmm13) (%_% xmm0) *)
  0x48; 0x83; 0xfa; 0x40;  (* CMP (% rdx) (Imm8 (word 64)) *)
  0x0f; 0x82; 0x17; 0x01; 0x00; 0x00;
                           (* JB (Imm32 (word 279)) *)
  0x66; 0x44; 0x0f; 0xef; 0xf0;
                           (* PXOR (%_% xmm14) (%_% xmm0) *)
  0x0f; 0x84; 0x5c; 0x01; 0x00; 0x00;
                           (* JE (Imm32 (word 348)) *)
  0xf3; 0x0f; 0x6f; 0x17;  (* MOVDQU (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0xf3; 0x0f; 0x6f; 0x5f; 0x10;
                           (* MOVDQU (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0xf3; 0x0f; 0x6f; 0x67; 0x20;
                           (* MOVDQU (%_% xmm4) (Memop Word128 (%% (rdi,32))) *)
  0xf3; 0x0f; 0x6f; 0x6f; 0x30;
                           (* MOVDQU (%_% xmm5) (Memop Word128 (%% (rdi,48))) *)
  0xf3; 0x0f; 0x6f; 0x77; 0x40;
                           (* MOVDQU (%_% xmm6) (Memop Word128 (%% (rdi,64))) *)
  0x48; 0x8d; 0x7f; 0x50;  (* LEA (% rdi) (%% (rdi,80)) *)
  0x66; 0x41; 0x0f; 0xef; 0xd2;
                           (* PXOR (%_% xmm2) (%_% xmm10) *)
  0x66; 0x41; 0x0f; 0xef; 0xdb;
                           (* PXOR (%_% xmm3) (%_% xmm11) *)
  0x66; 0x41; 0x0f; 0xef; 0xe4;
                           (* PXOR (%_% xmm4) (%_% xmm12) *)
  0x66; 0x41; 0x0f; 0xef; 0xed;
                           (* PXOR (%_% xmm5) (%_% xmm13) *)
  0x66; 0x41; 0x0f; 0xef; 0xf6;
                           (* PXOR (%_% xmm6) (%_% xmm14) *)
  0x66; 0x0f; 0xef; 0xff;  (* PXOR (%_% xmm7) (%_% xmm7) *)
  0xe8; 0xae; 0x03; 0x00; 0x00;
                           (* CALL (Imm32 (word 942)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x41; 0x0f; 0x57; 0xe4;  (* XORPS (%_% xmm4) (%_% xmm12) *)
  0x41; 0x0f; 0x57; 0xed;  (* XORPS (%_% xmm5) (%_% xmm13) *)
  0x41; 0x0f; 0x57; 0xf6;  (* XORPS (%_% xmm6) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd7;
                           (* MOVDQA (%_% xmm10) (%_% xmm15) *)
  0xf3; 0x0f; 0x7f; 0x16;  (* MOVDQU (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0xf3; 0x0f; 0x7f; 0x5e; 0x10;
                           (* MOVDQU (Memop Word128 (%% (rsi,16))) (%_% xmm3) *)
  0xf3; 0x0f; 0x7f; 0x66; 0x20;
                           (* MOVDQU (Memop Word128 (%% (rsi,32))) (%_% xmm4) *)
  0xf3; 0x0f; 0x7f; 0x6e; 0x30;
                           (* MOVDQU (Memop Word128 (%% (rsi,48))) (%_% xmm5) *)
  0xf3; 0x0f; 0x7f; 0x76; 0x40;
                           (* MOVDQU (Memop Word128 (%% (rsi,64))) (%_% xmm6) *)
  0x48; 0x8d; 0x76; 0x50;  (* LEA (% rsi) (%% (rsi,80)) *)
  0xe9; 0x44; 0x01; 0x00; 0x00;
                           (* JMP (Imm32 (word 324)) *)
  0x0f; 0x1f; 0x40; 0x00;  (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0x0f; 0x10; 0x17;        (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x48; 0x8d; 0x7f; 0x10;  (* LEA (% rdi) (%% (rdi,16)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x48; 0x8d; 0x49; 0x20;  (* LEA (% rcx) (%% (rcx,32)) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0xff; 0xc8;              (* DEC (% eax) *)
  0x0f; 0x10; 0x09;        (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,0))) *)
  0x48; 0x8d; 0x49; 0x10;  (* LEA (% rcx) (%% (rcx,16)) *)
  0x75; 0xf0;              (* JNE (Imm8 (word 240)) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd1;
                           (* AESENCLAST (%_% xmm2) (%_% xmm1) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd3;
                           (* MOVDQA (%_% xmm10) (%_% xmm11) *)
  0x0f; 0x11; 0x16;        (* MOVUPS (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0x48; 0x8d; 0x76; 0x10;  (* LEA (% rsi) (%% (rsi,16)) *)
  0xe9; 0xfd; 0x00; 0x00; 0x00;
                           (* JMP (Imm32 (word 253)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x66; 0x90;              (* NOP *)
  0x0f; 0x10; 0x17;        (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x0f; 0x10; 0x5f; 0x10;  (* MOVUPS (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0x48; 0x8d; 0x7f; 0x20;  (* LEA (% rdi) (%% (rdi,32)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0xe8; 0xa8; 0x01; 0x00; 0x00;
                           (* CALL (Imm32 (word 424)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd4;
                           (* MOVDQA (%_% xmm10) (%_% xmm12) *)
  0x0f; 0x11; 0x16;        (* MOVUPS (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0x0f; 0x11; 0x5e; 0x10;  (* MOVUPS (Memop Word128 (%% (rsi,16))) (%_% xmm3) *)
  0x48; 0x8d; 0x76; 0x20;  (* LEA (% rsi) (%% (rsi,32)) *)
  0xe9; 0xbb; 0x00; 0x00; 0x00;
                           (* JMP (Imm32 (word 187)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x0f; 0x10; 0x17;        (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x0f; 0x10; 0x5f; 0x10;  (* MOVUPS (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0x0f; 0x10; 0x67; 0x20;  (* MOVUPS (%_% xmm4) (Memop Word128 (%% (rdi,32))) *)
  0x48; 0x8d; 0x7f; 0x30;  (* LEA (% rdi) (%% (rdi,48)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x41; 0x0f; 0x57; 0xe4;  (* XORPS (%_% xmm4) (%_% xmm12) *)
  0xe8; 0xc0; 0x01; 0x00; 0x00;
                           (* CALL (Imm32 (word 448)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x41; 0x0f; 0x57; 0xe4;  (* XORPS (%_% xmm4) (%_% xmm12) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd5;
                           (* MOVDQA (%_% xmm10) (%_% xmm13) *)
  0x0f; 0x11; 0x16;        (* MOVUPS (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0x0f; 0x11; 0x5e; 0x10;  (* MOVUPS (Memop Word128 (%% (rsi,16))) (%_% xmm3) *)
  0x0f; 0x11; 0x66; 0x20;  (* MOVUPS (Memop Word128 (%% (rsi,32))) (%_% xmm4) *)
  0x48; 0x8d; 0x76; 0x30;  (* LEA (% rsi) (%% (rsi,48)) *)
  0xeb; 0x6e;              (* JMP (Imm8 (word 110)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x0f; 0x1f; 0x00;        (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0x0f; 0x10; 0x17;        (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rdi,0))) *)
  0x0f; 0x10; 0x5f; 0x10;  (* MOVUPS (%_% xmm3) (Memop Word128 (%% (rdi,16))) *)
  0x0f; 0x10; 0x67; 0x20;  (* MOVUPS (%_% xmm4) (Memop Word128 (%% (rdi,32))) *)
  0x0f; 0x10; 0x6f; 0x30;  (* MOVUPS (%_% xmm5) (Memop Word128 (%% (rdi,48))) *)
  0x48; 0x8d; 0x7f; 0x40;  (* LEA (% rdi) (%% (rdi,64)) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x41; 0x0f; 0x57; 0xdb;  (* XORPS (%_% xmm3) (%_% xmm11) *)
  0x41; 0x0f; 0x57; 0xe4;  (* XORPS (%_% xmm4) (%_% xmm12) *)
  0x41; 0x0f; 0x57; 0xed;  (* XORPS (%_% xmm5) (%_% xmm13) *)
  0xe8; 0xd8; 0x01; 0x00; 0x00;
                           (* CALL (Imm32 (word 472)) *)
  0x66; 0x41; 0x0f; 0xef; 0xd2;
                           (* PXOR (%_% xmm2) (%_% xmm10) *)
  0x66; 0x41; 0x0f; 0xef; 0xdb;
                           (* PXOR (%_% xmm3) (%_% xmm11) *)
  0x66; 0x41; 0x0f; 0xef; 0xe4;
                           (* PXOR (%_% xmm4) (%_% xmm12) *)
  0x66; 0x41; 0x0f; 0xef; 0xed;
                           (* PXOR (%_% xmm5) (%_% xmm13) *)
  0x66; 0x45; 0x0f; 0x6f; 0xd6;
                           (* MOVDQA (%_% xmm10) (%_% xmm14) *)
  0xf3; 0x0f; 0x7f; 0x16;  (* MOVDQU (Memop Word128 (%% (rsi,0))) (%_% xmm2) *)
  0xf3; 0x0f; 0x7f; 0x5e; 0x10;
                           (* MOVDQU (Memop Word128 (%% (rsi,16))) (%_% xmm3) *)
  0xf3; 0x0f; 0x7f; 0x66; 0x20;
                           (* MOVDQU (Memop Word128 (%% (rsi,32))) (%_% xmm4) *)
  0xf3; 0x0f; 0x7f; 0x6e; 0x30;
                           (* MOVDQU (Memop Word128 (%% (rsi,48))) (%_% xmm5) *)
  0x48; 0x8d; 0x76; 0x40;  (* LEA (% rsi) (%% (rsi,64)) *)
  0xeb; 0x06;              (* JMP (Imm8 (word 6)) *)
  0x66; 0x0f; 0x1f; 0x44; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x49; 0x83; 0xe1; 0x0f;  (* AND (% r9) (Imm8 (word 15)) *)
  0x74; 0x59;              (* JE (Imm8 (word 89)) *)
  0x4c; 0x89; 0xca;        (* MOV (% rdx) (% r9) *)
  0x0f; 0xb6; 0x07;        (* MOVZX (% eax) (Memop Byte (%% (rdi,0))) *)
  0x0f; 0xb6; 0x4e; 0xf0;  (* MOVZX (% ecx) (Memop Byte (%% (rsi,18446744073709551600))) *)
  0x48; 0x8d; 0x7f; 0x01;  (* LEA (% rdi) (%% (rdi,1)) *)
  0x88; 0x46; 0xf0;        (* MOV (Memop Byte (%% (rsi,18446744073709551600))) (% al) *)
  0x88; 0x0e;              (* MOV (Memop Byte (%% (rsi,0))) (% cl) *)
  0x48; 0x8d; 0x76; 0x01;  (* LEA (% rsi) (%% (rsi,1)) *)
  0x48; 0x83; 0xea; 0x01;  (* SUB (% rdx) (Imm8 (word 1)) *)
  0x75; 0xe6;              (* JNE (Imm8 (word 230)) *)
  0x4c; 0x29; 0xce;        (* SUB (% rsi) (% r9) *)
  0x48; 0x89; 0xe9;        (* MOV (% rcx) (% rbp) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0x0f; 0x10; 0x56; 0xf0;  (* MOVUPS (%_% xmm2) (Memop Word128 (%% (rsi,18446744073709551600))) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x48; 0x8d; 0x49; 0x20;  (* LEA (% rcx) (%% (rcx,32)) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0xff; 0xc8;              (* DEC (% eax) *)
  0x0f; 0x10; 0x09;        (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,0))) *)
  0x48; 0x8d; 0x49; 0x10;  (* LEA (% rcx) (%% (rcx,16)) *)
  0x75; 0xf0;              (* JNE (Imm8 (word 240)) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd1;
                           (* AESENCLAST (%_% xmm2) (%_% xmm1) *)
  0x41; 0x0f; 0x57; 0xd2;  (* XORPS (%_% xmm2) (%_% xmm10) *)
  0x0f; 0x11; 0x56; 0xf0;  (* MOVUPS (Memop Word128 (%% (rsi,18446744073709551600))) (%_% xmm2) *)
  0x0f; 0x57; 0xc0;        (* XORPS (%_% xmm0) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xc9;  (* PXOR (%_% xmm1) (%_% xmm1) *)
  0x66; 0x0f; 0xef; 0xd2;  (* PXOR (%_% xmm2) (%_% xmm2) *)
  0x66; 0x0f; 0xef; 0xdb;  (* PXOR (%_% xmm3) (%_% xmm3) *)
  0x66; 0x0f; 0xef; 0xe4;  (* PXOR (%_% xmm4) (%_% xmm4) *)
  0x66; 0x0f; 0xef; 0xed;  (* PXOR (%_% xmm5) (%_% xmm5) *)
  0x66; 0x0f; 0xef; 0xf6;  (* PXOR (%_% xmm6) (%_% xmm6) *)
  0x66; 0x0f; 0xef; 0xff;  (* PXOR (%_% xmm7) (%_% xmm7) *)
  0x66; 0x45; 0x0f; 0xef; 0xc0;
                           (* PXOR (%_% xmm8) (%_% xmm8) *)
  0x66; 0x45; 0x0f; 0xef; 0xc9;
                           (* PXOR (%_% xmm9) (%_% xmm9) *)
  0x66; 0x45; 0x0f; 0xef; 0xd2;
                           (* PXOR (%_% xmm10) (%_% xmm10) *)
  0x66; 0x45; 0x0f; 0xef; 0xdb;
                           (* PXOR (%_% xmm11) (%_% xmm11) *)
  0x66; 0x45; 0x0f; 0xef; 0xe4;
                           (* PXOR (%_% xmm12) (%_% xmm12) *)
  0x66; 0x45; 0x0f; 0xef; 0xed;
                           (* PXOR (%_% xmm13) (%_% xmm13) *)
  0x66; 0x45; 0x0f; 0xef; 0xf6;
                           (* PXOR (%_% xmm14) (%_% xmm14) *)
  0x66; 0x45; 0x0f; 0xef; 0xff;
                           (* PXOR (%_% xmm15) (%_% xmm15) *)
  0x0f; 0x29; 0x04; 0x24;  (* MOVAPS (Memop Word128 (%% (rsp,0))) (%_% xmm0) *)
  0x0f; 0x29; 0x44; 0x24; 0x10;
                           (* MOVAPS (Memop Word128 (%% (rsp,16))) (%_% xmm0) *)
  0x0f; 0x29; 0x44; 0x24; 0x20;
                           (* MOVAPS (Memop Word128 (%% (rsp,32))) (%_% xmm0) *)
  0x0f; 0x29; 0x44; 0x24; 0x30;
                           (* MOVAPS (Memop Word128 (%% (rsp,48))) (%_% xmm0) *)
  0x0f; 0x29; 0x44; 0x24; 0x40;
                           (* MOVAPS (Memop Word128 (%% (rsp,64))) (%_% xmm0) *)
  0x0f; 0x29; 0x44; 0x24; 0x50;
                           (* MOVAPS (Memop Word128 (%% (rsp,80))) (%_% xmm0) *)
  0x0f; 0x29; 0x44; 0x24; 0x60;
                           (* MOVAPS (Memop Word128 (%% (rsp,96))) (%_% xmm0) *)
  0x49; 0x8b; 0x6b; 0xf8;  (* MOV (% rbp) (Memop Quadword (%% (r11,18446744073709551608))) *)
  0x49; 0x8d; 0x23;        (* LEA (% rsp) (%% (r11,0)) *)
  0xc3;                    (* RET *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x0f; 0x57; 0xd8;        (* XORPS (%_% xmm3) (%_% xmm0) *)
  0x0f; 0x10; 0x41; 0x20;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,32))) *)
  0x48; 0x8d; 0x4c; 0x01; 0x20;
                           (* LEA (% rcx) (%%%% (rcx,0,rax,&32)) *)
  0x48; 0xf7; 0xd8;        (* NEG (% rax) *)
  0x48; 0x83; 0xc0; 0x10;  (* ADD (% rax) (Imm8 (word 16)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x0f; 0x10; 0x0c; 0x01;  (* MOVUPS (%_% xmm1) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xf0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &16))) *)
  0x75; 0xdd;              (* JNE (Imm8 (word 221)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd0;
                           (* AESENCLAST (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd8;
                           (* AESENCLAST (%_% xmm3) (%_% xmm0) *)
  0xc3;                    (* RET *)
  0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Doubleword (%%% (rax,0,rax))) *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x0f; 0x57; 0xd8;        (* XORPS (%_% xmm3) (%_% xmm0) *)
  0x0f; 0x57; 0xe0;        (* XORPS (%_% xmm4) (%_% xmm0) *)
  0x0f; 0x10; 0x41; 0x20;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,32))) *)
  0x48; 0x8d; 0x4c; 0x01; 0x20;
                           (* LEA (% rcx) (%%%% (rcx,0,rax,&32)) *)
  0x48; 0xf7; 0xd8;        (* NEG (% rax) *)
  0x48; 0x83; 0xc0; 0x10;  (* ADD (% rax) (Imm8 (word 16)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x0f; 0x10; 0x0c; 0x01;  (* MOVUPS (%_% xmm1) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xf0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &16))) *)
  0x75; 0xd3;              (* JNE (Imm8 (word 211)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd0;
                           (* AESENCLAST (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd8;
                           (* AESENCLAST (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe0;
                           (* AESENCLAST (%_% xmm4) (%_% xmm0) *)
  0xc3;                    (* RET *)
  0x90;                    (* NOP *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x0f; 0x57; 0xd8;        (* XORPS (%_% xmm3) (%_% xmm0) *)
  0x0f; 0x57; 0xe0;        (* XORPS (%_% xmm4) (%_% xmm0) *)
  0x0f; 0x57; 0xe8;        (* XORPS (%_% xmm5) (%_% xmm0) *)
  0x0f; 0x10; 0x41; 0x20;  (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,32))) *)
  0x48; 0x8d; 0x4c; 0x01; 0x20;
                           (* LEA (% rcx) (%%%% (rcx,0,rax,&32)) *)
  0x48; 0xf7; 0xd8;        (* NEG (% rax) *)
  0x0f; 0x1f; 0x00;        (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0x48; 0x83; 0xc0; 0x10;  (* ADD (% rax) (Imm8 (word 16)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x0f; 0x10; 0x0c; 0x01;  (* MOVUPS (%_% xmm1) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xf0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &16))) *)
  0x75; 0xc9;              (* JNE (Imm8 (word 201)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd0;
                           (* AESENCLAST (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd8;
                           (* AESENCLAST (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe0;
                           (* AESENCLAST (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe8;
                           (* AESENCLAST (%_% xmm5) (%_% xmm0) *)
  0xc3;                    (* RET *)
  0x0f; 0x1f; 0x80; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0x0f; 0x10; 0x01;        (* MOVUPS (%_% xmm0) (Memop Word128 (%% (rcx,0))) *)
  0x0f; 0x10; 0x49; 0x10;  (* MOVUPS (%_% xmm1) (Memop Word128 (%% (rcx,16))) *)
  0x48; 0x8d; 0x4c; 0x01; 0x20;
                           (* LEA (% rcx) (%%%% (rcx,0,rax,&32)) *)
  0x48; 0xf7; 0xd8;        (* NEG (% rax) *)
  0x0f; 0x57; 0xd0;        (* XORPS (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xd8;  (* PXOR (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xe0;  (* PXOR (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xe8;  (* PXOR (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xf0;  (* PXOR (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xf8;  (* PXOR (%_% xmm7) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x0f; 0x10; 0x04; 0x01;  (* MOVUPS (%_% xmm0) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x10;  (* ADD (% rax) (Imm8 (word 16)) *)
  0xeb; 0x1d;              (* JMP (Imm8 (word 29)) *)
  0x66; 0x66; 0x2e; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x0f; 0x1f; 0x00;        (* NOP_N (Memop Doubleword (%% (rax,0))) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x0f; 0x10; 0x0c; 0x01;  (* MOVUPS (%_% xmm1) (Memop Word128 (%%% (rcx,0,rax))) *)
  0x48; 0x83; 0xc0; 0x20;  (* ADD (% rax) (Imm8 (word 32)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd0;
                           (* AESENC (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd8;
                           (* AESENC (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe0;
                           (* AESENC (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe8;
                           (* AESENC (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf0;
                           (* AESENC (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf8;
                           (* AESENC (%_% xmm7) (%_% xmm0) *)
  0x0f; 0x10; 0x44; 0x01; 0xf0;
                           (* MOVUPS (%_% xmm0) (Memop Word128 (%%%% (rcx,0,rax,-- &16))) *)
  0x75; 0xb5;              (* JNE (Imm8 (word 181)) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd1;
                           (* AESENC (%_% xmm2) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xd9;
                           (* AESENC (%_% xmm3) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe1;
                           (* AESENC (%_% xmm4) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xe9;
                           (* AESENC (%_% xmm5) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf1;
                           (* AESENC (%_% xmm6) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdc; 0xf9;
                           (* AESENC (%_% xmm7) (%_% xmm1) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd0;
                           (* AESENCLAST (%_% xmm2) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xd8;
                           (* AESENCLAST (%_% xmm3) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe0;
                           (* AESENCLAST (%_% xmm4) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xe8;
                           (* AESENCLAST (%_% xmm5) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xf0;
                           (* AESENCLAST (%_% xmm6) (%_% xmm0) *)
  0x66; 0x0f; 0x38; 0xdd; 0xf8;
                           (* AESENCLAST (%_% xmm7) (%_% xmm0) *)
  0xc3;                    (* RET *)
  0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00
                           (* NOP_N (Memop Doubleword (%%% (rax,0,rax))) *)
  ]
  [135; 0; 0; 0; 0; 0; 0; 0; 1; 0; 0; 0; 0; 0; 0; 0];;

let AES_HW_XTS_ENCRYPT_EXEC = X86_MK_EXEC_RULE aes_hw_xts_encrypt_mc;;
let AES_HW_XTS_ENCRYPT_CLEAN_EXEC = X86_MK_EXEC_RULE aes_hw_xts_encrypt_clean_mc;;

let key_schedule_equiv = new_definition
  `forall s s' key_ptr.
   (key_schedule_equiv:(x86state#x86state)->int64->bool) (s,s') key_ptr <=>
   (exists k0 k1 k2 k3 k4 k5 k6 k7 k8 k9 k10 k11 k12 k13 k14.
    read (memory :> bytes128 key_ptr) s = k0 /\
    read (memory :> bytes128 key_ptr) s' = k0 /\
    read (memory :> bytes128 (word_add key_ptr (word 16))) s = k1 /\
    read (memory :> bytes128 (word_add key_ptr (word 16))) s' = k1 /\
    read (memory :> bytes128 (word_add key_ptr (word 32))) s = k2 /\
    read (memory :> bytes128 (word_add key_ptr (word 32))) s' = k2 /\
    read (memory :> bytes128 (word_add key_ptr (word 48))) s = k3 /\
    read (memory :> bytes128 (word_add key_ptr (word 48))) s' = k3 /\
    read (memory :> bytes128 (word_add key_ptr (word 64))) s = k4 /\
    read (memory :> bytes128 (word_add key_ptr (word 64))) s' = k4 /\
    read (memory :> bytes128 (word_add key_ptr (word 80))) s = k5 /\
    read (memory :> bytes128 (word_add key_ptr (word 80))) s' = k5 /\
    read (memory :> bytes128 (word_add key_ptr (word 96))) s = k6 /\
    read (memory :> bytes128 (word_add key_ptr (word 96))) s' = k6 /\
    read (memory :> bytes128 (word_add key_ptr (word 112))) s = k7 /\
    read (memory :> bytes128 (word_add key_ptr (word 112))) s' = k7 /\
    read (memory :> bytes128 (word_add key_ptr (word 128))) s = k8 /\
    read (memory :> bytes128 (word_add key_ptr (word 128))) s' = k8 /\
    read (memory :> bytes128 (word_add key_ptr (word 144))) s = k9 /\
    read (memory :> bytes128 (word_add key_ptr (word 144))) s' = k9 /\
    read (memory :> bytes128 (word_add key_ptr (word 160))) s = k10 /\
    read (memory :> bytes128 (word_add key_ptr (word 160))) s' = k10 /\
    read (memory :> bytes128 (word_add key_ptr (word 176))) s = k11 /\
    read (memory :> bytes128 (word_add key_ptr (word 176))) s' = k11 /\
    read (memory :> bytes128 (word_add key_ptr (word 192))) s = k12 /\
    read (memory :> bytes128 (word_add key_ptr (word 192))) s' = k12 /\
    read (memory :> bytes128 (word_add key_ptr (word 208))) s = k13 /\
    read (memory :> bytes128 (word_add key_ptr (word 208))) s' = k13 /\
    read (memory :> bytes128 (word_add key_ptr (word 224))) s = k14 /\
    read (memory :> bytes128 (word_add key_ptr (word 224))) s' = k14 /\
    read (memory :> bytes32 (word_add key_ptr (word 240))) s = word 13 /\
    read (memory :> bytes32 (word_add key_ptr (word 240))) s' = word 13
    )`;;

let ghost_ymms = new_definition
  `forall s. (ghost_ymms:x86state->bool) s <=>
   (exists y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15.
    read YMM0 s = y0 /\
    read YMM1 s = y1 /\
    read YMM2 s = y2 /\
    read YMM3 s = y3 /\
    read YMM4 s = y4 /\
    read YMM5 s = y5 /\
    read YMM6 s = y6 /\
    read YMM7 s = y7 /\
    read YMM8 s = y8 /\
    read YMM9 s = y9 /\
    read YMM10 s = y10 /\
    read YMM11 s = y11 /\
    read YMM12 s = y12 /\
    read YMM13 s = y13 /\
    read YMM14 s = y14 /\
    read YMM15 s = y15
  )`;;

(* TODO: Currently assuming just one block *)
let aes_xts_eqin = new_definition
  `forall s1 s1' in_ptr out_ptr key1_ptr key2_ptr iv_ptr r1 stack_pointer.
    (aes_xts_eqin:(x86state#x86state)->int64->int64->int64->int64->int64->int64->int64->bool)
      (s1,s1') in_ptr out_ptr key1_ptr key2_ptr iv_ptr r1 stack_pointer<=>
     (read RDI s1 = in_ptr /\
      read RDI s1' = in_ptr /\
      read RSI s1 = out_ptr /\
      read RSI s1' = out_ptr /\
      read RDX s1 = word 16 /\
      read RDX s1' = word 16 /\
      read RSP s1 = stack_pointer /\
      read RSP s1' = stack_pointer /\
      read RCX s1 = key1_ptr /\
      read RCX s1' = key1_ptr /\
      read R8 s1 = key2_ptr /\
      read R8 s1' = key2_ptr /\
      read R9 s1 = iv_ptr /\
      read R9 s1' = iv_ptr /\
      // Memory equivalence at in_ptr for 16-bytes (one block)
      (exists n.
        read (memory :> bytes128 in_ptr) s1 = n /\
        read (memory :> bytes128 in_ptr) s1' = n) /\
      // Key1 equivalence
      (key_schedule_equiv (s1,s1') key1_ptr) /\
      // Key2 equivalence
      (key_schedule_equiv (s1,s1') key2_ptr) /\
      // iv equivalence
      (exists iv.
      read (memory :> bytes128 iv_ptr) s1 = iv /\
      read (memory :> bytes128 iv_ptr) s1' = iv) /\
      // ghost values
      (ghost_ymms s1) /\ (ghost_ymms s1')
      )`;;

let aes_xts_eqout = new_definition
  `forall s1 s1' r1 out_ptr.
    (aes_xts_eqout:(x86state#x86state)->int64->int64->bool) (s1,s1') r1 out_ptr <=>
     (read RSI s1 = word_add out_ptr (word 16)  /\
      read RSI s1' = word_add out_ptr (word 16) /\
      (exists n.
        read (memory :> bytes128 out_ptr) s1 = n /\
        read (memory :> bytes128 out_ptr) s1' = n))`;;

(* TODO: need to figure out about pc_ofs1/2_to and the step number *)
let equiv_goal = mk_equiv_statement
  `ALL (nonoverlapping (stack_pointer,128))
  [word pc,LENGTH (APPEND aes_hw_xts_encrypt_mc xts_magic);
   word pc2,LENGTH (APPEND aes_hw_xts_encrypt_clean_mc xts_magic_clean);
   in_ptr:int64,16; iv_ptr:int64,16; key1_ptr:int64,244; key2_ptr:int64,244] /\
  ALL (nonoverlapping (out_ptr,16))
  [word pc,LENGTH (APPEND aes_hw_xts_encrypt_mc xts_magic);
   word pc2,LENGTH (APPEND aes_hw_xts_encrypt_clean_mc xts_magic_clean);
   stack_pointer,128; in_ptr,16; iv_ptr,16; key1_ptr,244; key2_ptr,244] /\
  aligned 16 stack_pointer /\
  aligned 16 (word (pc + 2480):int64) /\
  aligned 16 (word (pc2 + 2512):int64)`
  (* the above two alignments are for constant value xts_magic *)
  aes_xts_eqin
  aes_xts_eqout
  aes_hw_xts_encrypt_mc (Some xts_magic) 17 1903
  (* TODO: currently RBP is being used *)
  `MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
   MAYCHANGE [memory :> bytes128 out_ptr;
              memory :> bytes128 stack_pointer;
              memory :> bytes128 (word_add stack_pointer (word 16));
              memory :> bytes128 (word_add stack_pointer (word 32));
              memory :> bytes128 (word_add stack_pointer (word 48));
              memory :> bytes128 (word_add stack_pointer (word 64));
              memory :> bytes128 (word_add stack_pointer (word 80));
              memory :> bytes128 (word_add stack_pointer (word 96))] ,,
   MAYCHANGE [RSP; RBP]`
  aes_hw_xts_encrypt_clean_mc (Some xts_magic_clean) 17 1935
  `MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
   MAYCHANGE [memory :> bytes128 out_ptr;
              memory :> bytes128 stack_pointer;
              memory :> bytes128 (word_add stack_pointer (word 16));
              memory :> bytes128 (word_add stack_pointer (word 32));
              memory :> bytes128 (word_add stack_pointer (word 48));
              memory :> bytes128 (word_add stack_pointer (word 64));
              memory :> bytes128 (word_add stack_pointer (word 80));
              memory :> bytes128 (word_add stack_pointer (word 96))] ,,
   MAYCHANGE [RSP; RBP]`
  `(\s:x86state. 237)`
  `(\s:x86state. 237)`;;

x86_print_log := true;;
components_print_log := true;;

let AESENCLOOP_TAC k =
  EQUIV_STEPS_TAC [
    ("equal",k,k+1,k,k+1);
    ("replace",k+1,k+4,k+1,k+4);
    ("equal",k+4,k+5,k+4,k+5);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV));;

let AESENC_TAC (k,q) =
  MAP_EVERY AESENCLOOP_TAC
    ((k -- q) |> List.filter (fun x -> (x - k) mod 5 = 0));;

(* TODO: Need to generalize, inspired by BIGNUM_FROM_MEMORY_BOUND *)
let MEMORY_BYTES_BOUND = prove
  (`read (memory :> bytes (x,16)) s < 2 EXP dimindex (:128)`,
  REWRITE_TAC[READ_COMPONENT_COMPOSE; DIMINDEX_128] THEN
  SUBST1_TAC(ARITH_RULE `128 = 8 * 16`) THEN REWRITE_TAC[READ_BYTES_BOUND]
  );;

(* Adapted from bignum_copy_row_from_table_8n.ml *)
let READ_MEMORY_BYTES_BYTES128 = prove(`!z s.
    read (memory :> bytes (z,16)) s = val (read (memory :> bytes128 z) s)`,
  REPEAT GEN_TAC THEN
  REWRITE_TAC[el 1 (CONJUNCTS READ_MEMORY_BYTESIZED_SPLIT)] THEN
  REWRITE_TAC[VAL_WORD_JOIN;DIMINDEX_64;DIMINDEX_128] THEN
  IMP_REWRITE_TAC[MOD_LT] THEN
  REWRITE_TAC[ARITH_RULE`2 EXP 128 = 2 EXP 64 * 2 EXP 64`] THEN
  IMP_REWRITE_TAC[LT_MULT_ADD_MULT] THEN
  REWRITE_TAC[VAL_BOUND_64;ARITH_RULE`0<2 EXP 64`;LE_REFL] THEN
  REWRITE_TAC[ARITH_RULE`16 = 8*(1+1)`;GSYM BIGNUM_FROM_MEMORY_BYTES;BIGNUM_FROM_MEMORY_STEP;BIGNUM_FROM_MEMORY_SING] THEN
  REWRITE_TAC[ARITH_RULE`8*1=8`;ARITH_RULE`64*1=64`] THEN ARITH_TAC);;

let READ_MEMORY_BYTES128_BYTES = prove(`!z s.
    read (memory :> bytes128 z) s = word (read (memory :> bytes (z,16)) s)`,
  REPEAT STRIP_TAC THEN
  ONCE_REWRITE_TAC[GSYM VAL_EQ] THEN
  IMP_REWRITE_TAC [VAL_WORD_EQ] THEN
  CONJ_TAC THENL [REWRITE_TAC [READ_MEMORY_BYTES_BYTES128]; ALL_TAC] THEN
  REWRITE_TAC [MEMORY_BYTES_BOUND]
  );;

(* TODO: need to generalize, use NUM_OF_BYTELIST_BOUND *)
let XTS_MAGIC_NUM_OF_BYTELIST_BOUND = prove
  (`num_of_bytelist xts_magic < 2 EXP dimindex (:128)`,
    TRANS_TAC LTE_TRANS `256 EXP (LENGTH xts_magic):num` THEN
    CONJ_TAC THEN REWRITE_TAC [NUM_OF_BYTELIST_BOUND] THEN
    REWRITE_TAC [CONV_RULE (RAND_CONV LENGTH_CONV) (AP_TERM `LENGTH:byte list->num` xts_magic)] THEN
    REWRITE_TAC [DIMINDEX_128] THEN ARITH_TAC
  );;

let XTS_MAGIC_CLEAN_NUM_OF_BYTELIST_BOUND = prove
  (`num_of_bytelist xts_magic_clean < 2 EXP dimindex (:128)`,
    TRANS_TAC LTE_TRANS `256 EXP (LENGTH xts_magic_clean):num` THEN
    CONJ_TAC THEN REWRITE_TAC [NUM_OF_BYTELIST_BOUND] THEN
    REWRITE_TAC [CONV_RULE (RAND_CONV LENGTH_CONV) (AP_TERM `LENGTH:byte list->num` xts_magic_clean)] THEN
    REWRITE_TAC [DIMINDEX_128] THEN ARITH_TAC
  );;

(* TODO: generalize, inspired by BYTES_LOADED_DATA from CURVE25519 and ED25519 proofs*)
let BYTES128_LOADED_DATA = prove
 (`bytes_loaded s (word (pc + 2480)) xts_magic <=>
   read (memory :> bytes128 (word (pc + 2480))) s =
   (word (num_of_bytelist xts_magic)):int128`,
  REWRITE_TAC[READ_MEMORY_BYTES128_BYTES] THEN
  REWRITE_TAC[bytes_loaded; READ_BYTELIST_EQ_BYTES;
    CONV_RULE (RAND_CONV LENGTH_CONV)
     (AP_TERM `LENGTH:byte list->num` xts_magic)] THEN
  CONV_TAC SYM_CONV THEN
  MATCH_MP_TAC WORD_EQ_IMP THEN
  CONJ_TAC THEN
  REWRITE_TAC [MEMORY_BYTES_BOUND; XTS_MAGIC_NUM_OF_BYTELIST_BOUND]
  );;

let BYTES128_LOADED_DATA_CLEAN = prove
 (`bytes_loaded s (word (pc + 2512)) xts_magic_clean <=>
   read (memory :> bytes128 (word (pc + 2512))) s =
   word (num_of_bytelist xts_magic_clean)`,
  REWRITE_TAC[READ_MEMORY_BYTES128_BYTES] THEN
  REWRITE_TAC[bytes_loaded; READ_BYTELIST_EQ_BYTES;
    CONV_RULE (RAND_CONV LENGTH_CONV)
     (AP_TERM `LENGTH:byte list->num` xts_magic_clean)] THEN
  CONV_TAC SYM_CONV THEN
  MATCH_MP_TAC WORD_EQ_IMP THEN
  CONJ_TAC THEN
  REWRITE_TAC [MEMORY_BYTES_BOUND; XTS_MAGIC_CLEAN_NUM_OF_BYTELIST_BOUND]
  );;

(* TODO: Need to generalize, alignement proofs? Any inspirations? *)
(* Q: How to think about the case when PC wraps around? *)
let load_xts_magic_pc_equiv = prove
  ( `word ((val ((word (pc + 108)):int64)) + 2372) = ((word (pc + 2480)):int64)`,
  CONV_TAC WORD_RULE
   );;
let load_xts_magic_clean_pc2_equiv = prove
  ( `word ((val ((word (pc2 + 112)):int64)) + 2400) = ((word (pc2 + 2512)):int64)`,
  CONV_TAC WORD_RULE);;

let alignment_lemma1 = prove
  (`aligned 16 ((word (pc+2480)):int64) ==>
    aligned 16 ((word (val ((word (pc + 108)):int64)+2372)):int64)`,
   REWRITE_TAC[crock1]
    );;

let alignment_lemma2 = prove
  (`aligned 16 ((word (pc2+2512)):int64) ==>
    aligned 16 ((word (val ((word (pc2 + 112)):int64)+2400)):int64)`,
    REWRITE_TAC[crock2]);;

let LENGTH_xts_magic_lemma = prove
  (`LENGTH xts_magic=16`,
    REWRITE_TAC [(REWRITE_CONV [xts_magic] THENC LENGTH_CONV) `LENGTH xts_magic`]);;
let LENGTH_xts_magic_clean_lemma = prove
  (`LENGTH xts_magic_clean=16`,
    REWRITE_TAC [(REWRITE_CONV [xts_magic_clean] THENC LENGTH_CONV) `LENGTH xts_magic_clean`]);;

let XTS_MAGIC_EQUIV = prove
  (`xts_magic = xts_magic_clean`, REWRITE_TAC[xts_magic; xts_magic_clean]);;

let rw = Compute.bool_compset();;
word_compute_add_convs rw;;
num_compute_add_convs rw;;
Compute.add_thms [aes_hw_xts_encrypt_mc; aes_hw_xts_encrypt_clean_mc; LENGTH] rw;;
let my_conv = Compute.WEAK_CBV_CONV rw;;
my_conv `LENGTH aes_hw_xts_encrypt_mc`;;
my_conv `LENGTH aes_hw_xts_encrypt_clean_mc`;;


let ADD_IMP_ASSUM_TAC lemma =
  MP_TAC lemma THEN ANTS_TAC THENL [ASM_REWRITE_TAC[] THEN NO_TAC; STRIP_TAC];;

let REWRITE_IMP_ASSUM_TAC lemma =
  MP_TAC lemma THEN ANTS_TAC THENL [ASM_REWRITE_TAC[] THEN NO_TAC; STRIP_TAC];;

let ADD_ASSUM_TAC lemma =
  MP_TAC lemma THEN STRIP_TAC;;

let assert_pat (t:term) (pat:term): unit =
  let maybe_pat,maybe_state = dest_binary "read" (lhs t) in
  if maybe_pat <> pat then failwith ("Not a valid pattern: "^(name_of pat)) else ();;

let FORCE_READ_EQ_TAC (pat:term):tactic =
  FIRST_X_ASSUM (fun th -> assert_pat (concl th) pat;
    FIRST_X_ASSUM (fun th2 -> assert_pat (concl th2) pat;
      ABBREV_READS_TAC (th,th2) true));;

let TWEAK_TAC k reg =
  EQUIV_STEPS_TAC [
    ("replace",k,k+8,k,k+8);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  FORCE_READ_EQ_TAC `YMM9` THEN FORCE_READ_EQ_TAC `YMM14` THEN
  FORCE_READ_EQ_TAC `YMM15` THEN FORCE_READ_EQ_TAC reg;;

let TWEAK_LAST_TAC k reg =
  EQUIV_STEPS_TAC [
    ("replace",k,k+6,k,k+6);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  FORCE_READ_EQ_TAC `YMM9` THEN FORCE_READ_EQ_TAC reg THEN
  FORCE_READ_EQ_TAC `YMM15`;;

let PRINT_TAC:string->tactic =
  fun str g -> let _ = Printf.printf "%s\n" str in ALL_TAC g;;

let org_extra_word_conv = !extra_word_CONV;;

(* Enable simplification of word_subwords by default *)
extra_word_CONV := [WORD_SIMPLE_SUBWORD_CONV] @ !extra_word_CONV;;

(* let stack_pointer_aligned = prove(
  `aligned 16 (stack_pointer:int64) ==>
   word_and (word_add stack_pointer (word 8)) (word 18446744073709551600) = stack_pointer`,
   CHEAT_TAC
);; *)

let EQUIV = prove(equiv_goal,

  (* Rewrite SOME_FLAGS, ALL, nonoverlapping, and LENGTH * *)
  REWRITE_TAC[SOME_FLAGS; ALL;NONOVERLAPPING_CLAUSES;LENGTH_APPEND;
              fst AES_HW_XTS_ENCRYPT_EXEC;LENGTH_xts_magic_lemma;
              fst AES_HW_XTS_ENCRYPT_CLEAN_EXEC;LENGTH_xts_magic_clean_lemma] THEN
  CONV_TAC (ONCE_DEPTH_CONV NUM_ADD_CONV) THEN
  REPEAT STRIP_TAC THEN
  REWRITE_TAC[BYTES_LOADED_APPEND_CLAUSE] THEN
  REWRITE_TAC[fst AES_HW_XTS_ENCRYPT_EXEC; fst AES_HW_XTS_ENCRYPT_CLEAN_EXEC] THEN
  (* Separate loading of constants *)
  REWRITE_TAC[BYTES128_LOADED_DATA; BYTES128_LOADED_DATA_CLEAN] THEN

  (** Initialize **)
  EQUIV_INITIATE_TAC aes_xts_eqin THEN
  EVERY_ASSUM(fun th ->
   try MP_TAC(GEN_REWRITE_RULE I [key_schedule_equiv;ghost_ymms] th)
   with Failure _ -> ALL_TAC) THEN
  REPEAT STRIP_TAC THEN
  (* TODO: use DISCARD_MATCHING_ASSUMPTIONS to remove original assumptions *)
  (* Shift the stackpointer by 128 bytes to avoid subtraction *)
  (* REPEAT(POP_ASSUM MP_TAC) THEN
  SPEC_TAC (`stack_pointer:int64`, `stack_pointer:int64`) THEN
  WORD_FORALL_OFFSET_TAC 128 THEN
  CONV_TAC(ONCE_DEPTH_CONV NORMALIZE_RELATIVE_ADDRESS_CONV) THEN
  REPEAT STRIP_TAC THEN *)

  ADD_ASSUM_TAC XTS_MAGIC_EQUIV THEN

  (* EQUIV_STEPS_TAC [
    ("equal", 0,1,0,1);
    ("replace", 1,3,1,3);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  EQUIV_STEPS_TAC [
    ("replace", 3,5,3,5);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  (* Clean up stack_pointer expression *)
  MP_TAC stack_pointer_aligned THEN ANTS_TAC THENL
  [ASM_REWRITE_TAC[] THEN NO_TAC;
   DISCH_THEN(fun th -> RULE_ASSUM_TAC(REWRITE_RULE[th]))] THEN *)

  EQUIV_STEPS_TAC [
    ("equal",0,1,0,1);
    ("replace",1,3,1,3);
    ("equal",3,5,3,5);
    ("replace",5,6,5,6);
    ("equal",6,7,6,7);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  (* .Loop_enc1_6 *)
  AESENC_TAC (7,67) THEN
  EQUIV_STEPS_TAC [
    ("equal",72,75,72,75);
    ("replace",75,79,75,79);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  EQUIV_STEPS_TAC [
    ("equal",79,80,79,80);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  (* resolving alignment for movdqa *)
  ADD_IMP_ASSUM_TAC alignment_lemma1 THEN
  ADD_IMP_ASSUM_TAC alignment_lemma2 THEN
  (* avoid YMM8 being wrongly dropped from the assumptions *)
  ADD_ASSUM_TAC load_xts_magic_pc_equiv THEN
  ADD_ASSUM_TAC load_xts_magic_clean_pc2_equiv THEN
  EQUIV_STEPS_TAC [
    ("replace",80,84,80,84);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  FORCE_READ_EQ_TAC `YMM1` THEN
  FORCE_READ_EQ_TAC `YMM8` THEN FORCE_READ_EQ_TAC `YMM9` THEN

  TWEAK_TAC 84 `YMM10` THEN
  TWEAK_TAC 92 `YMM11` THEN
  TWEAK_TAC 100 `YMM12` THEN
  TWEAK_TAC 108 `YMM13` THEN
  TWEAK_LAST_TAC 116 `YMM14` THEN

  EQUIV_STEPS_TAC [
    ("equal",116,117,116,117);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  EQUIV_STEPS_TAC [
    ("replace",117,119,117,119);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN

  (* .Lxts_enc_short *)
  EQUIV_STEPS_TAC [
    ("replace",119,120,119,120);
    ("equal",120,121,120,121);
    ("replace",121,123,121,123);
    ("equal",123,124,123,124);
    ("replace",124,126,124,126);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  (* .Lxts_enc_one *)
  EQUIV_STEPS_TAC [
    ("replace",126,128,126,128);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  FORCE_READ_EQ_TAC `RDI` THEN
  EQUIV_STEPS_TAC [
    ("equal",128,129,128,129);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN

  EQUIV_STEPS_TAC [
    ("equal",129,131,129,131);
    ("replace",131,132,131,132);
    ("equal",132,133,132,133);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  AESENC_TAC (133,193) THEN
  EQUIV_STEPS_TAC [
    ("equal",198,202,198,202);
    ("replace",202,204,202,204);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  (* .Lxts_enc_done *)
  EQUIV_STEPS_TAC [
    ("replace",204,206,204,206);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN
  (* .Lxts_enc_ret *)
  EQUIV_STEPS_TAC [
    ("replace",206,214,206,214);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN

  EQUIV_STEPS_TAC [
    ("replace", 214,231,214,231);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN
  RULE_ASSUM_TAC (CONV_RULE (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV)) THEN

  REPEAT_N 2 ENSURES_N_FINAL_STATE_TAC THEN
  ASM_REWRITE_TAC[] THEN
  CONJ_TAC THENL [
    (** SUBGOAL 1. Outputs **)
    ASM_REWRITE_TAC[aes_xts_eqout] THEN
    REPEAT (HINT_EXISTS_REFL_TAC THEN ASM_REWRITE_TAC[]);
    (** SUBGOAL 2. Maychange pair **)
    REWRITE_TAC[MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI] THEN
    MONOTONE_MAYCHANGE_CONJ_TAC
  ]);;


let TOP_LEVEL_EQUIV = time prove(
  `forall pc pc2 in_ptr key1_ptr key2_ptr iv_ptr stack_pointer r1 out_ptr.
         ALL (nonoverlapping (word_sub stack_pointer (word 128),128))
         [word pc,LENGTH (APPEND aes_hw_xts_encrypt_mc xts_magic);
          word pc2,
          LENGTH (APPEND aes_hw_xts_encrypt_clean_mc xts_magic_clean);
          in_ptr,16; iv_ptr,16; key1_ptr,244; key2_ptr,244] /\
         ALL (nonoverlapping (out_ptr,16))
         [word pc,LENGTH (APPEND aes_hw_xts_encrypt_mc xts_magic);
          word pc2,
          LENGTH (APPEND aes_hw_xts_encrypt_clean_mc xts_magic_clean);
          (word_sub stack_pointer (word 128)),128; in_ptr,16; iv_ptr,16; key1_ptr,244; key2_ptr,244] /\
         aligned 16 stack_pointer /\
         aligned 16 (word (pc + 2480)) /\
         aligned 16 (word (pc2 + 2512))
         ==> ensures2 x86
             (\(s,s2).
                  bytes_loaded s (word pc)
                  (APPEND aes_hw_xts_encrypt_mc xts_magic) /\
                  read RIP s = word (pc + 17) /\
                  bytes_loaded s2 (word pc2)
                  (APPEND aes_hw_xts_encrypt_clean_mc xts_magic_clean) /\
                  read RIP s2 = word (pc2 + 17) /\
                  aes_xts_eqin (s,s2) in_ptr out_ptr key1_ptr key2_ptr iv_ptr
                  r1
                  stack_pointer)
             (\(s,s2).
                  bytes_loaded s (word pc)
                  (APPEND aes_hw_xts_encrypt_mc xts_magic) /\
                  read RIP s = word (pc + 1903) /\
                  bytes_loaded s2 (word pc2)
                  (APPEND aes_hw_xts_encrypt_clean_mc xts_magic_clean) /\
                  read RIP s2 = word (pc2 + 1935) /\
                  aes_xts_eqout (s,s2) r1 out_ptr)
             (\(s,s2) (s',s2').
                  (MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
                   MAYCHANGE
                   [memory :> bytes128 out_ptr;
                    memory :> bytes128 stack_pointer;
                    memory :> bytes128 (word_add stack_pointer (word 16));
                    memory :> bytes128 (word_add stack_pointer (word 32));
                    memory :> bytes128 (word_add stack_pointer (word 48));
                    memory :> bytes128 (word_add stack_pointer (word 64));
                    memory :> bytes128 (word_add stack_pointer (word 80));
                    memory :> bytes128 (word_add stack_pointer (word 96))] ,,
                   MAYCHANGE [RSP; RBP])
                  s
                  s' /\
                  (MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
                   MAYCHANGE
                   [memory :> bytes128 out_ptr;
                    memory :> bytes128 stack_pointer;
                    memory :> bytes128 (word_add stack_pointer (word 16));
                    memory :> bytes128 (word_add stack_pointer (word 32));
                    memory :> bytes128 (word_add stack_pointer (word 48));
                    memory :> bytes128 (word_add stack_pointer (word 64));
                    memory :> bytes128 (word_add stack_pointer (word 80));
                    memory :> bytes128 (word_add stack_pointer (word 96))] ,,
                   MAYCHANGE [RSP; RBP])
                  s2
                  s2')
             (\s. 237)
             (\s. 237)`,
);;

extra_word_CONV := org_extra_word_conv;;
