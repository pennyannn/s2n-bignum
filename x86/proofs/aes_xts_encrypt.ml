(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

needs "x86/proofs/equiv.ml";;

print_coda_from_elf 0x9b0 "x86/aes-xts/aes_hw_xts_encrypt.o";;
print_coda_from_elf 0x9b0 "x86/aes-xts/aes_hw_xts_encrypt_clean.o";;

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

let AES_HW_XTS_ENCRYPT_EXEC = X86_MK_EXEC_RULE aes_hw_xts_encrypt_mc;;
let AES_HW_XTS_ENCRYPT_CLEAN_EXEC = X86_MK_EXEC_RULE aes_hw_xts_encrypt_clean_mc;;

(* TODO: Currently assuming just one block *)
let aes_xts_eqin = new_definition
  `forall s1 s1' in_ptr out_ptr len key1_ptr key2_ptr iv_ptr.
    (aes_xts_eqin:(x86state#x86state)->int64->int64->int64->int64->int64->int64->bool)
      (s1,s1') in_ptr out_ptr len key1_ptr key2_ptr iv_ptr <=>
     (read RDI s1 = in_ptr /\
      read RDI s1' = in_ptr /\
      read RSI s1 = out_ptr /\
      read RSI s1' = out_ptr /\
      read RDX s1 = len /\
      read RDX s1' = len /\
      len = word 16 /\
      read RCX s1 = key1_ptr /\
      read RCX s1' = key1_ptr /\
      read R8 s1 = key2_ptr /\
      read R8 s1' = key2_ptr /\
      read R9 s1 = iv_ptr /\
      read R9 s1' = iv_ptr /\
      // Memory equivalence at in_ptr for 16-bytes (one block)
      // Q1: Why use exists?
      (exists n.
        bignum_from_memory (in_ptr,2) s1 = n /\
        bignum_from_memory (in_ptr,2) s1' = n) /\
      // Key1 equivalence, 248 is size of AES_KEY
      (exists k.
        bignum_from_memory (key1_ptr,31) s1 = k /\
        bignum_from_memory (key1_ptr,31) s1' = k) /\
      // Key2 equivalence, 248 is size of AES_KEY
      (exists k.
        bignum_from_memory (key2_ptr,31) s1 = k /\
        bignum_from_memory (key2_ptr,31) s1' = k) /\
      // iv equivalence
      (exists iv.
        bignum_from_memory (iv_ptr,2) s1 = iv /\
        bignum_from_memory (iv_ptr,2) s1' = iv)
      )`;;

let aes_xts_eqout = new_definition
  `forall s1 s1' out_ptr.
    (aes_xts_eqout:(x86state#x86state)->int64->bool) (s1,s1') out_ptr <=>
     (read RSI s1 = out_ptr /\
      read RSI s1' = out_ptr /\
      (exists n.
        bignum_from_memory (out_ptr,16) s1 = n /\
        bignum_from_memory (out_ptr,16) s1' = n))`;;

let equiv_goal = mk_equiv_statement_simple
  `ALL (nonoverlapping (out_ptr,8)) [
    (word pc:int64, LENGTH aes_hw_xts_encrypt_mc);
    (word pc2:int64, LENGTH aes_hw_xts_encrypt_clean_mc)
  ]`
  aes_xts_eqin
  aes_xts_eqout
  aes_hw_xts_encrypt_mc AES_HW_XTS_ENCRYPT_EXEC
  `MAYCHANGE [RSP] ,, MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
   MAYCHANGE [memory :> bytes (out_ptr, 16)] ,,
   MAYCHANGE SOME_FLAGS`
  aes_hw_xts_encrypt_clean_mc AES_HW_XTS_ENCRYPT_CLEAN_EXEC
  `MAYCHANGE [RSP] ,, MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
   MAYCHANGE [memory :> bytes (out_ptr, 16)] ,,
   MAYCHANGE SOME_FLAGS`;;

`forall pc pc2 in_ptr len key1_ptr key2_ptr iv_ptr out_ptr.
     ALL (nonoverlapping (out_ptr,8))
     [word pc,LENGTH aes_hw_xts_encrypt_mc;
      word pc2,LENGTH aes_hw_xts_encrypt_clean_mc]
     ==> ensures2 x86
         (\(s,s2).
              bytes_loaded s (word pc) aes_hw_xts_encrypt_mc /\
              read RIP s = word pc /\
              bytes_loaded s2 (word pc2) aes_hw_xts_encrypt_clean_mc /\
              read RIP s2 = word pc2 /\
              aes_xts_eqin (s,s2) in_ptr out_ptr len key1_ptr key2_ptr iv_ptr)
         (\(s,s2).
              bytes_loaded s (word pc) aes_hw_xts_encrypt_mc /\
              read RIP s = word (pc + 2480) /\
              bytes_loaded s2 (word pc2) aes_hw_xts_encrypt_clean_mc /\
              read RIP s2 = word (pc2 + 2480) /\
              aes_xts_eqout (s,s2) out_ptr)
         (\(s,s2) (s',s2').
              (MAYCHANGE [RSP] ,,
               MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
               MAYCHANGE [memory :> bytes (out_ptr,16)] ,,
               MAYCHANGE SOME_FLAGS)
              s
              s' /\
              (MAYCHANGE [RSP] ,,
               MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
               MAYCHANGE [memory :> bytes (out_ptr,16)] ,,
               MAYCHANGE SOME_FLAGS)
              s2
              s2')
         (\s. 544)
         (\s. 544)`

let EQUIV = prove(equiv_goal,

  (* Rewrite SOME_FLAGS, ALL, nonoverlapping, and LENGTH * *)
  REWRITE_TAC[SOME_FLAGS; ALL;NONOVERLAPPING_CLAUSES;
              fst AES_HW_XTS_ENCRYPT_EXEC; 
              fst AES_HW_XTS_ENCRYPT_CLEAN_EXEC] THEN
  REPEAT STRIP_TAC THEN

  (** Initialize **)
  EQUIV_INITIATE_TAC aes_xts_eqin THEN
  RULE_ASSUM_TAC (REWRITE_RULE[BIGNUM_FROM_MEMORY_BYTES]) THEN

  (* Do symbolic simulations on the two programs using EQUIV_STEPS_TAC.
     As explained before, the action is an OCaml list.
     Each item describes:
     - ("equal",begin line number of program 1 (start from 0),
                end line number of program 1 (not inclusive),
                begin line number of program 2,
                end line number of program 2)
       : means that these instructions in program 1 and program 2 must
         yield sysmbolically equivalent output. Therefore, EQUIV_STEPS_TAC
         uses a lock-step simulation for these.
         If the symbolic outputs of the matching instructions are not having
         equal expression, it will print an error message.
         Actually, it tries to solve a simple bit-vector equality such as
           'x * (y + 1) = x * y + x',
         and can succeed. This is exactly the example case here.
     - ("replace",beign line number of program 1,
                  end line number of program 1 (not inclusive),
                  begin line number of program 2,
                  end line number of program 2)
       : means that these instructions in program 1 and 2 differ.
         EQUIV_STEPS_TAC uses stuttering simulations for each program.
  *)
  EQUIV_STEPS_TAC [
    ("equal",0,544,0,544);
  ] AES_HW_XTS_ENCRYPT_EXEC AES_HW_XTS_ENCRYPT_CLEAN_EXEC THEN

  ENSURES_N_FINAL_STATE_TAC THEN
  REPEAT_N 2 ENSURES_N_FINAL_STATE_TAC THEN
  (* Prove remaining clauses from the postcondition *)
  ASM_REWRITE_TAC[] THEN
  (* This tactic below is typically fixed and probably you will want to reuse. :) *)
  CONJ_TAC THENL [
    (** SUBGOAL 1. Outputs **)
    ASM_REWRITE_TAC[eqout;
                    BIGNUM_EXPAND_CONV `bignum_from_memory (outbuf,1) s`] THEN
    REPEAT (HINT_EXISTS_REFL_TAC THEN ASM_REWRITE_TAC[]);

    (** SUBGOAL 2. Maychange pair **)
    MONOTONE_MAYCHANGE_CONJ_TAC
  ]);;