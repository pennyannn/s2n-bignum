(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

use_file_raise_failure := true;;
arm_print_log := true;;

needs "arm/proofs/base.ml";;
loadt "arm/proofs/aes_xts_decrypt_spec.ml";;

(* print_literal_from_elf "arm/aes-xts/aes_xts_decrypt_armv8.o";; *)
let aes_xts_decrypt_mc = define_assert_from_elf "aes_xts_decrypt_mc" "arm/aes-xts/aes_xts_decrypt_armv8.o"
[
  0xd10183ff;       (* arm_SUB SP SP (rvalue (word 0x60)) *)
  0x6d0227e8;       (* arm_STP D8 D9 SP (Immediate_Offset (iword (&0x20))) *)
  0x6d032fea;       (* arm_STP D10 D11 SP (Immediate_Offset (iword (&0x30))) *)
  0x6d0437ec;       (* arm_STP D12 D13 SP (Immediate_Offset (iword (&0x40))) *)
  0x6d053fee;       (* arm_STP D14 D15 SP (Immediate_Offset (iword (&0x50))) *)
  0xa90053f3;       (* arm_STP X19 X20 SP (Immediate_Offset (iword (&0x0))) *)
  0xa9015bf5;       (* arm_STP X21 X22 SP (Immediate_Offset (iword (&0x10))) *)
  0xf100405f;       (* arm_CMP X2 (rvalue (word 0x10)) *)
  0x5400570b;       (* arm_BLT (word 0xae0) *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0x92400c55;       (* arm_AND X21 X2 (rvalue (word 0xf)) *)
  0x927cec42;       (* arm_AND X2 X2 (rvalue (word 0xfffffffffffffff0)) *)
  0xb940f086;       (* arm_LDR W6 X4 (Immediate_Offset (word 0xf0)) *)
  0x4cdf7880;       (* arm_LDR Q0 X4 (Postimmediate_Offset (word 0x10)) *)
  0x4c4070a6;       (* arm_LDR Q6 X5 No_Offset *)
  0x510008c6;       (* arm_SUB W6 W6 (rvalue (word 0x2)) *)
  0x4cdf7881;       (* arm_LDR Q1 X4 (Postimmediate_Offset (word 0x10)) *)
  0x4e284806;       (* arm_AESE Q6 Q0 *)
  0x4e2868c6;       (* arm_AESMC Q6 Q6 *)
  0x4cdf7880;       (* arm_LDR Q0 X4 (Postimmediate_Offset (word 0x10)) *)
  0x710008c6;       (* arm_SUBS W6 W6 (rvalue (word 0x2)) *)
  0x4e284826;       (* arm_AESE Q6 Q1 *)
  0x4e2868c6;       (* arm_AESMC Q6 Q6 *)
  0x4cdf7881;       (* arm_LDR Q1 X4 (Postimmediate_Offset (word 0x10)) *)
  0x54ffff2c;       (* arm_BGT (word 0x1fffe4) *)
  0x4e284806;       (* arm_AESE Q6 Q0 *)
  0x4e2868c6;       (* arm_AESMC Q6 Q6 *)
  0x4c407880;       (* arm_LDR Q0 X4 No_Offset *)
  0x4e284826;       (* arm_AESE Q6 Q1 *)
  0x6e201cc6;       (* arm_EOR_VEC Q6 Q6 Q0 0x80 *)
  0x9e6600c9;       (* arm_FMOV_FtoI X9 Q6 0x0 0x40 *)
  0x9eae00ca;       (* arm_FMOV_FtoI X10 Q6 0x1 0x40 *)
  0x528010f3;       (* arm_MOV W19 (rvalue (word 0x87)) *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670128;       (* arm_FMOV_ItoF Q8 X9 0x0 *)
  0x9eaf0148;       (* arm_FMOV_ItoF Q8 X10 0x1 *)
  0xaa0303e7;       (* arm_MOV X7 X3 *)
  0x4cdfa8f0;       (* arm_LDP Q16 Q17 X7 (Postimmediate_Offset (word 0x20)) *)
  0x4cdfa8ec;       (* arm_LDP Q12 Q13 X7 (Postimmediate_Offset (word 0x20)) *)
  0x4cdfa8ee;       (* arm_LDP Q14 Q15 X7 (Postimmediate_Offset (word 0x20)) *)
  0x4cdfa8e4;       (* arm_LDP Q4 Q5 X7 (Postimmediate_Offset (word 0x20)) *)
  0x4cdfa8f2;       (* arm_LDP Q18 Q19 X7 (Postimmediate_Offset (word 0x20)) *)
  0x4cdfa8f4;       (* arm_LDP Q20 Q21 X7 (Postimmediate_Offset (word 0x20)) *)
  0x4cdfa8f6;       (* arm_LDP Q22 Q23 X7 (Postimmediate_Offset (word 0x20)) *)
  0x4c4078e7;       (* arm_LDR Q7 X7 No_Offset *)
  0xf2400ebf;       (* arm_TST X21 (rvalue (word 0xf)) *)
  0x54000080;       (* arm_BEQ (word 0x10) *)
  0xf1004042;       (* arm_SUBS X2 X2 (rvalue (word 0x10)) *)
  0xf100405f;       (* arm_CMP X2 (rvalue (word 0x10)) *)
  0x5400492b;       (* arm_BLT (word 0x924) *)
  0xb202e7e8;       (* arm_MOV X8 (rvalue (word 0xcccccccccccccccc)) *)
  0xf29999a8;       (* arm_MOVK X8 (word 0xcccd) 0x0 *)
  0x9bc87c48;       (* arm_UMULH X8 X2 X8 *)
  0xd346fd08;       (* arm_LSR X8 X8 0x6 *)
  0xf100805f;       (* arm_CMP X2 (rvalue (word 0x20)) *)
  0x54004343;       (* arm_BCC (word 0x868) *)
  0xf100c05f;       (* arm_CMP X2 (rvalue (word 0x30)) *)
  0x54003a23;       (* arm_BCC (word 0x744) *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670129;       (* arm_FMOV_ItoF Q9 X9 0x0 *)
  0x9eaf0149;       (* arm_FMOV_ItoF Q9 X10 0x1 *)
  0xf101005f;       (* arm_CMP X2 (rvalue (word 0x40)) *)
  0x54002c43;       (* arm_BCC (word 0x588) *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e67012a;       (* arm_FMOV_ItoF Q10 X9 0x0 *)
  0x9eaf014a;       (* arm_FMOV_ItoF Q10 X10 0x1 *)
  0xf101405f;       (* arm_CMP X2 (rvalue (word 0x50)) *)
  0x54001a43;       (* arm_BCC (word 0x348) *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e67012b;       (* arm_FMOV_ItoF Q11 X9 0x0 *)
  0x9eaf014b;       (* arm_FMOV_ItoF Q11 X10 0x1 *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0xacc28400;       (* arm_LDP Q0 Q1 X0 (Postimmediate_Offset (iword (&0x50))) *)
  0xad7ee418;       (* arm_LDP Q24 Q25 X0 (Immediate_Offset (iword (-- &0x30))) *)
  0x3cdf001a;       (* arm_LDR Q26 X0 (Immediate_Offset (word 0xfffffffffffffff0)) *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x6e281c21;       (* arm_EOR_VEC Q1 Q1 Q8 0x80 *)
  0x6e291f18;       (* arm_EOR_VEC Q24 Q24 Q9 0x80 *)
  0x6e2a1f39;       (* arm_EOR_VEC Q25 Q25 Q10 0x80 *)
  0x6e2b1f5a;       (* arm_EOR_VEC Q26 Q26 Q11 0x80 *)
  0x4e285a00;       (* arm_AESD Q0 Q16 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a01;       (* arm_AESD Q1 Q16 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a18;       (* arm_AESD Q24 Q16 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a19;       (* arm_AESD Q25 Q16 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a1a;       (* arm_AESD Q26 Q16 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285a20;       (* arm_AESD Q0 Q17 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a21;       (* arm_AESD Q1 Q17 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a38;       (* arm_AESD Q24 Q17 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a39;       (* arm_AESD Q25 Q17 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a3a;       (* arm_AESD Q26 Q17 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285980;       (* arm_AESD Q0 Q12 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285981;       (* arm_AESD Q1 Q12 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285998;       (* arm_AESD Q24 Q12 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285999;       (* arm_AESD Q25 Q12 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e28599a;       (* arm_AESD Q26 Q12 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e2859a0;       (* arm_AESD Q0 Q13 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859a1;       (* arm_AESD Q1 Q13 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859b8;       (* arm_AESD Q24 Q13 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859b9;       (* arm_AESD Q25 Q13 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e2859ba;       (* arm_AESD Q26 Q13 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e2859c0;       (* arm_AESD Q0 Q14 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859c1;       (* arm_AESD Q1 Q14 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859d8;       (* arm_AESD Q24 Q14 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859d9;       (* arm_AESD Q25 Q14 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e2859da;       (* arm_AESD Q26 Q14 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e2859e0;       (* arm_AESD Q0 Q15 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859e1;       (* arm_AESD Q1 Q15 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859f8;       (* arm_AESD Q24 Q15 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859f9;       (* arm_AESD Q25 Q15 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e2859fa;       (* arm_AESD Q26 Q15 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285880;       (* arm_AESD Q0 Q4 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285881;       (* arm_AESD Q1 Q4 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285898;       (* arm_AESD Q24 Q4 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285899;       (* arm_AESD Q25 Q4 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e28589a;       (* arm_AESD Q26 Q4 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e2858a0;       (* arm_AESD Q0 Q5 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2858a1;       (* arm_AESD Q1 Q5 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2858b8;       (* arm_AESD Q24 Q5 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2858b9;       (* arm_AESD Q25 Q5 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e2858ba;       (* arm_AESD Q26 Q5 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285a40;       (* arm_AESD Q0 Q18 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a41;       (* arm_AESD Q1 Q18 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a58;       (* arm_AESD Q24 Q18 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a59;       (* arm_AESD Q25 Q18 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a5a;       (* arm_AESD Q26 Q18 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285a60;       (* arm_AESD Q0 Q19 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a61;       (* arm_AESD Q1 Q19 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a78;       (* arm_AESD Q24 Q19 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a79;       (* arm_AESD Q25 Q19 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a7a;       (* arm_AESD Q26 Q19 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285a80;       (* arm_AESD Q0 Q20 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a81;       (* arm_AESD Q1 Q20 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a98;       (* arm_AESD Q24 Q20 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a99;       (* arm_AESD Q25 Q20 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a9a;       (* arm_AESD Q26 Q20 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285aa0;       (* arm_AESD Q0 Q21 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285aa1;       (* arm_AESD Q1 Q21 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285ab8;       (* arm_AESD Q24 Q21 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285ab9;       (* arm_AESD Q25 Q21 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285aba;       (* arm_AESD Q26 Q21 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285ac0;       (* arm_AESD Q0 Q22 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285ac1;       (* arm_AESD Q1 Q22 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285ad8;       (* arm_AESD Q24 Q22 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285ad9;       (* arm_AESD Q25 Q22 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285ada;       (* arm_AESD Q26 Q22 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4e285ae0;       (* arm_AESD Q0 Q23 *)
  0x4e285ae1;       (* arm_AESD Q1 Q23 *)
  0x4e285af8;       (* arm_AESD Q24 Q23 *)
  0x4e285af9;       (* arm_AESD Q25 Q23 *)
  0x4e285afa;       (* arm_AESD Q26 Q23 *)
  0x6e271c00;       (* arm_EOR_VEC Q0 Q0 Q7 0x80 *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670126;       (* arm_FMOV_ItoF Q6 X9 0x0 *)
  0x9eaf0146;       (* arm_FMOV_ItoF Q6 X10 0x1 *)
  0x6e271c21;       (* arm_EOR_VEC Q1 Q1 Q7 0x80 *)
  0x6e281c21;       (* arm_EOR_VEC Q1 Q1 Q8 0x80 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670128;       (* arm_FMOV_ItoF Q8 X9 0x0 *)
  0x9eaf0148;       (* arm_FMOV_ItoF Q8 X10 0x1 *)
  0x6e271f18;       (* arm_EOR_VEC Q24 Q24 Q7 0x80 *)
  0x6e291f18;       (* arm_EOR_VEC Q24 Q24 Q9 0x80 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670129;       (* arm_FMOV_ItoF Q9 X9 0x0 *)
  0x9eaf0149;       (* arm_FMOV_ItoF Q9 X10 0x1 *)
  0x6e271f39;       (* arm_EOR_VEC Q25 Q25 Q7 0x80 *)
  0x6e2a1f39;       (* arm_EOR_VEC Q25 Q25 Q10 0x80 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e67012a;       (* arm_FMOV_ItoF Q10 X9 0x0 *)
  0x9eaf014a;       (* arm_FMOV_ItoF Q10 X10 0x1 *)
  0x6e271f5a;       (* arm_EOR_VEC Q26 Q26 Q7 0x80 *)
  0x6e2b1f5a;       (* arm_EOR_VEC Q26 Q26 Q11 0x80 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e67012b;       (* arm_FMOV_ItoF Q11 X9 0x0 *)
  0x9eaf014b;       (* arm_FMOV_ItoF Q11 X10 0x1 *)
  0xac828420;       (* arm_STP Q0 Q1 X1 (Postimmediate_Offset (iword (&0x50))) *)
  0xad3ee438;       (* arm_STP Q24 Q25 X1 (Immediate_Offset (iword (-- &0x30))) *)
  0x3c9f003a;       (* arm_STR Q26 X1 (Immediate_Offset (word 0xfffffffffffffff0)) *)
  0xf1014042;       (* arm_SUBS X2 X2 (rvalue (word 0x50)) *)
  0xf1000508;       (* arm_SUBS X8 X8 (rvalue (word 0x1)) *)
  0xb5ffe888;       (* arm_CBNZ X8 (word 0x1ffd10) *)
  0xf101005f;       (* arm_CMP X2 (rvalue (word 0x40)) *)
  0x54000140;       (* arm_BEQ (word 0x28) *)
  0xf100c05f;       (* arm_CMP X2 (rvalue (word 0x30)) *)
  0x54001200;       (* arm_BEQ (word 0x240) *)
  0xf100805f;       (* arm_CMP X2 (rvalue (word 0x20)) *)
  0x54001ea0;       (* arm_BEQ (word 0x3d4) *)
  0xf100405f;       (* arm_CMP X2 (rvalue (word 0x10)) *)
  0x54002740;       (* arm_BEQ (word 0x4e8) *)
  0x14000162;       (* arm_B (word 0x588) *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0x4cdfa000;       (* arm_LDP Q0 Q1 X0 (Postimmediate_Offset (word 0x20)) *)
  0x4cdfa018;       (* arm_LDP Q24 Q25 X0 (Postimmediate_Offset (word 0x20)) *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x6e281c21;       (* arm_EOR_VEC Q1 Q1 Q8 0x80 *)
  0x6e291f18;       (* arm_EOR_VEC Q24 Q24 Q9 0x80 *)
  0x6e2a1f39;       (* arm_EOR_VEC Q25 Q25 Q10 0x80 *)
  0x4e285a00;       (* arm_AESD Q0 Q16 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a01;       (* arm_AESD Q1 Q16 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a18;       (* arm_AESD Q24 Q16 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a19;       (* arm_AESD Q25 Q16 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a20;       (* arm_AESD Q0 Q17 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a21;       (* arm_AESD Q1 Q17 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a38;       (* arm_AESD Q24 Q17 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a39;       (* arm_AESD Q25 Q17 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285980;       (* arm_AESD Q0 Q12 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285981;       (* arm_AESD Q1 Q12 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285998;       (* arm_AESD Q24 Q12 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285999;       (* arm_AESD Q25 Q12 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e2859a0;       (* arm_AESD Q0 Q13 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859a1;       (* arm_AESD Q1 Q13 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859b8;       (* arm_AESD Q24 Q13 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859b9;       (* arm_AESD Q25 Q13 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e2859c0;       (* arm_AESD Q0 Q14 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859c1;       (* arm_AESD Q1 Q14 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859d8;       (* arm_AESD Q24 Q14 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859d9;       (* arm_AESD Q25 Q14 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e2859e0;       (* arm_AESD Q0 Q15 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859e1;       (* arm_AESD Q1 Q15 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859f8;       (* arm_AESD Q24 Q15 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859f9;       (* arm_AESD Q25 Q15 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285880;       (* arm_AESD Q0 Q4 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285881;       (* arm_AESD Q1 Q4 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285898;       (* arm_AESD Q24 Q4 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285899;       (* arm_AESD Q25 Q4 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e2858a0;       (* arm_AESD Q0 Q5 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2858a1;       (* arm_AESD Q1 Q5 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2858b8;       (* arm_AESD Q24 Q5 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2858b9;       (* arm_AESD Q25 Q5 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a40;       (* arm_AESD Q0 Q18 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a41;       (* arm_AESD Q1 Q18 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a58;       (* arm_AESD Q24 Q18 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a59;       (* arm_AESD Q25 Q18 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a60;       (* arm_AESD Q0 Q19 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a61;       (* arm_AESD Q1 Q19 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a78;       (* arm_AESD Q24 Q19 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a79;       (* arm_AESD Q25 Q19 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285a80;       (* arm_AESD Q0 Q20 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a81;       (* arm_AESD Q1 Q20 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a98;       (* arm_AESD Q24 Q20 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a99;       (* arm_AESD Q25 Q20 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285aa0;       (* arm_AESD Q0 Q21 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285aa1;       (* arm_AESD Q1 Q21 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285ab8;       (* arm_AESD Q24 Q21 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285ab9;       (* arm_AESD Q25 Q21 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285ac0;       (* arm_AESD Q0 Q22 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285ac1;       (* arm_AESD Q1 Q22 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285ad8;       (* arm_AESD Q24 Q22 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285ad9;       (* arm_AESD Q25 Q22 *)
  0x4e287b39;       (* arm_AESIMC Q25 Q25 *)
  0x4e285ae0;       (* arm_AESD Q0 Q23 *)
  0x4e285ae1;       (* arm_AESD Q1 Q23 *)
  0x4e285af8;       (* arm_AESD Q24 Q23 *)
  0x4e285af9;       (* arm_AESD Q25 Q23 *)
  0x6e271c00;       (* arm_EOR_VEC Q0 Q0 Q7 0x80 *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x6e271c21;       (* arm_EOR_VEC Q1 Q1 Q7 0x80 *)
  0x6e281c21;       (* arm_EOR_VEC Q1 Q1 Q8 0x80 *)
  0x6e271f18;       (* arm_EOR_VEC Q24 Q24 Q7 0x80 *)
  0x6e291f18;       (* arm_EOR_VEC Q24 Q24 Q9 0x80 *)
  0x6e271f39;       (* arm_EOR_VEC Q25 Q25 Q7 0x80 *)
  0x6e2a1f39;       (* arm_EOR_VEC Q25 Q25 Q10 0x80 *)
  0x9e660149;       (* arm_FMOV_FtoI X9 Q10 0x0 0x40 *)
  0x9eae014a;       (* arm_FMOV_FtoI X10 Q10 0x1 0x40 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670126;       (* arm_FMOV_ItoF Q6 X9 0x0 *)
  0x9eaf0146;       (* arm_FMOV_ItoF Q6 X10 0x1 *)
  0x4c9fa020;       (* arm_STP Q0 Q1 X1 (Postimmediate_Offset (word 0x20)) *)
  0x4c9fa038;       (* arm_STP Q24 Q25 X1 (Postimmediate_Offset (word 0x20)) *)
  0x140000db;       (* arm_B (word 0x36c) *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0xd503201f;       (* arm_NOP *)
  0x4cdfa000;       (* arm_LDP Q0 Q1 X0 (Postimmediate_Offset (word 0x20)) *)
  0x4cdf7018;       (* arm_LDR Q24 X0 (Postimmediate_Offset (word 0x10)) *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x6e281c21;       (* arm_EOR_VEC Q1 Q1 Q8 0x80 *)
  0x6e291f18;       (* arm_EOR_VEC Q24 Q24 Q9 0x80 *)
  0x4e285a00;       (* arm_AESD Q0 Q16 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a01;       (* arm_AESD Q1 Q16 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a18;       (* arm_AESD Q24 Q16 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a20;       (* arm_AESD Q0 Q17 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a21;       (* arm_AESD Q1 Q17 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a38;       (* arm_AESD Q24 Q17 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285980;       (* arm_AESD Q0 Q12 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285981;       (* arm_AESD Q1 Q12 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285998;       (* arm_AESD Q24 Q12 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859a0;       (* arm_AESD Q0 Q13 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859a1;       (* arm_AESD Q1 Q13 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859b8;       (* arm_AESD Q24 Q13 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859c0;       (* arm_AESD Q0 Q14 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859c1;       (* arm_AESD Q1 Q14 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859d8;       (* arm_AESD Q24 Q14 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2859e0;       (* arm_AESD Q0 Q15 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859e1;       (* arm_AESD Q1 Q15 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859f8;       (* arm_AESD Q24 Q15 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285880;       (* arm_AESD Q0 Q4 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285881;       (* arm_AESD Q1 Q4 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285898;       (* arm_AESD Q24 Q4 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e2858a0;       (* arm_AESD Q0 Q5 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2858a1;       (* arm_AESD Q1 Q5 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2858b8;       (* arm_AESD Q24 Q5 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a40;       (* arm_AESD Q0 Q18 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a41;       (* arm_AESD Q1 Q18 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a58;       (* arm_AESD Q24 Q18 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a60;       (* arm_AESD Q0 Q19 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a61;       (* arm_AESD Q1 Q19 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a78;       (* arm_AESD Q24 Q19 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285a80;       (* arm_AESD Q0 Q20 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a81;       (* arm_AESD Q1 Q20 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a98;       (* arm_AESD Q24 Q20 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285aa0;       (* arm_AESD Q0 Q21 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285aa1;       (* arm_AESD Q1 Q21 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285ab8;       (* arm_AESD Q24 Q21 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285ac0;       (* arm_AESD Q0 Q22 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285ac1;       (* arm_AESD Q1 Q22 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285ad8;       (* arm_AESD Q24 Q22 *)
  0x4e287b18;       (* arm_AESIMC Q24 Q24 *)
  0x4e285ae0;       (* arm_AESD Q0 Q23 *)
  0x4e285ae1;       (* arm_AESD Q1 Q23 *)
  0x4e285af8;       (* arm_AESD Q24 Q23 *)
  0x6e271c00;       (* arm_EOR_VEC Q0 Q0 Q7 0x80 *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x6e271c21;       (* arm_EOR_VEC Q1 Q1 Q7 0x80 *)
  0x6e281c21;       (* arm_EOR_VEC Q1 Q1 Q8 0x80 *)
  0x6e271f18;       (* arm_EOR_VEC Q24 Q24 Q7 0x80 *)
  0x6e291f18;       (* arm_EOR_VEC Q24 Q24 Q9 0x80 *)
  0x9e660129;       (* arm_FMOV_FtoI X9 Q9 0x0 0x40 *)
  0x9eae012a;       (* arm_FMOV_FtoI X10 Q9 0x1 0x40 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670126;       (* arm_FMOV_ItoF Q6 X9 0x0 *)
  0x9eaf0146;       (* arm_FMOV_ItoF Q6 X10 0x1 *)
  0x4c9fa020;       (* arm_STP Q0 Q1 X1 (Postimmediate_Offset (word 0x20)) *)
  0x4c9f7038;       (* arm_STR Q24 X1 (Postimmediate_Offset (word 0x10)) *)
  0x14000071;       (* arm_B (word 0x1c4) *)
  0x4cdfa000;       (* arm_LDP Q0 Q1 X0 (Postimmediate_Offset (word 0x20)) *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x6e281c21;       (* arm_EOR_VEC Q1 Q1 Q8 0x80 *)
  0x4e285a00;       (* arm_AESD Q0 Q16 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a01;       (* arm_AESD Q1 Q16 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a20;       (* arm_AESD Q0 Q17 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a21;       (* arm_AESD Q1 Q17 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285980;       (* arm_AESD Q0 Q12 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285981;       (* arm_AESD Q1 Q12 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859a0;       (* arm_AESD Q0 Q13 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859a1;       (* arm_AESD Q1 Q13 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859c0;       (* arm_AESD Q0 Q14 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859c1;       (* arm_AESD Q1 Q14 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2859e0;       (* arm_AESD Q0 Q15 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859e1;       (* arm_AESD Q1 Q15 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285880;       (* arm_AESD Q0 Q4 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285881;       (* arm_AESD Q1 Q4 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e2858a0;       (* arm_AESD Q0 Q5 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2858a1;       (* arm_AESD Q1 Q5 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a40;       (* arm_AESD Q0 Q18 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a41;       (* arm_AESD Q1 Q18 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a60;       (* arm_AESD Q0 Q19 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a61;       (* arm_AESD Q1 Q19 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285a80;       (* arm_AESD Q0 Q20 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a81;       (* arm_AESD Q1 Q20 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285aa0;       (* arm_AESD Q0 Q21 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285aa1;       (* arm_AESD Q1 Q21 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285ac0;       (* arm_AESD Q0 Q22 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285ac1;       (* arm_AESD Q1 Q22 *)
  0x4e287821;       (* arm_AESIMC Q1 Q1 *)
  0x4e285ae0;       (* arm_AESD Q0 Q23 *)
  0x4e285ae1;       (* arm_AESD Q1 Q23 *)
  0x6e271c00;       (* arm_EOR_VEC Q0 Q0 Q7 0x80 *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x6e271c21;       (* arm_EOR_VEC Q1 Q1 Q7 0x80 *)
  0x6e281c21;       (* arm_EOR_VEC Q1 Q1 Q8 0x80 *)
  0x4c9fa020;       (* arm_STP Q0 Q1 X1 (Postimmediate_Offset (word 0x20)) *)
  0x9e660109;       (* arm_FMOV_FtoI X9 Q8 0x0 0x40 *)
  0x9eae010a;       (* arm_FMOV_FtoI X10 Q8 0x1 0x40 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670126;       (* arm_FMOV_ItoF Q6 X9 0x0 *)
  0x9eaf0146;       (* arm_FMOV_ItoF Q6 X10 0x1 *)
  0x1400002a;       (* arm_B (word 0xa8) *)
  0x4cdf7000;       (* arm_LDR Q0 X0 (Postimmediate_Offset (word 0x10)) *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x4e285a00;       (* arm_AESD Q0 Q16 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a20;       (* arm_AESD Q0 Q17 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285980;       (* arm_AESD Q0 Q12 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859a0;       (* arm_AESD Q0 Q13 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859c0;       (* arm_AESD Q0 Q14 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2859e0;       (* arm_AESD Q0 Q15 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285880;       (* arm_AESD Q0 Q4 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e2858a0;       (* arm_AESD Q0 Q5 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a40;       (* arm_AESD Q0 Q18 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a60;       (* arm_AESD Q0 Q19 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285a80;       (* arm_AESD Q0 Q20 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285aa0;       (* arm_AESD Q0 Q21 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285ac0;       (* arm_AESD Q0 Q22 *)
  0x4e287800;       (* arm_AESIMC Q0 Q0 *)
  0x4e285ae0;       (* arm_AESD Q0 Q23 *)
  0x6e271c00;       (* arm_EOR_VEC Q0 Q0 Q7 0x80 *)
  0x6e261c00;       (* arm_EOR_VEC Q0 Q0 Q6 0x80 *)
  0x4c9f7020;       (* arm_STR Q0 X1 (Postimmediate_Offset (word 0x10)) *)
  0x9e6600c9;       (* arm_FMOV_FtoI X9 Q6 0x0 0x40 *)
  0x9eae00ca;       (* arm_FMOV_FtoI X10 Q6 0x1 0x40 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670126;       (* arm_FMOV_ItoF Q6 X9 0x0 *)
  0x9eaf0146;       (* arm_FMOV_ItoF Q6 X10 0x1 *)
  0x14000001;       (* arm_B (word 0x4) *)
  0xf2400ebf;       (* arm_TST X21 (rvalue (word 0xf)) *)
  0x54000780;       (* arm_BEQ (word 0xf0) *)
  0xaa0303e7;       (* arm_MOV X7 X3 *)
  0x9e6600c9;       (* arm_FMOV_FtoI X9 Q6 0x0 0x40 *)
  0x9eae00ca;       (* arm_FMOV_FtoI X10 Q6 0x1 0x40 *)
  0x93ca8156;       (* arm_ROR X22 X10 0x20 *)
  0x93c9fd4a;       (* arm_EXTR X10 X10 X9 0x3f *)
  0x0a967e6b;       (* arm_AND W11 W19 (Shiftedreg W22 ASR 0x1f) *)
  0xca090569;       (* arm_EOR X9 X11 (Shiftedreg X9 LSL 0x1) *)
  0x9e670128;       (* arm_FMOV_ItoF Q8 X9 0x0 *)
  0x9eaf0148;       (* arm_FMOV_ItoF Q8 X10 0x1 *)
  0x4cdf7800;       (* arm_LDR Q0 X0 (Postimmediate_Offset (word 0x10)) *)
  0x6e281c1a;       (* arm_EOR_VEC Q26 Q0 Q8 0x80 *)
  0xb940f066;       (* arm_LDR W6 X3 (Immediate_Offset (word 0xf0)) *)
  0x4cdf7860;       (* arm_LDR Q0 X3 (Postimmediate_Offset (word 0x10)) *)
  0x510008c6;       (* arm_SUB W6 W6 (rvalue (word 0x2)) *)
  0x4cdf7861;       (* arm_LDR Q1 X3 (Postimmediate_Offset (word 0x10)) *)
  0x4e28581a;       (* arm_AESD Q26 Q0 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4cdf7860;       (* arm_LDR Q0 X3 (Postimmediate_Offset (word 0x10)) *)
  0x710008c6;       (* arm_SUBS W6 W6 (rvalue (word 0x2)) *)
  0x4e28583a;       (* arm_AESD Q26 Q1 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4cdf7861;       (* arm_LDR Q1 X3 (Postimmediate_Offset (word 0x10)) *)
  0x54ffff2c;       (* arm_BGT (word 0x1fffe4) *)
  0x4e28581a;       (* arm_AESD Q26 Q0 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4c407860;       (* arm_LDR Q0 X3 No_Offset *)
  0x4e28583a;       (* arm_AESD Q26 Q1 *)
  0x6e201f5a;       (* arm_EOR_VEC Q26 Q26 Q0 0x80 *)
  0x6e281f5a;       (* arm_EOR_VEC Q26 Q26 Q8 0x80 *)
  0x4c00703a;       (* arm_STR Q26 X1 No_Offset *)
  0xaa0003f4;       (* arm_MOV X20 X0 *)
  0x9100402d;       (* arm_ADD X13 X1 (rvalue (word 0x10)) *)
  0xf10006b5;       (* arm_SUBS X21 X21 (rvalue (word 0x1)) *)
  0x3875682f;       (* arm_LDRB W15 X1 (Register_Offset X21) *)
  0x38756a8e;       (* arm_LDRB W14 X20 (Register_Offset X21) *)
  0x383569af;       (* arm_STRB W15 X13 (Register_Offset X21) *)
  0x3835682e;       (* arm_STRB W14 X1 (Register_Offset X21) *)
  0x54ffff6c;       (* arm_BGT (word 0x1fffec) *)
  0x4c40703a;       (* arm_LDR Q26 X1 No_Offset *)
  0x6e261f5a;       (* arm_EOR_VEC Q26 Q26 Q6 0x80 *)
  0xb940f0e6;       (* arm_LDR W6 X7 (Immediate_Offset (word 0xf0)) *)
  0x4cdf70e0;       (* arm_LDR Q0 X7 (Postimmediate_Offset (word 0x10)) *)
  0x510008c6;       (* arm_SUB W6 W6 (rvalue (word 0x2)) *)
  0x4cdf70e1;       (* arm_LDR Q1 X7 (Postimmediate_Offset (word 0x10)) *)
  0x4e28581a;       (* arm_AESD Q26 Q0 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4cdf78e0;       (* arm_LDR Q0 X7 (Postimmediate_Offset (word 0x10)) *)
  0x710008c6;       (* arm_SUBS W6 W6 (rvalue (word 0x2)) *)
  0x4e28583a;       (* arm_AESD Q26 Q1 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4cdf78e1;       (* arm_LDR Q1 X7 (Postimmediate_Offset (word 0x10)) *)
  0x54ffff2c;       (* arm_BGT (word 0x1fffe4) *)
  0x4e28581a;       (* arm_AESD Q26 Q0 *)
  0x4e287b5a;       (* arm_AESIMC Q26 Q26 *)
  0x4c4078e0;       (* arm_LDR Q0 X7 No_Offset *)
  0x4e28583a;       (* arm_AESD Q26 Q1 *)
  0x6e201f5a;       (* arm_EOR_VEC Q26 Q26 Q0 0x80 *)
  0x6e261f5a;       (* arm_EOR_VEC Q26 Q26 Q6 0x80 *)
  0x4c00703a;       (* arm_STR Q26 X1 No_Offset *)
  0x6d4227e8;       (* arm_LDP D8 D9 SP (Immediate_Offset (iword (&0x20))) *)
  0x6d432fea;       (* arm_LDP D10 D11 SP (Immediate_Offset (iword (&0x30))) *)
  0x6d4437ec;       (* arm_LDP D12 D13 SP (Immediate_Offset (iword (&0x40))) *)
  0x6d453fee;       (* arm_LDP D14 D15 SP (Immediate_Offset (iword (&0x50))) *)
  0xa94053f3;       (* arm_LDP X19 X20 SP (Immediate_Offset (iword (&0x0))) *)
  0xa9415bf5;       (* arm_LDP X21 X22 SP (Immediate_Offset (iword (&0x10))) *)
  0x910183ff;       (* arm_ADD SP SP (rvalue (word 0x60)) *)
  0xd65f03c0        (* arm_RET X30 *)
];;

let AES_XTS_DECRYPT_EXEC = ARM_MK_EXEC_RULE aes_xts_decrypt_mc;;

(** Definitions **)

let set_key_schedule = new_definition
  `set_key_schedule (s:armstate) (key_ptr:int64) (k0:int128)
     (k1:int128) (k2:int128) (k3:int128) (k4:int128) (k5:int128)
     (k6:int128) (k7:int128) (k8:int128) (k9:int128) (ka:int128)
     (kb:int128) (kc:int128) (kd:int128) (ke:int128) : bool =
     (read(memory :> bytes128 key_ptr) s = k0 /\
      read(memory :> bytes128 (word_add key_ptr (word 16))) s = k1 /\
      read(memory :> bytes128 (word_add key_ptr (word 32))) s = k2 /\
      read(memory :> bytes128 (word_add key_ptr (word 48))) s = k3 /\
      read(memory :> bytes128 (word_add key_ptr (word 64))) s = k4 /\
      read(memory :> bytes128 (word_add key_ptr (word 80))) s = k5 /\
      read(memory :> bytes128 (word_add key_ptr (word 96))) s = k6 /\
      read(memory :> bytes128 (word_add key_ptr (word 112))) s = k7 /\
      read(memory :> bytes128 (word_add key_ptr (word 128))) s = k8 /\
      read(memory :> bytes128 (word_add key_ptr (word 144))) s = k9 /\
      read(memory :> bytes128 (word_add key_ptr (word 160))) s = ka /\
      read(memory :> bytes128 (word_add key_ptr (word 176))) s = kb /\
      read(memory :> bytes128 (word_add key_ptr (word 192))) s = kc /\
      read(memory :> bytes128 (word_add key_ptr (word 208))) s = kd /\
      read(memory :> bytes128 (word_add key_ptr (word 224))) s = ke /\
      read(memory :> bytes32 (word_add key_ptr (word 240))) s = word 14)`;;

(** Tactics **)

let AESENC_TAC =
  REWRITE_TAC [aes256_encrypt] THEN
  REWRITE_TAC EL_15_128_CLAUSES THEN
  REWRITE_TAC [aes256_encrypt_round] THEN
  CONV_TAC(TOP_DEPTH_CONV let_CONV) THEN
  REWRITE_TAC [aese;aesmc] THEN
  GEN_REWRITE_TAC LAND_CONV [WORD_XOR_SYM] THEN
  REFL_TAC;;

let AESDEC_TAC =
  REWRITE_TAC [aes256_decrypt] THEN
  REWRITE_TAC EL_15_128_CLAUSES THEN
  CONV_TAC(TOP_DEPTH_CONV let_CONV) THEN
  REWRITE_TAC [aes256_decrypt_round] THEN
  CONV_TAC(TOP_DEPTH_CONV let_CONV) THEN
  REWRITE_TAC [aesd;aesimc] THEN
  (* NOTE: BITBLAST_TAC couldn't handle this goal *)
  GEN_REWRITE_TAC LAND_CONV [WORD_XOR_SYM] THEN
  AP_THM_TAC THEN AP_TERM_TAC THEN
  GEN_REWRITE_TAC LAND_CONV [WORD_XOR_SYM] THEN
  AP_THM_TAC THEN AP_TERM_TAC THEN AP_TERM_TAC THEN AP_TERM_TAC THEN
  REPLICATE_TAC 13 (AP_THM_TAC THEN (REPLICATE_TAC 4 AP_TERM_TAC)) THEN
  AP_THM_TAC THEN AP_TERM_TAC THEN
  GEN_REWRITE_TAC LAND_CONV [WORD_XOR_SYM] THEN REFL_TAC;;

(** Proof **)

let AES_XTS_DECRYPT_CORRECT = prove(
  `!ct_ptr pt_ptr key0_ptr key1_ptr iv_ptr ib iv
    k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k0a k0b k0c k0d k0e
    k10 k11 k12 k13 k14 k15 k16 k17 k18 k19 k1a k1b k1c k1d k1e
    pc.
    nonoverlapping (word pc, LENGTH aes_xts_decrypt_mc) (pt_ptr, 16)
    ==> ensures arm
    (\s. aligned_bytes_loaded s (word pc) aes_xts_decrypt_mc /\
         read PC s = word (pc + 0x1c) /\
         C_ARGUMENTS [ct_ptr; pt_ptr; word 16; key0_ptr; key1_ptr; iv_ptr] s /\
         read(memory :> bytes128 ct_ptr) s = ib /\
         read(memory :> bytes128 iv_ptr) s = iv /\
         set_key_schedule s key0_ptr k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k0a k0b k0c k0d k0e /\
         set_key_schedule s key1_ptr k10 k11 k12 k13 k14 k15 k16 k17 k18 k19 k1a k1b k1c k1d k1e)
    (\s. read PC s = word (pc + 0xa10) /\
         read(memory :> bytes128 pt_ptr) s =
           aes256_xts_decrypt_1block ib iv
           [k00; k01; k02; k03; k04; k05; k06; k07; k08; k09; k0a; k0b; k0c; k0d; k0e]
           [k10; k11; k12; k13; k14; k15; k16; k17; k18; k19; k1a; k1b; k1c; k1d; k1e]
         )
    (MAYCHANGE [PC] ,, MAYCHANGE [events] ,,
     MAYCHANGE [X21;X2;X6;X4;X9;X10;X19;X22;X11;X7;X0;X1;X8] ,,
     MAYCHANGE [Q6;Q1;Q0;Q8;Q16;Q17;Q12;Q13;Q14;Q15;Q4;Q5;Q18;Q19;Q20;Q21;Q22;Q23;Q7;Q29;Q24] ,,
     MAYCHANGE SOME_FLAGS,, MAYCHANGE [memory :> bytes128 pt_ptr])
    `,
  REWRITE_TAC [(REWRITE_CONV [aes_xts_decrypt_mc] THENC LENGTH_CONV) `LENGTH aes_xts_decrypt_mc`] THEN
  REWRITE_TAC[set_key_schedule; C_ARGUMENTS; SOME_FLAGS; NONOVERLAPPING_CLAUSES] THEN
  REPEAT STRIP_TAC THEN

  (* Start symbolic simulation*)
  ENSURES_INIT_TAC "s0" THEN
  (* Simulate until the first tweak and verify the first tweak equiv the spec *)
  ARM_ACCSTEPS_TAC AES_XTS_DECRYPT_EXEC [] (1--69) THEN
  FIRST_X_ASSUM(MP_TAC o SPEC
    `(aes256_encrypt iv [k10; k11; k12; k13; k14; k15; k16; k17; k18; k19; k1a; k1b; k1c; k1d; k1e]):int128`
    o  MATCH_MP (MESON[] `read Q6 s = a ==> !a'. a = a' ==> read Q6 s = a'`)) THEN
  ANTS_TAC THENL [ASM_REWRITE_TAC[] THEN AESENC_TAC; DISCH_TAC] THEN

  (* Simulating until finish decrypting one block *)
  ARM_ACCSTEPS_TAC AES_XTS_DECRYPT_EXEC [] (70--126) THEN
  FIRST_X_ASSUM(MP_TAC o
    SPEC `(aes256_xts_decrypt_1block ib iv
       [k00; k01; k02; k03; k04; k05; k06; k07; k08; k09; k0a; k0b; k0c; k0d; k0e]
       [k10; k11; k12; k13; k14; k15; k16; k17; k18; k19; k1a; k1b; k1c; k1d; k1e]):int128`
    o  MATCH_MP (MESON[] `read Q0 s = a ==> !a'. a = a' ==> read Q0 s = a'`)) THEN
  ANTS_TAC THENL [
    REWRITE_TAC [aes256_xts_decrypt_1block] THEN
    REWRITE_TAC [xts_init_tweak] THEN
    CONV_TAC(TOP_DEPTH_CONV let_CONV) THEN
    REWRITE_TAC [aes256_xts_decrypt_round] THEN
    CONV_TAC(TOP_DEPTH_CONV let_CONV) THEN
    AESDEC_TAC; DISCH_TAC] THEN

    (* Simulate to the end *)
    ARM_ACCSTEPS_TAC AES_XTS_DECRYPT_EXEC [] (127--137) THEN
    ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC []
);;


(*******************************************)
(* Full proof *)

(* Taken from Amanda's code at https://github.com/amanda-zx/s2n-bignum/blob/ed25519/arm/sha512/utils.ml *)

let byte_list_at = define
  `byte_list_at (m : byte list) (m_p : int64) s =
    ! i. i < LENGTH m ==> read (memory :> bytes8(word_add m_p (word i))) s = EL i m`;;

let tail_len_lt_16_lemma = prove(
  `!tail_len:int64.
    word_and len (word 0xf) = tail_len ==> val tail_len < 16`,
  BITBLAST_TAC
);;

let num_blocks_ge_80_lemma = prove(
  `!num_blocks:int64.
    word_and len (word 0xfffffffffffffff0) = num_blocks /\ val len >= 0x50
    ==> val num_blocks >= 0x50`,
  BITBLAST_TAC
);;

let crock_lemma = prove(
  `!a:num b:num. a >= b /\ b > 0 ==> ~(a DIV b = 0)`,
  REPEAT GEN_TAC THEN
  MP_TAC (SPECL [`a:num`; `b:num`] DIV_EQ_0) THEN
  ARITH_TAC
);;

let word_split_lemma = prove(
  `!len:int64. len = word_add (word_and len (word 0xf))
                              (word_and len (word 0xfffffffffffffff0))`,
  BITBLAST_TAC);;

let blt_lemma = prove(
  `!len:int64 x:num.
    val len >= x /\ val len < 2 EXP 63
    ==> (ival (word_sub len (word x)) < &0 <=> ~(ival len - &x = ival (word_sub len (word x))))`,
  CHEAT_TAC);;

(* TODO: The ending pc will be an if-then-else depending on which branch it goes to *)
let AES_XTS_DECRYPT_CORRECT = prove(
  `!ct_ptr pt_ptr ct pt_init key1_ptr key2_ptr iv_ptr iv len
    k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k0a k0b k0c k0d k0e
    k10 k11 k12 k13 k14 k15 k16 k17 k18 k19 k1a k1b k1c k1d k1e
    pc.
    nonoverlapping (word pc, LENGTH aes_xts_decrypt_mc) (pt_ptr, 16)
    /\ val len >= 16 /\ val len <= 2 EXP 24
    ==> ensures arm
    (\s. aligned_bytes_loaded s (word pc) aes_xts_decrypt_mc /\
         read PC s = word (pc + 0x1c) /\
         C_ARGUMENTS [ct_ptr; pt_ptr; len; key1_ptr; key2_ptr; iv_ptr] s /\
         byte_list_at ct ct_ptr s /\
         byte_list_at pt_init pt_ptr s /\
         read(memory :> bytes128 iv_ptr) s = iv /\
         set_key_schedule s key1_ptr k00 k01 k02 k03 k04 k05 k06 k07 k08 k09 k0a k0b k0c k0d k0e /\
         set_key_schedule s key2_ptr k10 k11 k12 k13 k14 k15 k16 k17 k18 k19 k1a k1b k1c k1d k1e)
    (\s. read PC s = word (pc + 0xa10) /\
         byte_list_at (aes256_xts_decrypt ct (val len) iv
              [k00; k01; k02; k03; k04; k05; k06; k07; k08; k09; k0a; k0b; k0c; k0d; k0e]
              [k10; k11; k12; k13; k14; k15; k16; k17; k18; k19; k1a; k1b; k1c; k1d; k1e]
              pt_init) pt_ptr s
         )
    (MAYCHANGE [PC] ,, MAYCHANGE [events] ,,
     MAYCHANGE [X21;X2;X6;X4;X9;X10;X19;X22;X11;X7;X0;X1;X8] ,,
     MAYCHANGE [Q6;Q1;Q0;Q8;Q16;Q17;Q12;Q13;Q14;Q15;Q4;Q5;Q18;Q19;Q20;Q21;Q22;Q23;Q7;Q29;Q24] ,,
     MAYCHANGE SOME_FLAGS,, MAYCHANGE [memory :> bytes128 pt_ptr])
    `,
    REWRITE_TAC [(REWRITE_CONV [aes_xts_decrypt_mc] THENC LENGTH_CONV) `LENGTH aes_xts_decrypt_mc`] THEN
    REWRITE_TAC[set_key_schedule; C_ARGUMENTS; SOME_FLAGS; NONOVERLAPPING_CLAUSES; byte_list_at] THEN
    REPEAT STRIP_TAC THEN

    (* Break len into full blocks and tail *)
    SUBGOAL_THEN `len:int64 = word_add (word_and len (word 0xf))
      (word_and len (word 0xfffffffffffffff0))` ASSUME_TAC THENL
    [REWRITE_TAC[word_split_lemma]; ALL_TAC] THEN
    ABBREV_TAC `num_blocks:int64 = word_and len (word 0xfffffffffffffff0)` THEN
    ABBREV_TAC `tail_len:int64 = word_and len (word 0xf)` THEN
    ABBREV_TAC `key1:int128 list = [k00; k01; k02; k03; k04; k05; k06; k07; k08; k09; k0a; k0b; k0c; k0d; k0e]` THEN
    ABBREV_TAC `key2:int128 list = [k10; k11; k12; k13; k14; k15; k16; k17; k18; k19; k1a; k1b; k1c; k1d; k1e]` THEN

    (* Case splits on length:
      len < 16 -- error case
      len < 32 -- one block, or one block and a tail
      len < 48 -- two blocks, or two blocks and a tail
      len < 64 -- three blocks, or three blocks and a tail
      len < 80 -- four blocks, or four blocks and a tail
      len >= 80 -- five blocks and up
     *)
    ASM_CASES_TAC `val (len:int64) < 80` THENL [CHEAT_TAC; ALL_TAC] THEN

    (* Setting up the loop invariant *)
    (* Invariant:
       X0 holds ct_ptr
       X1 hols pt_ptr
       X3 holds key1_ptr
       X4 holds key2_ptr
       X5 holds iv_ptr (may not need)
       X21 holds tail_len

       X2 holds number of blocks left
       X8 holds number of 5xblocks left
       Q6, Q8, Q9, Q10, Q11 holds the next 5 tweaks
       Up to the new five blocks in output pt_ptr matche the specification
    *)
    ENSURES_WHILE_DOWN_TAC
      `(val (num_blocks:int64) DIV 0x50):num` `pc + 0x170` `pc + 0x460`
      `\i s.
             read X0 s = ct_ptr /\
             read X1 s = pt_ptr /\
             read X3 s = key1_ptr /\
             read X4 s = key2_ptr /\
             read X21 s = tail_len /\
             read X2 s = word_sub num_blocks (word_mul (word 0x50) (word i)) /\
             read X8 s = word_sub (word (val num_blocks DIV 0x50)) (word i) /\
             read Q6 s = calculate_tweak (i * 5) iv key2 /\
             read Q8 s = calculate_tweak (i * 5 + 1) iv key2 /\
             read Q9 s = calculate_tweak (i * 5 + 2) iv key2 /\
             read Q10 s = calculate_tweak (i * 5 + 3) iv key2 /\
             read Q11 s = calculate_tweak (i * 5 + 4) iv key2 /\
             byte_list_at (aes256_xts_decrypt ct (i * 5 * 16) iv key1 key2 pt_init) pt_ptr s
      ` THEN
    ASM_REWRITE_TAC[] THEN REPEAT CONJ_TAC THENL
    [
      (* Subgoal 1. Bound of loop is not zero *)
      SUBGOAL_THEN `val (num_blocks:int64) >= 0x50` ASSUME_TAC THENL
      [
        (* First establish len >= 0x50 *)
        SUBGOAL_THEN `val (len:int64) >= 0x50` ASSUME_TAC THENL
        [ASM_ARITH_TAC; ALL_TAC] THEN
        (* Then establish num_blocks >= 50 *)
        MATCH_MP_TAC num_blocks_ge_80_lemma THEN CONJ_TAC THENL
        [ASM_REWRITE_TAC[];ASM_REWRITE_TAC[]];

        (* Prove subgoal1 using the lemma: a >= b /\ b > 0 ==> ~(a DIV b = 0) *)
        MATCH_MP_TAC crock_lemma THEN CONJ_TAC THENL
        [ASM_REWRITE_TAC[]; ARITH_TAC]
      ];

      (* Subgoal 2. Invariant holds before entering the loop *)
      (* ===> Symbolic Simulation: Start symbolic simulation*)
      ENSURES_INIT_TAC "s0" THEN
      ARM_ACCSTEPS_TAC AES_XTS_DECRYPT_EXEC [] (1--2) THEN
      (* Discharge if condition *)
      SUBGOAL_THEN
        `ival (word_sub (word_add (tail_len:int64) (num_blocks:int64)) (word 0x10)) < &0x0 <=>
          ~(ival (word_add tail_len num_blocks) - &0x10 =
            ival (word_sub (word_add tail_len num_blocks) (word 0x10)))` ASSUME_TAC THENL
      [ MATCH_MP_TAC blt_lemma THEN CONJ_TAC THENL
        [ UNDISCH_TAC `len:int64 = word_add tail_len num_blocks` THEN
          UNDISCH_TAC `val (len:int64) >= 16` THEN
          WORD_ARITH_TAC;
          UNDISCH_TAC `len:int64 = word_add tail_len num_blocks` THEN
          UNDISCH_TAC `val (len:int64) <= 2 EXP 24` THEN
          WORD_ARITH_TAC];
        ALL_TAC] THEN
      POP_ASSUM(fun th -> RULE_ASSUM_TAC(REWRITE_RULE[th])) THEN
      (* ===> Symbolic Simulation: Symbolic execution for initialization of tweak *)
      ARM_ACCSTEPS_TAC AES_XTS_DECRYPT_EXEC [] (3--69) THEN
      (* Prove Q6 stores initial tweak *)
      FIRST_X_ASSUM(MP_TAC o SPEC
        `(aes256_encrypt iv [k10; k11; k12; k13; k14; k15; k16; k17; k18; k19; k1a; k1b; k1c; k1d; k1e]):int128`
        o  MATCH_MP (MESON[] `read Q6 s = a ==> !a'. a = a' ==> read Q6 s = a'`)) THEN
      ANTS_TAC THENL [AESENC_TAC; DISCH_TAC] THEN
      (* ===> Symbolic Simulation: Symbolic simulating untill next branch *)
      ARM_ACCSTEPS_TAC AES_XTS_DECRYPT_EXEC [] (70--89) THEN
      (* TODO: think about how to treat this case split *)
      CHEAT_TAC
      ;
      CHEAT_TAC;
      CHEAT_TAC;
      CHEAT_TAC
    ]
);;