(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

 needs "x86/proofs/base.ml";;

(******************************************************************************
  Proving a mlkem_keccak_f1600 property about program 'mlkem_keccak_f1600.S'
******************************************************************************)
(* When there is a table *)
(**** print_coda_from_elf (-1) "x86/mlkem/mlkem_keccak_f1600_loop_invar_4.o";;
 ****)

(* When there is no table *)
 (**** print_literal_from_elf "x86/mlkem/mlkem_keccak_f1600_loop_invar.o";;
 ****)

let mlkem_keccak_f1600_mc_loop_invar_4 = define_assert_from_elf
  "mlkem_keccak_f1600_mc_loop_invar_4" "x86/mlkem/mlkem_keccak_f1600_loop_invar.o"         
[
  0x49; 0x89; 0xf7;        (* MOV (% r15) (% rsi) *)
  0x49; 0xc7; 0xc4; 0x00; 0x00; 0x00; 0x00;
                           (* MOV (% r12) (Imm32 (word 0)) *)
  0x4d; 0x8d; 0x7f; 0x08;  (* LEA (% r15) (%% (r15,8)) *)
  0x49; 0x83; 0xc4; 0x01;  (* ADD (% r12) (Imm8 (word 1)) *)
  0x49; 0xf7; 0xc4; 0x18; 0x00; 0x00; 0x00;
                           (* TEST (% r12) (Imm32 (word 24)) *)
  0x75; 0xef;              (* JNE (Imm8 (word 239)) *)
  0xc3                     (* RET *)
];;


 let mlkem_keccak_f1600_loop_invar_4 = define_trimmed "mlkem_keccak_f1600_loop_invar_4" mlkem_keccak_f1600_mc_loop_invar_4;;

 let MLKEM_KECCAK_F1600_EXEC = X86_MK_EXEC_RULE mlkem_keccak_f1600_loop_invar_4;;


(* let MLKEM_KECCAK_F1600_SPEC = prove(
  `forall pc:num stackpointer:int64 bitstate:int64 returnaddress.
       nonoverlapping_modulo (2 EXP 64) (pc, 0x344) (val (word_sub stackpointer (word 248):int64),248) /\
       nonoverlapping_modulo (2 EXP 64) (pc, 0x344) (val (word_add bitstate (word 0):int64),200)
   ==> ensures x86
  // Precondition
  (\s. bytes_loaded s (word pc) mlkem_keccak_f1600_loop_invar_4 /\
       read RIP s = word pc /\
       read RSP s = stackpointer /\
       read (memory :> bytes64 stackpointer) s = returnaddress /\
       read RDI s = bitstate)
  // Postcondition
  (\s.  read RIP s = returnaddress /\
         read RSP s = word_add stackpointer (word 8))
  (MAYCHANGE [RIP;RSP;RAX;RBX;RCX;RDX;RBP;R8;R9;R10;R11;R12;R13;R14;R15;RDI;RSI] ,, MAYCHANGE SOME_FLAGS ,, 
  MAYCHANGE [memgory :> bytes (word_sub stackpointer (word 248), 248)],,
  MAYCHANGE [memory :> bytes (word_add bitstate (word 0), 200)])` *)

  let MLKEM_KECCAK_F1600_SPEC = prove(
  `forall pc:num stackpointer:int64 returnaddress.
      ensures x86
  // Precondition
  (\s. bytes_loaded s (word pc) mlkem_keccak_f1600_loop_invar_4 /\
       read RIP s = word pc /\
       read RSP s = stackpointer /\
       read (memory :> bytes64 stackpointer) s = returnaddress)
  // Postcondition
  (\s.  read RIP s = returnaddress /\
         read RSP s = word_add stackpointer (word 8)/\
         read R12 s = word 24)
  (MAYCHANGE [RIP;RSP;RAX;RBX;RCX;RDX;RBP;R8;R9;R10;R11;R12;R13;R14;R15;RDI;RSI] ,, MAYCHANGE SOME_FLAGS)`
  ,

  REWRITE_TAC[SOME_FLAGS] THEN
  REPEAT STRIP_TAC THEN

  (* REWRITE_TAC[fst MLKEM_KECCAK_F1600_EXEC] THEN 
  MAP_EVERY X_GEN_TAC [`pc:num`] THEN
  WORD_FORALL_OFFSET_TAC 248 THEN
  CONV_TAC(ONCE_DEPTH_CONV NORMALIZE_RELATIVE_ADDRESS_CONV) THEN
  MAP_EVERY X_GEN_TAC [`stackpointer:int64`;`bitstate:int64`] THEN
  REPEAT STRIP_TAC THEN
  REWRITE_TAC[SOME_FLAGS] THEN 
  REPEAT STRIP_TAC THEN *)

    ENSURES_WHILE_PAUP_TAC
    `0` (* counter begin number *)
    `24` (* counter end number *)
    `pc + 0xa` (* loop body start PC *)
    `pc + 0x19` (* loop backedge branch PC *)
    `\i s. // loop invariant at the end of the iteration
           (read R12 s = word i /\
            read RSP s = stackpointer /\
            read (memory :> bytes64 stackpointer) s = returnaddress) /\
           // loop backedge condition
           (read ZF s <=> i = 24)` THEN

    REPEAT CONJ_TAC THENL 
[
    (* counter begin < counter end *)
    ARITH_TAC;

    (* entrance to the loop *)
    (* Let's use X86_SIM_TAC which is ENSURES_INIT_TAC + X86_STEPS_TAC +
       ENSURES_FINAL_STATE_TAC + some post-processing. *)
    X86_SIM_TAC MLKEM_KECCAK_F1600_EXEC (1--2) THEN
    REPEAT CONJ_TAC THEN
    CONV_TAC WORD_RULE;

    (* The loop body. let's prove this later. *)
    (* If you are interactively exploring this proof, try `r 1;;`. *)
    ALL_TAC;

    (* Prove that backedge is taken if i != 10. *)
    REPEAT STRIP_TAC THEN
    X86_SIM_TAC EXEC [1];

    (* Loop exit to the end of the program *)
    X86_SIM_TAC EXEC (1--2) THEN
    (* word (10*2) = word 20 *)
    CONV_TAC WORD_RULE
  ] 
    (* counter begin < counter end *)
    ARITH_TAC;


  ENSURES_INIT_TAC "s0" THEN
  REPEAT STRIP_TAC THEN

  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (1--1) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (2--2) THEN

  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (3--3) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (4--4) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (5--5) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (6--10) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (11--50) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (51--150) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (151--175) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (176--190) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (191--200) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (201--210) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (211--215) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (216--216) THEN
    X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (217--217) THEN
        X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (218--218) THEN
  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (201--210) THEN

  X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (4--218) THEN
   X86_STEPS_TAC MLKEM_KECCAK_F1600_EXEC (219--219) THEN

  ENSURES_FINAL_STATE_TAC THEN

  ASM_REWRITE_TAC[]
  );;
