(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

(******************************************************************************
  Proving a simple property about program 'simple.S'
******************************************************************************)

(* Please copy this file to the root directory of s2n-bignum, then
   follow the instructions. *)

needs "x86/proofs/base.ml";;

(* Let's prove a simple property of the following program:

   0: c5 fd fd d1        vpaddw ymm2, ymm0, %ymm1

  Let's start with defining a byte sequence of a program 'simple.S'
*)
let simple_mc = new_definition `simple_mc = [
    word 0xc5; word 0xfd; word 0xfd; word 0xd1
  ]:((8)word)list`;;

print_literal_from_elf "x86/tutorial/simple_avx2.o";;

(* Or, you can read .o file and store the byte list as follows:
let simple_mc = define_assert_from_elf "simple_mc" "x86/tutorial/simple_avx2.o"
[
  0xc5; 0xfd; 0xfd; 0xd1   (* VPADDW (%_% ymm2) (%_% ymm0) (%_% ymm1) *)
];;

You can get the above OCaml list data structure from
`print_literal_from_elf "<.o file>"` or `save_literal_from_elf "<out.txt>"
"<.o file>"`.
*)

(* X86_MK_EXEC_RULE decodes the byte sequence into conjunction of
  equalities between the bytes and instructions. *)

let EXEC = X86_MK_EXEC_RULE simple_mc;;

(*
  In s2n-bignum, a specification (ensures) has three components:
  1. precondition: assume that a program starts from some program state satisfying the critera
  2. postcondition: the program must reach to a program state satisfying the criteria
  3. frame: the start program state and end program state must satisfy this relation
     (e.g., this program only changes callee-save register)
  In this file,
  1. precondition is:
    - the 'simple' binary is loaded at some location in memory, say 'pc'
    - the x86 program counter register, RIP, has value pc
    - the x86 register YMM0 has a symbolic value a and YMM1 has a symbolic value b
  2. postcondition is:
    - the x86 program counter RIP, has value pc+4
      (meaning that two instructions have been executed)
    - the x86 register YMM2 has value `simd16 word_add a b`
  3. frame is:
    - the register values of RIP, YMM2 and flags might have been changed

  If you are using the VSCode plugin of HOL Light, you can ctrl+click
  (cmd+click for Mac) to jump to definitions.
*)
let SIMPLE_SPEC = prove(
  `forall pc a b.
  ensures x86
    // Precondition
    (\s. // bytes_loaded states that a byte sequence 'simple_mc'
         // is loaded at memory location 'pc' in the state 's'.
         bytes_loaded s (word pc) simple_mc /\
         // 'word' is a bit-vector type in HOL Light.
         // 'word a' means it is a bit-vector whose numeral (:num type)
         // is 'a'. Its bit-width is inferred as 256 bits here, but it can
         // be manually annotated as (word a:(256)word).
         read RIP s = word pc /\
         read YMM0 s = word a /\
         read YMM1 s = word b)
    // Postcondition
    (\s. read RIP s = word (pc+4) /\
         read YMM2 s = simd16 word_add (word a) (word b))
    // Registers (and memory locations) that may change after execution
    (MAYCHANGE [RIP] ,, MAYCHANGE [YMM2])`,

  (* Strips the outermost universal quantifier from the conclusion of a goal *)
  REPEAT STRIP_TAC THEN
  (* ENSURES_FINAL_STATE_TAC does not understand SOME_FLAGS in MAYCHANGE. Let's
     unfold this in advance. *)
  (* Start symbolic execution with state 's0' *)
  ENSURES_INIT_TAC "s0" THEN

  (* Symbolically run one instruction *)
  X86_STEPS_TAC EXEC (1--1) THEN
  (* Try to prove the postcondition and frame as much as possible *)
  ENSURES_FINAL_STATE_TAC THEN

  (* Use ASM_REWRITE_TAC[] to rewrite the goal using equalities in assumptions. *)
  ASM_REWRITE_TAC[] THEN

  (* Proving equivalence *)
  (* Use all_simd_rules to rewrite simd16, simd8, simd4, and simd2 *)
  REWRITE_TAC all_simd_rules THEN 
  (* Rewrite DIMINDEX *)
  DIMINDEX_TAC THEN
  (* Enable reasoning about word_subword, for example:
   (word_subword
    (word_subword (word_subword (word_subword (word a) (0,128)) (0,64))
    (0,32))
   (0,16)) = (word_subword (word a) (0, 16))
   *)
  CONV_TAC (TOP_DEPTH_CONV WORD_SIMPLE_SUBWORD_CONV) THEN 
  (* Apply refexivity *)
  REFL_TAC
  );;

(* Note that symbolic simulator will discard the output of instructions
   if its inputs do not have their symbolic expressions defined in assumption.
   To list which instructions are discarded by the simulation tactic.
   set:
    x86_print_log := true;;
   This flag will also print helpful informations that are useful. *)