needs "x86/proofs/base.ml";;
needs "x86/proofs/equiv.ml";;

print_coda_from_elf 0xf "x86/aes-xts/example_left.o";;
print_coda_from_elf 0xf "x86/aes-xts/example_right.o";;

let example_left_mc = define_assert_from_elf "example_left_mc" "x86/aes-xts/example_left.o" [
  0x0f; 0x57; 0xc0;        (* XORPS (%_% xmm0) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xc9;  (* PXOR (%_% xmm1) (%_% xmm1) *)
  0x0f; 0x29; 0x04; 0x24;  (* MOVAPS (Memop Word128 (%% (rsp,0))) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xd2   (* PXOR (%_% xmm2) (%_% xmm2) *)
];;

let example_right_mc = define_assert_from_elf "example_right_mc" "x86/aes-xts/example_right.o" [
  0x0f; 0x57; 0xc0;        (* XORPS (%_% xmm0) (%_% xmm0) *)
  0x66; 0x0f; 0xef; 0xc9;  (* PXOR (%_% xmm1) (%_% xmm1) *)
  0x66; 0x0f; 0xef; 0xd2;  (* PXOR (%_% xmm2) (%_% xmm2) *)
  0x0f; 0x29; 0x04; 0x24   (* MOVAPS (Memop Word128 (%% (rsp,0))) (%_% xmm0) *)
];;

let LEFT_EXEC = X86_MK_EXEC_RULE example_left_mc;;
let RIGHT_EXEC = X86_MK_EXEC_RULE example_right_mc;;

let LENGTH_example_left_mc = prove
    (`LENGTH example_left_mc=15`, CHEAT_TAC);;

let LENGTH_example_right_mc = prove
    (`LENGTH example_right_mc=15`, CHEAT_TAC);;

let eqin = new_definition
  `forall y0 y1 y2 y0' y1' y2' stack_pointer.
    (eqin:(x86state#x86state)->int256->int256->int256->int256->int256->int256->int64->bool)
      (s1,s1') y0 y1 y2 y0' y1' y2' stack_pointer<=>
     (read YMM0 s1 = y0 /\
      read YMM1 s1 = y1 /\
      read YMM2 s1 = y2 /\
      read YMM0 s1' = y0' /\
      read YMM1 s1' = y1' /\
      read YMM2 s1' = y2' /\
      read RSP s1 = stack_pointer /\
      read RSP s1' = stack_pointer
      )`;;

let eqout = new_definition
  `forall s1 s1' stack_pointer.
   (eqout:(x86state#x86state)->int64->bool) (s1,s1') stack_pointer<=>
     (read XMM0 s1 = word 0 /\
      read XMM0 s1' = word 0 /\
      read XMM1 s1 = word 0 /\
      read XMM1 s1' = word 0 /\
      read XMM2 s1 = word 0 /\
      read XMM2 s1' = word 0 /\
      read (memory :> bytes128 stack_pointer) s1 = word 0 /\
      read (memory :> bytes128 stack_pointer) s1' = word 0
      )`;;

let equiv_goal = mk_equiv_statement_simple
  ` ALL (nonoverlapping (stack_pointer,16))
      [word pc,LENGTH example_left_mc;word pc2,LENGTH example_right_mc] /\
    aligned 16 (stack_pointer:int64)`
  eqin
  eqout
  example_left_mc LEFT_EXEC
  `MAYCHANGE [RIP] ,,
   MAYCHANGE [ZMM0; ZMM1; ZMM2] ,,
   MAYCHANGE SOME_FLAGS ,,
   MAYCHANGE [memory :> bytes128 stack_pointer]`
  example_right_mc RIGHT_EXEC
  `MAYCHANGE [RIP] ,,
   MAYCHANGE [ZMM0; ZMM1; ZMM2] ,,
   MAYCHANGE SOME_FLAGS ,,
   MAYCHANGE [memory :> bytes128 stack_pointer]`;;

let ADD_ASSUM_TAC lemma =
  MP_TAC lemma THEN STRIP_TAC;;

let false_lemma = prove(`nonoverlapping_modulo (2 EXP 64) (val (stack_pointer:int64),16) (pc+96,16)`,CHEAT_TAC);;

let EXAMPLE_CORRECT = time prove
  (equiv_goal,
  REWRITE_TAC[ALL; SOME_FLAGS; NONOVERLAPPING_CLAUSES;
    fst LEFT_EXEC; fst RIGHT_EXEC;
    LENGTH_example_left_mc; LENGTH_example_right_mc] THEN
  REPEAT STRIP_TAC THEN
  EQUIV_INITIATE_TAC eqin THEN
  EQUIV_STEPS_TAC [
    ("replace",0,2,0,2);
  ] LEFT_EXEC RIGHT_EXEC THEN
  (* Injected a bogus lemma *)
  ADD_ASSUM_TAC false_lemma THEN
  (* The following tactic will create an error:
  replace failed: stuttering left: reason: NONOVERLAPPING_TAC: 
  cannot prove `nonoverlapping_modulo (2 EXP 64) (val (word pc),15)
  (val (word_add stack_pointer (word 0)),16)`: reason: type_match
   *)
  EQUIV_STEPS_TAC [
    ("replace",2,4,2,4);
  ] LEFT_EXEC RIGHT_EXEC THEN

  REPEAT_N 2 ENSURES_N_FINAL_STATE_TAC THEN
  ASM_REWRITE_TAC[] THEN
  CONJ_TAC THENL [
    (** SUBGOAL 1. Outputs **)
    ASM_REWRITE_TAC[eqout] THEN
    REPEAT (HINT_EXISTS_REFL_TAC THEN ASM_REWRITE_TAC[]) THEN CHEAT_TAC;
    (** SUBGOAL 2. Maychange pair **)
    MONOTONE_MAYCHANGE_CONJ_TAC
  ]
);;