(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

(* Auxiliary instructions are for making sure operand registers don't depend
   on RSP. This is because RSP in the theorem statement is an arbitrary value
   represented by `stackpointer`. However in actual machine run, it is a
   concrete value. If certain register's value depends on RSP value then the
   machine run and the instruction modeling result won't match. *)

(* Constant: use of registers, operand size = 64
   Randomized: addressing mode parameters *)
let cosimulate_mem_insns(opcode) =
   let stack_start = Random.int 248 in
   let _ = print_string ("stack_start: " ^ string_of_int stack_start) in
   let _ = print_string "\n" in
   let rest = 248 - stack_start in
   let base = if rest = 0 then 0 else Random.int (min rest 8) in
   let _ = print_string ("base: " ^ string_of_int base) in
   let _ = print_string "\n" in
   let rest = rest - base in
   let index = if rest = 0 then 0 else Random.int (min rest 8) in
   let _ = print_string ("index: " ^ string_of_int index) in
   let _ = print_string "\n" in
   let log2_int = fun x -> int_of_float (Float.log2 (float_of_int x)) in
   let scale =
     if index = 0 then Random.int 4
     else
       let scale_range = log2_int (rest/index) in
       if scale_range = 0 then 0
       else Random.int (min scale_range 4) in
   let _ = print_string ("scale: " ^ string_of_int scale) in
   let _ = print_string "\n" in
   let rest = rest - index * int_of_float (2.0 ** (float_of_int scale)) in
   (* disp is a signed value *)
   let disp = if rest = 0 then 0 else Random.int (min 128 rest) in
   let _ = print_string ("disp: " ^ string_of_int disp) in
   let _ = print_string "\n" in
   let sib = scale * int_of_float (2.0**6.0) + 0b001011 in
   let _ = print_string ("sib: " ^ string_of_int sib) in
   let _ = print_string "\n" in
   let _ = print_string "\n" in
   [[0x48; 0xC7; 0xC1; index; 0x00; 0x00; 0x00]; (* MOV rcx, index *)
    [0x48; 0x89; 0xda]; (* MOV rdx, rbx *)
    [0x48; 0x8d; 0x5c; 0x24; stack_start]; (* LEA rbx, [rsp+stack_start] *)
    [0x48] @ opcode @ [0x44; sib; disp];  (* INST [rbx + scale*rcx + displacement], rax *)
    [0x48; 0x89; 0xd3]; (* MOV rbx, rdx *)
   ];;

for i = 1 to 256 do cosimulate_mem_insns([0x03]) done;;

let mem_iclasses = [
   (* ADD r/m64, r64 *)
   cosimulate_mem_insns([0x01]);
   (* ADD r64, r/m64 *)
   cosimulate_mem_insns([0x03]);
   (* ADC r/m64, r64 *)
   cosimulate_mem_insns([0x11]);
   (* ADC r64, r/m64 *)
   cosimulate_mem_insns([0x13]);
   (* OR r/m64, r64 *)
   cosimulate_mem_insns([0x09]);
   (* OR r64, r/m64 *)
   cosimulate_mem_insns([0x0B]);
   (* SBB r/m64, r64 *)
   cosimulate_mem_insns([0x19]);
   (* SBB r64, r/m64 *)
   cosimulate_mem_insns([0x1B]);
   (* SUB r/m64, r64 *)
   cosimulate_mem_insns([0x29]);
   (* SUB r64, r/m64 *)
   cosimulate_mem_insns([0x2B]);
   (* XOR r/m64, r64 *)
   cosimulate_mem_insns([0x31]);
   (* XOR r64, r/m64 *)
   cosimulate_mem_insns([0x33]);
   (* MOV r/m64, r64 *)
   cosimulate_mem_insns([0x89]);
   (* MOV r64, r/m64 *)
   cosimulate_mem_insns([0x8B]);
   (* CMOVA r64, r/m64 *)
   cosimulate_mem_insns([0x0F; 0x47]);
   (* CMOVB r64, r/m64 *)
   cosimulate_mem_insns([0x0F; 0x42]);
    (*
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x01; 0x44; 0xCC; 0x04];  (* ADD [rsp + 8*rcx + 4], rax *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x03; 0x44; 0xCC; 0x04];  (* ADD rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x11; 0x44; 0xCC; 0x04];  (* ADC [rsp + 8*rcx + 4], rax *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x13; 0x44; 0xCC; 0x04];  (* ADC rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x09; 0x44; 0xCC; 0x04];  (* OR [rsp + 8*rcx + 4], rax *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x0B; 0x44; 0xCC; 0x04];  (* OR rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x19; 0x44; 0xCC; 0x04];  (* SBB [rsp + 8*rcx + 4], rax *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x1B; 0x44; 0xCC; 0x04];  (* SBB rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x29; 0x44; 0xCC; 0x04];  (* SUB [rsp + 8*rcx + 4], rax *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x2B; 0x44; 0xCC; 0x04];  (* SUB rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x31; 0x44; 0xCC; 0x04];  (* XOR [rsp + 8*rcx + 4], rax *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x33; 0x44; 0xCC; 0x04];  (* XOR rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x89; 0x44; 0xCC; 0x04];  (* MOV [rsp + 8*rcx + 4], rax *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x8B; 0x44; 0xCC; 0x04];  (* MOV rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x0F; 0x47; 0x44; 0xCC; 0x04];  (* CMOVA rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x0F; 0x42; 0x44; 0xCC; 0x04];  (* CMOVB rax, [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0x89; 0xd9]; (* MOV rcx, rbx *)
     [0x48; 0x8d; 0x5C; 0x24; 0x5d]; (* LEA rbx, [rsp+93] *)
     [0x48; 0xF7; 0x63; 0x60];  (* MUL [rbx+96] *)
     [0x48; 0x89; 0xcb]; (* MOV rbx, rcx *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0x89; 0xd8]; (* MOV r8, rbx *)
     [0x48; 0x8d; 0x5c; 0x24; 0x03]; (* LEA rbx, [rsp+3] *)
     [0x48; 0xF7; 0x64; 0xCB; 0x04];  (* MUL [rbx + 8*rcx + 4] *)
     [0x4C; 0x89; 0xC3]; (* MOV rbx, r8 *)
    ];
    [[0x48; 0xC7; 0xC1; 0x01; 0x00; 0x00; 0x00]; (* MOV rcx, 0x1 *)
     [0x48; 0xF7; 0x64; 0xCC; 0x04];  (* MUL [rsp + 8*rcx + 4] *)
    ];

    [[0x48; 0x8d; 0x64; 0x24; 0x10]; (* lea rsp, [rsp + 16] *)
     [0x50]; (* push rax *)
     [0x48; 0x8d; 0x64; 0x24; 0xf8] (* lea rsp, [rsp - 8] *)
     ];
    [[0x48; 0x8d; 0x64; 0x24; 0x10]; (* lea rsp, [rsp + 16] *)
     [0x58]; (* pop rax *)
     [0x48; 0x8d; 0x64; 0x24; 0xE8] (* lea rsp, [rsp - 24] *)
     ]; *)
  ];;
