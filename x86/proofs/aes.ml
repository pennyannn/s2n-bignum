(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

(* References:
   Intel 64 and IA-32 Architectures Software Developer's Manual Volume 1:
     Basic Architecture, page 311-316
   Intel 64 and IA-32 Architectures Software Developer's Manual Volume 2:
     Instruction Set Reference, A-Z, 2A 3-63
   White Paper: Intel Advanced Encryption Standard (AES) New Instructions Set *)

let aesenc = new_definition
 `aesenc (state:(128)word) (roundkey:(128)word) : (128)word =
   let state = aes_shift_rows state in
   let state = aes_sub_bytes joined_GF2 state in
   let state = aes_mix_columns state in
   (word_xor state roundkey)`;;

let AESENC_HELPER_CONV =
  REWRITE_CONV [aesenc] THENC
  AES_SHIFT_ROWS_CONV THENC
  AES_SUB_BYTES_CONV THENC
  AES_MIX_COLUMNS_CONV THENC
  DEPTH_CONV (WORD_RED_CONV ORELSEC NUM_RED_CONV);;

let AESENC_REDUCE_CONV tm =
  match tm with
    Comb(Comb(Const("aesenc",_),
         Comb(Const("word",_),state)),
         Comb(Const("word",_),roundkey))
    when is_numeral state && is_numeral roundkey -> AESENC_HELPER_CONV tm
    | _ -> failwith "AESENC_REDUCE_CONV: inapplicable";;
