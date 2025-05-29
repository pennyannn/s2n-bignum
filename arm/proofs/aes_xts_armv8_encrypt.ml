(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

use_file_raise_failure := true;;

needs "arm/proofs/base.ml";;

print_literal_from_elf "arm/aes-xts/aes_xts_armv8_encrypt.o";;
(* save_literal_from_elf "arm/aes-xts/aes-xts-armv8.txt" "arm/aes-xts/aes-xts-armv8.o";; *)
