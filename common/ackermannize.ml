(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

needs "meson.ml";;
needs "Library/words.ml";;


(** ------------------------------------ **)
(* A simple example and the pseudocode for the algorithm *)

let foo = define `foo a = a`;;

let example = `word_xor (a:int128) (foo (word_xor (b:int128) (c:int128))) = word_xor (foo (word_xor c b)) a`;;

(*
Algorithm:

Traverse example in post-order
First see `b`, which is a variable, we do nothing.
Then we see `word_xor b`, which is an interpreted, so we do nothing.
Then we see `(word_xor b) c`, which is interpreted, so we do nothing.
Then we see `foo (word_xor b c)`, which is an uninterpreted function application,
    We found that this function hasn't been stored yet and the actual is also not stored, so we:
    First get its arguments,
    Then we create a free variable for function call `f0 = foo (word_xor b c)` and store in hash table: f.[(x0,f0,eq_thm for f0 = foo x0)]
    For the list value, maybe it could be a hashtable based on arguments, this is an optimization for eliminating generating equalities for the same call
    We then substitute in the variables
Then see `a`, which is a variable, do nothing.
Then we see `word_xor a (foo ...)` which is interpreted, so we do nothing.
Then we see `=`, which is known function, do nothing.
Then we see `c`, do nothing,
Then we see `word_xor c`, which is interpreted, so we do nothing.
Then we see `(word_xor c) b`, which is interpreted, so we do nothing.
Then we see `foo (word_xor c b)`,which is uninterpreted function application,
    We found that this function has been stored before, so we need to create a antecedent for each previous expressions seen.
    In this case, we need to create a variable `x1 = word_xor c b` and a variable `f1 = foo (word_xor c b)` and store the latter in hash tables: f.[(x0,f0,eq_proof for f0 = foo x0);(x1,f1,|- f1 = foo x1)]
      and then create the uninterpreted function lemma for the pair `(x0,f0)` and `(x1,f1)`.
    That is, we create the lemma `foo x0 = f0 /\ foo x1 = f1 ==> (x0 = x1) ==> f0 = f1` based on theory of uninterpreted functions.
    Since `foo x0 = f0 /\ foo x1 = f1` could be easily proved based on previous established eq_thms `|- fx = f x`,
    We can safely add `(x0 = x1) ==> f0 = f1` into the antecedent of the goal. (I'm not super clear about how to do this in HOL Light)


Proof:
|- foo x0 = f0
|- foo x1 = f1
|- foo x0 = f0 /\ foo x1 = f1 ==> (x0 = x1) ==> f0 = f1
-----------
|- (x0 = x1) ==> f0 = f1

Ackermannize should generate a theorem that
|- (((x0 = x1) ==> f0 = f1) ==> substituted_original_term) ==> original_term

In order to genenerate this theorem. I think the function will have to start with the following:
|- original_term ==> original_term (instantiate a lemma a==>a)
Also, there needs to be a check that original term is of type :bool

The function table:
f . [(x0, f0, |- foo x0 = f0); (x1, f1, |- foo x1 = f1)]

Q: what should I use to facilitate the validity of the substitution?

*)

let ack_example = `((x0 = word_xor (b:int128) c) /\ (x1 = word_xor c b) /\ ((x0 = x1) ==> f0 = f1)) ==> (word_xor a (f0:int128) = word_xor f1 a)`;;
let ack_example' = `((word_xor (b:int128) c = word_xor c b) ==> f0 = f1) ==> (word_xor a (f0:int128) = word_xor f1 a)`;;

time BITBLAST_RULE ack_example;;
time BITBLAST_RULE ack_example';;


(** ------------------------------------ **)

(* First write a function that traverses the a term and stores function call names *)
(*
let rec traverse_term tm acc = 
  match tm with
    | Var (name, ty) -> acc
    | Const (name, ty) -> name::acc
    | Comb (fn, tm) -> traverse_term tm (traverse_term fn acc)
    | _ -> failwith "Abs not supported in traverse_term";;

traverse_term example [];;

(* Only store function for once *)
let rec traverse_term tm ht = 
  match tm with
    | Var (name, ty) -> ht
    | Const (name, ty) -> Hashtbl.replace ht name []; ht
    | Comb (fn, tm) -> traverse_term tm (traverse_term fn ht)
    | _ -> failwith "Abs not supported in traverse_term";;

let rec traverse_term_top tm =
  let ht = Hashtbl.create 100 in
  traverse_term tm ht;;

traverse_term_top example;;
*)
let print_hashtbl ht =
  Hashtbl.iter (fun key _ ->
    Printf.printf "Key: %s\n" key
  ) ht;;

let interpreted = Hashtbl.create 100;;
Hashtbl.add interpreted "word_xor" [];;
Hashtbl.add interpreted "=" [];;
Hashtbl.add interpreted "/\\" [];;

let rec traverse_term tm ht =
  match tm with
    | Var (name, ty) -> ()
    | Comb (Const ("word", ty), tm) -> ()
    | Const (name, ty) ->
        if Hashtbl.mem interpreted name then ()
        else Hashtbl.replace ht name []
    | Comb (fn, tm) -> traverse_term fn ht; traverse_term tm ht
    | _ -> failwith "Abs not supported in traverse_term";;

let rec traverse_term_top tm =
  let ht = Hashtbl.create 100 in
  traverse_term tm ht; print_hashtbl ht;;

print_hashtbl interpreted;;
traverse_term_top example;;

val example : term =
  Comb
   (Comb (Const ("=", `:(128)word->(128)word->bool`),
     Comb
      (Comb (Const ("word_xor", `:(128)word->(128)word->(128)word`),
        Var ("a", `:(128)word`)),
      Comb (Const ("foo", `:(128)word->(128)word`),
       Comb
        (Comb (Const ("word_xor", `:(128)word->(128)word->(128)word`),
          Var ("b", `:(128)word`)),
        Var ("c", `:(128)word`))))),
   Comb
    (Comb (Const ("word_xor", `:(128)word->(128)word->(128)word`),
      Comb (Const ("foo", `:(128)word->(128)word`),
       Comb
        (Comb (Const ("word_xor", `:(128)word->(128)word->(128)word`),
          Var ("c", `:(128)word`)),
        Var ("b", `:(128)word`)))),
    Var ("a", `:(128)word`)));;

(* Write a function that traverses a term and create hash table for all function calls and their actuals *)

let rec traverse_term2 (tm:term) ht (args:term list) =
  match tm with
    | Var (name, ty) -> ()
    | Comb (Const ("word", ty), tm) -> ()
    | Const (name, ty) ->
        if Hashtbl.mem interpreted name then ()
        else Hashtbl.replace ht name []
    | Comb (fn, tm) -> traverse_term2 fn ht; traverse_term tm ht
    | _ -> failwith "Abs not supported in traverse_term2";;

(** ------------------------------------ **)
(* Random Experiments *)
(* Not exactly sure what create_equality_axioms does yet *)
Meson.create_equality_axioms [`!(f:num->num) (g:num->num) (a:num) (b:num). a + b = b + a /\ a = a /\ b = b /\ f a = f a /\ g b = g b`];;
(* Package the list with BITBLAST_TAC and generate conjuncts for uninterpreted function calls *)

let example2 = `word_add x (word(bitval (p <=> word_add a b = word_add b c))) = word 0`;;

let gather_uninterpreted =
  let rec gather_uninterpreted acc tm = 
    match tm with;;

let atoms =
  let rec atoms acc tm =
    match tm with
      Comb(Comb(Const("/\\",_),l),r)
    | Comb(Comb(Const("\\/",_),l),r)
    | Comb(Comb(Const("==>",_),l),r)
    | Comb(Comb(Const("=",Tyapp("fun",[Tyapp("bool",[]);_])),l),r) ->
          atoms (atoms acc l) r
    | Comb(Const("~",_),l) -> atoms acc l
    | _ -> (tm |-> ()) acc in
  fun tm -> if type_of tm <> bool_ty then failwith "atoms: not Boolean"
            else foldl (fun a x y -> x::a) [] (atoms undefined tm);;

atoms example2;;
BITBLAST_RULE example2;;
(* Package the list with BITBLAST_TAC and generate conjuncts for uninterpreted function calls *)
