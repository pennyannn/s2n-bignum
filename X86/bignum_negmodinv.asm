 ; * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 ; *
 ; * Licensed under the Apache License, Version 2.0 (the "License").
 ; * You may not use this file except in compliance with the License.
 ; * A copy of the License is located at
 ; *
 ; *  http://aws.amazon.com/apache2.0
 ; *
 ; * or in the "LICENSE" file accompanying this file. This file is distributed
 ; * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 ; * express or implied. See the License for the specific language governing
 ; * permissions and limitations under the License.

; ----------------------------------------------------------------------------
; Negated modular inverse, z := (-1/x) mod 2^{64k}
; Input x[k]; output z[k]
;
;    extern void bignum_negmodinv
;     (uint64_t k, uint64_t *z, uint64_t *x);
;
; Assuming x is odd (otherwise nothing makes sense) the result satisfies
;
;       x * z + 1 == 0 (mod 2^{64 * k})
;
; but is not necessarily reduced mod x.
;
; Standard x86-64 ABI: RDI = k, RSI = z, RDX = x
; ----------------------------------------------------------------------------

                global bignum_negmodinv

                section .text

%define k rdi
%define z rsi
%define x rcx           ; Moved from initial location to free rdx

%define a rax
%define d rdx
%define i r8
%define m r9
%define h r10
%define w r11
%define t r12
%define e rbx

bignum_negmodinv:

                push    rbx
                push    r12

; If k = 0 do nothing (actually we could have avoiding the pushes and pops)

                test    k, k
                jz      end

; Move the x pointer into its permanent home (rdx is needed for muls)

                mov     x, rdx

; Compute word-level negated modular inverse w for x[0].

                mov     a, [x]

                mov     d, a
                mov     w, a
                shl     d, 2
                sub     w, d
                xor     w, 2

                mov     d, w
                imul    d, a
                mov     a, 2
                add     a, d
                add     d, 1

                imul    w, a

                imul    d, d
                mov     a, 1
                add     a, d
                imul    w, a

                imul    d, d
                mov     a, 1
                add     a, d
                imul    w, a

                imul    d, d
                mov     a, 1
                add     a, d
                imul    w, a

; Write that as lowest word of the output, then if k = 1 we're finished

                mov     [z], w
                cmp     k, 1
                jz      end

; Otherwise compute and write the other digits (1..k-1) of w * x + 1

                mov     a, [x]
                xor     h, h
                mul     w
                add     a, 1
                adc     h, d
                mov     i, 1
initloop:
                mov     a, [x+8*i]
                mul     w
                add     a, h
                adc     d, 0
                mov     [z+8*i], a
                mov     h, d
                inc     i
                cmp     i, k
                jc      initloop

; For simpler indexing, z := z + 8 and k := k - 1 per outer iteration
; Then we can use the same index for x and for z and effective size k.
;
; But we also offset k by 1 so the "real" size is k + 1; after doing
; the special zeroth bit we count with t through k more digits, so
; getting k + 1 total as required.
;
; This lets us avoid some special cases inside the loop at the cost
; of needing the additional "finale" tail for the final iteration
; since we do one outer loop iteration too few.

                sub     k, 2
                jz      finale

outerloop:
                add     z, 8

                mov     h, [z]
                mov     m, w
                imul    m, h
                mov     [z], m
                mov     a, [x]
                mul     m
                add     a, h
                adc     d, 0
                mov     h, d
                mov     i, 1
                mov     t, k
 innerloop:
                adc     h, [z+8*i]
                sbb     e, e
                mov     a, [x+8*i]
                mul     m
                sub     d, e
                add     a, h
                mov     [z+8*i], a
                mov     h, d
                inc     i
                dec     t
                jnz     innerloop

                dec     k
                jnz     outerloop

finale:
                mov     a, [z+8]
                imul    a, w
                mov     [z+8], a

end:
                pop     r12
                pop     rbx
                ret
