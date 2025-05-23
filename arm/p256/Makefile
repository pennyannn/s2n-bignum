#############################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
#############################################################################

# If actually on an ARM8 machine, just use the GNU assembler (as). Otherwise
# use a cross-assembling version so that the code can still be assembled
# and the proofs checked against the object files (though you won't be able
# to run code without additional emulation infrastructure). The aarch64
# cross-assembling version can be installed manually by something like:
#
#  sudo apt-get install binutils-aarch64-linux-gnu

UNAME_RESULT=$(shell uname -p)

ifeq ($(UNAME_RESULT),aarch64)
GAS=as
else
GAS=aarch64-linux-gnu-as
endif

# List of object files

OBJ = bignum_add_p256.o \
      bignum_bigendian_4.o \
      bignum_cmul_p256.o \
      bignum_deamont_p256.o \
      bignum_demont_p256.o \
      bignum_double_p256.o \
      bignum_half_p256.o \
      bignum_inv_p256.o \
      bignum_littleendian_4.o \
      bignum_mod_n256.o \
      bignum_mod_n256_4.o \
      bignum_mod_p256.o \
      bignum_mod_p256_4.o \
      bignum_montinv_p256.o \
      bignum_montmul_p256.o \
      bignum_montmul_p256_alt.o \
      bignum_montsqr_p256.o \
      bignum_montsqr_p256_alt.o \
      bignum_mux_4.o \
      bignum_neg_p256.o \
      bignum_nonzero_4.o \
      bignum_optneg_p256.o \
      bignum_sub_p256.o \
      bignum_tomont_p256.o \
      bignum_triple_p256.o \
      p256_montjadd.o \
      p256_montjadd_alt.o \
      p256_montjdouble.o \
      p256_montjdouble_alt.o \
      p256_montjmixadd.o \
      p256_montjmixadd_alt.o \
      p256_montjscalarmul.o \
      p256_montjscalarmul_alt.o \
      p256_scalarmul.o \
      p256_scalarmul_alt.o \
      p256_scalarmulbase.o \
      p256_scalarmulbase_alt.o

%.o : %.S ; $(CC) -E -I../../include $< | $(GAS) -o $@ -

default: $(OBJ);

clean:; rm -f *.o *.correct unopt/*.o
