#############################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
#############################################################################

# The x86 assembly (.S) files are all written for the GNU assembler

OBJ = aes_hw_xts_encrypt.o \
      aes_hw_xts_encrypt_clean.o \
      aes_hw_xts_decrypt.o \
      example_left.o \
      example_right.o

%.o : %.S ; $(CC) -E -I../../include $< | as -o $@ -

default: $(OBJ);

clean:; rm -f *.o *.correct
