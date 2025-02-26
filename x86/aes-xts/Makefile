#############################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
#############################################################################

# The x86 assembly (.S) files are all written for the GNU assembler

OBJ = aesni-x86_64-encrypt.o \
      aesni-x86_64-decrypt.o \
      aes-xts-avx512-encrypt.o \
      aes-xts-avx512-decrypt.o

%.o : %.S ; $(CC) -E -I../../include $< | as -o $@ -

default: $(OBJ);

clean:; rm -f *.o *.correct
