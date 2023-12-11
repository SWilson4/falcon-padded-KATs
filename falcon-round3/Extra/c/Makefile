# Build script for the Falcon implementation.
#
# ==========================(LICENSE BEGIN)============================
#
# Copyright (c) 2017-2019  Falcon Project
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# ===========================(LICENSE END)=============================
#
# @author   Thomas Pornin <thomas.pornin@nccgroup.com>

.POSIX:

# =====================================================================
#
# Configurable options:
#   CC       C compiler; GCC or Clang are fine; MSVC (2015+) works too.
#   CFLAGS   Compilation flags:
#             * Optimization level -O2 or higher is recommended
#            See config.h for some possible configuration macros.
#   LD       Linker; normally the same command as the compiler.
#   LDFLAGS  Linker options, not counting the extra libs.
#   LIBS     Extra libraries for linking:
#             * If using the native FPU, test_falcon and application
#               code that calls this library may need: -lm
#               (normally not needed on x86, both 32-bit and 64-bit)

CC = clang
CFLAGS = -Wall -Wextra -Wshadow -Wundef -O3 #-pg -fno-pie
LD = clang
LDFLAGS = #-pg -no-pie
LIBS = #-lm

# =====================================================================

OBJ = codec.o common.o falcon.o fft.o fpr.o keygen.o rng.o shake.o sign.o vrfy.o
KAT_OBJ = katrng.o
KAT512_OBJ = nist_512.o
KAT1024_OBJ = nist_1024.o

all: test_falcon speed PQCgenKAT_sign_512 PQCgenKAT_sign_1024

clean:
	-rm -f $(OBJ) $(KAT_OBJ) $(KAT512_OBJ) $(KAT1024_OBJ) test_falcon test_falcon.o speed speed.o PQCgenKAT_sign_512 PQCgenKAT_sign_512.o PQCgenKAT_sign_1024 PQCgenKAT_sign_1024.o

test_falcon: test_falcon.o $(OBJ)
	$(LD) $(LDFLAGS) -o test_falcon test_falcon.o $(OBJ) $(LIBS)

speed: speed.o $(OBJ)
	$(LD) $(LDFLAGS) -o speed speed.o $(OBJ) $(LIBS)

PQCgenKAT_sign_512: PQCgenKAT_sign_512.o $(OBJ) $(KAT_OBJ) $(KAT512_OBJ)
	$(LD) $(LDFLAGS) -o PQCgenKAT_sign_512 PQCgenKAT_sign_512.o $(OBJ) $(KAT_OBJ) $(KAT512_OBJ) $(LIBS)

PQCgenKAT_sign_1024: PQCgenKAT_sign_1024.o $(OBJ) $(KAT_OBJ) $(KAT1024_OBJ)
	$(LD) $(LDFLAGS) -o PQCgenKAT_sign_1024 PQCgenKAT_sign_1024.o $(OBJ) $(KAT_OBJ) $(KAT1024_OBJ) $(LIBS)

codec.o: codec.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o codec.o codec.c

common.o: common.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o common.o common.c

falcon.o: falcon.c falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o falcon.o falcon.c

fft.o: fft.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o fft.o fft.c

fpr.o: fpr.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o fpr.o fpr.c

katrng.o: katrng.c katrng.h
	$(CC) $(CFLAGS) -c -o katrng.o katrng.c

keygen.o: keygen.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o keygen.o keygen.c

nist_512.o: nist_512.c api_512.h inner.h
	ln -s api_512.h api.h && $(CC) $(CFLAGS) -c -o nist_512.o nist_512.c && rm api.h

nist_1024.o: nist_1024.c api_1024.h inner.h
	ln -s api_1024.h api.h && $(CC) $(CFLAGS) -c -o nist_1024.o nist_1024.c && rm api.h

PQCgenKAT_sign_512.o: PQCgenKAT_sign.c api_512.h katrng.h
	ln -s api_512.h api.h && $(CC) $(CFLAGS) -c -o PQCgenKAT_sign_512.o PQCgenKAT_sign.c && rm api.h

PQCgenKAT_sign_1024.o: PQCgenKAT_sign.c api_1024.h katrng.h
	ln -s api_1024.h api.h && $(CC) $(CFLAGS) -c -o PQCgenKAT_sign_1024.o PQCgenKAT_sign.c && rm api.h

rng.o: rng.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o rng.o rng.c

shake.o: shake.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o shake.o shake.c

sign.o: sign.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o sign.o sign.c

speed.o: speed.c falcon.h
	$(CC) $(CFLAGS) -c -o speed.o speed.c

test_falcon.o: test_falcon.c falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o test_falcon.o test_falcon.c

vrfy.o: vrfy.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o vrfy.o vrfy.c
