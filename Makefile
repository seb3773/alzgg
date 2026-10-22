CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
# -Isrc/bzip2_dec: src/egg_bzip2.c includes "bzlib.h", and it is the header of
# the vendored 1.0.5 that must be read, not a /usr/include/bzlib.h from the
# machine (linking already happens against the 1.0.5 objects in src/bzip2_dec/:
# without this -I the build worked by accident, against the system 1.0.8 header,
# and failed on a machine without libbz2-dev).
I       = -Isrc -Isrc/zlib_deflate -Isrc/bzip2_dec -DHAVE_UNISTD_H

ZL_SRCS = src/zlib_deflate/deflate.c src/zlib_deflate/trees.c \
          src/zlib_deflate/crc32.c src/zlib_deflate/adler32.c \
          src/zlib_deflate/zutil.c src/zlib_deflate/compress.c

# bzip2 1.0.5 (third-party library, bzip2 licence): copied as is into
# src/bzip2_dec/ to decode EGG blocks of method 2. Built separately, without
# -Wextra: its warnings are not this project's, and masking them locally beats
# silencing them everywhere.
BZ_SRCS = src/bzip2_dec/bzlib.c src/bzip2_dec/decompress.c \
          src/bzip2_dec/blocksort.c src/bzip2_dec/compress.c \
          src/bzip2_dec/crctable.c src/bzip2_dec/huffman.c \
          src/bzip2_dec/randtable.c
BZ_OBJS = $(BZ_SRCS:.c=.o)

src/bzip2_dec/%.o: src/bzip2_dec/%.c
	$(CC) -O2 -std=c11 -D_DEFAULT_SOURCE -Isrc/bzip2_dec -c -o $@ $<

# LZMA SDK 4.65 (public domain, licence in src/lzma_sdk/README.txt): version and
# settings pinned because they alone reproduce the 25 reference blocks byte for
# byte (see src/egg_lzma.h). -D_7ZIP_ST: the SDK's single-threaded encoder; the
# stream it produces is identical and does not depend on threads.
LZ_SRCS = src/lzma_sdk/LzmaEnc.c src/lzma_sdk/LzmaDec.c src/lzma_sdk/LzFind.c
LZ_OBJS = $(LZ_SRCS:.c=.o)

src/lzma_sdk/%.o: src/lzma_sdk/%.c
	$(CC) -O2 -std=c11 -D_DEFAULT_SOURCE -D_7ZIP_ST -Isrc/lzma_sdk -c -o $@ $<

# A single binary, like ALZipCon: src/alz.c routes to the ALZ implementation
# (src/cli_alz.c) or the EGG one (src/cli_egg.c) based on the file magic or the
# output extension. Both implementations are linked together; their static
# symbols do not meet and each main became alz_cli_main / egg_cli_main.
ALZ_SRCS = src/alz.c src/cli_alz.c src/cli_egg.c \
           src/egg.c src/egg_w.c src/egg_crypt.c src/egg_lea.c src/alz_inflate.c \
           src/egg_bzip2.c src/egg_azo.c src/egg_lzma.c \
           $(ZL_SRCS) $(BZ_OBJS) $(LZ_OBJS)

alzgg: $(ALZ_SRCS)
	$(CC) $(CFLAGS) $(I) -o $@ $(ALZ_SRCS) -lm
	@echo "-> alzgg ready (ALZ + EGG)"

alz: alzgg

# Internal encoder checkers, outside the user binary: they live in tests/bin/ so
# the root is not cluttered with tools only the test suite uses.
#
# bz2enc: re-encodes every (input, reference bzip2 stream) pair and requires
# byte-for-byte equality. It is the tool that pins blockSize100k on the corpus
# blocks; `alzgg` alone is not enough (the bzip2 route only exists in the
# Optimized profile, for its extensions).
tests/bin/bz2enc: src/bz2enc.c src/egg_bzip2.c src/zlib_deflate/crc32.c $(BZ_OBJS)
	@mkdir -p tests/bin
	$(CC) $(CFLAGS) $(I) -o $@ src/bz2enc.c src/egg_bzip2.c \
		src/zlib_deflate/crc32.c $(BZ_OBJS) -lm
	@echo "-> tests/bin/bz2enc ready"

# azoenc: re-encodes every (input, reference AZO payload) pair and requires
# byte-for-byte equality. It is the tool that pins the internal 2^19 slicing
# (the sysmulti_sys_optimized.egg reference carries two, 524,288 + 109,492
# bytes) and the reset of the models between slices: a single-slice archive
# would not tell them apart.
tests/bin/azoenc: src/azoenc.c src/egg_azo.c src/zlib_deflate/crc32.c
	@mkdir -p tests/bin
	$(CC) $(CFLAGS) $(I) -o $@ src/azoenc.c src/egg_azo.c \
		src/zlib_deflate/crc32.c -lm
	@echo "-> tests/bin/azoenc ready"

# leatv: replays the LEA standard vectors (KS X 3246, annex A) against
# src/egg_lea.c. The rest of the LEA crypto chain (PBKDF2, verifier, HMAC, CTR)
# is pinned byte for byte by the six archives of packed_egg/
# (hello_normal_lea128/256, lea128/256_store_two...), produced by ALZip 12.30
# with its undocumented -tp3/-tp4.
tests/bin/leatv: src/leatv.c src/egg_lea.c
	@mkdir -p tests/bin
	$(CC) $(CFLAGS) $(I) -o $@ src/leatv.c src/egg_lea.c
	@echo "-> tests/bin/leatv ready"

test: alzgg tests/bin/bz2enc tests/bin/azoenc tests/bin/leatv
	bash tests/run_tests.sh

# HEAVY check, outside `make test`: the 5 GiB encrypted EGG member (two blocks,
# a single encryption context, verifier over the whole member CRC), read back and
# rebuilt byte for byte against its ALZip reference. Expect ~15 GiB of temporary
# space and several minutes; skips cleanly if corpus/huge/ or the reference is
# missing (fixtures/build-fixtures.py --only h regenerates both).
heavy: alzgg
	sh tests/heavy_multiblock.sh

# Same suite, but built with AddressSanitizer/UBSan/LeakSanitizer (also covers
# packed_egg_8.0/: splitmany 3 volumes, non-ASCII names, the five block methods
# — AZO and its two internal slices included — and the two solid routes). ASan
# must be the first library loaded: if the environment sets an LD_PRELOAD
# (libgtk3-nocsd.so.0 for instance), it is removed for this run, otherwise the
# runtime refuses to start. A failure leaves the instrumented binaries in place:
# rerun `make` before measuring anything.
SANFLAGS = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
           -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE

sanitize:
	$(MAKE) -B alzgg tests/bin/bz2enc tests/bin/azoenc tests/bin/leatv \
		CFLAGS='$(SANFLAGS)'
	env -u LD_PRELOAD ASAN_OPTIONS=detect_leaks=1 bash tests/run_tests.sh
	$(MAKE) -B alzgg tests/bin/bz2enc tests/bin/azoenc tests/bin/leatv
	@echo "-> ASan/UBSan/LSan run: OK; optimized binaries restored"

PREFIX  ?= /usr/local
DESTDIR ?=

debug: CFLAGS = -g -O0 -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
debug: clean alzgg

install: alzgg
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 alzgg $(DESTDIR)$(PREFIX)/bin/alzgg

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/alzgg

deb:
	@chmod +x build_deb.sh
	./build_deb.sh

dist:
	@chmod +x build_dist.sh
	./build_dist.sh

clean:
	rm -f alz alzgg tests/bin/bz2enc tests/bin/azoenc tests/bin/leatv \
		src/zlib_deflate/*.o src/bzip2_dec/*.o src/lzma_sdk/*.o
	rm -rf build .tmp_*
	rmdir tests/bin 2>/dev/null || true

.PHONY: clean test sanitize heavy debug install uninstall deb dist
