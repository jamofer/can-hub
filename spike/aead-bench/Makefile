# AEAD bench — standalone, not part of the main can-hub build.
#
# Links the archives an existing build tree already produced, so it measures the
# engines that build negotiates. Point BUILD at that tree:
#
#   make BUILD=../../build/x86_64/release && ./aead_bench
#   make BUILD=../../build/arm64/release   # on the arm64 target, not cross
#
# Fusion is x86-64 only; the build tree's own gate decides, so pass FUSION=0
# when the tree was configured without it (every non-x86-64 target).

BUILD ?= ../../build/x86_64/release
ROOT := ../..
PICOTLS_SRC := $(ROOT)/build/picotls-src
FUSION ?= 1

CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS := -I$(ROOT)/src -I$(PICOTLS_SRC)/include -I$(PICOTLS_SRC)/lib -I$(ROOT)/build/monocypher-src/src
LIBS := $(BUILD)/picotls-build/libpicotls-minicrypto.a \
        $(BUILD)/picotls-build/libpicotls-core.a \
        $(BUILD)/libmonocypher.a

ifeq ($(FUSION),1)
CFLAGS += -maes -mpclmul -mssse3 -mavx2
CPPFLAGS += -DCAN_HUB_TLS_FUSION
LIBS := $(BUILD)/picotls-build/libpicotls-fusion.a $(LIBS)
endif

aead_bench: aead_bench.c $(ROOT)/src/platform/linux/shared/tls_aead.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f aead_bench

.PHONY: clean
