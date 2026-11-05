# geneva_c — plain Makefile, works natively and with any cross compiler:
#   make                         native build
#   make STATIC=1                static binary (musl / mingw)
#   make CC=mipsel-linux-musl-gcc STATIC=1
#   make CC="zig cc -target mipsel-linux-musleabi" STATIC=1
#   make CC=x86_64-w64-mingw32-gcc        (Windows; detected from the target)
#   make test                    unit tests
#   make EXT=0                   without the --ext extensions (src/ext/)
#   make EXT_CRYPTO=0            extensions without cryptography (no QUIC decryption)

CC      ?= cc
AR      ?= ar
STRIP   ?= strip
O       ?= build
EXT     ?= 1
EXT_CRYPTO ?= 1
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 1.2.0)

TARGET_TRIPLE := $(shell $(CC) -dumpmachine 2>/dev/null)
ifneq (,$(findstring mingw,$(TARGET_TRIPLE))$(findstring windows,$(TARGET_TRIPLE)))
  OS_TARGET ?= windows
endif
OS_TARGET ?= posix

WARN    := -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes -Wno-unused-parameter
CFLAGS  ?= -O2 -g
LDFLAGS ?=
# Internal flags live in separate variables so that CFLAGS/LDFLAGS given on
# the command line add to them instead of replacing them.
XCFLAGS := -std=c11 $(WARN) -Isrc -D_GNU_SOURCE -DGENEVA_VERSION=\"$(VERSION)\"
XLDFLAGS :=
LDLIBS  :=

ifeq ($(OS_TARGET),windows)
  EXE     := .exe
  LDLIBS  += -lws2_32 -liphlpapi
  XCFLAGS += -U_WIN32_WINNT -D_WIN32_WINNT=0x0601 -D__USE_MINGW_ANSI_STDIO=1
else
  EXE     :=
  LDLIBS  += -lpthread -lm
endif

ifeq ($(STATIC),1)
  XLDFLAGS += -static
endif

ifeq ($(SMALL),1)
  # size-optimized build for routers with tiny flash
  XCFLAGS += -Os -ffunction-sections -fdata-sections
  XLDFLAGS += -Wl,--gc-sections
endif

SRCS    := $(filter-out src/main.c,$(wildcard src/*.c))
HDRS    := $(wildcard src/*.h)
ifeq ($(EXT),1)
  XCFLAGS += -DGENEVA_EXT=1
  SRCS    += $(wildcard src/ext/*.c)
  ifeq ($(EXT_CRYPTO),0)
    XCFLAGS += -DGENEVA_EXT_CRYPTO=0
    SRCS    := $(filter-out src/ext/crypto_%.c,$(SRCS))
  else
    XCFLAGS += -DGENEVA_EXT_CRYPTO=1
  endif
  HDRS    += $(wildcard src/ext/*.h)
else
  XCFLAGS += -DGENEVA_EXT=0
endif
OBJS    := $(SRCS:src/%.c=$(O)/%.o)
TSRCS   := $(wildcard tests/*.c)
TOBJS   := $(TSRCS:tests/%.c=$(O)/tests/%.o)

BIN     := $(O)/geneva$(EXE)
TBIN    := $(O)/geneva-tests$(EXE)

# What the objects depend on besides their sources: a different EXT (or
# compiler, or flags) in the same O= rebuilds everything instead of mixing
# objects of both builds.
CONFIG      := $(O)/config.mk
CONFIG_TEXT := CC=$(CC) EXT=$(EXT) EXT_CRYPTO=$(EXT_CRYPTO) OS=$(OS_TARGET) SMALL=$(SMALL) CFLAGS=$(CFLAGS)

.PHONY: all test clean strip FORCE

all: $(BIN)

$(O) $(O)/tests $(O)/ext:
	@mkdir -p $@

$(CONFIG): FORCE | $(O)
	@if [ "$$(cat $@ 2>/dev/null)" != '$(CONFIG_TEXT)' ]; then echo '$(CONFIG_TEXT)' > $@; fi

# src/ext/ before the generic rule: GNU make before 3.82 takes the first
# matching pattern rule, not the one with the shortest stem
$(O)/ext/%.o: src/ext/%.c $(HDRS) $(CONFIG) | $(O)/ext
	$(CC) $(CFLAGS) $(XCFLAGS) -Isrc -c -o $@ $<

$(O)/%.o: src/%.c $(HDRS) $(CONFIG) | $(O)
	$(CC) $(CFLAGS) $(XCFLAGS) -c -o $@ $<

$(O)/tests/%.o: tests/%.c tests/*.h $(HDRS) $(CONFIG) | $(O)/tests
	$(CC) $(CFLAGS) $(XCFLAGS) -Isrc -c -o $@ $<

# a fresh archive: "ar r" would keep members whose objects are no longer built
$(O)/libgeneva.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(BIN): $(O)/main.o $(O)/libgeneva.a
	$(CC) $(LDFLAGS) $(XLDFLAGS) -o $@ $^ $(LDLIBS)

$(TBIN): $(TOBJS) $(O)/libgeneva.a
	$(CC) $(LDFLAGS) $(XLDFLAGS) -o $@ $^ $(LDLIBS)

test: $(TBIN) $(BIN)
	$(TBIN)

strip: $(BIN)
	$(STRIP) $(BIN)

clean:
	rm -rf $(O)
