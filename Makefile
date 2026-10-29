# geneva_c — plain Makefile, works natively and with any cross compiler:
#   make                         native build
#   make STATIC=1                static binary (musl / mingw)
#   make CC=mipsel-linux-musl-gcc STATIC=1
#   make CC="zig cc -target mipsel-linux-musleabi" STATIC=1
#   make CC=x86_64-w64-mingw32-gcc        (Windows; detected from the target)
#   make test                    unit tests

CC      ?= cc
AR      ?= ar
STRIP   ?= strip
O       ?= build
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)

TARGET_TRIPLE := $(shell $(CC) -dumpmachine 2>/dev/null)
ifneq (,$(findstring mingw,$(TARGET_TRIPLE))$(findstring windows,$(TARGET_TRIPLE)))
  OS_TARGET ?= windows
endif
OS_TARGET ?= posix

WARN    := -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes -Wno-unused-parameter
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 $(WARN) -D_GNU_SOURCE -DGENEVA_VERSION=\"$(VERSION)\"
LDLIBS  :=

ifeq ($(OS_TARGET),windows)
  EXE     := .exe
  LDLIBS  += -lws2_32 -liphlpapi
  CFLAGS  += -D_WIN32_WINNT=0x0601
else
  EXE     :=
  LDLIBS  += -lpthread -lm
endif

ifeq ($(STATIC),1)
  LDFLAGS += -static
endif

ifeq ($(SMALL),1)
  # size-optimized build for routers with tiny flash
  CFLAGS  += -Os -ffunction-sections -fdata-sections
  LDFLAGS += -Wl,--gc-sections
endif

SRCS    := $(filter-out src/main.c,$(wildcard src/*.c))
OBJS    := $(SRCS:src/%.c=$(O)/%.o)
TSRCS   := $(wildcard tests/*.c)
TOBJS   := $(TSRCS:tests/%.c=$(O)/tests/%.o)

BIN     := $(O)/geneva$(EXE)
TBIN    := $(O)/geneva-tests$(EXE)

.PHONY: all test clean strip

all: $(BIN)

$(O) $(O)/tests:
	@mkdir -p $@

$(O)/%.o: src/%.c src/*.h | $(O)
	$(CC) $(CFLAGS) -c -o $@ $<

$(O)/tests/%.o: tests/%.c tests/*.h src/*.h | $(O)/tests
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

$(O)/libgeneva.a: $(OBJS)
	$(AR) rcs $@ $^

$(BIN): $(O)/main.o $(O)/libgeneva.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TBIN): $(TOBJS) $(O)/libgeneva.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: $(TBIN) $(BIN)
	$(TBIN)

strip: $(BIN)
	$(STRIP) $(BIN)

clean:
	rm -rf $(O)
