#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) Build the project libraries with the sanitizers + DWARF 3, instrumented by AFL++'s afl-clang-fast
#    (Mayhem fuzzes the target natively as an AFL binary, `afl: true`). -DFUZZING_AFL is upstream's own
#    fuzz switch: it makes CheckRegisteredSessions() accept any session handle, so the harness can
#    reach every encapsulation command without a handshake (only the libs are built, never upstream's
#    main.c, which does not link and skips the setup the harness needs).
# Benign, ubiquitous UB in the endian helpers (e.g. endianconv.c:101 `buffer[3] << 24` on an int):
# relax only shift-base so it does not mask real findings; ASan and every other UBSan check still halt.
RELAX_FLAGS="-fno-sanitize=shift-base"
# The AFL compiler is named explicitly (not -DCMAKE_C_COMPILER, which would re-key the cache on a re-run).
AFL_CC=afl-clang-fast
CC=$AFL_CC cmake -S source -B build/fuzz -G Ninja \
  -DOpENer_PLATFORM:STRING=POSIX -DCMAKE_BUILD_TYPE:STRING= -DBUILD_SHARED_LIBS:BOOL=OFF \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $RELAX_FLAGS -DFUZZING_AFL" >/dev/null
cmake --build build/fuzz -j"$MAYHEM_JOBS" \
  --target CIP Utils SAMPLE_APP ENET_ENCAP NVDATA PLATFORM_GENERIC POSIXPLATFORM

LIBS=(PLATFORM_GENERIC POSIXPLATFORM SAMPLE_APP CIP ENET_ENCAP NVDATA Utils)
LIBPATHS=()
for l in "${LIBS[@]}"; do LIBPATHS+=("$(find build/fuzz -name "lib${l}.a" | head -n1)"); done
INCS=(-Isource -Isource/src -Isource/src/cip -Isource/src/enet_encap -Isource/src/ports
      -Isource/src/utils -Isource/src/ports/nvdata -Isource/src/ports/POSIX
      -Isource/src/ports/POSIX/sample_application -Ibuild/fuzz/src/ports)
DEFS=(-D_POSIX_C_SOURCE=200112L -D_GNU_SOURCE -DOPENER_POSIX -DRESTRICT=restrict -DOPENER_CONSUMED_DATA_HAS_RUN_IDLE_HEADER
      -DPC_OPENER_ETHERNET_BUFFER_SIZE=512)

# 2) Harness: AFL binary (reads one packet from stdin; run outside AFL it handles stdin once, so it
#    is its own reproducer), with LeakSanitizer switched off at build time.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o /tmp/lsan_off.o
$AFL_CC $SANITIZER_FLAGS $DEBUG_FLAGS $RELAX_FLAGS "${DEFS[@]}" "${INCS[@]}" \
  mayhem/fuzz_enip.c /tmp/lsan_off.o \
  -Wl,--start-group "${LIBPATHS[@]}" -Wl,--end-group -lrt -lpthread -o /mayhem/fuzz_enip

# 3) Test suite (CppUTest, project's NORMAL flags, own build tree).
CC=gcc CXX=g++ cmake -S source -B build/tests -G Ninja \
  -DOpENer_PLATFORM:STRING=POSIX -DOpENer_TESTS:BOOL=ON -DCPPUTEST_HOME=/usr \
  -DCMAKE_BUILD_TYPE:STRING= \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build build/tests -j"$MAYHEM_JOBS" --target OpENer_Tests
