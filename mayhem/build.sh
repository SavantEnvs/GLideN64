#!/usr/bin/env bash
# mayhem/build.sh — build the GLideNHQ fuzz harnesses (+ standalone reproducers) and the selftest.
#
# GLideNHQ (src/GLideNHQ) is GLideN64's hi-res texture / texture-filter library. Upstream builds it
# as a static lib from src/GLideNHQ/CMakeLists.txt, linked against prebuilt libpng/zlib/zstd in
# src/GLideNHQ/lib; we compile the same source list here with the fuzz flags and link the system
# (apt) libpng/zlib/zstd instead (upstream's USE_SYSTEM_LIBS route). The GL enum table the library
# uses for its colour formats lives in src/Graphics/OpenGLContext/opengl_Parameters.cpp and is
# compiled in too, so no GL context is needed.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
S="$SRC/src"
HQ="$S/GLideNHQ"
CPP_SRCS="TextureFilters.cpp TextureFilters_2xsai.cpp TextureFilters_hq2x.cpp TextureFilters_hq4x.cpp
  TextureFilters_xbrz.cpp TxCache.cpp TxDbg.cpp TxFilter.cpp TxFilterExport.cpp TxHiResLoader.cpp
  TxHiResCache.cpp TxHiResNoCache.cpp TxImage.cpp TxQuantize.cpp TxReSample.cpp TxTexCache.cpp TxUtil.cpp"
C_SRCS="zstd/zstd_zlibwrapper.c zstd/gzclose.c zstd/gzlib.c zstd/gzread.c zstd/gzwrite.c"
# Upstream's Linux defines minus -DNDEBUG (asserts stay on). No -I$HQ/inc: the system png.h/zlib.h
# must match the linked libraries.
DEFS="-DOS_LINUX -DTXFILTER_LIB -DZWRAP_USE_ZSTD -I$S -I$S/osal -I$S/inc -I$HQ"
LIBS="-lpng -lz -lzstd -lpthread -lm"

# build_lib <objdir> <flags...>: compile GLideNHQ + osal + GL parameter table into <objdir>/libglidenhq.a
build_lib() {
  local out="$1"; shift
  local flags="$*"
  mkdir -p "$out"
  local jobs=()
  for f in $CPP_SRCS; do
    jobs+=("$CXX -std=c++17 $flags $DEFS -c $HQ/$f -o $out/$(basename "${f%.*}").o")
  done
  for f in $C_SRCS; do
    jobs+=("$CC $flags $DEFS -c $HQ/$f -o $out/$(basename "${f%.*}").o")
  done
  jobs+=("$CC $flags $DEFS -c $S/osal/osal_files_unix.c -o $out/osal_files_unix.o")
  # osal_keys_unix.c (upstream's no-keyboard osal) rather than osal_keys_linux.c, which polls
  # /dev/input so a user can abort a texture-pack load; device state must not steer a fuzz run.
  jobs+=("$CC $flags $DEFS -c $S/osal/osal_keys_unix.c -o $out/osal_keys_unix.o")
  jobs+=("$CXX -std=c++17 $flags $DEFS -DMUPENPLUSAPI -c $S/Graphics/OpenGLContext/opengl_Parameters.cpp -o $out/opengl_Parameters.o")
  printf '%s\n' "${jobs[@]}" | xargs -P "$MAYHEM_JOBS" -I{} sh -c '{}'
  rm -f "$out/libglidenhq.a"
  ar rcs "$out/libglidenhq.a" "$out"/*.o
}

FUZZ_OBJ="$SRC/mayhem/build-fuzz"
TEST_OBJ="$SRC/mayhem/build-test"

# 1) the library, instrumented (ASan+UBSan halting, DWARF 3) + SanCov for the fuzzers
build_lib "$FUZZ_OBJ" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FUZZ_OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_OBJ/standalone_main.o"

# 2) one fuzzer + one standalone reproducer per mode of mayhem/harnesses/fuzz_glidenhq.cpp
for t in hires_png:FUZZ_HIRES_PNG hires_bmp:FUZZ_HIRES_BMP cache_hts:FUZZ_CACHE_HTS \
         cache_htc:FUZZ_CACHE_HTC filter:FUZZ_FILTER; do
  name="fuzz_${t%%:*}"; def="${t#*:}"
  $CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -D"$def" $DEFS \
    -c "$SRC/mayhem/harnesses/fuzz_glidenhq.cpp" -o "$FUZZ_OBJ/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$FUZZ_OBJ/$name.o" "$FUZZ_OBJ/lsan_off.o" \
    "$FUZZ_OBJ/libglidenhq.a" $LIBS -o "/mayhem/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$FUZZ_OBJ/$name.o" "$FUZZ_OBJ/standalone_main.o" "$FUZZ_OBJ/lsan_off.o" \
    "$FUZZ_OBJ/libglidenhq.a" $LIBS -o "/mayhem/$name-standalone"
done

# 2b) the whole video plugin (mupen64plus API, EGL, no OSD) built with upstream's CMake and its
#     Release configuration, instrumented, for fuzz_dlist. Notes:
#     - CMAKE_HAVE_LIBC_PTHREAD: GLideNHQ/CMakeLists.txt adds -static to its C flags, which makes
#       CMake's pthread probe fail to link under ASan; glibc has pthreads built in.
#     - mayhem/plugin_sanitize.cmake (CMAKE_PROJECT_INCLUDE) adds -fno-sanitize=array-bounds to
#       src/GBI.cpp's compile line only: its F3DEX3 name probe trips UBSan's bounds check on EVERY
#       microcode load, before any input is read. All other plugin files keep the full UBSan set.
PLUGIN_BUILD="$SRC/mayhem/build-plugin"
PLUGIN_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1"
mkdir -p "$PLUGIN_BUILD"
cmake -S "$S" -B "$PLUGIN_BUILD" -DCMAKE_BUILD_TYPE=Release -DMUPENPLUSAPI=On -DNO_OSD=On -DEGL=On \
  -DUSE_SYSTEM_LIBS=On -DUSE_IPO=Off -DCMAKE_HAVE_LIBC_PTHREAD=ON \
  -DCMAKE_PROJECT_INCLUDE="$SRC/mayhem/plugin_sanitize.cmake" \
  -DCMAKE_C_FLAGS="$PLUGIN_FLAGS" -DCMAKE_CXX_FLAGS="$PLUGIN_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$SANITIZER_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS"
cmake --build "$PLUGIN_BUILD" -j"$MAYHEM_JOBS"
PLUGIN_SO="$PLUGIN_BUILD/plugin/Release/mupen64plus-video-GLideN64.so"
# the emulator-core side (Config*/VidExt_* over EGL), loaded RTLD_LOCAL by the harness
$CXX -std=c++17 -fPIC -shared $DEBUG_FLAGS -O1 -DFAKECORE -I"$S/inc" \
  "$SRC/mayhem/harnesses/fuzz_dlist.cpp" -lEGL -o "$PLUGIN_BUILD/libfuzzcore.so"
# fuzz_dlist: HLE display lists (ProcessDList); fuzz_rdp: LLE RDP command lists (ProcessRDPList) + FB* API
for t in fuzz_dlist: fuzz_rdp:-DFUZZ_RDP; do
  name="${t%%:*}"; def="${t#*:}"
  $CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $def -DFAKECORE_PATH="\"$PLUGIN_BUILD/libfuzzcore.so\"" -I"$S/inc" -I"$S" \
    -c "$SRC/mayhem/harnesses/fuzz_dlist.cpp" -o "$PLUGIN_BUILD/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$PLUGIN_BUILD/$name.o" "$FUZZ_OBJ/lsan_off.o" \
    "$PLUGIN_SO" -Wl,-rpath,"$(dirname "$PLUGIN_SO")" -ldl -o "/mayhem/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$PLUGIN_BUILD/$name.o" "$FUZZ_OBJ/standalone_main.o" "$FUZZ_OBJ/lsan_off.o" \
    "$PLUGIN_SO" -Wl,-rpath,"$(dirname "$PLUGIN_SO")" -ldl -o "/mayhem/$name-standalone"
done

# 3) the functional selftest, normal flags (no sanitizers), run by mayhem/test.sh
build_lib "$TEST_OBJ" -O2 $COVERAGE_FLAGS
$CXX -std=c++17 -O2 $COVERAGE_FLAGS $DEFS "$SRC/mayhem/selftest.cpp" "$TEST_OBJ/libglidenhq.a" $LIBS \
  -o "$TEST_OBJ/glidenhq_selftest"
