// libFuzzer harnesses for GLideNHQ, GLideN64's hi-res texture / texture-filter library, driven
// only through its exported C API (src/GLideNHQ/TxFilterExport.h: txfilter_init, txfilter_hirestex,
// txfilter_filter, txfilter_shutdown). One source, built into one binary per FUZZ_MODE:
//
//   FUZZ_HIRES_PNG  a hi-res texture pack PNG (TxHiResNoCache -> TxHiResLoader -> TxImage::readPNG)
//   FUZZ_HIRES_BMP  a hi-res texture pack BMP (TxHiResLoader -> TxImage::readBMP)
//   FUZZ_CACHE_HTS  a <ident>_HIRESTEXTURES.hts texture storage file (TxFileStorage::load/get/readData)
//   FUZZ_CACHE_HTC  a <ident>_HIRESTEXTURES.htc texture cache file (TxMemoryCache::load/get, gz/zstd reader)
//   FUZZ_FILTER     a raw N64 texture run through txfilter_filter (quantize, hqNx/xBRZ/2xSaI, smooth/sharp)
//
// Each input gets a fresh library instance (txfilter_init ... txfilter_shutdown) and its files are
// written into a private scratch dir under $TMPDIR, removed again before the next input, so no
// state carries over between inputs.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <wchar.h>

#include "TxFilterExport.h"
#include <Graphics/Parameters.h>

static std::string g_root;   // scratch dir for this process
static std::wstring g_wroot;
static const wchar_t *kIdent = L"FUZZ";

static std::wstring widen(const std::string &s) { return std::wstring(s.begin(), s.end()); }

static void write_file(const std::string &path, const uint8_t *data, size_t size) {
  FILE *f = fopen(path.c_str(), "wb");
  if (!f) abort();  // the scratch dir is ours; failing to write it is a harness bug
  if (size && fwrite(data, 1, size, f) != size) abort();
  fclose(f);
}


extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  const char *tmp = getenv("TMPDIR");
  std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") + "/glidenhq-fuzz-XXXXXX";
  char *buf = strdup(tmpl.c_str());
  if (!mkdtemp(buf)) abort();
  g_root = buf;
  free(buf);
  for (const char *sub : {"/pack", "/pack/FUZZ", "/cache", "/dump"})
    mkdir((g_root + sub).c_str(), 0700);
  g_wroot = widen(g_root);
  return 0;
}

static void clear_scratch() {
  for (const char *sub : {"/pack/FUZZ", "/cache", "/dump"}) {
    std::string d = g_root + sub;
    if (DIR *dp = opendir(d.c_str())) {
      while (struct dirent *e = readdir(dp)) {
        if (e->d_name[0] == '.') continue;
        unlink((d + "/" + e->d_name).c_str());
      }
      closedir(dp);
    }
  }
}

static boolean init(int maxwh, int options, int cachesize) {
  std::wstring cache = g_wroot + L"/cache", dump = g_wroot + L"/dump", pack = g_wroot + L"/pack";
  return txfilter_init(maxwh, maxwh, 32, options, cachesize, cache.c_str(), dump.c_str(),
                       pack.c_str(), kIdent, nullptr);
}

#if defined(FUZZ_HIRES_PNG) || defined(FUZZ_HIRES_BMP)
// Input: byte 0 = N64 format (0 RGBA,1 YUV,2 CI,3 IA,4 I) / size (0..3 = 4/8/16/32 bit) of the
// texture the file replaces, byte 1 = file-name suffix variant; the rest is the image file.
// Texture pack file names follow the Rice convention <ident>#<CRC>#<fmt>#<siz>_<suffix>
// (TxHiResLoader::checkFileName); the CRC is fixed and the lookup below asks for it.
static const uint32_t kCrc = 0x1234ABCDu;
static int run(const uint8_t *data, size_t size) {
  if (size < 2) return -1;
  const unsigned fmt = (data[0] >> 4) % 5, siz = data[0] & 3;
#ifdef FUZZ_HIRES_PNG
  static const char *suffixes[] = {"all.png", "ciByRGBA.png", "allciByRGBA.png", "rgb.png"};
#else
  static const char *suffixes[] = {"rgb.bmp", "rgb.bmp", "rgb.bmp", "rgb.bmp"};
#endif
  const char *suffix = suffixes[data[1] & 3];
  char name[128];
  snprintf(name, sizeof name, "FUZZ#%08X#%01X#%01X_%s", kCrc, fmt, siz, suffix);
  write_file(g_root + "/pack/FUZZ/" + name, data + 2, size - 2);

  // GHQ_HIRESTEXTURES + FILE_NOTEXCACHE: index the pack dir, load the file on lookup.
  init(4096, GHQ_HIRESTEXTURES | FILE_NOTEXCACHE | (data[1] & 0x80 ? FORCE16BPP_HIRESTEX : 0) |
                 (data[1] & 0x40 ? LET_TEXARTISTS_FLY : 0), 0);
  uint16 palette[256];
  for (int i = 0; i < 256; i++) palette[i] = (uint16)(i * 0x0101);
  GHQTexInfo info;
  // TxHiResLoader::loadFileInfoTex tests for the _rgb.*/_a.* companions by bare file name, i.e.
  // relative to the working directory, so the lookup runs with the pack dir as cwd (as when the
  // emulator is started from it); restored right after so libFuzzer artifacts land in the real cwd.
  char cwd[4096];
  if (!getcwd(cwd, sizeof cwd)) abort();
  if (chdir((g_root + "/pack/FUZZ").c_str()) != 0) abort();
  txfilter_hirestex(0, Checksum(kCrc, 0), palette, N64FormatSize(fmt, siz), &info);
  if (chdir(cwd) != 0) abort();
  txfilter_shutdown();
  return 0;
}
#endif

#if defined(FUZZ_CACHE_HTS) || defined(FUZZ_CACHE_HTC)
// Input: byte 0 = number of lookups n (0..7), then n * (8-byte checksum, 2-byte N64 format/size),
// then the cache file. The cache stores textures under (checksum, format/size) keys, so the
// lookups are what makes the stored texture records get read back.
static int run(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  size_t n = data[0] & 7;
  if (size < 1 + n * 10) return -1;
  const uint8_t *q = data + 1;
  const uint8_t *file = q + n * 10;
  size_t file_size = size - 1 - n * 10;
#ifdef FUZZ_CACHE_HTS
  write_file(g_root + "/cache/FUZZ_HIRESTEXTURES.hts", file, file_size);
  const int options = GHQ_HIRESTEXTURES | FILE_HIRESTEXCACHE;
#else
  write_file(g_root + "/cache/FUZZ_HIRESTEXTURES.htc", file, file_size);
  const int options = GHQ_HIRESTEXTURES | DUMP_HIRESTEXCACHE | GZ_HIRESTEXCACHE;
#endif
  // No pack dir for this ident -> TxHiResCache loads the cache file with force=true.
  rmdir((g_root + "/pack/FUZZ").c_str());
  init(1024, options, 0);
  for (size_t i = 0; i < n; i++, q += 10) {
    uint64_t crc;
    uint16_t fs;
    memcpy(&crc, q, 8);
    memcpy(&fs, q + 8, 2);
    GHQTexInfo info;
    txfilter_hirestex(0, Checksum(crc), nullptr, N64FormatSize(fs & 0xff, fs >> 8), &info);
  }
  txfilter_shutdown();
  mkdir((g_root + "/pack/FUZZ").c_str(), 0700);
  return 0;
}
#endif

#ifdef FUZZ_FILTER
// Input: byte 0 = filter (smooth 0..4 | sharp 0..2), byte 1 = enhancement (0..12) + deposterize
// + force16bpp, byte 2 = source format, bytes 3/4 = width/height (1..64), then the pixels. The
// API contract (txfilter_filter) is a src buffer of width*height texels of srcformat, so a short
// input is rejected rather than padded.
static int run(const uint8_t *data, size_t size) {
  if (size < 5) return -1;
  static const int smooth[] = {NO_SMOOTH_FILTER, SMOOTH_FILTER_1, SMOOTH_FILTER_2, SMOOTH_FILTER_3, SMOOTH_FILTER_4};
  static const int sharp[] = {NO_SHARP_FILTER, SHARP_FILTER_1, SHARP_FILTER_2};
  int options = smooth[(data[0] & 0x0f) % 5] | sharp[(data[0] >> 4) % 3];
  options |= ((data[1] & 0x0f) % 13) << 8;
  if (data[1] & 0x10) options |= DEPOSTERIZE;
  if (data[1] & 0x20) options |= FORCE16BPP_TEX;
  const int maxbpp_16 = data[1] & 0x40;
  uint32_t fmts[] = {u32(graphics::internalcolorFormat::RGBA8), u32(graphics::internalcolorFormat::RGBA4),
                     u32(graphics::internalcolorFormat::RGB5_A1), u32(graphics::internalcolorFormat::RGB8)};
  const unsigned fi = data[2] & 3;
  const int bpp = fi == 0 ? 4 : 2;
  const int w = (data[3] & 63) + 1, h = (data[4] & 63) + 1;
  const size_t need = (size_t)w * h * bpp;
  if (size - 5 < need) return -1;
  // The plugin hands txfilter_filter textures held in 32-bit words (TxQuantize reads the source
  // a word at a time), so the buffer is the texture rounded up to whole words, zero-padded.
  const size_t alloc = (need + 3) & ~(size_t)3;
  uint8_t *src = (uint8_t *)calloc(1, alloc);
  memcpy(src, data + 5, need);
  std::wstring cache = g_wroot + L"/cache", dump = g_wroot + L"/dump", pack = g_wroot + L"/pack";
  txfilter_init(1024, 1024, maxbpp_16 ? 16 : 32, options, 0, cache.c_str(), dump.c_str(),
                pack.c_str(), kIdent, nullptr);
  GHQTexInfo info;
  txfilter_filter(src, w, h, (uint16)fmts[fi], 0, N64FormatSize(0, 2), &info);
  txfilter_shutdown();
  free(src);
  return 0;
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (g_root.empty()) LLVMFuzzerInitialize(nullptr, nullptr);
  clear_scratch();
  int r = run(data, size);
  clear_scratch();
  return r;
}
