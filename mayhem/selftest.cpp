// Known-answer functional checks for GLideNHQ through its exported API (txfilter_*).
// Built by mayhem/build.sh with normal flags, run by mayhem/test.sh. Each CHECK prints
// "PASS <name>" or "FAIL <name>"; test.sh counts them.
#include <png.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "TxFilterExport.h"
#include <Graphics/Parameters.h>

static int failures = 0;
#define CHECK(name, cond)                                   \
  do {                                                      \
    if (cond) printf("PASS %s\n", name);                    \
    else { printf("FAIL %s\n", name); failures++; }         \
  } while (0)

static std::string root;
static std::wstring w(const std::string &s) { return std::wstring(s.begin(), s.end()); }

static bool write_png(const std::string &path, int width, int height, const uint8_t *rgba) {
  // libpng's simplified write API (no error longjmp to manage)
  png_image image;
  memset(&image, 0, sizeof image);
  image.version = PNG_IMAGE_VERSION;
  image.width = width;
  image.height = height;
  image.format = PNG_FORMAT_RGBA;
  return png_image_write_to_file(&image, path.c_str(), 0, rgba, 0, nullptr) != 0;
}

static void put32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }

static bool init(int options) {
  return txfilter_init(1024, 1024, 32, options, 0, w(root + "/cache").c_str(), w(root + "/dump").c_str(),
                       w(root + "/pack").c_str(), L"TEST", nullptr);
}

int main() {
  char tmpl[] = "/tmp/glidenhq-selftest-XXXXXX";
  if (!mkdtemp(tmpl)) return 2;
  root = tmpl;
  for (const char *d : {"/pack", "/pack/TEST", "/cache", "/dump"}) mkdir((root + d).c_str(), 0700);

  // 1. PNG hi-res texture: a 4x8 RGBA image, looked up by its Rice CRC/format/size.
  uint8_t img[8][4][4];
  for (int y = 0; y < 8; y++)
    for (int x = 0; x < 4; x++) { img[y][x][0] = x * 60; img[y][x][1] = y * 30; img[y][x][2] = 7; img[y][x][3] = 255; }
  const std::string png = root + "/pack/TEST/TEST#CAFEBABE#0#2_all.png";
  CHECK("png_fixture_written", write_png(png, 4, 8, &img[0][0][0]));
  init(GHQ_HIRESTEXTURES | FILE_NOTEXCACHE);
  GHQTexInfo info;
  boolean hit = txfilter_hirestex(0, Checksum(0xCAFEBABEu, 0), nullptr, N64FormatSize(0, 2), &info);
  CHECK("png_hirestex_hit", hit);
  CHECK("png_hirestex_width", hit && info.width == 4);
  CHECK("png_hirestex_height", hit && info.height == 8);
  CHECK("png_hirestex_format", hit && info.format == u32(graphics::internalcolorFormat::RGBA8));
  CHECK("png_hirestex_pixels", hit && info.data && memcmp(info.data, img, sizeof img) == 0);
  GHQTexInfo miss;
  CHECK("png_hirestex_wrong_crc_misses", !txfilter_hirestex(0, Checksum(0xCAFEBABFu, 0), nullptr, N64FormatSize(0, 2), &miss));
  CHECK("png_hirestex_wrong_size_misses", !txfilter_hirestex(0, Checksum(0xCAFEBABEu, 0), nullptr, N64FormatSize(0, 1), &miss));
  txfilter_shutdown();
  unlink(png.c_str());

  // 2. BMP hi-res texture: a 2x2 24-bit bottom-up BMP.
  uint8_t bmp[54 + 16] = {0};
  bmp[0] = 'B'; bmp[1] = 'M';
  put32(bmp + 2, sizeof bmp); put32(bmp + 10, 54); put32(bmp + 14, 40);
  put32(bmp + 18, 2); put32(bmp + 22, 2); put16(bmp + 26, 1); put16(bmp + 28, 24);
  put32(bmp + 34, 16);
  // bottom row (y=1 in image), then top row; each row padded to 8 bytes. BGR order.
  const uint8_t rows[16] = {0, 0, 255, 0, 255, 0, 0, 0, /* bottom: red, green */
                            255, 0, 0, 255, 255, 255, 0, 0 /* top: blue, white */};
  memcpy(bmp + 54, rows, 16);
  const std::string bmpf = root + "/pack/TEST/TEST#0BADF00D#0#3_rgb.bmp";
  FILE *f = fopen(bmpf.c_str(), "wb");
  fwrite(bmp, 1, sizeof bmp, f);
  fclose(f);
  // TxHiResLoader::loadFileInfoTex checks for the _rgb.* file by its bare name (relative to the
  // working directory), so a _rgb.* texture only loads with the pack dir as cwd.
  char cwd[4096];
  if (!getcwd(cwd, sizeof cwd)) return 2;
  if (chdir((root + "/pack/TEST").c_str()) != 0) return 2;
  init(GHQ_HIRESTEXTURES | FILE_NOTEXCACHE);
  hit = txfilter_hirestex(0, Checksum(0x0BADF00Du, 0), nullptr, N64FormatSize(0, 3), &info);
  if (chdir(cwd) != 0) return 2;
  CHECK("bmp_hirestex_hit", hit);
  CHECK("bmp_hirestex_dims", hit && info.width == 2 && info.height == 2);
  // top-left texel is blue; readBMP keeps the file's B,G,R byte order -> 255,0,0
  CHECK("bmp_hirestex_topleft_blue", hit && info.data && info.data[0] == 255 && info.data[1] == 0 && info.data[2] == 0);
  // bottom-right texel is green
  CHECK("bmp_hirestex_bottomright_green", hit && info.data && info.data[12] == 0 && info.data[13] == 255 && info.data[14] == 0);
  txfilter_shutdown();
  unlink(bmpf.c_str());

  // 3. txfilter_filter with the 2x enhancement doubles the texture size.
  static uint8_t tex[8 * 8 * 4];
  for (size_t i = 0; i < sizeof tex; i++) tex[i] = (uint8_t)(i * 13);
  txfilter_init(1024, 1024, 32, X2_ENHANCEMENT, 0, w(root + "/cache").c_str(), w(root + "/dump").c_str(),
                w(root + "/pack").c_str(), L"TEST", nullptr);
  hit = txfilter_filter(tex, 8, 8, (uint16)u32(graphics::internalcolorFormat::RGBA8), 0, N64FormatSize(0, 3), &info);
  CHECK("filter_x2_ok", hit);
  CHECK("filter_x2_dims", hit && info.width == 16 && info.height == 16);
  CHECK("filter_x2_format", hit && info.format == u32(graphics::internalcolorFormat::RGBA8));
  txfilter_shutdown();

  // 4. checksum is deterministic and content-sensitive
  // checksums are only computed with hi-res textures or texture dumping enabled
  txfilter_init(1024, 1024, 32, (int)DUMP_TEX, 0, w(root + "/cache").c_str(), w(root + "/dump").c_str(),
                w(root + "/pack").c_str(), L"TEST", nullptr);
  uint64 c1 = txfilter_checksum(tex, 8, 8, 3, 8 * 4, nullptr);
  uint64 c2 = txfilter_checksum(tex, 8, 8, 3, 8 * 4, nullptr);
  tex[5] ^= 1;
  uint64 c3 = txfilter_checksum(tex, 8, 8, 3, 8 * 4, nullptr);
  CHECK("checksum_nonzero", c1 != 0);
  CHECK("checksum_deterministic", c1 == c2);
  CHECK("checksum_content_sensitive", c1 != c3);
  txfilter_shutdown();

  for (const char *d : {"/pack/TEST", "/pack", "/cache", "/dump"}) rmdir((root + d).c_str());
  rmdir(root.c_str());
  printf("selftest: %d failure(s)\n", failures);
  return failures ? 1 : 0;
}
