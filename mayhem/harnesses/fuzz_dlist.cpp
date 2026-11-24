// libFuzzer harness for the GLideN64 video plugin, driven through the mupen64plus video-plugin API
// it exports (PluginStartup, InitiateGFX, RomOpen, ProcessDList, UpdateScreen) exactly as an
// emulator core drives it. The harness plays the core: the Config* and VidExt_* core functions the
// plugin looks up with dlsym live in a small "core" library built from this file with -DFAKECORE
// and loaded RTLD_LOCAL (the plugin has global variables with the very same names, so they cannot
// be exported from the executable), the harness owns the emulated RDRAM/DMEM/IMEM and registers,
// and rendering goes through Mesa's software GL (EGL, surfaceless platform, llvmpipe).
//
// Input: byte 0 picks the graphics microcode the "game" loaded (its identification string is put
// in the ucode data segment, as a game's ucode carries it); byte 1 picks VI settings; the rest is
// the display list and its data, copied to RDRAM at 0x100000 where the task header points.
// Each input's result depends only on that input. Per input the harness resets RDRAM, DMEM and the
// registers, and resets the plugin the way RomClosed + RomOpen would, minus tearing down the GL
// context (that costs ~300 ms an input on llvmpipe): GBI.destroy/init drops the loaded
// microcodes, RSP_Init re-runs the ROM-open RSP setup, pending texrects are flushed, the frame-buffer
// and depth-buffer lists are destroyed and re-created, the texture cache is cleared, and the plugin's
// global RSP/RDP state structs (RSP, RDP, gSP, gDP, VI: plain structs whose only pointers point into
// gDP itself) are restored to the snapshot taken right after the first RomOpen.
// Kept on purpose, none of it carrying guest data from one input into the next:
//  - the EGL context and the plugin's GL objects: shader programs, the compiled-combiner cache keyed
//    by the combine mode, the texrect drawer's and post-processor's own render targets, the
//    zlut/palette textures (re-uploaded before each use) and the cache's dummy texture;
//  - the plugin's config (read-only, from the fake core);
//  - two file-static words in RDP.cpp (lbw0/lbw1), written by every LoadBlock before they are read.
//
// Built a second time with -DFUZZ_RDP (target `rdp`): the input is then a raw RDP command list run
// through ProcessRDPList followed by the core's frame-buffer API calls (see the FUZZ_RDP block).
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>

#ifdef FAKECORE
#include <EGL/egl.h>
#include <EGL/eglext.h>
#endif

#define M64P_CORE_PROTOTYPES 1
#include "m64p_types.h"
#include "m64p_plugin.h"

#define EXPORT_C extern "C" __attribute__((visibility("default")))

#ifdef FAKECORE
// ---------------------------------------------------------------- core config API (key/value)
struct Value { int i = 0; float f = 0; std::string s; };
static std::map<std::string, Value> g_cfg;
static std::string key(m64p_handle h, const char *name) { return std::string((const char *)h) + "/" + name; }

static void set_override(const char *section_name, int v) { g_cfg[section_name].i = v; g_cfg[section_name].f = (float)v; }

EXPORT_C m64p_error ConfigOpenSection(const char *name, m64p_handle *h) { *h = (m64p_handle)strdup(name); return M64ERR_SUCCESS; }
EXPORT_C m64p_error ConfigDeleteSection(const char *) { return M64ERR_SUCCESS; }
EXPORT_C m64p_error ConfigSaveSection(const char *) { return M64ERR_SUCCESS; }
EXPORT_C m64p_error ConfigSaveFile(void) { return M64ERR_SUCCESS; }
EXPORT_C m64p_error ConfigSetDefaultInt(m64p_handle h, const char *n, int v, const char *) {
  auto k = key(h, n); if (!g_cfg.count(k)) { g_cfg[k].i = v; g_cfg[k].f = (float)v; } return M64ERR_SUCCESS; }
EXPORT_C m64p_error ConfigSetDefaultFloat(m64p_handle h, const char *n, float v, const char *) {
  auto k = key(h, n); if (!g_cfg.count(k)) { g_cfg[k].f = v; g_cfg[k].i = (int)v; } return M64ERR_SUCCESS; }
EXPORT_C m64p_error ConfigSetDefaultBool(m64p_handle h, const char *n, int v, const char *) {
  auto k = key(h, n); if (!g_cfg.count(k)) { g_cfg[k].i = v; g_cfg[k].f = (float)v; } return M64ERR_SUCCESS; }
EXPORT_C m64p_error ConfigSetDefaultString(m64p_handle h, const char *n, const char *v, const char *) {
  auto k = key(h, n); if (!g_cfg.count(k)) g_cfg[k].s = v ? v : ""; return M64ERR_SUCCESS; }
EXPORT_C int ConfigGetParamInt(m64p_handle h, const char *n) { return g_cfg[key(h, n)].i; }
EXPORT_C float ConfigGetParamFloat(m64p_handle h, const char *n) { return g_cfg[key(h, n)].f; }
EXPORT_C int ConfigGetParamBool(m64p_handle h, const char *n) { return g_cfg[key(h, n)].i; }
EXPORT_C const char *ConfigGetParamString(m64p_handle h, const char *n) { return g_cfg[key(h, n)].s.c_str(); }
static std::string g_dir = [] {
  const char *tmp = getenv("TMPDIR");
  return std::string(tmp && *tmp ? tmp : "/tmp");
}();
EXPORT_C const char *ConfigGetSharedDataFilepath(const char *) { return nullptr; }
EXPORT_C const char *ConfigGetUserConfigPath(void) { return g_dir.c_str(); }
EXPORT_C const char *ConfigGetUserDataPath(void) { return g_dir.c_str(); }
EXPORT_C const char *ConfigGetUserCachePath(void) { return g_dir.c_str(); }
EXPORT_C m64p_error ConfigExternalOpen(const char *, m64p_handle *) { return M64ERR_FILES; }
EXPORT_C m64p_error ConfigExternalClose(m64p_handle) { return M64ERR_SUCCESS; }
EXPORT_C m64p_error ConfigExternalGetParameter(m64p_handle, const char *, const char *, char *, int) { return M64ERR_INPUT_NOT_FOUND; }

// the core's version: 2.5.9, new enough for GFX_INFO version 2 (RDRAM size, SP status)
EXPORT_C m64p_error PluginGetVersion(m64p_plugin_type *type, int *version, int *api, const char **name, int *caps) {
  if (type) *type = M64PLUGIN_CORE;
  if (version) *version = 0x020509;
  if (api) *api = 0x020001;
  if (name) *name = "fuzz core";
  if (caps) *caps = 0;
  return M64ERR_SUCCESS;
}

static int init_overrides = [] {
  // settings a core would read from the user's config: no threaded GL backend (it spawns its own
  // GL thread), no on-disk shader cache, no texture packs, no frame-buffer dumps to disk
  set_override("Video-GLideN64/ThreadedVideo", 0);
  set_override("Video-GLideN64/EnableShadersStorage", 0);
  set_override("Video-GLideN64/txHiresEnable", 0);
  set_override("Video-GLideN64/txDump", 0);
  set_override("Video-GLideN64/txSaveCache", 0);
  set_override("Video-GLideN64/txEnhancedTextureFileStorage", 0);
  set_override("Video-GLideN64/txHiresTextureFileStorage", 0);
  set_override("Video-GLideN64/EnableCopyColorToRDRAM", 1);
  set_override("Video-GLideN64/EnableCopyDepthToRDRAM", 1);
  set_override("Video-GLideN64/EnableCopyColorFromRDRAM", 1);
  set_override("Video-GLideN64/DisableFBInfo", 0);  // the core's FBRead/FBWrite/FBGetFrameBufferInfo
  set_override("Video-General/ScreenWidth", 320);
  set_override("Video-General/ScreenHeight", 240);
  return 0;
}();

// ---------------------------------------------------------------- core video extension (EGL)
static EGLDisplay g_dpy = EGL_NO_DISPLAY;
static EGLContext g_ctx = EGL_NO_CONTEXT;
static EGLSurface g_surf = EGL_NO_SURFACE;
static int g_major = 3, g_minor = 3;

EXPORT_C m64p_error VidExt_Init(void) {
  auto getPlatformDisplay = (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
  g_dpy = getPlatformDisplay ? getPlatformDisplay(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, nullptr)
                             : eglGetDisplay(EGL_DEFAULT_DISPLAY);
  if (g_dpy == EGL_NO_DISPLAY || !eglInitialize(g_dpy, nullptr, nullptr)) return M64ERR_SYSTEM_FAIL;
  return M64ERR_SUCCESS;
}
EXPORT_C m64p_error VidExt_Quit(void) { return M64ERR_SUCCESS; }
EXPORT_C m64p_error VidExt_ListFullscreenModes(m64p_2d_size *, int *n) { *n = 0; return M64ERR_SUCCESS; }
EXPORT_C m64p_error VidExt_ListFullscreenRates(m64p_2d_size, int *n, int *) { *n = 0; return M64ERR_SUCCESS; }
EXPORT_C m64p_error VidExt_SetVideoMode(int w, int h, int, m64p_video_mode, m64p_video_flags) {
  if (g_ctx != EGL_NO_CONTEXT) return M64ERR_SUCCESS;
  const EGLint cfg_attr[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
                             EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_DEPTH_SIZE, 16, EGL_NONE};
  EGLConfig cfg;
  EGLint n = 0;
  if (!eglChooseConfig(g_dpy, cfg_attr, &cfg, 1, &n) || n < 1) return M64ERR_SYSTEM_FAIL;
  eglBindAPI(EGL_OPENGL_API);
  const EGLint ctx_attr[] = {EGL_CONTEXT_MAJOR_VERSION, g_major, EGL_CONTEXT_MINOR_VERSION, g_minor,
                             EGL_CONTEXT_OPENGL_PROFILE_MASK, EGL_CONTEXT_OPENGL_CORE_PROFILE_BIT, EGL_NONE};
  g_ctx = eglCreateContext(g_dpy, cfg, EGL_NO_CONTEXT, ctx_attr);
  if (g_ctx == EGL_NO_CONTEXT) return M64ERR_SYSTEM_FAIL;
  const EGLint pb_attr[] = {EGL_WIDTH, w > 0 ? w : 640, EGL_HEIGHT, h > 0 ? h : 480, EGL_NONE};
  g_surf = eglCreatePbufferSurface(g_dpy, cfg, pb_attr);
  if (!eglMakeCurrent(g_dpy, g_surf, g_surf, g_ctx)) return M64ERR_SYSTEM_FAIL;
  return M64ERR_SUCCESS;
}
EXPORT_C m64p_error VidExt_SetVideoModeWithRate(int w, int h, int, int bpp, m64p_video_mode m, m64p_video_flags f) {
  return VidExt_SetVideoMode(w, h, bpp, m, f); }
EXPORT_C m64p_error VidExt_ResizeWindow(int, int) { return M64ERR_SUCCESS; }
EXPORT_C m64p_error VidExt_SetCaption(const char *) { return M64ERR_SUCCESS; }
EXPORT_C m64p_error VidExt_ToggleFullScreen(void) { return M64ERR_SUCCESS; }
EXPORT_C m64p_function VidExt_GL_GetProcAddress(const char *name) { return (m64p_function)eglGetProcAddress(name); }
EXPORT_C m64p_error VidExt_GL_SetAttribute(m64p_GLattr a, int v) {
  if (a == M64P_GL_CONTEXT_MAJOR_VERSION) g_major = v;
  if (a == M64P_GL_CONTEXT_MINOR_VERSION) g_minor = v;
  return M64ERR_SUCCESS; }
EXPORT_C m64p_error VidExt_GL_GetAttribute(m64p_GLattr a, int *v) {
  *v = a == M64P_GL_CONTEXT_MAJOR_VERSION ? g_major : a == M64P_GL_CONTEXT_MINOR_VERSION ? g_minor : 0;
  return M64ERR_SUCCESS; }
EXPORT_C m64p_error VidExt_GL_SwapBuffers(void) { eglSwapBuffers(g_dpy, g_surf); return M64ERR_SUCCESS; }
EXPORT_C uint32_t VidExt_GL_GetDefaultFramebuffer(void) { return 0; }

#else
// ---------------------------------------------------------------- the plugin's exported API
extern "C" {
m64p_error PluginStartup(m64p_dynlib_handle, void *, void (*)(void *, int, const char *));
int InitiateGFX(GFX_INFO);
int RomOpen(void);
void ProcessDList(void);
void ProcessRDPList(void);
void FBRead(unsigned int addr);
void FBWrite(unsigned int addr, unsigned int size);
void FBGetFrameBufferInfo(void *pinfo);
void UpdateScreen(void);
void ViStatusChanged(void);
void ViWidthChanged(void);
}

// the plugin's global RSP/RDP state (exported from the plugin; types from its headers)
#include "RSP.h"
#include "RDP.h"
#include "gSP.h"
#include "gDP.h"
#include "VI.h"
#include "GBI.h"
#include "FrameBuffer.h"
#include "DepthBuffer.h"
#include "Textures.h"
#include "DisplayWindow.h"
static RSPInfo g_rsp0; static RDPInfo g_rdp0; static gSPInfo g_gsp0; static gDPInfo g_gdp0; static VIInfo g_vi0;
static void snapshot_state() {
  memcpy(&g_rsp0, &RSP, sizeof RSP); memcpy(&g_rdp0, &RDP, sizeof RDP); memcpy(&g_gsp0, &gSP, sizeof gSP);
  memcpy(&g_gdp0, &gDP, sizeof gDP); memcpy(&g_vi0, &VI, sizeof VI);
}
static void reset_plugin() {
  dwnd().getDrawer().flush();  // draw texrects still pending from the last input, as a frame end does
  FrameBuffer_Destroy();
  DepthBuffer_Destroy();
  textureCache().clear();      // the loaded (guest) textures; frame-buffer textures went with their buffers
  DepthBuffer_Init();
  FrameBuffer_Init();
  GBI.destroy();
  GBI.init();
  RSP_Init();
  memcpy(&RSP, &g_rsp0, sizeof RSP); memcpy(&RDP, &g_rdp0, sizeof RDP); memcpy(&gSP, &g_gsp0, sizeof gSP);
  memcpy(&gDP, &g_gdp0, sizeof gDP); memcpy(&VI, &g_vi0, sizeof VI);
}

// ---------------------------------------------------------------- emulated machine
static const uint32_t kRdramSize = 8 * 1024 * 1024;
static uint8_t *g_rdram, g_dmem[0x1000], g_imem[0x1000], g_header[0x40];
static unsigned int g_regs[40];
static const unsigned int g_rdram_size = kRdramSize;
static void check_interrupts(void) {}

enum { MI_INTR, DPC_START, DPC_END, DPC_CURRENT, DPC_STATUS, DPC_CLOCK, DPC_BUFBUSY, DPC_PIPEBUSY, DPC_TMEM,
       VI_STATUS, VI_ORIGIN, VI_WIDTH, VI_INTR, VI_V_CURRENT_LINE, VI_TIMING, VI_V_SYNC, VI_H_SYNC, VI_LEAP,
       VI_H_START, VI_V_START, VI_V_BURST, VI_X_SCALE, VI_Y_SCALE, SP_STATUS };

struct FBInfoEntry { unsigned int addr, size, width, height; };

// Identification strings as the microcodes carry them in their data segment (GBI.cpp matches them).
static const char *kUcodes[] = {
    "RSP SW Version: 2.0D, 04-01-96",
    "RSP Gfx ucode F3DEX         1.21 Yoshitaka Yasumoto 1998 Nintendo.",
    "RSP Gfx ucode F3DEX       fifo 2.08  Yoshitaka Yasumoto 1999 Nintendo.",
    "RSP Gfx ucode F3DZEX.NoN  fifo 2.06H Yoshitaka Yasumoto 1998 Nintendo.",
    "RSP Gfx ucode L3DEX       fifo 2.08  Yoshitaka Yasumoto 1999 Nintendo.",
    "RSP Gfx ucode S2DEX  1.06 Yoshitaka Yasumoto Nintendo",
    "RSP Gfx ucode S2DEX       fifo 2.05  Yoshitaka Yasumoto 1998 Nintendo.",
    "RSP Gfx ucode ZSortp 0.33 Yoshitaka Yasumoto Nintendo.",
};
static const uint32_t kUcStart = 0x1000, kUcData = 0x2000, kUcDataSize = 0x800, kDlist = 0x100000,
                      kFrameBuffer = 0x300000;

static void put32(uint8_t *mem, uint32_t off, uint32_t v) { memcpy(mem + off, &v, 4); }

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  setenv("EGL_PLATFORM", "surfaceless", 0);
  setenv("LIBGL_ALWAYS_SOFTWARE", "1", 0);
  setenv("LP_NUM_THREADS", "0", 0);
  setenv("MESA_SHADER_CACHE_DISABLE", "true", 0);  // no on-disk state outside the input

  g_rdram = (uint8_t *)calloc(1, kRdramSize);
  void *core = dlopen(FAKECORE_PATH, RTLD_NOW | RTLD_LOCAL);
  if (!core) { fprintf(stderr, "dlopen %s: %s\n", FAKECORE_PATH, dlerror()); abort(); }
  if (PluginStartup(core, nullptr, nullptr) != M64ERR_SUCCESS) { fprintf(stderr, "PluginStartup failed\n"); abort(); }

  GFX_INFO gi;
  memset(&gi, 0, sizeof gi);
  memcpy(g_header + 0x20, "FUZZ DLIST          ", 20);
  gi.HEADER = g_header; gi.RDRAM = g_rdram; gi.DMEM = g_dmem; gi.IMEM = g_imem;
  gi.MI_INTR_REG = &g_regs[MI_INTR];
  gi.DPC_START_REG = &g_regs[DPC_START]; gi.DPC_END_REG = &g_regs[DPC_END];
  gi.DPC_CURRENT_REG = &g_regs[DPC_CURRENT]; gi.DPC_STATUS_REG = &g_regs[DPC_STATUS];
  gi.DPC_CLOCK_REG = &g_regs[DPC_CLOCK]; gi.DPC_BUFBUSY_REG = &g_regs[DPC_BUFBUSY];
  gi.DPC_PIPEBUSY_REG = &g_regs[DPC_PIPEBUSY]; gi.DPC_TMEM_REG = &g_regs[DPC_TMEM];
  gi.VI_STATUS_REG = &g_regs[VI_STATUS]; gi.VI_ORIGIN_REG = &g_regs[VI_ORIGIN]; gi.VI_WIDTH_REG = &g_regs[VI_WIDTH];
  gi.VI_INTR_REG = &g_regs[VI_INTR]; gi.VI_V_CURRENT_LINE_REG = &g_regs[VI_V_CURRENT_LINE];
  gi.VI_TIMING_REG = &g_regs[VI_TIMING]; gi.VI_V_SYNC_REG = &g_regs[VI_V_SYNC]; gi.VI_H_SYNC_REG = &g_regs[VI_H_SYNC];
  gi.VI_LEAP_REG = &g_regs[VI_LEAP]; gi.VI_H_START_REG = &g_regs[VI_H_START]; gi.VI_V_START_REG = &g_regs[VI_V_START];
  gi.VI_V_BURST_REG = &g_regs[VI_V_BURST]; gi.VI_X_SCALE_REG = &g_regs[VI_X_SCALE]; gi.VI_Y_SCALE_REG = &g_regs[VI_Y_SCALE];
  gi.CheckInterrupts = check_interrupts;
  gi.version = 2;
  gi.SP_STATUS_REG = &g_regs[SP_STATUS];
  gi.RDRAM_SIZE = &g_rdram_size;
  if (!InitiateGFX(gi)) { fprintf(stderr, "InitiateGFX failed\n"); abort(); }
  if (!RomOpen()) { fprintf(stderr, "RomOpen failed (no GL context?)\n"); abort(); }
  snapshot_state();
  return 0;
}

static void setup_vi(uint8_t vi) {
  // VI: 320x240 16-bit (or 32-bit) NTSC frame buffer at kFrameBuffer
  g_regs[VI_STATUS] = (vi & 1) ? 0x311F : 0x311E;
  g_regs[VI_ORIGIN] = kFrameBuffer + ((vi & 1) ? 1280 : 640);
  g_regs[VI_WIDTH] = (vi & 2) ? 640 : 320;
  g_regs[VI_TIMING] = 0x03E52239; g_regs[VI_V_SYNC] = 0x20D; g_regs[VI_H_SYNC] = 0xC15;
  g_regs[VI_LEAP] = 0x0C150C15; g_regs[VI_H_START] = 0x006C02EC; g_regs[VI_V_START] = 0x002501FF;
  g_regs[VI_V_BURST] = 0x000E0204; g_regs[VI_X_SCALE] = (vi & 2) ? 0x400 : 0x200; g_regs[VI_Y_SCALE] = 0x400;
}

#ifdef FUZZ_RDP
// Low-level mode: the core hands the plugin a raw RDP command list (DPC_START..DPC_END, in RDRAM or,
// with the XBUS bit of DPC_STATUS, in DMEM) through ProcessRDPList, then — as mupen64plus does when the
// CPU touches frame-buffer memory — calls FBGetFrameBufferInfo, FBRead and FBWrite.
// Input: byte 0 = flags (bit 0: XBUS/DMEM command source), byte 1 = VI settings,
// bytes 2..9 = FBRead (buffer index, 24-bit offset) and FBWrite (buffer index, 16-bit offset, size),
// the addresses taken relative to a buffer FBGetFrameBufferInfo reported (or the VI origin);
// the rest is the RDP command list as 32-bit host-order words.
static const size_t kRdpHeader = 10;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < kRdpHeader) return -1;
  if (!g_rdram) LLVMFuzzerInitialize(nullptr, nullptr);
  const bool xbus = data[0] & 1;
  const size_t cap = xbus ? sizeof g_dmem : kFrameBuffer - kDlist;
  size_t len = size - kRdpHeader > cap ? cap : size - kRdpHeader;
  len &= ~(size_t)3;

  reset_plugin();
  memset(g_rdram, 0, kRdramSize);
  memset(g_dmem, 0, sizeof g_dmem);
  memset(g_regs, 0, sizeof g_regs);
  setup_vi(data[1]);
  g_regs[SP_STATUS] = 0x203;
  const uint32_t base = xbus ? 0 : kDlist;
  memcpy(xbus ? g_dmem : g_rdram + kDlist, data + kRdpHeader, len);
  g_regs[DPC_STATUS] = xbus ? 1 : 0;
  g_regs[DPC_START] = g_regs[DPC_CURRENT] = base;
  g_regs[DPC_END] = base + (uint32_t)len;

  ViStatusChanged();
  ViWidthChanged();
  ProcessRDPList();
  UpdateScreen();

  FBInfoEntry info[6];
  FBGetFrameBufferInfo(info);
  auto pick = [&](uint8_t idx) -> uint32_t {
    const FBInfoEntry &e = info[idx % 6];
    return e.addr != 0 ? e.addr : kFrameBuffer;
  };
  const uint32_t rd = (pick(data[2]) + (data[3] | data[4] << 8 | data[5] << 16)) & (kRdramSize - 1);
  const uint32_t wr = (pick(data[6]) + (data[7] | data[8] << 8)) & (kRdramSize - 1);
  const uint32_t wsize = 1u << (data[9] % 3);  // the core writes 1, 2 or 4 bytes at a time
  FBWrite(wr & ~(wsize - 1), wsize);
  FBRead(rd & ~3u);
  ProcessRDPList();  // the next frame's list (a no-op unless DPC_END moved) and its screen update
  UpdateScreen();
  return 0;
}
#else
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return -1;
  if (!g_rdram) LLVMFuzzerInitialize(nullptr, nullptr);
  const size_t nuc = sizeof kUcodes / sizeof kUcodes[0];
  const size_t dl_size = size - 2 > kFrameBuffer - kDlist ? kFrameBuffer - kDlist : size - 2;

  reset_plugin();
  memset(g_rdram, 0, kRdramSize);
  memset(g_dmem, 0, sizeof g_dmem);
  memset(g_regs, 0, sizeof g_regs);
  // RDRAM holds the N64's big-endian memory as host-order 32-bit words (byte address ^ 3)
  for (const char *p = kUcodes[data[0] % nuc], *b = p; *p; p++)
    g_rdram[(kUcData + 0x100 + (uint32_t)(p - b)) ^ 3] = (uint8_t)*p;
  memcpy(g_rdram + kDlist, data + 2, dl_size);

  // OSTask header in DMEM, as the RSP HLE / core hands it over
  put32(g_dmem, 0xFC0, 1);                 // M_GFXTASK
  put32(g_dmem, 0xFD0, kUcStart);          // ucode
  put32(g_dmem, 0xFD8, kUcData);           // ucode data
  put32(g_dmem, 0xFDC, kUcDataSize);       // ucode data size
  put32(g_dmem, 0xFE4, 0x400);             // dram stack size
  put32(g_dmem, 0xFF0, kDlist);            // data_ptr: the display list
  put32(g_dmem, 0xFF4, (uint32_t)dl_size); // data_size

  setup_vi(data[1]);
  g_regs[SP_STATUS] = 0x203; // halt | broke | taskdone, as the RSP plugin sets them
  g_regs[DPC_STATUS] = 0;

  ViStatusChanged();
  ViWidthChanged();
  ProcessDList();
  UpdateScreen();
  return 0;
}
#endif  // FUZZ_RDP
#endif
