// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "uov.h"

#include "hw/top/dt/acc.h"
#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/crypto/include/sha3.h"
#include "sw/device/lib/dif/dif_acc.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/acc_testutils.h"
#include "sw/device/lib/testing/test_framework/ujson_ottf.h"

#define MODULE_ID MAKE_MODULE_ID('c', 'u', 'v')

// Backend tier, from the BUILD target; the default is the deployed one. Every
// tier answers the same host protocol, so only the app names change here.
// keygen: dmem32k/keygen_stream, sign: dmem32k/sign_ldirect (in the sign_rtl
// hostfed harness), verify: dmem32k/verify_stream.
#ifndef UOV_TIER
#define UOV_TIER bngfaes
#endif
#define UOV_CAT_(a, b, c, d, e) a##b##c##d##e
#define UOV_CAT(a, b, c, d, e) UOV_CAT_(a, b, c, d, e)
#define UOV_KEYGEN(p) UOV_CAT(ov_, p, _keygen_stream_, UOV_TIER, )
#define UOV_SIGN(p) UOV_CAT(ov_, p, _sign_rtl_, UOV_TIER, _hostfed)
#define UOV_VERIFY(p) UOV_CAT(ov_, p, _verify_stream_, UOV_TIER, )

// Rows per window, as the arm's own msgwin allows: the vectors have to run the
// geometry the arm is benchmarked with, or a pass here says nothing about it.
#ifndef UOV_IP_ROWS
#define UOV_IP_ROWS 13, 31
#endif
#ifndef UOV_IS_ROWS
#define UOV_IS_ROWS 17, 29, 18
#endif
#ifndef UOV_IP3_ROWS
#define UOV_IP3_ROWS 13, 32
#endif

// Sign uses the host-fed build: empty buffers, filled over the bus.
#define UOV_DECLARE(p)                               \
  ACC_DECLARE_APP_SYMBOLS(UOV_KEYGEN(p));            \
  ACC_DECLARE_APP_SYMBOLS(UOV_SIGN(p));              \
  ACC_DECLARE_APP_SYMBOLS(UOV_VERIFY(p));            \
  ACC_DECLARE_SYMBOL_ADDR(UOV_KEYGEN(p), slice);     \
  ACC_DECLARE_SYMBOL_ADDR(UOV_KEYGEN(p), slice_end); \
  ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(p), sk_seed);     \
  ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(p), msg_len);     \
  ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(p), msg);         \
  ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(p), sig);         \
  ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(p), sign_s_output_addr)

// Each build embeds only the sets it is given (UOV_WITH_*): all nine apps of
// one tier overflow flash.
#ifdef UOV_WITH_IP
UOV_DECLARE(Ip);
#endif
#ifdef UOV_WITH_IS
UOV_DECLARE(Is);
#endif
#ifdef UOV_WITH_IP3
ACC_DECLARE_APP_SYMBOLS(UOV_KEYGEN(Ip3));
ACC_DECLARE_APP_SYMBOLS(UOV_SIGN(Ip3));
ACC_DECLARE_APP_SYMBOLS(UOV_VERIFY(Ip3));
ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(Ip3), sk_seed);
ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(Ip3), msg_len);
ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(Ip3), msg);
ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(Ip3), sign_s_output_addr);
// Ip3's salt sits at sig byte 119, which no word write can stage.
ACC_DECLARE_SYMBOL_ADDR(UOV_SIGN(Ip3), salt_input);
// The Ip3 keygen kernels export no slice symbols; both sources put it at 0x60,
// 45 rows of WJ x 64 B (WJ 6 with bn.gfmul, 5 without).
#ifndef UOV_IP3_SLICE_BYTES
#error "UOV_IP3_SLICE_BYTES: 17280 (bngfaes, bngfonly) or 14400 (sw, bnaesonly)"
#endif
enum { kIp3Slice = 0x60 };
#endif

enum {
  kCtrlAddr = 0x000,  // phase, arg0, arg1, status
  kSkSeedAddr = 0x020,
  kPkSeedAddr = 0x040,
  kSeedBytes = 16,  // cpk's leading pk_seed
};

enum { kPhaseInit = 0, kPhaseWindow = 1 };
enum { kStatusOk = 0, kSentinel = 0x5a5a5a5a };

// Everything else is derived from the ELF at run time.
typedef struct uov_geometry {
  uint32_t oil_dim;
  uint32_t entry;  // packed bytes per cpk slot
  uint32_t pitch;  // column pitch inside a slice row; Ip pads 44 B into 64
  uint32_t cpk_bytes;
} uov_geometry_t;

static const uov_geometry_t
    __attribute__((unused)) kGeomIp = {44, 44, 64, 43576};
static const uov_geometry_t
    __attribute__((unused)) kGeomIs = {64, 32, 32, 66576};
static const uov_geometry_t
    __attribute__((unused)) kGeomIp3 = {45, 45, 64, 46591};

typedef struct uov_keygen_app {
  acc_app_t app;
  acc_addr_t slice;
  acc_addr_t slice_end;
  const uov_geometry_t *geom;
} uov_keygen_app_t;

typedef struct uov_sign_app {
  acc_app_t app;
  acc_addr_t sk_seed;
  acc_addr_t msg_len;
  acc_addr_t msg;
  acc_addr_t salt;  // 16 B; Ip and Is read it from the sig slot's tail
  acc_addr_t sig_out;
  uint32_t sig_bytes;
} uov_sign_app_t;

// Verify streams cpk through DMEM: INIT, one UPDATE per row-aligned window of
// the packed P3 map, then FINAL. The deployed kernels carry no data segment,
// so unlike keygen this is not read from the ELF - it is the map in the
// kernel's file header, and `rows` the schedule the Verilator cells run.
typedef struct uov_verify_app {
  acc_app_t app;
  bool gf16;  // GF16 packs two field elements per byte, GF256 one
  uint32_t oil_dim;
  uint32_t cpk_bytes;
  uint32_t sig_bytes;
  uint32_t sig_slot;  // zero-padded; INIT reads all of it
  uint32_t oil_addr;
  uint32_t sig_addr;
  uint32_t seed_addr;
  uint32_t win_addr;
  uint32_t win_prefix;   // bytes the kernel skips before a window's first entry
  const uint32_t *rows;  // rows per window
  uint32_t windows;
  // Bytes written per window, zeros after the entries: the loaders read ahead.
  // win_fixed if set, else the entries rounded to 32 B plus win_slack.
  uint32_t win_fixed;
  uint32_t win_slack;
} uov_verify_app_t;

static const uint32_t __attribute__((unused)) kIpRows[] = {UOV_IP_ROWS};
static const uint32_t __attribute__((unused)) kIsRows[] = {UOV_IS_ROWS};
static const uint32_t __attribute__((unused)) kIp3Rows[] = {UOV_IP3_ROWS};

// Ip's loader prefetches up to 352 B past the last entry. Is loads one entry
// at a time and needs no pad - and on its software-AES arms the pad would land
// past winend. Ip3 fills exactly msgwin, as its ISS driver does: more would
// reach the bngfonly arm's constants.
// clang-format off
#ifdef UOV_WITH_IP
static const uov_verify_app_t kVerifyIp = {
    ACC_APP_T_INIT(UOV_VERIFY(Ip)), /*gf16=*/false, /*oil_dim=*/44,
    /*cpk_bytes=*/43576, /*sig_bytes=*/128, /*sig_slot=*/128, /*oil=*/0x060, /*sig=*/0x0E0,
    /*seed=*/0x160, /*win=*/0x180, /*win_prefix=*/16, kIpRows,
    ARRAYSIZE(kIpRows), /*win_fixed=*/0, /*win_slack=*/512};
#endif
#ifdef UOV_WITH_IS
static const uov_verify_app_t kVerifyIs = {
    ACC_APP_T_INIT(UOV_VERIFY(Is)), /*gf16=*/true, /*oil_dim=*/64,
    /*cpk_bytes=*/66576, /*sig_bytes=*/96, /*sig_slot=*/96, /*oil=*/0x040, /*sig=*/0x080,
    /*seed=*/0x0E0, /*win=*/0x100, /*win_prefix=*/0, kIsRows,
    ARRAYSIZE(kIsRows), /*win_fixed=*/0, /*win_slack=*/0};
#endif
#ifdef UOV_WITH_IP3
static const uov_verify_app_t kVerifyIp3 = {
    ACC_APP_T_INIT(UOV_VERIFY(Ip3)), /*gf16=*/false, /*oil_dim=*/45,
    /*cpk_bytes=*/46591, /*sig_bytes=*/135, /*sig_slot=*/160, /*oil=*/0x060, /*sig=*/0x0E0,
    /*seed=*/0x180, /*win=*/0x1A0, /*win_prefix=*/16, kIp3Rows,
    ARRAYSIZE(kIp3Rows), /*win_fixed=*/23968, /*win_slack=*/0};
#endif
// clang-format on

enum { kVerifyInit = 0, kVerifyUpdate = 1, kVerifyFinal = 2 };
enum { kVerifyAccept = 0, kVerifyReject = -1 };

/** Packed bytes per P3 slot, one per oil element. */
static uint32_t entry_bytes(const uov_verify_app_t *a) {
  return a->gf16 ? a->oil_dim / 2 : a->oil_dim;
}

#define UOV_KEYGEN_APP(p, geom)                              \
  ((uov_keygen_app_t){ACC_APP_T_INIT(UOV_KEYGEN(p)),         \
                      ACC_ADDR_T_INIT(UOV_KEYGEN(p), slice), \
                      ACC_ADDR_T_INIT(UOV_KEYGEN(p), slice_end), geom})

static status_t keygen_app(uint32_t param, uov_keygen_app_t *out) {
  switch (param) {
#ifdef UOV_WITH_IP
    case kUovParamUovIp:
      *out = UOV_KEYGEN_APP(Ip, &kGeomIp);
      return OK_STATUS();
#endif
#ifdef UOV_WITH_IS
    case kUovParamUovIs:
      *out = UOV_KEYGEN_APP(Is, &kGeomIs);
      return OK_STATUS();
#endif
#ifdef UOV_WITH_IP3
    case kUovParamUovIp3:
      *out = (uov_keygen_app_t){ACC_APP_T_INIT(UOV_KEYGEN(Ip3)), kIp3Slice,
                                kIp3Slice + UOV_IP3_SLICE_BYTES, &kGeomIp3};
      return OK_STATUS();
#endif
    default:
      LOG_ERROR("Unsupported UOV parameter set: %d", param);
      return INVALID_ARGUMENT();
  }
}

#define UOV_SIGN_APP(p, salt, sig_bytes)                                  \
  ((uov_sign_app_t){                                                      \
      ACC_APP_T_INIT(UOV_SIGN(p)), ACC_ADDR_T_INIT(UOV_SIGN(p), sk_seed), \
      ACC_ADDR_T_INIT(UOV_SIGN(p), msg_len),                              \
      ACC_ADDR_T_INIT(UOV_SIGN(p), msg), salt,                            \
      ACC_ADDR_T_INIT(UOV_SIGN(p), sign_s_output_addr), sig_bytes})

static status_t sign_app(uint32_t param, uov_sign_app_t *out) {
  switch (param) {
#ifdef UOV_WITH_IP
    case kUovParamUovIp:
      *out = UOV_SIGN_APP(Ip, ACC_ADDR_T_INIT(UOV_SIGN(Ip), sig) + 112, 128);
      return OK_STATUS();
#endif
#ifdef UOV_WITH_IS
    case kUovParamUovIs:
      *out = UOV_SIGN_APP(Is, ACC_ADDR_T_INIT(UOV_SIGN(Is), sig) + 80, 96);
      return OK_STATUS();
#endif
#ifdef UOV_WITH_IP3
    case kUovParamUovIp3:
      *out = UOV_SIGN_APP(Ip3, ACC_ADDR_T_INIT(UOV_SIGN(Ip3), salt_input), 135);
      return OK_STATUS();
#endif
    default:
      LOG_ERROR("Unsupported UOV parameter set: %d", param);
      return INVALID_ARGUMENT();
  }
}

static status_t verify_app(uint32_t param, const uov_verify_app_t **out) {
  switch (param) {
#ifdef UOV_WITH_IP
    case kUovParamUovIp:
      *out = &kVerifyIp;
      return OK_STATUS();
#endif
#ifdef UOV_WITH_IS
    case kUovParamUovIs:
      *out = &kVerifyIs;
      return OK_STATUS();
#endif
#ifdef UOV_WITH_IP3
    case kUovParamUovIp3:
      *out = &kVerifyIp3;
      return OK_STATUS();
#endif
    default:
      LOG_ERROR("Unsupported UOV parameter set: %d", param);
      return INVALID_ARGUMENT();
  }
}

static uint32_t round4(uint32_t n) { return (n + 3) & ~UINT32_C(3); }

static status_t write_word(dif_acc_t *acc, uint32_t addr, uint32_t value) {
  return acc_testutils_write_data(acc, sizeof(value), &value, addr);
}

/** Run one phase and check ctrl.status. */
static status_t run_phase(dif_acc_t *acc) {
  TRY(acc_testutils_execute(acc));
  TRY(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));

  int32_t status;
  TRY(acc_testutils_read_data(acc, sizeof(status), kCtrlAddr + 12, &status));
  if (status != kStatusOk) {
    LOG_ERROR("phase reported status %d", status);
    return INTERNAL();
  }
  return OK_STATUS();
}

/** Byte offset of cpk slot (a,b), a <= b, in the packed upper triangle. */
static uint32_t slot_offset(const uov_geometry_t *g, uint32_t a, uint32_t b) {
  return (a * g->oil_dim - a * (a - 1) / 2 + (b - a)) * g->entry;
}

static status_t hash_output(const uint8_t *data, size_t len,
                            cryptotest_uov_output_t *out) {
  otcrypto_const_byte_buf_t msg = {.data = data, .len = len};
  otcrypto_hash_digest_t digest = {.data = (uint32_t *)out->hash,
                                   .len = 8,
                                   .mode = kOtcryptoHashModeSha3_256};
  return otcrypto_sha3_256(msg, &digest);
}

static status_t handle_keygen(ujson_t *uj, dif_acc_t *acc,
                              uov_test_scratch_t *s) {
  cryptotest_uov_keygen_data_t *d = &s->cmd.keygen;
  TRY(ujson_deserialize_cryptotest_uov_keygen_data_t(uj, d));

  uov_keygen_app_t k;
  TRY(keygen_app(d->parameter_set, &k));
  const uov_geometry_t *g = k.geom;

  uint32_t stride = (k.slice_end - k.slice) / g->oil_dim;
  uint32_t wj = stride / g->pitch;
  if (wj == 0 || wj > g->oil_dim) {
    LOG_ERROR("derived window width %d out of range", wj);
    return INTERNAL();
  }

  TRY(acc_testutils_load_app(acc, k.app));
  memset(s->cpk, 0, g->cpk_bytes);

  // INIT expands the seed; pk_seed becomes cpk's first 16 B.
  TRY(write_word(acc, kCtrlAddr + 12, kSentinel));
  TRY(write_word(acc, kCtrlAddr, kPhaseInit));
  TRY(acc_testutils_write_data(acc, d->sk_seed_len, d->sk_seed, kSkSeedAddr));
  TRY(run_phase(acc));
  TRY(acc_testutils_read_data(acc, kSeedBytes, kPkSeedAddr, s->cpk));

  uint8_t *p3 = (uint8_t *)s->cpk + kSeedBytes;

  // One EXECUTE per window; the kernel rewrites the slice, so fold before the
  // next.
  for (uint32_t cs = 0; cs < g->oil_dim; cs += wj) {
    uint32_t wc = (g->oil_dim - cs) < wj ? (g->oil_dim - cs) : wj;

    TRY(write_word(acc, kCtrlAddr + 12, kSentinel));
    TRY(write_word(acc, kCtrlAddr, kPhaseWindow));
    TRY(write_word(acc, kCtrlAddr + 4, cs));
    TRY(write_word(acc, kCtrlAddr + 8, wc));
    TRY(run_phase(acc));

    for (uint32_t j = 0; j < wc; ++j) {
      uint32_t c = cs + j;
      for (uint32_t r = 0; r < g->oil_dim; ++r) {
        uint32_t entry[16];  // >= max entry bytes / 4 (Ip3: 12 words)
        // Whole words: Ip3's 45 B entry reads 3 B of its slot pad.
        TRY(acc_testutils_read_data(
            acc, round4(g->entry), k.slice + r * stride + j * g->pitch, entry));

        uint32_t off = slot_offset(g, r < c ? r : c, r < c ? c : r);
        if (off + g->entry > g->cpk_bytes - kSeedBytes) {
          LOG_ERROR("slot (%d,%d) out of range", r, c);
          return INTERNAL();
        }
        // Byte-wise: Ip3's slots are not word-aligned.
        const uint8_t *src = (const uint8_t *)entry;
        for (size_t b = 0; b < g->entry; ++b) {
          p3[off + b] ^= src[b];
        }
      }
    }
  }

  cryptotest_uov_output_t out;
  memset(&out, 0, sizeof(out));
  TRY(hash_output((const uint8_t *)s->cpk, g->cpk_bytes, &out));
  out.success = true;
  RESP_OK(ujson_serialize_cryptotest_uov_output_t, uj, &out);
  return OK_STATUS();
}

static status_t handle_sign(ujson_t *uj, dif_acc_t *acc,
                            uov_test_scratch_t *s) {
  cryptotest_uov_sign_data_t *d = &s->cmd.sign;
  TRY(ujson_deserialize_cryptotest_uov_sign_data_t(uj, d));

  uov_sign_app_t a;
  TRY(sign_app(d->parameter_set, &a));

  TRY(acc_testutils_load_app(acc, a.app));
  TRY(acc_testutils_write_data(acc, d->sk_seed_len, d->sk_seed, a.sk_seed));
  uint32_t msg_len = (uint32_t)d->message_len;
  TRY(acc_testutils_write_data(acc, sizeof(msg_len), &msg_len, a.msg_len));
  if (msg_len > 0) {
    // The bus needs whole words; the kernel reads only msg_len bytes.
    size_t padded = (d->message_len + 3) & ~(size_t)3;
    memset(d->message + d->message_len, 0, padded - d->message_len);
    TRY(acc_testutils_write_data(acc, padded, d->message, a.msg));
  }
  if (d->salt_len != 16) {
    LOG_ERROR("salt is %d B", (uint32_t)d->salt_len);
    return INVALID_ARGUMENT();
  }
  TRY(acc_testutils_write_data(acc, 16, d->salt, a.salt));

  TRY(acc_testutils_execute(acc));
  TRY(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));

  uint32_t sig[UOV_CMD_MAX_SIG_BYTES / sizeof(uint32_t)];
  TRY(acc_testutils_read_data(acc, round4(a.sig_bytes), a.sig_out, sig));

  cryptotest_uov_output_t out;
  memset(&out, 0, sizeof(out));
  TRY(hash_output((const uint8_t *)sig, a.sig_bytes, &out));
  out.success = true;
  RESP_OK(ujson_serialize_cryptotest_uov_output_t, uj, &out);
  return OK_STATUS();
}

/**
 * The oil half of the signature, left-aligned on `row_start`.
 *
 * The kernel wants element `row_start` first, so every window past the first
 * re-sends it shifted - by bytes for Ip, by nibbles for Is, whose schedule
 * starts a window on an odd row.
 */
static void oil_window(const uov_verify_app_t *a, const uint8_t *sig,
                       uint32_t row_start, uint8_t *oil, uint32_t oil_bytes) {
  // The oil elements are the tail of the signature's x part, salt excluded.
  const uint8_t *src = sig + a->sig_bytes - 16 - entry_bytes(a);
  memset(oil, 0, oil_bytes);
  for (uint32_t k = 0; k < a->oil_dim - row_start; ++k) {
    uint32_t e = row_start + k;
    if (!a->gf16) {
      oil[k] = src[e];
    } else {
      uint8_t v = (uint8_t)((src[e / 2] >> (4 * (e & 1))) & 0xF);
      oil[k / 2] |= (uint8_t)(v << (4 * (k & 1)));
    }
  }
}

/** EXECUTE one INIT or UPDATE; it leaves the status word alone unless it fails.
 */
static status_t verify_phase(dif_acc_t *acc) {
  TRY(acc_testutils_execute(acc));
  TRY(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));
  uint32_t status;
  TRY(acc_testutils_read_data(acc, sizeof(status), kCtrlAddr + 12, &status));
  if (status != kSentinel) {
    LOG_ERROR("verify phase reported status %d", (int32_t)status);
    return INTERNAL();
  }
  return OK_STATUS();
}

/**
 * Write one P3 window: `prefix` bytes (cpk's seed for the first window, zeros
 * after, as the ISS driver does; the kernel skips them), the entries, then
 * zeros up to `total`. Staged in words: Ip3's entries are not word-aligned.
 */
static status_t write_window(dif_acc_t *acc, uint32_t addr, const uint8_t *pk,
                             uint32_t prefix, bool first, uint32_t off,
                             uint32_t body, uint32_t total) {
  static uint32_t stage[256];
  uint8_t *buf = (uint8_t *)stage;
  for (uint32_t pos = 0; pos < total; pos += sizeof(stage)) {
    uint32_t len = total - pos < sizeof(stage) ? total - pos : sizeof(stage);
    for (uint32_t i = 0; i < len; ++i) {
      uint32_t b = pos + i;
      if (b < prefix) {
        buf[i] = first ? pk[b] : 0;
      } else if (b < body) {
        buf[i] = pk[kSeedBytes + off + b - prefix];
      } else {
        buf[i] = 0;
      }
    }
    TRY(acc_testutils_write_data(acc, len, buf, addr + pos));
  }
  return OK_STATUS();
}

/**
 * Drive INIT -> UPDATE x K -> FINAL over the whole cpk and return the verdict.
 *
 * Only accept and reject are verdicts; any other status means the kernel
 * refused the sequence, or never wrote the word at all.
 */
static status_t run_verify(dif_acc_t *acc, const uov_verify_app_t *a,
                           const uint32_t *cpk, const uint8_t *sig,
                           const uint8_t *msg, size_t msg_len,
                           int32_t *verdict) {
  const uint8_t *pk = (const uint8_t *)cpk;
  uint32_t entry = entry_bytes(a);
  uint32_t oil_bytes = (entry + 31) & ~UINT32_C(31);

  TRY(acc_testutils_load_app(acc, a->app));

  // A fresh DMEM reads back as zero, which is also the accept code, so stamp
  // the status word first: a verdict then proves FINAL wrote it.
  TRY(write_word(acc, kCtrlAddr + 12, kSentinel));

  // INIT hashes msg || salt (the signature's tail) into the target and folds
  // P1/P2, both expanded from cpk's leading seed. The bus write rounds up to a
  // whole block, of which the kernel hashes only msg_len bytes.
  uint8_t seed[32];
  memset(seed, 0, sizeof(seed));
  memcpy(seed, pk, kSeedBytes);
  TRY(write_word(acc, kCtrlAddr, kVerifyInit));
  TRY(write_word(acc, kCtrlAddr + 4, (uint32_t)msg_len));
  uint32_t slot[UOV_CMD_MAX_SIG_BYTES / sizeof(uint32_t)];
  memset(slot, 0, sizeof(slot));
  memcpy(slot, sig, a->sig_bytes);
  TRY(acc_testutils_write_data(acc, a->sig_slot, slot, a->sig_addr));
  TRY(acc_testutils_write_data(acc, sizeof(seed), seed, a->seed_addr));
  TRY(acc_testutils_write_data(acc, (msg_len + 31) & ~(size_t)31, msg,
                               a->win_addr));
  TRY(verify_phase(acc));

  uint32_t row = 0, entries = 0;
  for (uint32_t w = 0; w < a->windows; ++w) {
    uint32_t rows = a->rows[w];
    uint32_t n = 0;
    for (uint32_t r = row; r < row + rows; ++r) {
      n += a->oil_dim - r;
    }

    uint32_t body = a->win_prefix + n * entry;
    uint32_t total = a->win_fixed
                         ? a->win_fixed
                         : ((body + 31) & ~UINT32_C(31)) + a->win_slack;
    if (total < body) {
      LOG_ERROR("window %d: %d B of entries, %d B window", w, body, total);
      return INTERNAL();
    }

    uint8_t oil[64];  // >= oil_bytes
    oil_window(a, sig, row, oil, oil_bytes);

    TRY(write_word(acc, kCtrlAddr, kVerifyUpdate));
    TRY(write_word(acc, kCtrlAddr + 4, row));
    TRY(write_word(acc, kCtrlAddr + 8, rows));
    TRY(acc_testutils_write_data(acc, oil_bytes, oil, a->oil_addr));
    TRY(write_window(acc, a->win_addr, pk, a->win_prefix, w == 0,
                     entries * entry, body, total));
    TRY(verify_phase(acc));

    row += rows;
    entries += n;
  }

  TRY(write_word(acc, kCtrlAddr, kVerifyFinal));
  TRY(acc_testutils_execute(acc));
  TRY(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));

  int32_t status;
  TRY(acc_testutils_read_data(acc, sizeof(status), kCtrlAddr + 12, &status));
  if (status != kVerifyAccept && status != kVerifyReject) {
    LOG_ERROR("FINAL reported status %d", status);
    return INTERNAL();
  }
  *verdict = status;
  return OK_STATUS();
}

static status_t handle_verify(ujson_t *uj, dif_acc_t *acc,
                              uov_test_scratch_t *s) {
  cryptotest_uov_verify_data_t *d = &s->cmd.verify;
  TRY(ujson_deserialize_cryptotest_uov_verify_data_t(uj, d));

  const uov_verify_app_t *a;
  TRY(verify_app(d->parameter_set, &a));
  if (d->pk_len != a->cpk_bytes || d->signature_len != a->sig_bytes) {
    LOG_ERROR("pk %d B, signature %d B", (uint32_t)d->pk_len,
              (uint32_t)d->signature_len);
    return INVALID_ARGUMENT();
  }

  // cpk is tens of KB, so the host sends it in chunks; both sides derive their
  // number from pk_len.
  for (size_t got = 0; got < d->pk_len;) {
    TRY(ujson_deserialize_cryptotest_uov_pk_chunk_t(uj, &s->chunk));
    if (s->chunk.len == 0 || got + s->chunk.len > d->pk_len) {
      LOG_ERROR("chunk at offset %d is %d B", (uint32_t)got,
                (uint32_t)s->chunk.len);
      return INVALID_ARGUMENT();
    }
    memcpy((uint8_t *)s->cpk + got, s->chunk.data, s->chunk.len);
    got += s->chunk.len;
  }

  int32_t verdict;
  TRY(run_verify(acc, a, s->cpk, d->signature, d->message, d->message_len,
                 &verdict));

  cryptotest_uov_output_t out;
  memset(&out, 0, sizeof(out));
  out.success = (verdict == kVerifyAccept);
  RESP_OK(ujson_serialize_cryptotest_uov_output_t, uj, &out);
  return OK_STATUS();
}

status_t handle_uov(ujson_t *uj, uov_test_scratch_t *s) {
  dif_acc_t acc;
  TRY(dif_acc_init_from_dt((dt_acc_t)0, &acc));

  uov_subcommand_t sub;
  TRY(ujson_deserialize_uov_subcommand_t(uj, &sub));
  switch (sub) {
    case kUovSubcommandUovKeygen:
      return handle_keygen(uj, &acc, s);
    case kUovSubcommandUovSign:
      return handle_sign(uj, &acc, s);
    case kUovSubcommandUovVerify:
      return handle_verify(uj, &acc, s);
    default:
      LOG_ERROR("Unsupported UOV subcommand: %d", sub);
      return INVALID_ARGUMENT();
  }
}
